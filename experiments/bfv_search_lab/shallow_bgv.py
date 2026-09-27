"""Depth-one BGV-style RLWE reference with an explicit correctness bound.

This is an experimental alternative to BFV, not a complete leveled BGV library:
no modulus switching, relinearization, rotations, authentication or security
parameter approval. Products remain three-component ciphertexts. All private
operations use variable-time Python/GMP and are for local synthetic experiments.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets

import gmpy2
from gmpy2 import mpz

from cuhepy.bfv.scheme import _coefficient_modulus, _rns_coefficient_primes, _ring_product, _small_poly, _ternary_poly
from cuhepy.types import BFVPolynomial


@dataclass(frozen=True)
class PublicKey:
    n: int
    t: int
    q: mpz
    eta: int
    a: BFVPolynomial
    b: BFVPolynomial
    key_id: str

    @property
    def fresh_bound(self) -> int:
        # m + t*(e*u + e0 + e1*s); each error coefficient is in [-eta,eta]
        # and each ternary coefficient in [-1,1]. Negacyclic signs do not change
        # the infinity-norm product bound N*||a||inf*||b||inf.
        return self.t // 2 + self.t * self.eta * (2 * self.n + 1)


@dataclass(frozen=True)
class SecretKey:
    s: BFVPolynomial
    key_id: str


@dataclass(frozen=True)
class Ciphertext:
    components: tuple[BFVPolynomial, ...]
    key_id: str
    phase_bound: int  # Public conservative bound, not a private noise diagnostic.


def key_gen(n: int, t: int = 1031, q_bits: int = 180, eta: int = 21,
            *, rns_modulus: bool = False) -> tuple[PublicKey, SecretKey]:
    if (
        type(n) is not int
        or not 8 <= n <= 32768
        or n & (n - 1)
        or type(t) is not int
        or not 3 <= t < (1 << 30)
        or t % 2 != 1
        or type(q_bits) is not int
        or not 32 <= q_bits <= 240
        or type(eta) is not int
        or not 1 <= eta <= 64
        or type(rns_modulus) is not bool
    ):
        raise ValueError("Invalid shallow BGV fixture parameters")
    # An opt-in product modulus enables persistent RNS public evaluation. It
    # changes the key context and requires a newly encrypted index.
    q = mpz(1) if rns_modulus else _coefficient_modulus(q_bits)
    if rns_modulus:
        for prime in _rns_coefficient_primes(n, q_bits):
            q *= prime
    fresh_bound = t // 2 + t * eta * (2 * n + 1)
    if 2 * n * fresh_bound**2 >= q:
        raise ValueError("Q is too small for the conservative one-product correctness bound")
    s = _ternary_poly(n, q)
    a = tuple(mpz(secrets.randbelow(int(q))) for _ in range(n))
    e = _small_poly(n, eta, q)
    product = _ring_product(a, s, q)
    b = tuple((t * error - value) % q for error, value in zip(e, product, strict=True))
    digest = hashlib.sha256(f"cuhepy-shallow-bgv-v1:{n}:{t}:{q}:{eta}".encode())
    for poly in (a, b):
        digest.update(int(gmpy2.pack(list(poly), q_bits)).to_bytes((n * q_bits + 7) // 8, "little"))
    key_id = digest.hexdigest()
    return PublicKey(n, t, q, eta, a, b, key_id), SecretKey(s, key_id)


def _validate(cipher: Ciphertext, pk: PublicKey) -> None:
    if (
        cipher.key_id != pk.key_id
        or len(cipher.components) not in (2, 3)
        or not 0 <= cipher.phase_bound < pk.q // 2
        or any(
            len(poly) != pk.n or any(not 0 <= x < pk.q for x in poly) for poly in cipher.components
        )
    ):
        raise ValueError("Invalid shallow BGV ciphertext/context")


def encrypt(plaintext: list[int], pk: PublicKey) -> Ciphertext:
    if len(plaintext) != pk.n or any(type(x) is not int for x in plaintext):
        raise ValueError("Expected N integer plaintext coefficients")
    message = [((x + pk.t // 2) % pk.t) - pk.t // 2 for x in plaintext]
    u = _ternary_poly(pk.n, pk.q)
    e0, e1 = _small_poly(pk.n, pk.eta, pk.q), _small_poly(pk.n, pk.eta, pk.q)
    bu, au = _ring_product(pk.b, u, pk.q), _ring_product(pk.a, u, pk.q)
    c0 = tuple((v + pk.t * e + m) % pk.q for v, e, m in zip(bu, e0, message, strict=True))
    c1 = tuple((v + pk.t * e) % pk.q for v, e in zip(au, e1, strict=True))
    return Ciphertext((c0, c1), pk.key_id, pk.fresh_bound)


def multiply(
    lhs: Ciphertext, rhs: Ciphertext, pk: PublicKey, *, karatsuba: bool = False
) -> Ciphertext:
    _validate(lhs, pk)
    _validate(rhs, pk)
    if len(lhs.components) != 2 or len(rhs.components) != 2:
        raise ValueError("Only one ciphertext multiplication is supported")
    bound = pk.n * lhs.phase_bound * rhs.phase_bound
    if 2 * bound >= pk.q:
        raise ValueError("One-product correctness bound exceeded")
    a0, a1 = lhs.components
    b0, b1 = rhs.components
    c0, c2 = _ring_product(a0, b0, pk.q), _ring_product(a1, b1, pk.q)
    if karatsuba:
        # All terms are in R_q: unlike BFV scaling, no wide integer lift is
        # required. One extra product recovers both cross terms exactly.
        left = tuple((a + b) % pk.q for a, b in zip(a0, a1, strict=True))
        right = tuple((a + b) % pk.q for a, b in zip(b0, b1, strict=True))
        cross = _ring_product(left, right, pk.q)
        c1 = tuple((v - a - b) % pk.q for v, a, b in zip(cross, c0, c2, strict=True))
    else:
        cross0, cross1 = _ring_product(a0, b1, pk.q), _ring_product(a1, b0, pk.q)
        c1 = tuple((a + b) % pk.q for a, b in zip(cross0, cross1, strict=True))
    return Ciphertext((c0, c1, c2), pk.key_id, bound)


def decrypt(cipher: Ciphertext, pk: PublicKey, sk: SecretKey) -> list[int]:
    _validate(cipher, pk)
    if sk.key_id != pk.key_id or len(sk.s) != pk.n:
        raise ValueError("Wrong shallow BGV secret key")
    phase = cipher.components[-1]
    for poly in reversed(cipher.components[:-1]):
        product = _ring_product(phase, sk.s, pk.q)
        phase = tuple((a + b) % pk.q for a, b in zip(poly, product, strict=True))
    return [int((c if c <= pk.q // 2 else c - pk.q) % pk.t) for c in phase]


def coefficient_inputs(
    query: list[int], vectors: list[list[int]], n: int
) -> tuple[list[int], list[list[int]]]:
    """Signed coefficient layout shared with the independent plaintext oracle."""
    d = len(query)
    if not d or any(x not in (0, 1) for x in query):
        raise ValueError("Expected a nonempty binary query")
    padded = 1 << (d - 1).bit_length()
    if n < padded or n % padded:
        raise ValueError("Invalid coefficient layout ring")
    capacity = n // padded
    backward = [0] * n
    for j, bit in enumerate(query):
        backward[padded - 1 - j] = 1 - 2 * bit
    tiles = []
    for start in range(0, len(vectors), capacity):
        tile = [0] * n
        for lane, vector in enumerate(vectors[start : start + capacity]):
            if len(vector) != d or any(x not in (0, 1) for x in vector):
                raise ValueError("Invalid binary index vector")
            for j, bit in enumerate(vector):
                tile[lane * padded + j] = 1 - 2 * bit
        tiles.append(tile)
    return backward, tiles


def decode_coefficients(
    polynomials: list[list[int]], count: int, dimension: int, n: int, t: int
) -> list[int]:
    if type(dimension) is not int or dimension < 1 or type(n) is not int or n < dimension:
        raise ValueError("Invalid coefficient response layout")
    padded = 1 << (dimension - 1).bit_length()
    if n % padded:
        raise ValueError("Invalid coefficient response layout")
    capacity = n // padded
    if (
        t <= 2 * dimension
        or type(count) is not int
        or count < 0
        or len(polynomials) != (count + capacity - 1) // capacity
        or any(
            len(poly) != n or any(type(x) is not int or not 0 <= x < t for x in poly)
            for poly in polynomials
        )
    ):
        raise ValueError("Invalid coefficient response shape/modulus")
    result = []
    for group, poly in enumerate(polynomials):
        for lane in range(min(capacity, count - group * capacity)):
            dot = poly[lane * padded + padded - 1]
            if dot > t // 2:
                dot -= t
            if not -dimension <= dot <= dimension or (dimension - dot) % 2:
                raise ValueError("Invalid signed correlation")
            result.append((dimension - dot) // 2)
    return result
