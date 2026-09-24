"""Terminal BGV modulus reduction for local, authenticated-by-construction fixtures.

Choose P < Q with P = Q (mod t). Round (P/Q)*c to the nearest integer equal
to c modulo t. Before reducing modulo P the rounding error is at most t/2.
For a two-component ciphertext and a ternary secret, the new centered phase
has bound ceil(P*B/Q) + ceil((N+1)*t/2). Reject unless it is below P/2.

Writing the original uncentered phase as v + Q*k, the rounded phase becomes
(P/Q)*v + P*k + e. Centering removes P*k. Its residue modulo t equals v
because every coefficient rounding preserves residue mod t and P = Q mod t.
This is the standard BGV modulus-switching idea specialized to a terminal
two-component result. No correction factor is needed with this modulus choice.

References: BGV, https://eprint.iacr.org/2011/277. This module supplies neither
a security estimate nor response authentication. All private math is variable
time, and all bounds are trusted local metadata, never decryption permissions.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

import gmpy2
from gmpy2 import mpz
import msgpack

from cuhepy.bfv.scheme import _ring_product
from cuhepy.types import BFVPolynomial
from experiments.bfv_search_lab import shallow_bgv as bgv


@dataclass(frozen=True)
class CompactCiphertext:
    components: tuple[BFVPolynomial, BFVPolynomial]
    key_id: str
    modulus: mpz
    phase_bound: int


@lru_cache(maxsize=128)
def terminal_modulus(q: mpz, t: int, bits: int) -> mpz:
    if type(bits) is not int or not 16 <= bits <= 60 or bits >= q.bit_length():
        raise ValueError("Invalid terminal modulus size")
    if not 3 <= t < (1 << (bits - 2)) or t % 2 != 1 or q % t == 0:
        raise ValueError("Invalid terminal plaintext modulus")
    p = mpz((1 << bits) - 1)
    p -= (p - q) % t
    if p % 2 == 0:
        p -= t
    while p >= (1 << (bits - 1)):
        if gmpy2.is_prime(p, 32):
            return p
        p -= 2 * t
    raise ValueError("No terminal prime in the requested interval")


def _round_coefficient(c: mpz, q: mpz, p: mpz, t: int) -> mpz:
    residue = c % t
    return ((2 * (p * c - q * residue) + q * t) // (2 * q * t)) * t + residue


def compact(cipher: bgv.Ciphertext, pk: bgv.PublicKey, bits: int = 32) -> CompactCiphertext:
    bgv._validate(cipher, pk)
    if len(cipher.components) != 2:
        raise ValueError("Terminal BGV reduction requires two components")
    p = terminal_modulus(pk.q, pk.t, bits)
    bound = int((p * cipher.phase_bound + pk.q - 1) // pk.q) + ((pk.n + 1) * pk.t + 1) // 2
    if 2 * bound >= p:
        raise ValueError("Terminal BGV correctness bound exceeds P/2")
    c0, c1 = (tuple(_round_coefficient(c, pk.q, p, pk.t) % p for c in poly)
              for poly in cipher.components)
    return CompactCiphertext((c0, c1), pk.key_id, p, bound)


def _validate(cipher: CompactCiphertext, pk: bgv.PublicKey) -> None:
    if (
        cipher.key_id != pk.key_id or not pk.t < cipher.modulus < pk.q
        or (cipher.modulus - pk.q) % pk.t
        or not 0 <= 2 * cipher.phase_bound < cipher.modulus
        or len(cipher.components) != 2
        or any(len(p) != pk.n or any(not 0 <= c < cipher.modulus for c in p)
               for p in cipher.components)
    ):
        raise ValueError("Invalid compact BGV ciphertext/context")


def decrypt(cipher: CompactCiphertext, pk: bgv.PublicKey, sk: bgv.SecretKey) -> list[int]:
    _validate(cipher, pk)
    if sk.key_id != pk.key_id or len(sk.s) != pk.n or any(c not in (0, 1, pk.q - 1) for c in sk.s):
        raise ValueError("Compact BGV requires the matching ternary secret")
    p = cipher.modulus
    secret = tuple(mpz(p - 1) if c == pk.q - 1 else c for c in sk.s)
    product = _ring_product(cipher.components[1], secret, p)
    phase = [(a + b) % p for a, b in zip(cipher.components[0], product, strict=True)]
    return [int((c if c <= p // 2 else c - p) % pk.t) for c in phase]


def pack(ciphertexts: list[CompactCiphertext], count: int, dimension: int,
         pk: bgv.PublicKey) -> bytes:
    """Measure an explicit local fixture envelope; no network parser is exposed."""
    if type(count) is not int or count < 1 or len(ciphertexts) != (count + pk.n - 1) // pk.n:
        raise ValueError("Invalid compact result count")
    if type(dimension) is not int or not 1 <= dimension <= pk.n // 2 or pk.t <= 2 * dimension:
        raise ValueError("Invalid compact result dimension")
    p = ciphertexts[0].modulus
    for cipher in ciphertexts:
        _validate(cipher, pk)
        if cipher.modulus != p:
            raise ValueError("Mixed compact response moduli")
    bits = p.bit_length()
    header = ["cuhepy-lab-bgv-compact-v1", pk.n, pk.t, p.to_bytes((bits + 7) // 8, "little"),
              bytes.fromhex(pk.key_id), count, dimension]
    body = [[gmpy2.pack(list(poly), bits).to_bytes((pk.n * bits + 7) // 8, "little")
             for poly in cipher.components] for cipher in ciphertexts]
    return msgpack.packb([header, body], use_bin_type=True)
