"""BGV-style coefficient projection and dense result packing reference.

Ring trace preserves positions divisible by D and multiplies them by D. Shift
the selected correlation coefficients there first, project, then combine tiles
by cheap monomial shifts. Invert D after decryption to avoid multiplying the
noise by a large plaintext inverse on the server. Variable-time research code;
no authenticated protocol or cryptographic parameter assurance is supplied.
"""

from __future__ import annotations

from dataclasses import dataclass
import secrets

from gmpy2 import mpz

from cuhepy.bfv.scheme import _automorphism, _ring_product, _small_poly
from cuhepy.types import BFVPolynomial
from experiments.bfv_search_lab import shallow_bgv as bgv

SwitchKey = tuple[tuple[BFVPolynomial, BFVPolynomial], ...]


@dataclass(frozen=True)
class EvaluationKeys:
    key_id: str
    padded: int
    digit_bits: int
    relin: SwitchKey
    rotations: tuple[tuple[int, SwitchKey], ...]
    switch_error_bound: int


def _layout(n: int, padded: int) -> None:
    if type(padded) is not int or not 1 <= padded <= n // 2 or padded & (padded - 1):
        raise ValueError("Invalid trace layout")


def evaluation_keys(
    pk: bgv.PublicKey, sk: bgv.SecretKey, padded: int, digit_bits: int = 30
) -> EvaluationKeys:
    """Owner-only key generation; all returned material is public evaluation data."""
    _layout(pk.n, padded)
    if sk.key_id != pk.key_id or len(sk.s) != pk.n:
        raise ValueError("Wrong trace key context")
    if type(digit_bits) is not int or not 4 <= digit_bits <= 60:
        raise ValueError("Invalid trace gadget width")
    digits = (pk.q.bit_length() + digit_bits - 1) // digit_bits
    switch_bound = pk.t * pk.eta * pk.n * ((1 << digit_bits) - 1) * digits

    def make_key(target: BFVPolynomial) -> SwitchKey:
        columns = []
        for j in range(digits):
            a = tuple(mpz(secrets.randbelow(int(pk.q))) for _ in range(pk.n))
            noise = _small_poly(pk.n, pk.eta, pk.q)
            product = _ring_product(a, sk.s, pk.q)
            power = mpz(1) << (j * digit_bits)
            b = tuple(
                (power * v + pk.t * e - prod) % pk.q
                for v, e, prod in zip(target, noise, product, strict=True)
            )
            columns.append((b, a))
        return tuple(columns)

    relin = make_key(_ring_product(sk.s, sk.s, pk.q))
    generator = 1 + 2 * pk.n // padded
    rotations = tuple(
        (exponent, make_key(_automorphism(sk.s, exponent, pk.q)))
        for exponent in (pow(generator, 1 << j, 2 * pk.n) for j in range(padded.bit_length() - 1))
    )
    return EvaluationKeys(pk.key_id, padded, digit_bits, relin, rotations, switch_bound)


def projected_bound(pk: bgv.PublicKey, keys: EvaluationKeys, tiles: int) -> int:
    """Public worst-case phase bound for one response group, including switches."""
    if keys.key_id != pk.key_id or type(tiles) is not int or not 1 <= tiles <= keys.padded:
        raise ValueError("Invalid trace bound context")
    product = pk.n * pk.fresh_bound**2
    relinearized = product + keys.switch_error_bound
    projected = keys.padded * relinearized + (keys.padded - 1) * keys.switch_error_bound
    return tiles * projected


def _bounded(
    components: tuple[BFVPolynomial, ...], bound: int, pk: bgv.PublicKey
) -> bgv.Ciphertext:
    if 2 * bound >= pk.q:
        raise ValueError("Trace correctness bound exceeds Q/2")
    return bgv.Ciphertext(components, pk.key_id, bound)


def _switch(
    poly: BFVPolynomial, key: SwitchKey, pk: bgv.PublicKey, bits: int
) -> tuple[BFVPolynomial, BFVPolynomial]:
    output = [[mpz(0)] * pk.n for _ in range(2)]
    mask = (mpz(1) << bits) - 1
    for j, column in enumerate(key):
        digits = tuple((c >> (j * bits)) & mask for c in poly)
        for k in range(2):
            product = _ring_product(digits, column[k], pk.q)
            output[k] = [(a + b) % pk.q for a, b in zip(output[k], product, strict=True)]
    return tuple(output[0]), tuple(output[1])


def _add(lhs: bgv.Ciphertext, rhs: bgv.Ciphertext, pk: bgv.PublicKey) -> bgv.Ciphertext:
    components = tuple(
        tuple((a + b) % pk.q for a, b in zip(p, q, strict=True))
        for p, q in zip(lhs.components, rhs.components, strict=True)
    )
    return _bounded(components, lhs.phase_bound + rhs.phase_bound, pk)


def _monomial(cipher: bgv.Ciphertext, shift: int, pk: bgv.PublicKey) -> bgv.Ciphertext:
    components = []
    for poly in cipher.components:
        result = [mpz(0)] * pk.n
        for i, value in enumerate(poly):
            at = (i + shift) % (2 * pk.n)
            result[at % pk.n] = value if at < pk.n else (-value) % pk.q
        components.append(tuple(result))
    return _bounded(tuple(components), cipher.phase_bound, pk)


def project_product(
    query: bgv.Ciphertext, tile: bgv.Ciphertext, pk: bgv.PublicKey, keys: EvaluationKeys
) -> bgv.Ciphertext:
    """Multiply, relinearize, shift and trace; no secret key is available here."""
    if keys.key_id != pk.key_id:
        raise ValueError("Wrong trace evaluation keys")
    _layout(pk.n, keys.padded)
    product = bgv.multiply(query, tile, pk, karatsuba=True)
    switched = _switch(product.components[2], keys.relin, pk, keys.digit_bits)
    reduced = _bounded(
        tuple(
            tuple((a + b) % pk.q for a, b in zip(p, q, strict=True))
            for p, q in zip(product.components[:2], switched, strict=True)
        ),
        product.phase_bound + keys.switch_error_bound,
        pk,
    )
    result = _monomial(reduced, -(keys.padded - 1), pk)
    for exponent, switch_key in keys.rotations:
        c0, c1 = (_automorphism(poly, exponent, pk.q) for poly in result.components)
        b, a = _switch(c1, switch_key, pk, keys.digit_bits)
        rotated = _bounded(
            (tuple((x + y) % pk.q for x, y in zip(c0, b, strict=True)), a),
            result.phase_bound + keys.switch_error_bound,
            pk,
        )
        result = _add(result, rotated, pk)
    return result


def search(
    query: bgv.Ciphertext,
    index: list[bgv.Ciphertext],
    count: int,
    pk: bgv.PublicKey,
    keys: EvaluationKeys,
) -> list[bgv.Ciphertext]:
    _layout(pk.n, keys.padded)
    capacity = pk.n // keys.padded
    if type(count) is not int or count < 0 or len(index) != (count + capacity - 1) // capacity:
        raise ValueError("Invalid trace index shape")
    bgv._validate(query, pk)
    result = []
    for start in range(0, len(index), keys.padded):
        tiles = index[start : start + keys.padded]
        if 2 * projected_bound(pk, keys, len(tiles)) >= pk.q:
            raise ValueError("Trace correctness bound exceeds Q/2")
        combined = None
        for offset, tile in enumerate(tiles):
            shifted = _monomial(project_product(query, tile, pk, keys), offset, pk)
            combined = shifted if combined is None else _add(combined, shifted, pk)
        assert combined is not None
        result.append(combined)
    return result


def decode(
    plaintexts: list[list[int]],
    count: int,
    dimension: int,
    pk: bgv.PublicKey,
) -> list[int]:
    if type(dimension) is not int or not 1 <= dimension <= pk.n // 2 or pk.t <= 2 * dimension:
        raise ValueError("Invalid trace decode dimension/modulus")
    padded = 1 << (dimension - 1).bit_length()
    capacity, inverse = pk.n // padded, pow(padded, -1, pk.t)
    if (
        type(count) is not int
        or count < 0
        or len(plaintexts) != (count + pk.n - 1) // pk.n
        or any(
            len(poly) != pk.n or any(type(x) is not int or not 0 <= x < pk.t for x in poly)
            for poly in plaintexts
        )
    ):
        raise ValueError("Invalid trace response shape")
    result = []
    for group, poly in enumerate(plaintexts):
        for position in range(min(pk.n, count - group * pk.n)):
            tile, lane = divmod(position, capacity)
            dot = poly[lane * padded + tile] * inverse % pk.t
            if dot > pk.t // 2:
                dot -= pk.t
            if not -dimension <= dot <= dimension or (dimension - dot) % 2:
                raise ValueError("Invalid trace correlation")
            result.append((dimension - dot) // 2)
    return result
