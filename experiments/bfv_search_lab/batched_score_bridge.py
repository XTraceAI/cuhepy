"""E87 exact public switching controls, not production encryption or a SNARK.

Plus-sign phases, odd-modulus balanced digits, bounded schoolbook arithmetic.
Toy key generation belongs in the tests/runner. Public keys contain no secrets.
Full recomputation receivers authenticate only owner-approved switch inputs;
they do not prove the upstream search, PBS or winner coverage.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from math import gcd


def context(q, radix):
    if (type(q) is not int or not 3 <= q < 1 << 64 or q % 2 == 0
            or type(radix) is not int or not 3 <= radix <= 257 or radix % 2 == 0):
        raise ValueError("Bounded odd modulus and odd radix required")
    levels, capacity = 0, 1
    while capacity < q:
        levels += 1
        capacity *= radix
    return levels


def centered(value, q):
    if type(value) is not int or not 0 <= value < q:
        raise ValueError("Noncanonical residue")
    return value if value <= q // 2 else value - q


def digits(value, q, radix):
    levels = context(q, radix)
    remaining, half, result = centered(value, q), radix // 2, []
    for _ in range(levels):
        digit = (remaining + half) % radix - half
        result.append(digit)
        remaining = (remaining - digit) // radix
    assert remaining == 0
    return tuple(result)


def _poly(poly, n, q):
    if (type(poly) is not tuple or len(poly) != n
            or any(type(x) is not int or not 0 <= x < q for x in poly)):
        raise ValueError("Noncanonical polynomial")


def _components(components, q):
    if (type(components) is not tuple or len(components) not in (2, 3)
            or type(components[0]) is not tuple):
        raise ValueError("Expected C0/C1 and optional C2")
    n = len(components[0])
    if not 2 <= n <= 16 or n & (n - 1):
        raise ValueError("Bounded power-of-two degree required")
    for poly in components:
        _poly(poly, n, q)
    return n


def convolution(left, right, q):
    """Independent integer schoolbook convolution; signed digits are allowed."""
    if len(left) != len(right):
        raise ValueError("Mixed convolution degree")
    n, result = len(left), [0] * len(left)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            result[(i + j) % n] += a * b * (1 if i + j < n else -1)
    return tuple(x % q for x in result)


def decompose(components, q, radix):
    n, levels = _components(components, q), context(q, radix)
    return tuple(tuple(tuple(digits(x, q, radix)[level] for x in poly)
                       for level in range(levels)) for poly in components[1:])


@dataclass(frozen=True)
class Scalar:
    a: tuple[int, ...]
    b: int


@dataclass(frozen=True)
class ColumnKeys:
    # family, coefficient, level; each entry is an ordinary scalar LWE body.
    q: int
    radix: int
    values: tuple[tuple[tuple[Scalar, ...], ...], ...]


@dataclass(frozen=True)
class PackedKeys:
    # family, level, (mask polynomial, body polynomial). Secret is a prefix.
    q: int
    radix: int
    target_dimension: int
    values: tuple[tuple[tuple[tuple[int, ...], tuple[int, ...]], ...], ...]


def _validate_keys(keys, components):
    if type(keys) not in (ColumnKeys, PackedKeys):
        raise ValueError("Unknown switch-key format")
    levels, n = context(keys.q, keys.radix), _components(components, keys.q)
    if type(keys.values) is not tuple or len(keys.values) != len(components) - 1:
        raise ValueError("Missing or extra key family")
    if type(keys) is ColumnKeys:
        dimension = None
        for family in keys.values:
            if type(family) is not tuple or len(family) != n:
                raise ValueError("Incomplete coefficient keys")
            for row in family:
                if type(row) is not tuple or len(row) != levels:
                    raise ValueError("Incomplete gadget keys")
                for sample in row:
                    if type(sample) is not Scalar or type(sample.a) is not tuple:
                        raise ValueError("Noncanonical scalar key")
                    if dimension is None:
                        dimension = len(sample.a)
                    if not 1 <= dimension <= 16:
                        raise ValueError("Bounded scalar dimension required")
                    _poly(sample.a, dimension, keys.q)
                    centered(sample.b, keys.q)
    else:
        dimension = keys.target_dimension
        if type(dimension) is not int or not 1 <= dimension <= n:
            raise ValueError("Partial-key prefix exceeds polynomial degree")
        for family in keys.values:
            if type(family) is not tuple or len(family) != levels:
                raise ValueError("Incomplete packed gadget keys")
            for pair in family:
                if type(pair) is not tuple or len(pair) != 2:
                    raise ValueError("Incomplete packed key ciphertext")
                for poly in pair:
                    _poly(poly, n, keys.q)
    return n, levels, dimension


def literal_switch(components, keys):
    n, levels, dimension = _validate_keys(keys, components)
    if type(keys) is not ColumnKeys:
        raise ValueError("Literal scalar control needs scalar keys")
    result = []
    for k in range(n):
        values = [0] * dimension + [components[0][k]]
        for family, poly in zip(keys.values, components[1:], strict=True):
            for j in range(n):
                mask = (poly[k - j] if j <= k else -poly[k - j + n]) % keys.q
                for level, digit in enumerate(digits(mask, keys.q, keys.radix)):
                    sample = family[j][level]
                    for v, coordinate in enumerate((*sample.a, sample.b)):
                        values[v] += digit * coordinate
        result.append(Scalar(tuple(x % keys.q for x in values[:-1]), values[-1] % keys.q))
    return tuple(result)


def column_switch(components, keys):
    n, levels, dimension = _validate_keys(keys, components)
    if type(keys) is not ColumnKeys:
        raise ValueError("Column convolution needs scalar keys")
    decomposed, outputs = decompose(components, keys.q, keys.radix), [[0] * n for _ in range(dimension + 1)]
    outputs[-1] = list(components[0])
    for family, digit_polys in zip(keys.values, decomposed, strict=True):
        for level in range(levels):
            for v in range(dimension + 1):
                key_poly = tuple((*row[level].a, row[level].b)[v] for row in family)
                product = convolution(digit_polys[level], key_poly, keys.q)
                outputs[v] = [x + y for x, y in zip(outputs[v], product, strict=True)]
    return tuple(Scalar(tuple(outputs[v][k] % keys.q for v in range(dimension)),
                        outputs[-1][k] % keys.q) for k in range(n))


def packed_switch(components, keys):
    n, levels, _ = _validate_keys(keys, components)
    if type(keys) is not PackedKeys:
        raise ValueError("Packed switch requires polynomial keys")
    outputs = [[0] * n, list(components[0])]
    for family, digit_polys in zip(keys.values, decompose(components, keys.q, keys.radix), strict=True):
        for level in range(levels):
            for v in range(2):
                product = convolution(digit_polys[level], family[level][v], keys.q)
                outputs[v] = [x + y for x, y in zip(outputs[v], product, strict=True)]
    return tuple(tuple(x % keys.q for x in poly) for poly in outputs)


def extract_packed(output, k, dimension, q):
    if (type(output) is not tuple or len(output) != 2 or type(output[0]) is not tuple
            or type(k) is not int or not 0 <= k < len(output[0])
            or type(dimension) is not int or not 1 <= dimension <= len(output[0])):
        raise ValueError("Invalid extraction position or prefix")
    n = len(output[0])
    for poly in output:
        _poly(poly, n, q)
    return Scalar(tuple((output[0][k - j] if j <= k else -output[0][k - j + n]) % q
                        for j in range(dimension)), output[1][k])


def from_rns(limbs, moduli):
    """Reconstruct EVERY component from a complete, canonical public RNS input."""
    if (type(moduli) is not tuple or not 1 <= len(moduli) <= 4
            or any(type(p) is not int or not 3 <= p <= 65537 or p % 2 == 0 for p in moduli)
            or any(gcd(a, b) != 1 for i, a in enumerate(moduli) for b in moduli[i + 1:])
            or type(limbs) is not tuple or len(limbs) != len(moduli)):
        raise ValueError("Incomplete/coprime RNS context required")
    count, n, q = len(limbs[0]), _components(limbs[0], moduli[0]), 1
    for p, component in zip(moduli, limbs, strict=True):
        if len(component) != count or _components(component, p) != n:
            raise ValueError("RNS component mismatch")
        q *= p
    if q >= 1 << 64:
        raise ValueError("Toy CRT bound exceeded")
    weights = tuple(q // p * pow(q // p, -1, p) for p in moduli)
    return tuple(tuple(sum(limb[f][k] * weight for limb, weight in zip(limbs, weights, strict=True)) % q
                       for k in range(n)) for f in range(count))


@dataclass(frozen=True)
class ApprovedInput:
    epoch: str
    components: tuple[tuple[int, ...], ...]
    keys: ColumnKeys | PackedKeys
    positions: tuple[int, ...]
    digest: str


@dataclass(frozen=True)
class Transcript:
    epoch: str
    input_digest: str
    positions: tuple[int, ...]
    digit_polys: tuple[tuple[tuple[int, ...], ...], ...]
    output: tuple


def register(epoch, components, keys, positions):
    n, _, _ = _validate_keys(keys, components)
    if (type(epoch) is not str or not 1 <= len(epoch) <= 64 or not epoch.isascii()
            or type(positions) is not tuple or not 1 <= len(positions) <= n
            or any(type(k) is not int or not 0 <= k < n for k in positions)
            or len(set(positions)) != len(positions)):
        raise ValueError("Invalid owner epoch/ordered score coverage")
    public = {"domain": "E87-owner-approved-switch-only-v1", "epoch": epoch,
              "components": components, "keys": asdict(keys), "key_format": type(keys).__name__,
              "positions": positions}
    digest = hashlib.sha256(json.dumps(public, separators=(",", ":")).encode()).hexdigest()
    return ApprovedInput(epoch, components, keys, positions, digest)


def recompute(approved):
    if type(approved) is not ApprovedInput:
        raise ValueError("Trusted registration required")
    operation = column_switch if type(approved.keys) is ColumnKeys else packed_switch
    return Transcript(approved.epoch, approved.digest, approved.positions,
                      decompose(approved.components, approved.keys.q, approved.keys.radix),
                      operation(approved.components, approved.keys))


def verify_recomputation(approved, transcript):
    """Fail closed BEFORE private work, paying the full recomputation control.

    No decryption callback, hidden evaluation point or feedback security claim.
    Python equality/timing is public; this is only a bounded local receiver.
    """
    if type(approved) is not ApprovedInput or type(transcript) is not Transcript:
        return False
    q, radix = approved.keys.q, approved.keys.radix
    n, levels, dimension = _validate_keys(approved.keys, approved.components)
    if (type(transcript.epoch) is not str or type(transcript.input_digest) is not str
            or type(transcript.positions) is not tuple
            or any(type(x) is not int for x in transcript.positions)
            or type(transcript.digit_polys) is not tuple
            or len(transcript.digit_polys) != len(approved.components) - 1):
        return False
    for family in transcript.digit_polys:
        if type(family) is not tuple or len(family) != levels:
            return False
        for poly in family:
            if (type(poly) is not tuple or len(poly) != n
                    or any(type(x) is not int or abs(x) > radix // 2 for x in poly)):
                return False
    try:
        if type(transcript.output) is not tuple:
            return False
        if type(approved.keys) is ColumnKeys:
            if len(transcript.output) != n:
                return False
            for sample in transcript.output:
                if type(sample) is not Scalar:
                    return False
                _poly(sample.a, dimension, q)
                centered(sample.b, q)
        else:
            if len(transcript.output) != 2:
                return False
            for poly in transcript.output:
                _poly(poly, n, q)
    except ValueError:
        return False
    return transcript == recompute(approved)
