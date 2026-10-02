"""E91 exact public quadratic drift controls, not parameter or protocol assurance.

GMP supplies integer arithmetic; polynomial packing, moments and verification
are homemade. No SEAL/PBS or floating arithmetic participates in a bound.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json

import gmpy2


def _ones(length, bits):
    one = gmpy2.mpz(1)
    return ((one << (length * bits)) - 1) // ((one << bits) - 1)


def linear_product(left, right):
    """Exact signed Kronecker product with a strict, explicitly priced bit bound."""
    n = len(left)
    if len(right) != n or not 2 <= n <= 16384 or n & (n - 1):
        raise ValueError("Bounded equal power-of-two polynomial lengths required")
    a, b = max(map(abs, left)), max(map(abs, right))
    if a == 0 or b == 0:
        return (0,) * (2 * n - 1)
    bound = n * int(a) * int(b)
    bits = (2 * bound).bit_length()
    # Offset packing uses GMP's linear array pack/unpack, rather than N shifts.
    pa = gmpy2.pack([int(x + a) for x in left], bits) - a * _ones(n, bits)
    pb = gmpy2.pack([int(x + b) for x in right], bits) - b * _ones(n, bits)
    digits = gmpy2.unpack(pa * pb + bound * _ones(2 * n - 1, bits), bits)
    digits.extend([gmpy2.mpz(0)] * (2 * n - 1 - len(digits)))
    assert len(digits) == 2 * n - 1
    return tuple(int(x - bound) for x in digits)


def ring_product(left, right):
    raw, n = linear_product(left, right), len(left)
    return tuple(raw[i] - (raw[i + n] if i + n < len(raw) else 0) for i in range(n))


def circular_product(left, right):
    raw, n = linear_product(left, right), len(left)
    return tuple(raw[i] + (raw[i + n] if i + n < len(raw) else 0) for i in range(n))


def star(poly):
    return (poly[0], *(-x for x in reversed(poly[1:])))


def ceil_root(value, degree):
    if type(value) is not int or value < 0 or type(degree) is not int or degree not in (2, 4, 8, 16):
        raise ValueError("Nonnegative exact even-root input required")
    root, exact = gmpy2.iroot(value, degree)
    return int(root) + int(not exact)


@dataclass(frozen=True)
class Moment:
    power: int
    polynomial: tuple[int, ...]
    trace: int
    root_upper: int


def moments(poly):
    current, result = ring_product(poly, star(poly)), []
    for power in (1, 2, 4, 8):
        if power > 1:
            current = ring_product(current, current)
        trace = len(poly) * current[0]
        assert trace >= 0
        result.append(Moment(power, current, trace, ceil_root(trace, 2 * power)))
    return tuple(result)


def linear_bound(poly, prefix):
    # Max cyclic window gives every output's exact coefficient-box bound.
    n, current = len(poly), sum(abs(x) for x in poly[:prefix])
    maximum = current
    for start in range(1, n):
        current += abs(poly[(start + prefix - 1) % n]) - abs(poly[start - 1])
        maximum = max(maximum, current)
    return maximum


def quadratic_box(poly, prefix):
    # A stronger control than D^2*max(abs(poly)): charge each ordered pair.
    support = (1,) * prefix + (0,) * (len(poly) - prefix)
    pairs = circular_product(support, support)
    return max(circular_product(tuple(map(abs, poly)), pairs))


@dataclass(frozen=True)
class Approved:
    q: int
    target: int
    prefix: int
    components: tuple[tuple[int, ...], ...]
    context_id: str
    key_id: str
    epoch: str
    drift_budget_numerator: int


def validate(approved):
    if (type(approved) is not Approved or type(approved.q) is not int or not 3 <= approved.q < 1 << 64
            or approved.q % 2 == 0 or type(approved.target) is not int
            or not 2 <= approved.target <= 1 << 64 or approved.target & (approved.target - 1)
            or type(approved.components) is not tuple or len(approved.components) != 3
            or type(approved.components[0]) is not tuple
            or any(type(s) is not str or not 1 <= len(s) <= 64
                   for s in (approved.context_id, approved.key_id, approved.epoch))
            or type(approved.drift_budget_numerator) is not int
            or not 0 <= approved.drift_budget_numerator < 1 << 256):
        raise ValueError("Invalid owner-approved public rounding context")
    n = len(approved.components[0])
    if (not 2 <= n <= 16384 or n & (n - 1) or type(approved.prefix) is not int
            or not 1 <= approved.prefix <= n
            or any(type(poly) is not tuple or len(poly) != n
                   or any(type(x) is not int or not 0 <= x < approved.q for x in poly)
                   for poly in approved.components)):
        raise ValueError("Canonical bounded C0/C1/C2 and public key prefix required")
    return n


def anchor(approved):
    validate(approved)
    body = json.dumps(asdict(approved), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(b"E91-public-drift-subrelation-v1\0" + body).hexdigest()


@dataclass(frozen=True)
class Certificate:
    anchor: str
    rounded: tuple[tuple[int, ...], ...]
    drift: tuple[tuple[int, ...], ...]
    moments: tuple[Moment, ...]
    body_bound: int
    linear_bound: int
    quadratic_box_bound: int
    quadratic_moment_bound: int
    total_bound: int


def build(approved):
    validate(approved)
    raw = tuple(tuple((2 * approved.target * x + approved.q) // (2 * approved.q) for x in poly)
                for poly in approved.components)
    drift = tuple(tuple(approved.q * r - approved.target * x for r, x in zip(out, src, strict=True))
                  for out, src in zip(raw, approved.components, strict=True))
    computed = moments(drift[2])
    body, linear = max(map(abs, drift[0])), linear_bound(drift[1], approved.prefix)
    box, spectral = quadratic_box(drift[2], approved.prefix), approved.prefix * min(m.root_upper for m in computed)
    rounded = tuple(tuple(x % approved.target for x in poly) for poly in raw)
    return Certificate(anchor(approved), rounded, drift, computed, body, linear, box, spectral,
                       body + linear + min(box, spectral))


def verify_and_release(approved, certificate, callback):
    """Paid full public subrelation check; callback is not a decryption authorization.

Original-score authentication and source-key/noise premises remain external.
Tests use an opaque callback to check that failures invoke no private work.
"""
    n = validate(approved)
    if (type(certificate) is not Certificate or type(certificate.anchor) is not str
            or certificate.anchor != anchor(approved)
            or type(certificate.moments) is not tuple or len(certificate.moments) != 4):
        raise ValueError("Wrong public certificate context or framing")
    for arrays in (certificate.rounded, certificate.drift):
        if (type(arrays) is not tuple or len(arrays) != 3
                or any(type(poly) is not tuple or len(poly) != n
                       or any(type(x) is not int or abs(x) >= 1 << 128 for x in poly) for poly in arrays)):
            raise ValueError("Missing or oversized rounding/drift coefficient")
    for moment, power in zip(certificate.moments, (1, 2, 4, 8), strict=True):
        if (type(moment) is not Moment or type(moment.power) is not int or moment.power != power
                or type(moment.polynomial) is not tuple or len(moment.polynomial) != n
                or any(type(x) is not int or abs(x) >= 1 << 2048 for x in moment.polynomial)
                or type(moment.trace) is not int or not 0 <= moment.trace < 1 << 2048
                or type(moment.root_upper) is not int or not 0 <= moment.root_upper < 1 << 256):
            raise ValueError("Noncanonical integer moment")
    if any(type(x) is not int or not 0 <= x < 1 << 256 for x in
           (certificate.body_bound, certificate.linear_bound, certificate.quadratic_box_bound,
            certificate.quadratic_moment_bound, certificate.total_bound)):
        raise ValueError("Noncanonical public bound")
    if certificate != build(approved):
        raise ValueError("False rounding, polynomial trace, root or bound")
    if certificate.total_bound > approved.drift_budget_numerator:
        raise ValueError("Public certified drift exceeds the approved budget")
    return callback(certificate)
