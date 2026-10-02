"""E85 public exact-arithmetic score-phase interface controls.

This is homemade bounded arithmetic, not an HE key switch, bootstrap, proof,
private-key API or production sampler. Sample extraction/modulus switching are
known controls. The repository's plus-sign phase convention is used throughout.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from math import gcd, prod


def _modulus(q):
    if type(q) is not int or not 3 <= q <= 65537:
        raise ValueError("Expected bounded modulus")


def _vector(values, q):
    _modulus(q)
    if (type(values) is not tuple or not 1 <= len(values) <= 16
            or any(type(x) is not int or not 0 <= x < q for x in values)):
        raise ValueError("Expected bounded canonical vector")


def nearest(numerator, denominator):
    """Nearest integer with ties toward +infinity, including negative values."""
    if (type(numerator) is not int or type(denominator) is not int
            or denominator < 1):
        raise ValueError("Expected integer numerator and positive denominator")
    return (2 * numerator + denominator) // (2 * denominator)


def ring_product(left, right, q):
    _vector(left, q)
    _vector(right, q)
    if len(left) != len(right):
        raise ValueError("Mismatched ring degrees")
    # Independent schoolbook convolution retains the wrap sign explicitly.
    n, result = len(left), [0] * len(left)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            result[(i + j) % n] += a * b * (1 if i + j < n else -1)
    return tuple(x % q for x in result)


def secret_powers(secret, q, components):
    _vector(secret, q)
    if type(components) is not int or not 2 <= components <= 3:
        raise ValueError("Expected C0/C1 or C0/C1/C2")
    return (secret,) if components == 2 else (secret, ring_product(secret, secret, q))


def ring_phase(components, secret, q):
    if type(components) is not tuple or not 2 <= len(components) <= 3:
        raise ValueError("Expected immutable components")
    powers = secret_powers(secret, q, len(components))
    for poly in components:
        _vector(poly, q)
        if len(poly) != len(secret):
            raise ValueError("Mismatched ring degrees")
    phase = list(components[0])
    for poly, power in zip(components[1:], powers, strict=True):
        phase = [(a + b) % q for a, b in zip(phase, ring_product(poly, power, q), strict=True)]
    return tuple(phase)


@dataclass(frozen=True)
class Sample:
    a: tuple[int, ...]
    b: int
    q: int


def _sample(sample):
    if type(sample) is not Sample:
        raise ValueError("Expected public sample")
    _vector(sample.a, sample.q)
    if type(sample.b) is not int or not 0 <= sample.b < sample.q:
        raise ValueError("Expected canonical body")


def extract(components, coefficient, q):
    """Copy/sign-permute all nonconstant ciphertext components; no secret read."""
    if type(components) is not tuple or not 2 <= len(components) <= 3:
        raise ValueError("Expected two or three immutable ciphertext components")
    for poly in components:
        _vector(poly, q)
    n = len(components[0])
    if (any(len(poly) != n for poly in components)
            or (len(components) - 1) * n > 16
            or type(coefficient) is not int or not 0 <= coefficient < n):
        raise ValueError("Invalid bounded extraction geometry")
    a = tuple((poly[coefficient - j] if j <= coefficient else -poly[coefficient - j + n]) % q
              for poly in components[1:] for j in range(n))
    return Sample(a, components[0][coefficient], q)


def sample_phase(sample, secret):
    """Local public-oracle diagnostic. Never use as a remote decryption API."""
    _sample(sample)
    if (type(secret) is not tuple or len(secret) != len(sample.a)
            or any(type(x) is not int or abs(x) > 65537 for x in secret)):
        raise ValueError("Expected bounded signed diagnostic secret")
    return (sample.b + sum(a * s for a, s in zip(sample.a, secret, strict=True))) % sample.q


def scale_sample(sample, target, divisor):
    """Public rounded scaling. Only divisor==Q is ordinary modulus switching."""
    _sample(sample)
    _modulus(target)
    if type(divisor) is not int or not 1 <= divisor <= 65537:
        raise ValueError("Invalid scale divisor")
    return Sample(tuple(nearest(target * x, divisor) % target for x in sample.a),
                  nearest(target * sample.b, divisor) % target, target)


def decode_scaled(phase, q, t):
    _modulus(q)
    if (type(phase) is not int or not 0 <= phase < q
            or type(t) is not int or not 2 <= t < q):
        raise ValueError("Invalid scaled phase/domain")
    return nearest(t * phase, q) % t


def decode_bgv(phase, q, t):
    _modulus(q)
    if (type(phase) is not int or not 0 <= phase < q
            or type(t) is not int or not 2 <= t < q):
        raise ValueError("Invalid centered phase/domain")
    return (phase if phase <= q // 2 else phase - q) % t


def bfv_switch_bound(q, t, target, noise_bound, secret_l1):
    """Sufficient worst-case torus distance from B*m/t for every m in 0..t-1.

    The floor remainder contributes (Q mod t)*m/t, and each rounded public
    coefficient contributes at most 1/2 times its signed secret magnitude.
    This bound excludes key switching/PBS and assumes a true bounded BFV phase.
    """
    _modulus(q)
    _modulus(target)
    if (type(t) is not int or not 2 <= t < min(q, target)
            or any(type(x) is not int or x < 0 for x in (noise_bound, secret_l1))):
        raise ValueError("Invalid conditional rounding bound")
    error = Fraction(target, q) * (noise_bound + Fraction((q % t) * (t - 1), t))
    error += Fraction(1 + secret_l1, 2)
    margin = Fraction(target, 2 * t)
    return {"error_bound": error, "nearest_message_margin": margin,
            "sufficient_strict_margin": error < margin}


def crt_value(residues, moduli):
    """Canonical CRT reconstruction, with context/canonicality validation."""
    if (type(moduli) is not tuple or type(residues) is not tuple
            or not 2 <= len(moduli) <= 4 or len(moduli) != len(residues)
            or any(type(p) is not int or p < 3 for p in moduli)
            or any(gcd(p, r) != 1 for i, p in enumerate(moduli) for r in moduli[i + 1:])
            or prod(moduli) > 65537
            or any(type(x) is not int or not 0 <= x < p for x, p in zip(residues, moduli, strict=True))):
        raise ValueError("Invalid bounded CRT context/residues")
    q = prod(moduli)
    return sum(x * (q // p) * pow(q // p, -1, p)
               for x, p in zip(residues, moduli, strict=True)) % q


def negacyclic_lookup(table, phase):
    """Read an integer LUT with its forced negative second half (toy only)."""
    if (type(table) is not tuple or not 1 <= len(table) <= 32
            or any(type(x) is not int for x in table)
            or type(phase) is not int or not 0 <= phase < 2 * len(table)):
        raise ValueError("Invalid bounded LUT/phase")
    n = len(table)
    return table[phase] if phase < n else -table[phase - n]
