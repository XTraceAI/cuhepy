"""E86 known modular-unit conversion, bounded homemade research adapter.

Only public coefficients are transformed. There is no secret-key operation,
encryption/PBS implementation, authentication or remote-release API here.
Returned components retain their original modulus and secret; the scaled
message has a public permutation. Do not feed them to a BGV plaintext decoder.
"""

from __future__ import annotations

from fractions import Fraction
from math import gcd


def unit_parameters(q, t, *, sign=1):
    if (type(q) is not int or type(t) is not int or not 3 <= q < 1 << 128
            or not 2 <= t < q or gcd(q, t) != 1
            or type(sign) is not int or sign not in (-1, 1)):
        raise ValueError("Expected bounded coprime modulus context and unit sign")
    inverse = pow(t, -1, q)
    k = (inverse * t - 1) // q
    assert inverse * t == 1 + k * q and gcd(k, t) == 1
    return {"q": q, "t": t, "multiplier": sign * inverse % q,
            "plaintext_permutation_multiplier": sign * k % t,
            "plaintext_permutation_inverse": pow(sign * k % t, -1, t),
            "sign": sign}


def convert(components, q, t, *, sign=1):
    """Apply the public unit to ALL components, including C2 when present."""
    context = unit_parameters(q, t, sign=sign)
    if (type(components) is not tuple or not 2 <= len(components) <= 3
            or any(type(poly) is not tuple or not 1 <= len(poly) <= 64 for poly in components)
            or any(len(poly) != len(components[0]) for poly in components)
            or any(type(x) is not int or not 0 <= x < q for poly in components for x in poly)):
        raise ValueError("Invalid bounded canonical ciphertext components")
    return tuple(tuple(x * context["multiplier"] % q for x in poly) for poly in components)


def scaled_decode_reference(phase, q, t, *, sign=1):
    """Local arithmetic diagnostic ONLY, not an authenticated decrypt API."""
    context = unit_parameters(q, t, sign=sign)
    if type(phase) is not int or not 0 <= phase < q:
        raise ValueError("Expected canonical diagnostic phase")
    permuted = ((2 * t * phase + q) // (2 * q)) % t
    return permuted * context["plaintext_permutation_inverse"] % t


def switched_bound(q, t, target, phase_bound, secret_l1):
    """Sufficient rounding margin AFTER unit conversion, excluding KS/PBS.

    Original centered BGV phase has |phi|<=phase_bound. The unit maps its
    phase/Q to k*h/t + phi/(t*Q) on the torus. Public rounding then adds
    (1+||u||_1)/2. Direct C2 extraction must include ||S²||_1 in ||u||_1.
    """
    unit_parameters(q, t)
    if (type(target) is not int or not t < target < 1 << 129
            or any(type(x) is not int or x < 0 for x in (phase_bound, secret_l1))
            or 2 * phase_bound >= q):
        raise ValueError("Invalid conditional centered-phase/rounding context")
    error = Fraction(target * phase_bound, t * q) + Fraction(1 + secret_l1, 2)
    margin = Fraction(target, 2 * t)
    return {"error_bound": error, "nearest_message_margin": margin,
            "sufficient_strict_margin": error < margin}
