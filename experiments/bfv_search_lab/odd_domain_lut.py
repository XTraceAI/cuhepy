"""E89 exact odd-domain negacyclic LUT controls; no encrypted bootstrap."""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd


def nearest(numerator, denominator):
    # Exact nearest integer, ties towards +infinity, including negative inputs.
    return (2 * numerator + denominator) // (2 * denominator)


def centers(t, degree, permutation=1):
    if (any(type(x) is not int for x in (t, degree, permutation))
            or not 2 <= t <= 65537 or not 2 <= degree <= 8192 or degree & (degree - 1)
            or not 1 <= permutation < t or gcd(permutation, t) != 1):
        raise ValueError("Invalid bounded lookup geometry/permutation")
    return tuple(nearest(2 * degree * ((permutation * h) % t), t) % (2 * degree) for h in range(t))


def spacing(t, degree, permutation=1):
    points = sorted(r % degree for r in centers(t, degree, permutation))
    if len(set(points)) != t:
        return 0
    return min(*(b - a for a, b in zip(points[:-1], points[1:], strict=True)), points[0] + degree - points[-1])


@dataclass(frozen=True)
class Lookup:
    t: int
    p: int
    degree: int
    permutation: int
    allowed_integer_error: int
    polynomial: tuple[int, ...]


def compile_lut(values, degree, p=65537, permutation=1):
    if (type(values) is not tuple or type(p) is not int or not 3 <= p <= 65537
            or any(type(x) is not int or not 0 <= x < p for x in values)):
        raise ValueError("Invalid public lookup outputs")
    t, points = len(values), centers(len(values), degree, permutation)
    distance = spacing(t, degree, permutation)
    if t % 2 == 0 or distance == 0:
        raise ValueError("General full-domain control needs odd t and distinct folded centers")
    error, coefficients = (distance - 1) // 2, [None] * degree
    for h, center in enumerate(points):
        for delta in range(-error, error + 1):
            index = (center + delta) % (2 * degree)
            target = values[h] * (1 if index < degree else -1) % p
            slot = index % degree
            if coefficients[slot] is not None and coefficients[slot] != target:
                raise AssertionError("Intersecting lookup neighborhoods")
            coefficients[slot] = target
    return Lookup(t, p, degree, permutation, error, tuple(0 if x is None else x for x in coefficients))


def evaluate(lut, rotation):
    if (type(lut) is not Lookup or type(rotation) is not int or not 0 <= rotation < 2 * lut.degree):
        raise ValueError("Noncanonical public rotation")
    # Constant coefficient of X^-rotation * L in X^degree+1.
    return lut.polynomial[rotation % lut.degree] * (1 if rotation < lut.degree else -1) % lut.p


def roundtrip_reference(lut, rotation):
    """Independent explicit signed monomial shift of every coefficient."""
    output = [0] * lut.degree
    for j, value in enumerate(lut.polynomial):
        exponent = j - rotation
        quotient, index = divmod(exponent, lut.degree)
        output[index] += value * (-1 if quotient % 2 else 1)
    return output[0] % lut.p


def scale_phase(mask, body, secret, q, target):
    """Local exact componentwise switch diagnostic, with a known test secret."""
    if (type(mask) is not tuple or type(secret) is not tuple or len(mask) != len(secret)
            or not 1 <= len(mask) <= 16 or type(q) is not int or not 3 <= q <= 65537
            or type(target) is not int or not 2 <= target <= 16384
            or type(body) is not int or not 0 <= body < q
            or any(type(x) is not int or not 0 <= x < q for x in mask)
            or any(type(x) is not int or abs(x) > 1 for x in secret)):
        raise ValueError("Invalid local bounded switch diagnostic")
    return (nearest(target * body, q) + sum(nearest(target * a, q) * s
                                          for a, s in zip(mask, secret, strict=True))) % target
