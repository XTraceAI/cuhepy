"""E84 exact integer coverage and small-field conversion controls.

This is an independent public oracle, not an HE evaluator, proof or release
API. A small-field grand product need not bind histogram multiplicities.
Coefficient packing must not be treated as scalar SIMD multiplication.
"""

from __future__ import annotations

from dataclasses import dataclass

from gmpy2 import is_prime


def _field(prime):
    if type(prime) is not int or not 3 <= prime <= 65537 or not is_prime(prime):
        raise ValueError("Expected bounded prime field")


def validate(scores, ids, dimension):
    if (type(dimension) is not int or not 0 <= dimension <= 512
            or type(scores) is not tuple or type(ids) is not tuple
            or len(scores) != len(ids) or not 0 <= len(scores) <= 64
            or any(type(s) is not int or not 0 <= s <= dimension for s in scores)
            or any(type(i) is not int or not 0 <= i < 1 << 64 for i in ids)
            or len(set(ids)) != len(ids)):
        raise ValueError("Expected bounded complete score/unique stable-ID domain")


@dataclass(frozen=True)
class Certificate:
    counts: tuple[int, ...]
    winners: tuple[tuple[int, int], ...]
    cutoff: tuple[int, int] | None
    row_count: int


def certificate(scores, ids, dimension, *, k=3):
    validate(scores, ids, dimension)
    if type(k) is not int or not 1 <= k <= 8:
        raise ValueError("Expected bounded winner count")
    counts = tuple(sum(s == value for s in scores) for value in range(dimension + 1))
    # Counting-sort reference keeps values/IDs attached. It differs from the
    # independent lexicographic sorted() oracle used by tests and benchmark.
    winners = []
    for value in range(dimension + 1):
        for stable_id in sorted(i for s, i in zip(scores, ids, strict=True) if s == value):
            if len(winners) < k:
                winners.append((value, stable_id))
    return Certificate(counts, tuple(winners), winners[-1] if winners else None, len(scores))


def check_certificate(scores, ids, dimension, claim, *, k=3):
    """Complete integer reference, explicitly reading ALL scores/IDs."""
    validate(scores, ids, dimension)
    if type(claim) is not Certificate or type(k) is not int or not 1 <= k <= 8:
        return False
    if (claim.row_count != len(scores) or type(claim.counts) is not tuple
            or len(claim.counts) != dimension + 1
            or any(type(c) is not int or not 0 <= c <= len(scores) for c in claim.counts)
            or sum(claim.counts) != len(scores)):
        return False
    if claim.counts != tuple(sum(s == value for s in scores) for value in range(dimension + 1)):
        return False
    expected = tuple(sorted(zip(scores, ids, strict=True))[:k])
    return claim.winners == expected and claim.cutoff == (expected[-1] if expected else None)


def histogram_product(counts, point, prime):
    _field(prime)
    if (type(counts) is not tuple or not 1 <= len(counts) <= 513
            or any(type(c) is not int or not 0 <= c <= 65538 for c in counts)
            or type(point) is not int or not 0 <= point < prime):
        raise ValueError("Expected bounded integer histogram and field challenge")
    value = 1
    for score, count in enumerate(counts):
        value = value * pow((point - score) % prime, count, prime) % prime
    return value


def f25_multiply(left, right):
    # F5[U]/(U^2+2): -2=3 is nonsquare, so this quotient is a field.
    for value in (left, right):
        if (type(value) is not tuple or len(value) != 2
                or any(type(x) is not int or not 0 <= x < 5 for x in value)):
            raise ValueError("Expected canonical F25 element")
    return ((left[0] * right[0] + 3 * left[1] * right[1]) % 5,
            (left[0] * right[1] + left[1] * right[0]) % 5)


def f25_power(value, exponent):
    f25_multiply(value, (1, 0))
    if type(exponent) is not int or not 0 <= exponent <= 65538:
        raise ValueError("Expected bounded nonnegative exponent")
    result = (1, 0)
    while exponent:
        if exponent & 1:
            result = f25_multiply(result, value)
        value = f25_multiply(value, value)
        exponent //= 2
    return result


def f25_histogram_product(counts, point):
    # Reuse integer histogram validation, without pretending point is F5.
    histogram_product(counts, 0, 5)
    f25_multiply(point, (1, 0))
    value = (1, 0)
    for score, count in enumerate(counts):
        factor = ((point[0] - score) % 5, point[1])
        value = f25_multiply(value, f25_power(factor, count))
    return value


def prefix_polynomial(dimension, threshold, prime):
    """Exact Lagrange control for 1[h<threshold] on the WHOLE integer domain."""
    _field(prime)
    if (type(dimension) is not int or not 0 <= dimension <= 16 or dimension >= prime
            or type(threshold) is not int or not 0 <= threshold <= dimension + 1):
        raise ValueError("Distinct score representatives and bounded interpolation required")
    result = [0] * (dimension + 1)
    for value in range(threshold):
        basis, denominator = [1], 1
        for other in range(dimension + 1):
            if other == value:
                continue
            expanded = [0] * (len(basis) + 1)
            for i, coefficient in enumerate(basis):
                expanded[i] = (expanded[i] - other * coefficient) % prime
                expanded[i + 1] = (expanded[i + 1] + coefficient) % prime
            basis = expanded
            denominator = denominator * (value - other) % prime
        inverse = pow(denominator, -1, prime)
        for i, coefficient in enumerate(basis):
            result[i] = (result[i] + coefficient * inverse) % prime
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return tuple(result)


def polynomial_value(coefficients, value, prime):
    _field(prime)
    if (type(coefficients) is not tuple or not coefficients
            or any(type(c) is not int or not 0 <= c < prime for c in coefficients)
            or type(value) is not int or not 0 <= value < prime):
        raise ValueError("Expected canonical polynomial")
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * value + coefficient) % prime
    return result


def challenge_degree(prime, degree, bits=128, attempts=1):
    _field(prime)
    if any(type(x) is not int or x < 1 for x in (degree, bits, attempts)) or bits > 256:
        raise ValueError("Invalid fixed-polynomial bound")
    power, extension = prime, 1
    target = degree * attempts * (1 << bits)
    while power < target:
        extension += 1
        power *= prime
    return {"prime": prime, "polynomial_degree_bound": degree,
            "attempts": attempts, "statistical_bits_target": bits,
            "extension_degree": extension, "field_order": str(power),
            "premises": "Nonzero polynomial fixed before uniform independent challenge; complete input/commitment binding additional"}


def ring_slot_structure(n, prime):
    _field(prime)
    if type(n) is not int or not 2 <= n <= 65536 or n & (n - 1):
        raise ValueError("Expected bounded power-of-two negacyclic degree")
    # Every root of X^n+1 has order 2n. Its Frobenius orbit size is
    # ord_(2n)(prime); all irreducible factors have this degree.
    residue, degree = prime % (2 * n), 1
    while residue != 1:
        residue = residue * prime % (2 * n)
        degree += 1
        if degree > n:
            raise AssertionError("Frobenius orbit exceeded ring dimension")
    assert n % degree == 0
    return {"n": n, "prime": prime, "irreducible_factor_degree": degree,
            "extension_field_slots": n // degree,
            "full_base_field_scalar_SIMD": degree == 1,
            "scope": "Ring algebra only; no HE transform, parameter or security assurance"}
