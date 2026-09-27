"""E21: exact answer-generating polynomials, tie recovery and cost obstructions.

All functions here are plaintext mathematical oracles. Prefix requests reveal
distance/routing information; this is not a private or authenticated protocol.
Scalar operation/field-element counts are not ciphertext bytes or GPU timings.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from math import isqrt


def validate_binary(query: list[int], rows: list[list[int]]) -> None:
    if (not query or any(type(x) is not int or x not in (0, 1) for x in query)
            or any(len(row) != len(query) or any(type(x) is not int or x not in (0, 1)
                                               for x in row) for row in rows)):
        raise ValueError("Expected nonempty binary query and equally sized binary rows")


def validate_field(prime: int, dimension: int, count: int) -> None:
    if (type(prime) is not int or not max(dimension, count, 2) < prime <= (1 << 31) - 1
            or prime % 2 == 0 or any(prime % x == 0 for x in range(3, isqrt(prime) + 1, 2))):
        raise ValueError("Expected an odd toy prime > dimension and count, at most 2**31-1")


def polynomial_product(a: list[int], b: list[int], prime: int) -> list[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] = (out[i + j] + x * y) % prime
    return out


def row_polynomial(query: list[int], row: list[int], prime: int) -> list[int]:
    """Literal balanced factor circuit; no branch on an individual mismatch."""
    work = [[(1 - (x + q - 2 * x * q)) % prime, (x + q - 2 * x * q) % prime]
            for x, q in zip(row, query, strict=True)]
    while len(work) > 1:
        work = [polynomial_product(work[i], work[i + 1], prime) if i + 1 < len(work)
                else work[i] for i in range(0, len(work), 2)]
    return work[0]


def factor_histogram(query: list[int], rows: list[list[int]], prime: int) -> list[int]:
    validate_binary(query, rows)
    validate_field(prime, len(query), len(rows))
    total = [0] * (len(query) + 1)
    for row in rows:
        total = [(x + y) % prime for x, y in zip(total, row_polynomial(query, row, prime), strict=True)]
    return total


def _interpolate(values: list[int], prime: int) -> list[int]:
    # Public Lagrange interpolation at the distinct points 0, ..., d.
    out = [0] * len(values)
    for i, value in enumerate(values):
        basis, denominator = [1], 1
        for j in range(len(values)):
            if i != j:
                basis = polynomial_product(basis, [-j % prime, 1], prime)
                denominator = denominator * (i - j) % prime
        scale = value * pow(denominator, -1, prime) % prime
        out = [(a + scale * b) % prime for a, b in zip(out, basis, strict=True)]
    return out


def evaluation_histogram(query: list[int], rows: list[list[int]], prime: int) -> list[int]:
    """Independent evaluation/interpolation construction of the same polynomial."""
    validate_binary(query, rows)
    validate_field(prime, len(query), len(rows))
    values = []
    for point in range(len(query) + 1):
        value = 0
        for row in rows:
            product = 1
            for x, q in zip(row, query, strict=True):
                product = product * (1 + (point - 1) * (x + q - 2 * x * q)) % prime
            value = (value + product) % prime
        values.append(value)
    return _interpolate(values, prime)


def walsh_histogram(query: list[int], rows: list[list[int]], prime: int) -> list[int]:
    """Exact separated-feature oracle, intentionally limited to tiny dimensions.

    This precomputes 2**d database Walsh moments. It is not a compact encrypted
    index or a private query protocol. Its exponential size is the experiment.
    """
    validate_binary(query, rows)
    validate_field(prime, len(query), len(rows))
    d = len(query)
    if d > 10:
        raise ValueError("Exponential reference limited to ten dimensions")
    def encode(bits: list[int]) -> int:
        return sum(bit << j for j, bit in enumerate(bits))
    frequency = [0] * (1 << d)
    for row in rows:
        frequency[encode(row)] += 1
    step = 1
    while step < len(frequency):
        for start in range(0, len(frequency), 2 * step):
            for j in range(start, start + step):
                a, b = frequency[j], frequency[j + step]
                frequency[j], frequency[j + step] = (a + b) % prime, (a - b) % prime
        step *= 2
    encoded_query = encode(query)
    inverse = pow(1 << d, -1, prime)
    values = []
    for point in range(d + 1):
        value = sum(
            moment * (-1 if (subset & encoded_query).bit_count() % 2 else 1)
            * pow(1 + point, d - subset.bit_count(), prime)
            * pow(1 - point, subset.bit_count(), prime)
            for subset, moment in enumerate(frequency)
        ) % prime
        values.append(value * inverse % prime)
    return _interpolate(values, prime)


@dataclass(frozen=True)
class PrefixProbe:
    distance: int
    start: int
    stop: int
    count: int


def recover_topk(
    histogram: list[int], count: int, k: int,
    count_in_range: Callable[[int, int, int], int],
) -> tuple[list[tuple[int, int]], list[PrefixProbe]]:
    """Recover stable (distance, ID) pairs using honest integer prefix counts.

    Root counts must be exact, not reduced modulo a small field. Basic range
    checks detect inconsistent counts, but provide no server authentication.
    The transcript deliberately exposes the adaptive requests for accounting.
    """
    if (type(count) is not int or count < 0 or type(k) is not int or k < 0
            or not histogram or any(type(x) is not int or x < 0 for x in histogram)
            or sum(histogram) != count):
        raise ValueError("Invalid exact histogram/count/k")
    answers: list[tuple[int, int]] = []
    transcript: list[PrefixProbe] = []

    def visit(distance: int, lo: int, hi: int, total: int, needed: int) -> None:
        if not needed:
            return
        if total == hi - lo:
            answers.extend((distance, i) for i in range(lo, lo + needed))
            return
        mid = (lo + hi) // 2
        left = count_in_range(distance, lo, mid)
        if type(left) is not int or not 0 <= left <= min(total, mid - lo) or total - left > hi - mid:
            raise ValueError("Inconsistent prefix count (not an authentication check)")
        transcript.append(PrefixProbe(distance, lo, mid, left))
        take_left = min(needed, left)
        visit(distance, lo, mid, left, take_left)
        visit(distance, mid, hi, total - left, needed - take_left)

    for distance, total in enumerate(histogram):
        needed = min(total, max(0, min(k, count) - len(answers)))
        visit(distance, 0, count, total, needed)
        if len(answers) == min(k, count):
            break
    return answers, transcript


def scalar_cost(count: int, dimension: int) -> dict[str, int]:
    """Literal balanced dense-polynomial and evaluation-point circuit counts.

    Public interpolation operations are omitted; no SIMD or packed-RLWE saving
    is assumed. The public constant evaluation at z=1 is not optimized.
    Mismatch bits cost d ciphertext products in this feature-major formulation.
    """
    if type(count) is not int or count < 0 or type(dimension) is not int or dimension < 1:
        raise ValueError("Expected nonnegative count and positive dimension")
    lengths, convolution = [2] * dimension, 0
    while len(lengths) > 1:
        following = []
        for i in range(0, len(lengths), 2):
            if i + 1 == len(lengths):
                following.append(lengths[i])
            else:
                convolution += lengths[i] * lengths[i + 1]
                following.append(lengths[i] + lengths[i + 1] - 1)
        lengths = following
    mismatch = count * dimension
    return {
        "mismatch_products": mismatch,
        "factor_products": count * (dimension + convolution),
        "evaluation_products": count * (dimension + (dimension + 1) * (dimension - 1)),
        "factor_multiplicative_depth": 1 + (dimension - 1).bit_length(),
        "histogram_field_elements": dimension + 1,
        "cached_row_field_elements": count * (dimension + 1),
        "distance_field_elements": count,
        "exact_separated_features": 1 << dimension,
    }


def kernel_rank(dimension: int, point: int, prime: int) -> int:
    """Gaussian-rank oracle for K[x,q]=point**Hamming(x,q), at d <= 6."""
    if type(dimension) is not int or not 1 <= dimension <= 6:
        raise ValueError("Rank reference limited to dimensions 1..6")
    validate_field(prime, dimension, 0)
    if type(point) is not int or not 0 <= point < prime:
        raise ValueError("Expected canonical evaluation point")
    size = 1 << dimension
    matrix = [[pow(point, (x ^ q).bit_count(), prime) for q in range(size)] for x in range(size)]
    rank = 0
    for column in range(size):
        pivot = next((i for i in range(rank, size) if matrix[i][column]), None)
        if pivot is None:
            continue
        matrix[rank], matrix[pivot] = matrix[pivot], matrix[rank]
        row = [x * pow(matrix[rank][column], -1, prime) % prime for x in matrix[rank]]
        matrix[rank] = row
        for i in range(rank + 1, size):
            scale = matrix[i][column]
            matrix[i] = [(a - scale * b) % prime for a, b in zip(matrix[i], row, strict=True)]
        rank += 1
    return rank
