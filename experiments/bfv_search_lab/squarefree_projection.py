"""E119 public squarefree-CRT oracle, not encryption or private release.

Only prime limbs admit field rank. Public polynomial/matrix inspection is
restricted to dimensions2/4/8; the norm-only certificate reads no polynomial.
This conditional full-uniform-mask algebra gives no concrete sampler,
cryptographic parameter, seeded-distribution, or originality approval.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from math import prod

from experiments.bfv_search_lab.one_prime_bounds import prime64


def _integers(*values):
    if any(type(value) is not int for value in values):
        raise ValueError("Expected exact integers")


def _primes(primes):
    if (type(primes) is not tuple or not 2 <= len(primes) <= 8
            or any(type(q) is not int or not prime64(q) for q in primes)
            or tuple(sorted(set(primes))) != primes):
        raise ValueError("Expected distinct increasing unsigned64 prime limbs")
    return primes


def _split(n, primes):
    _integers(n)
    _primes(primes)
    if (not 2 <= n <= 32768 or n & (n - 1)
            or any(q % (2 * n) != 1 for q in primes)):
        raise ValueError("Expected fully split prime limbs and power-of-two N")


@dataclass(frozen=True)
class Context:
    n: int
    primes: tuple[int, ...]
    primitive_roots: tuple[int, ...]

    def validate(self):
        _split(self.n, self.primes)
        if (type(self.primitive_roots) is not tuple
                or len(self.primitive_roots) != len(self.primes)
                or any(type(root) is not int or not 0 < root < q
                       or pow(root, self.n, q) != q - 1
                       for root, q in zip(self.primitive_roots, self.primes, strict=True))):
            raise ValueError("Expected one primitive2N root per prime limb")
        return self

    @property
    def q(self):
        self.validate()
        return prod(self.primes)

    def roots(self):
        self.validate()
        if self.n > 8:
            raise ValueError("Root oracle is restricted to public tiny rings")
        return tuple(tuple(pow(root, 2 * j + 1, q) for j in range(self.n))
                     for root, q in zip(self.primitive_roots, self.primes, strict=True))


@dataclass(frozen=True)
class NormCertificate:
    n: int
    primes: tuple[int, ...]
    squared_norm_cap: int
    limb_nullity_caps: tuple[int, ...]
    common_nullity_cap: int
    prefix_length: int

    def validate(self):
        _split(self.n, self.primes)
        _integers(self.squared_norm_cap, self.common_nullity_cap, self.prefix_length)
        if not 1 <= self.squared_norm_cap <= self.n * (1 << 40):
            raise ValueError("Invalid public squared-norm cap")
        if (type(self.limb_nullity_caps) is not tuple
                or len(self.limb_nullity_caps) != len(self.primes)
                or any(type(k) is not int for k in self.limb_nullity_caps)):
            raise ValueError("Invalid limb cap grammar")
        bound = self.squared_norm_cap ** (self.n // 2)
        for q, k in zip(self.primes, self.limb_nullity_caps, strict=True):
            if (not 0 <= k <= self.n or q ** k > bound
                    or (k < self.n and bound >= q ** (k + 1))):
                raise ValueError("False exact prime-limb norm/nullity cap")
        if (self.common_nullity_cap != max(self.limb_nullity_caps)
                or self.prefix_length != self.n - self.common_nullity_cap):
            raise ValueError("False common fixed-prefix certificate")
        return self


def norm_certificate(n, primes, squared_norm_cap):
    """Weighted determinant divisibility; common prefix uses max limb cap.

    For a NONZERO integer degree<N polynomial within the public norm envelope,
    product_i p_i^k_i divides its nonzero integer determinant, whose magnitude
    is <=norm2^(N/2). No assertion Q^max_i(k_i)|determinant is made. The fixed
    consecutive prefix may be empty; zero is not included in this conclusion.
    """
    _split(n, primes)
    _integers(squared_norm_cap)
    if not 1 <= squared_norm_cap <= n * (1 << 40):
        raise ValueError("Invalid public squared-norm cap")
    bound, caps = squared_norm_cap ** (n // 2), []
    for q in primes:
        lower, upper = 0, n
        while lower < upper:
            middle = (lower + upper + 1) // 2
            if q ** middle <= bound:
                lower = middle
            else:
                upper = middle - 1
        caps.append(lower)
    k = max(caps)
    return NormCertificate(n, primes, squared_norm_cap, tuple(caps), k, n - k).validate()


def _polynomial(value):
    if (type(value) is not tuple or len(value) not in (2, 4, 8)
            or any(type(x) is not int or abs(x) >= 1 << 20 for x in value)):
        raise ValueError("Expected a public tiny integer polynomial")
    return value


def _context_polynomial(secret, ctx):
    _polynomial(secret)
    if type(ctx) is not Context or len(secret) != ctx.n:
        raise ValueError("Wrong public squarefree context")
    return ctx.validate()


def multiplication_matrix(secret):
    """Integer negacyclic matrix from its signed coefficient formula."""
    _polynomial(secret)
    n = len(secret)
    return tuple(tuple(secret[(i-j) % n] * (1 if i >= j else -1)
                       for j in range(n)) for i in range(n))


def _matrix(matrix):
    if (type(matrix) is not tuple or not 1 <= len(matrix) <= 8
            or type(matrix[0]) is not tuple or not 1 <= len(matrix[0]) <= 8
            or any(type(row) is not tuple or len(row) != len(matrix[0])
                   or any(type(x) is not int for x in row) for row in matrix)):
        raise ValueError("Expected a tiny rectangular integer matrix")
    return matrix


def determinant(matrix):
    """Exact rational elimination, independent of the runner's Bareiss."""
    _matrix(matrix)
    if len(matrix) != len(matrix[0]):
        raise ValueError("Expected square matrix")
    rows = [[Fraction(value) for value in row] for row in matrix]
    value = Fraction(1)
    for column in range(len(rows)):
        pivot = next((i for i in range(column, len(rows)) if rows[i][column]), None)
        if pivot is None:
            return 0
        if pivot != column:
            rows[column], rows[pivot] = rows[pivot], rows[column]
            value = -value
        lead = rows[column][column]
        value *= lead
        for i in range(column + 1, len(rows)):
            factor = rows[i][column] / lead
            for j in range(column + 1, len(rows)):
                rows[i][j] -= factor * rows[column][j]
            rows[i][column] = 0
    if value.denominator != 1:
        raise ArithmeticError("Integer determinant is not integral")
    return value.numerator


def rank_mod(matrix, prime):
    """Tiny prime-field Gaussian elimination. Composite Q is never a field."""
    _matrix(matrix)
    _integers(prime)
    if not prime64(prime):
        raise ValueError("Expected a prime field, not the coefficient modulus")
    rows = [[x % prime for x in row] for row in matrix]
    rank = 0
    for column in range(len(rows[0])):
        pivot = next((i for i in range(rank, len(rows)) if rows[i][column]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        inverse = pow(rows[rank][column], -1, prime)
        rows[rank] = [x * inverse % prime for x in rows[rank]]
        for i in range(rank + 1, len(rows)):
            factor = rows[i][column]
            rows[i] = [(a-factor*b) % prime
                       for a, b in zip(rows[i], rows[rank], strict=True)]
        rank += 1
        if rank == len(rows):
            break
    return rank


def zero_roots(secret, ctx):
    _context_polynomial(secret, ctx)
    output = []
    for q, roots in zip(ctx.primes, ctx.roots(), strict=True):
        zeros = []
        for alpha in roots:
            value = 0
            for coefficient in reversed(secret):
                value = (value * alpha + coefficient) % q
            if value == 0:
                zeros.append(alpha)
        output.append(tuple(zeros))
    return tuple(output)


def projection_ranks(secret, ctx, coordinates):
    _context_polynomial(secret, ctx)
    if (type(coordinates) is not tuple
            or any(type(i) is not int or not 0 <= i < ctx.n for i in coordinates)
            or len(set(coordinates)) != len(coordinates)):
        raise ValueError("Expected distinct public coordinates")
    if not coordinates:
        return tuple(0 for _ in ctx.primes)
    matrix = multiplication_matrix(secret)
    return tuple(rank_mod(tuple(matrix[i] for i in coordinates), q) for q in ctx.primes)


def weighted_divisor(ctx, nullities):
    if type(ctx) is not Context:
        raise ValueError("Expected a squarefree context")
    ctx.validate()
    if (type(nullities) is not tuple or len(nullities) != len(ctx.primes)
            or any(type(k) is not int or not 0 <= k <= ctx.n for k in nullities)):
        raise ValueError("Invalid actual public nullities")
    return prod(q ** k for q, k in zip(ctx.primes, nullities, strict=True))


def crt_lift(residues, ctx):
    """Unique canonical coefficient from common, canonical prime residues."""
    if type(ctx) is not Context:
        raise ValueError("Expected a squarefree context")
    ctx.validate()
    if (type(residues) is not tuple or len(residues) != len(ctx.primes)
            or any(type(c) is not int or not 0 <= c < q
                   for c, q in zip(residues, ctx.primes, strict=True))):
        raise ValueError("Expected canonical residues in fixed prime order")
    q = prod(ctx.primes)
    return sum(c * (q // p) * pow(q // p, -1, p)
               for c, p in zip(residues, ctx.primes, strict=True)) % q


def multiply_via_crt(secret, mask, ctx):
    """Public tiny product: field-limb arithmetic and common coefficient CRT."""
    _context_polynomial(secret, ctx)
    q = ctx.q
    if (type(mask) is not tuple or len(mask) != ctx.n
            or any(type(c) is not int or not 0 <= c < q for c in mask)):
        raise ValueError("Expected a canonical whole-Q public mask")
    matrix = multiplication_matrix(secret)
    limb_vectors = tuple(tuple(sum(a * c for a, c in zip(row, mask, strict=True)) % p
                               for row in matrix) for p in ctx.primes)
    return tuple(crt_lift(tuple(vector[i] for vector in limb_vectors), ctx)
                 for i in range(ctx.n))
