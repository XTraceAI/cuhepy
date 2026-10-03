"""E118 public exact projection certificate; not encryption or private release.

The matrix oracle is restricted to public dimensions2/4/8. Large certificates
use only the public norm envelope, never a secret polynomial. Field admission
uses the existing E113 unsigned64-bit prime diagnostic; this is no HE parameter
approval, OS-randomness assurance or public-SHAKE distribution proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction

from experiments.bfv_search_lab.one_prime_bounds import prime64
from experiments.bfv_search_lab.query_quantizer_law import (
    QuantizerLaw, ceil_div, joint_mgf, upward_dyadic,
)


def _integers(*values):
    if any(type(value) is not int for value in values):
        raise ValueError("Expected exact integers")


def _split(n, q):
    _integers(n, q)
    if (not 2 <= n <= 32768 or n & (n - 1) or not prime64(q)
            or q % (2 * n) != 1):
        raise ValueError("Expected a bounded fully split prime power-of-two ring")


@dataclass(frozen=True)
class Context:
    n: int
    q: int
    root: int

    def validate(self):
        _split(self.n, self.q)
        _integers(self.root)
        if not 0 < self.root < self.q or pow(self.root, self.n, self.q) != self.q - 1:
            raise ValueError("Expected a primitive2N root")
        return self

    def roots(self):
        self.validate()
        if self.n > 8:
            raise ValueError("Root/secret oracle is restricted to public tiny rings")
        return tuple(pow(self.root, 2 * j + 1, self.q) for j in range(self.n))


@dataclass(frozen=True)
class NormCertificate:
    n: int
    q: int
    squared_norm_cap: int
    nullity_cap: int
    prefix_length: int

    def validate(self):
        _split(self.n, self.q)
        _integers(self.squared_norm_cap, self.nullity_cap, self.prefix_length)
        if not 1 <= self.squared_norm_cap <= self.n * (1 << 40):
            raise ValueError("Invalid public squared-norm cap")
        bound = self.squared_norm_cap ** (self.n // 2)
        if (not 0 <= self.nullity_cap <= self.n
                or self.prefix_length != self.n - self.nullity_cap
                or self.q ** self.nullity_cap > bound
                or (self.nullity_cap < self.n and bound >= self.q ** (self.nullity_cap + 1))):
            raise ValueError("False exact norm/nullity certificate")
        return self


def norm_certificate(n, q, squared_norm_cap):
    """Q^k divides nonzero determinant; Parseval bounds it by norm2^(N/2).

    The conclusion requires a NONZERO integer polynomial of degree<N within
    the supplied squared-norm bound. Zero is never included by this certificate.
    The guaranteed information set is a fixed consecutive prefix, not every
    arbitrary coordinate subset.
    """
    _split(n, q)
    _integers(squared_norm_cap)
    if not 1 <= squared_norm_cap <= n * (1 << 40):
        raise ValueError("Invalid public squared-norm cap")
    bound = squared_norm_cap ** (n // 2)
    lower, upper = 0, n
    while lower < upper:
        middle = (lower + upper + 1) // 2
        if q ** middle <= bound:
            lower = middle
        else:
            upper = middle - 1
    return NormCertificate(n, q, squared_norm_cap, lower, n - lower).validate()


def _polynomial(value):
    if (type(value) is not tuple or len(value) not in (2, 4, 8)
            or any(type(x) is not int or abs(x) >= 1 << 20 for x in value)):
        raise ValueError("Expected a public tiny integer polynomial")
    return value


def multiplication_matrix(secret):
    """Negacyclic matrix by its signed Toeplitz coefficient formula."""
    _polynomial(secret)
    n = len(secret)
    return tuple(tuple(secret[(row - column) % n] * (1 if row >= column else -1)
                       for column in range(n)) for row in range(n))


def _matrix(matrix):
    if (type(matrix) is not tuple or not 1 <= len(matrix) <= 8
            or type(matrix[0]) is not tuple or not 1 <= len(matrix[0]) <= 8
            or any(type(row) is not tuple or len(row) != len(matrix[0])
                   or any(type(x) is not int for x in row) for row in matrix)):
        raise ValueError("Expected a public tiny rectangular integer matrix")
    return matrix


def apply_matrix(matrix, vector, q):
    _matrix(matrix)
    if (type(vector) is not tuple or len(vector) != len(matrix[0])
            or any(type(x) is not int for x in vector) or not prime64(q)):
        raise ValueError("Invalid public finite-field matrix input")
    return tuple(sum(a * x for a, x in zip(row, vector, strict=True)) % q for row in matrix)


def rank_mod(matrix, q):
    """Exact field Gaussian elimination for the public tiny diagnostic."""
    _matrix(matrix)
    if not prime64(q):
        raise ValueError("Expected a prime field")
    rows = [[x % q for x in row] for row in matrix]
    rank = 0
    for column in range(len(rows[0])):
        pivot = next((i for i in range(rank, len(rows)) if rows[i][column]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        inverse = pow(rows[rank][column], -1, q)
        rows[rank] = [x * inverse % q for x in rows[rank]]
        for i in range(rank + 1, len(rows)):
            factor = rows[i][column]
            if factor:
                rows[i] = [(a - factor * b) % q for a, b in zip(rows[i], rows[rank], strict=True)]
        rank += 1
        if rank == len(rows):
            break
    return rank


def zero_roots(secret, ctx):
    _polynomial(secret)
    if type(ctx) is not Context or len(secret) != ctx.n:
        raise ValueError("Wrong public root context")
    roots = ctx.roots()
    zeros = []
    for alpha in roots:
        value = 0
        for coefficient in reversed(secret):
            value = (value * alpha + coefficient) % ctx.q
        if value == 0:
            zeros.append(alpha)
    return tuple(zeros)


def projection_rank(secret, q, coordinates):
    matrix = multiplication_matrix(secret)
    if (type(coordinates) is not tuple or not coordinates
            or any(type(i) is not int or not 0 <= i < len(secret) for i in coordinates)
            or len(set(coordinates)) != len(coordinates)):
        raise ValueError("Expected distinct public projection coordinates")
    return rank_mod(tuple(matrix[i] for i in coordinates), q)


def dyadic_upper(value):
    """Smallest reciprocal-power-of-two upper bound in [0,1], exactly."""
    if type(value) is not Fraction or not 0 < value <= 1:
        raise ValueError("Expected exact positive probability upper")
    bits = max(0, value.denominator.bit_length() - value.numerator.bit_length())
    while value.numerator * (1 << bits) > value.denominator:
        bits -= 1
    while value.numerator * (1 << (bits + 1)) <= value.denominator:
        bits += 1
    return bits, Fraction(1, 1 << bits)


@dataclass(frozen=True)
class Model:
    n: int
    dimension: int
    count: int
    q: int
    p: int
    t: int
    eta: int
    digit_bits: int
    drop: int

    def validate(self):
        _integers(self.n, self.dimension, self.count, self.q, self.p, self.t,
                  self.eta, self.digit_bits, self.drop)
        _split(self.n, self.q)
        if (not 1 <= self.dimension <= self.n // 2 or self.count < 1
                or not 2 * self.dimension < self.t < 1 << 30 or not self.t & 1
                or not self.t < self.p < self.q or not prime64(self.p)
                or self.p % self.t != self.q % self.t
                or not 1 <= self.eta <= 64 or not 4 <= self.digit_bits <= 60):
            raise ValueError("Invalid public complete correctness model")
        QuantizerLaw(self.q, self.t, self.drop)
        return self


def correctness_model(model):
    """Reconstruct one ideal-mask envelope from public inputs, not E115 outputs.

    Every nonzero ternary secret satisfies the norm certificate. Codec/CBD
    suffix terms are charged pointwise; only the fixed prefix gets an IID MGF.
    Zero is budgeted ONCE under the unconditioned raw secret law per one setup.
    No posterior setup, actual SHAKE, confidentiality or admission theorem.
    """
    if type(model) is not Model:
        raise ValueError("Expected a public model")
    model.validate()
    n, q, p, t, eta = model.n, model.q, model.p, model.t, model.eta
    certificate = norm_certificate(n, q, n)
    law = QuantizerLaw(q, t, model.drop)
    weight = 1 + t * eta
    d = 1 << (model.dimension - 1).bit_length()
    levels = ceil_div(q.bit_length(), model.digit_bits)
    switch = t * eta * n * levels * ((1 << model.digit_bits) - 1)
    maintenance = (2 * d - 1) * switch
    rounding = ceil_div((n + 1) * t, 2)
    available = (p - 1) // 2 - rounding
    radius = min((q - 1) // 2, q * available // p) if available >= 0 else -1
    original_threshold = (radius - maintenance) // d - model.dimension * weight + 1
    omitted_units = eta + ceil_div(law.intervals, 2)
    omitted = certificate.nullity_cap * t * weight * omitted_units
    threshold = original_threshold - omitted
    base = Fraction(16385, 16384)
    plus, minus = (joint_mgf(law, eta, b) for b in (base, 1 / base))
    mgf = max(Fraction(1), upward_dyadic(plus), upward_dyadic(minus))
    normalized = threshold // (t * weight)
    a = normalized * (base - 1) / base - certificate.prefix_length * (mgf - 1)
    floor_a = a.numerator // a.denominator
    per_output = (Fraction(1, 1 << (floor_a - 1))
                  if threshold > 0 and floor_a >= 1 else Fraction(1))
    outputs = n * ceil_div(model.count, n)
    union = (1 << 32) * outputs
    good_tail = min(Fraction(1), union * per_output)
    zero_mass = Fraction(1, 3 ** n)
    zero_bits, zero_dyadic = dyadic_upper(zero_mass)
    exact_total = zero_mass + (1 - zero_mass) * good_tail
    simple_sum = zero_dyadic + good_tail
    total_bits, total_dyadic = dyadic_upper(min(Fraction(1), simple_sum))
    public_fresh = t // 2 + t * eta * (2 * n + 1)
    return {"norm_certificate": certificate,
            "nullity_cap": certificate.nullity_cap,
            "prefix_uniform_coordinates": certificate.prefix_length,
            "index_phase_weight_cap": weight,
            "switch_bound": switch, "complete_maintenance_cap": maintenance,
            "safe_q_phase_radius": radius, "terminal_rounding_cap": rounding,
            "trace_factor": d, "original_random_threshold": original_threshold,
            "pointwise_bad_Z_units": omitted_units, "omitted_phase_cap": omitted,
            "retained_random_threshold": threshold,
            "retained_normalized_floor_threshold": normalized,
            "same_fixed_base": base, "same_outward_endpoint_mgf": mgf,
            "retained_log_exponent_lower": a, "floor_retained_log_exponent_lower": floor_a,
            "retained_per_output_tail_upper": per_output,
            "all_output_coefficients": outputs, "same_complete_lifetime_union": union,
            "good_nonzero_secret_lifetime_tail_upper": good_tail,
            "actual_unconditioned_raw_secret_zero_mass": zero_mass,
            "raw_secret_zero_mass_dyadic_bits": zero_bits,
            "raw_secret_zero_mass_dyadic_upper": zero_dyadic,
            "single_setup_plus_lifetime_exact_ideal_upper": exact_total,
            "single_setup_plus_lifetime_simple_sum_upper": simple_sum,
            "single_setup_plus_lifetime_dyadic_bits": total_bits,
            "single_setup_plus_lifetime_dyadic_upper": total_dyadic,
            "actual_general_keygen_guard_admits_profile": 2 * n * public_fresh ** 2 < q,
            "generic_given_derived_lemma_ratio": 1,
            "actual_SHAKE_ROM_or_security_approved": False}
