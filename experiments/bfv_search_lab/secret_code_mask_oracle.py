"""E82 finite projection/distribution controls, not query pads or a PCF API.

The bit-line candidate is a precise multi-coordinate projection: line pairs
share a slope, use independent intercepts, and the receiver selects one per
query bit. Source-coordinate count is small; its minimal-support key count
is exponential. No sampler, PRF, HE conversion, MAC or security parameter is
implemented. These bounded exhaustive distributions are public toy algebra.
"""

from __future__ import annotations

from collections import Counter
from fractions import Fraction
from itertools import product

from gmpy2 import is_prime


def _field(prime):
    if type(prime) is not int or not 3 <= prime <= 65537 or not is_prime(prime):
        raise ValueError("Expected bounded prime field")


def _vector(values, length, prime):
    if (type(values) is not tuple or len(values) != length
            or any(type(x) is not int or not 0 <= x < prime for x in values)):
        raise ValueError("Expected canonical field vector")


def rank(rows, prime):
    _field(prime)
    if (type(rows) is not tuple or not rows or not 1 <= len(rows) <= 32
            or not 1 <= len(rows[0]) <= 32):
        raise ValueError("Expected bounded matrix")
    for row in rows:
        _vector(row, len(rows[0]), prime)
    matrix, pivot = [list(row) for row in rows], 0
    for column in range(len(rows[0])):
        selected = next((i for i in range(pivot, len(rows)) if matrix[i][column]), None)
        if selected is None:
            continue
        matrix[pivot], matrix[selected] = matrix[selected], matrix[pivot]
        inverse = pow(matrix[pivot][column], -1, prime)
        matrix[pivot] = [x * inverse % prime for x in matrix[pivot]]
        for i in range(len(rows)):
            if i != pivot:
                factor = matrix[i][column]
                matrix[i] = [(a - factor * b) % prime for a, b in zip(matrix[i], matrix[pivot], strict=True)]
        pivot += 1
        if pivot == len(rows):
            break
    return pivot


def joint_projection_law(projection, prime):
    rank(projection, prime)
    width = len(projection[0])
    if prime ** width > 100000:
        raise ValueError("Projection population exceeds finite oracle")
    return Counter(tuple(sum(a * b for a, b in zip(row, secret, strict=True)) % prime
                         for row in projection)
                   for secret in product(range(prime), repeat=width))


def secret_line_transcript_law(queries, prime, *, affine_offset=False):
    """Exact law, averaging a SECRET nonzero line, fresh coefficients and offset.

    A fixed uniform affine offset hides a repeated unknown constant but does
    not hide differences between different queries. This distinguishes the
    two hypotheses instead of overclaiming a same-query attack on both.
    """
    _field(prime)
    if type(queries) is not tuple or not 1 <= len(queries) <= 4:
        raise ValueError("Expected bounded query sequence")
    dimension = len(queries[0])
    if not 1 <= dimension <= 4 or type(affine_offset) is not bool:
        raise ValueError("Invalid transcript geometry")
    for query in queries:
        _vector(query, dimension, prime)
    population = (prime ** dimension - 1) * prime ** len(queries)
    if affine_offset:
        population *= prime ** dimension
    if population > 1000000:
        raise ValueError("Transcript population exceeds finite oracle")
    law = Counter()
    offsets = tuple(product(range(prime), repeat=dimension)) if affine_offset else ((0,) * dimension,)
    for line in product(range(prime), repeat=dimension):
        if not any(line):
            continue
        for offset in offsets:
            for coefficients in product(range(prime), repeat=len(queries)):
                view = tuple(tuple((x - b - a * s) % prime
                                   for x, b, a in zip(query, offset, line, strict=True))
                             for query, s in zip(queries, coefficients, strict=True))
                law[view] += 1
    assert sum(law.values()) == population
    return law


def total_variation(left, right):
    if not left or not right or any(v <= 0 for v in (*left.values(), *right.values())):
        raise ValueError("Expected nonempty positive distributions")
    a, b = sum(left.values()), sum(right.values())
    return sum((abs(Fraction(left[x], a) - Fraction(right[x], b))
                for x in left.keys() | right.keys()), Fraction()) / 2


def bitline_codeword(slope, intercepts, prime):
    _field(prime)
    if type(slope) is not int or not 0 <= slope < prime or not 2 <= len(intercepts) <= 8:
        raise ValueError("Invalid bit-line source")
    _vector(intercepts, len(intercepts), prime)
    return tuple(value for i, b in enumerate(intercepts)
                 for value in (b, (b + pow(2, i, prime) * slope) % prime))


def enumerate_minimal_supports(bits, prime):
    _field(prime)
    if type(bits) is not int or not 2 <= bits <= 8 or prime ** (bits + 1) > 1000000:
        raise ValueError("Codeword population exceeds finite oracle")
    supports = set()
    for slope in range(prime):
        for intercepts in product(range(prime), repeat=bits):
            support = frozenset(i for i, x in enumerate(bitline_codeword(slope, intercepts, prime)) if x)
            if support:
                supports.add(support)
    minimal = []
    for support in sorted(supports, key=lambda s: (len(s), tuple(sorted(s)))):
        if not any(m < support for m in minimal):
            minimal.append(support)
    return tuple(minimal)


def predicted_minimal_supports(bits):
    if type(bits) is not int or not 2 <= bits <= 12:
        raise ValueError("Expected bounded bit count")
    pairs = tuple(frozenset((2 * i, 2 * i + 1)) for i in range(bits))
    transversals = tuple(frozenset(2 * i + b for i, b in enumerate(choices))
                        for choices in product((0, 1), repeat=bits))
    return pairs + transversals


def bitline_projection(slope, intercepts, scalar, prime):
    source = bitline_codeword(slope, intercepts, prime)
    if type(scalar) is not int or not 0 <= scalar < min(prime, 1 << len(intercepts)):
        raise ValueError("Scalar outside canonical bit projection")
    selected = tuple(2 * i + ((scalar >> i) & 1) for i in range(len(intercepts)))
    values = tuple(source[i] for i in selected)
    return {"sender": (slope, sum(intercepts) % prime),
            "receiver": (scalar, sum(values) % prime), "receiver_extra": values,
            "projection": selected}


def bitline_real_and_simulated_laws(bits, prime):
    """Enumerate joint target outputs plus receiver extra view independently.

    Simulation samples target (a,B,x) first, then a uniform vector of bit
    observations conditioned ONLY on its sum y=a*x+B. Agreement is an exact
    finite check of this projection, not computational PCF security.
    """
    _field(prime)
    if (type(bits) is not int or not 2 <= bits <= 5 or prime > 1 << bits
            or prime ** (bits + 2) > 1000000):
        raise ValueError("Projection simulation exceeds oracle")
    real, simulated = Counter(), Counter()
    for slope in range(prime):
        for intercepts in product(range(prime), repeat=bits):
            for scalar in range(prime):
                view = bitline_projection(slope, intercepts, scalar, prime)
                a, b = view["sender"]
                x, y = view["receiver"]
                real[(a, b, x, y, view["receiver_extra"])] += 1
    for a, b, x in product(range(prime), repeat=3):
        y = (a * x + b) % prime
        for prefix in product(range(prime), repeat=bits - 1):
            values = (*prefix, (y - sum(prefix)) % prime)
            simulated[(a, b, x, y, values)] += 1
    return real, simulated


def field_lift(value, prime):
    _field(prime)
    _vector((value,), 1, prime)
    return value if value <= prime // 2 else value - prime


def bitline_counts(prime):
    _field(prime)
    bits = (prime - 1).bit_length()
    return {"field": prime, "bits": bits, "source_coordinates": 2 * bits,
            "sender_minimal_support_keys": 2 ** bits + bits,
            "receiver_minimal_support_keys": 2 ** bits + bits - 1,
            "ordinary_line_sender_keys": prime,
            "ordinary_line_receiver_keys": prime - 1,
            "key_count_formula_scope": "Specified common-slope bit-line source, bits>=2; no general projection lower bound",
            "MAC_HE_setup_and_per_vector_expansion_cost": "unimplemented/additional"}
