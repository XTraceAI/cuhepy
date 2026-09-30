"""E38 exact schema range, unrestricted-query failure and CRT-root limits.

A public one-hot schema bounds binary Hamming diameter by twice its attribute
count, not bit-vector dimension. Enrollment AND queries must be validated.
These are plaintext exhaustive/count models; no general affine API is relaxed.
"""

from __future__ import annotations

import itertools

import gmpy2

from experiments.bfv_search_lab import field_frontier as fields


def validate(widths: tuple[int, ...]) -> None:
    if (type(widths) is not tuple or not 1 <= len(widths) <= 64
            or any(type(w) is not int or not 1 <= w <= 64 for w in widths) or sum(widths) > 512):
        raise ValueError("Expected a bounded public categorical schema")


def word(widths: tuple[int, ...], values: tuple[int, ...]) -> int:
    validate(widths)
    if (type(values) is not tuple or len(values) != len(widths)
            or any(type(v) is not int or not 0 <= v < w for v, w in zip(values, widths, strict=True))):
        raise ValueError("Invalid categorical input")
    result, offset = 0, 0
    for width, value in zip(widths, values, strict=True):
        result |= 1 << (offset + value)
        offset += width
    return result


def validate_word(widths: tuple[int, ...], value: int) -> None:
    validate(widths)
    if type(value) is not int or not 0 <= value < 1 << sum(widths):
        raise ValueError("Invalid bounded categorical word")
    offset = 0
    for width in widths:
        if ((value >> offset) & ((1 << width) - 1)).bit_count() != 1:
            raise ValueError("One-hot constraint violated")
        offset += width


def distance(widths: tuple[int, ...], a: int, b: int, prime: int) -> int:
    validate_word(widths, a)
    validate_word(widths, b)
    diameter = 2 * sum(w > 1 for w in widths)
    if type(prime) is not int or not diameter < prime <= 65537 or not prime % 2 or not gmpy2.is_prime(prime):
        raise ValueError("Plaintext field must cover the certified schema diameter")
    actual = (a.bit_count() + b.bit_count() - 2 * (a & b).bit_count()) % prime
    assert actual == (a ^ b).bit_count()
    return actual


def exhaustive(widths: tuple[int, ...], prime: int) -> dict:
    validate(widths)
    count = 1
    for w in widths:
        count *= w
    if count ** 2 > 65536:
        raise ValueError("Schema-pair enumeration exceeds the tiny oracle budget")
    rows = tuple(word(widths, values) for values in itertools.product(*(range(w) for w in widths)))
    maximum = 0
    for a, b in itertools.product(rows, repeat=2):
        maximum = max(maximum, distance(widths, a, b, prime))
    return {"widths": widths, "dimension": sum(widths), "rows": count, "pairs": count ** 2,
            "t": prime, "maximum_exact_distance": maximum, "all_valid_pairs_exact": True}


def frontier(widths: tuple[int, ...], *, slots: int, n: int = 16384) -> dict:
    validate(widths)
    if (type(slots) is not int or not 1 <= slots <= 64 or slots & (slots - 1)
            or type(n) is not int or not 8 <= n <= 32768 or n & (n - 1) or n < slots):
        raise ValueError("Expected a dyadic final slot count")
    diameter = 2 * sum(w > 1 for w in widths)
    minimum_score_prime = next(t for t in range(max(3, diameter + 1), 65538, 2 if diameter % 2 == 0 else 1)
                               if t % 2 and gmpy2.is_prime(t))
    minimum_joint_prime = next(t for t in range(max(3, diameter + 1), 65538)
                               if t % 2 and gmpy2.is_prime(t) and fields.max_slots(t) >= slots)
    # Raw single-map query/index models: no t-dependent affine map is assumed.
    t = minimum_score_prime
    d, b = sum(widths), t // 2
    phase = (b + 21 * t) * (1 + d * b)
    analytic = None
    for bits in range(max(16, n.bit_length() + 1), 57):
        try:
            if 2 * phase < fields.modulus(n, bits):
                analytic = bits
                break
        except ValueError:
            continue
    if analytic is None:
        raise ValueError("Schema phase model exceeds bounded modulus range")
    implemented = max(32, analytic)
    return {"dimension": d, "certified_diameter": diameter, "requested_slots": slots,
            "minimum_score_prime": minimum_score_prime, "score_prime_root_slots": fields.max_slots(t),
            "minimum_joint_score_root_prime": minimum_joint_prime,
            "raw_scalar_column_phase_model": phase, "raw_scalar_minimum_analytic_q_bits_model": analytic,
            "raw_scalar_supported_q_bits_model": implemented,
            "raw_scalar_index_body_bytes_model": d * 2 * n * ((implemented + 7) // 8),
            "scope": "Public schema/range and raw-column models only; no small-field affine map/encryption profile implemented."}
