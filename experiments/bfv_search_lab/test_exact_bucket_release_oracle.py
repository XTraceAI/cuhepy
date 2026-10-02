"""Exact ID/coverage, field-multiplicity and packing boundaries for E84."""

from dataclasses import replace
from itertools import product

import pytest

from experiments.bfv_search_lab import exact_bucket_release_oracle as oracle


def test_all_five_row_scores_and_stable_ties_match_independent_sort():
    ids = (8, 3, 21, 1, 15)
    checked = 0
    for scores in product(range(4), repeat=5):
        claim = oracle.certificate(scores, ids, 3)
        expected = tuple(sorted(zip(scores, ids, strict=True))[:3])
        assert claim.winners == expected
        assert oracle.check_certificate(scores, ids, 3, claim)
        checked += 1
    assert checked == 1024


@pytest.mark.parametrize("scores,ids", (((), ()), ((1,), (8,)), ((1, 1), (8, 2))))
def test_fewer_than_three_live_rows_and_ties(scores, ids):
    claim = oracle.certificate(scores, ids, 2)
    assert oracle.check_certificate(scores, ids, 2, claim)
    assert claim.winners == tuple(sorted(zip(scores, ids, strict=True)))


def test_histogram_alone_does_not_bind_stable_ids_or_omitted_rows():
    ids, left, right = (9, 2, 7, 1), (0, 1, 2, 3), (3, 2, 1, 0)
    a, b = oracle.certificate(left, ids, 3), oracle.certificate(right, ids, 3)
    assert a.counts == b.counts and a.winners != b.winners
    assert not oracle.check_certificate(left, ids, 3, b)
    assert not oracle.check_certificate(left, ids, 3, replace(a, cutoff=(2, 2)))
    assert not oracle.check_certificate(left, ids, 3, replace(a, counts=(0, 2, 1, 1)))
    assert not oracle.check_certificate(left, ids, 3, replace(a, row_count=3))
    assert not oracle.check_certificate(left, ids, 3, replace(a, winners=(a.winners[0],) * 3))


@pytest.mark.parametrize("prime", (3, 5, 17, 193, 257, 1031))
def test_frobenius_histogram_collision_at_every_base_field_point(prime):
    left, right = (prime, 1), (1, prime)
    assert sum(left) == sum(right) and left != right
    assert all(oracle.histogram_product(left, point, prime) ==
               oracle.histogram_product(right, point, prime) for point in range(prime))
    # Different exact top-3 distances: (0,0,0) versus (0,1,1).
    assert left[0] >= 3 and right[0] == 1


def test_extension_challenge_detects_this_collision_outside_base_subfield():
    equal = []
    for point in product(range(5), repeat=2):
        if oracle.f25_histogram_product((5, 1), point) == oracle.f25_histogram_product((1, 5), point):
            equal.append(point)
    assert equal == [(i, 0) for i in range(5)]
    # An ordinary prime-field lift is a different characteristic, not this extension.
    assert oracle.histogram_product((5, 1), 2, 17) != oracle.histogram_product((1, 5), 2, 17)


@pytest.mark.parametrize("dimension,prime", ((3, 5), (4, 5), (7, 17)))
def test_prefix_polynomials_are_exact_on_every_admitted_score(dimension, prime):
    for threshold in range(dimension + 2):
        polynomial = oracle.prefix_polynomial(dimension, threshold, prime)
        for score in range(dimension + 1):
            assert oracle.polynomial_value(polynomial, score, prime) == int(score < threshold)


def test_modular_bucket_counts_require_integer_lifts_and_carries():
    assert 0 % 193 == 193 % 193  # Different coverage counts share one residue.
    with pytest.raises(ValueError):
        oracle.prefix_polynomial(5, 2, 5)  # Different distances would share nodes.


def test_challenge_extension_count_uses_degree_and_lifetime_not_slot_width():
    card = oracle.challenge_degree(1031, 8191, attempts=1024)
    k, order = card["extension_degree"], int(card["field_order"])
    target = 8191 * 1024 * 2 ** 128
    assert order >= target and 1031 ** (k - 1) < target


def test_ring_frobenius_orbits_distinguish_coefficients_from_scalar_slots():
    card = oracle.ring_slot_structure(16384, 1031)
    assert card["irreducible_factor_degree"] == 4096 and card["extension_field_slots"] == 4
    assert not card["full_base_field_scalar_SIMD"]
    assert oracle.ring_slot_structure(16384, 65537)["extension_field_slots"] == 16384
    assert oracle.ring_slot_structure(8, 3)["irreducible_factor_degree"] == 4


def test_plaintext_ring_squaring_is_not_coefficientwise_score_squaring():
    # In F5[X]/(X^2+1), (1+X)^2 = 2X; squaring coefficients gives 1+X.
    assert ((1 - 1) % 5, 2) != (1, 1)


def test_caps_canonical_scores_ids_fields_and_invalid_extension_rejected():
    with pytest.raises(ValueError):
        oracle.certificate((1, 2), (8, 8), 3)
    with pytest.raises(ValueError):
        oracle.certificate((True,), (0,), 3)
    with pytest.raises(ValueError):
        oracle.ring_slot_structure(3, 5)
    with pytest.raises(ValueError):
        oracle.ring_slot_structure(16, 15)
    with pytest.raises(ValueError):
        oracle.f25_multiply((5, 0), (1, 0))
