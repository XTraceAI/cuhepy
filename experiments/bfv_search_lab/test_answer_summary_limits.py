"""Independent exact enumerations for the E39 aggregate/coverage controls."""

from __future__ import annotations

import itertools

import pytest

from experiments.bfv_search_lab import answer_summary_limits as limits


def test_three_distances_collide_for_count_sum_and_squares():
    buckets = {}
    found = set()
    for values in itertools.combinations_with_replacement(range(5), 3):
        key = (len(values), sum(values), sum(x * x for x in values))
        for other in buckets.get(key, []):
            if other[0] != values[0]:
                found.add((other, values))
        buckets.setdefault(key, []).append(values)
    assert ((0, 3, 3), (1, 1, 4)) in found
    assert limits.Collision((0, 3, 3), (1, 1, 4), 2).describe()["valid_query_zero_hamming_embedding"]


@pytest.mark.parametrize("degree", range(1, 9))
def test_known_partitions_equal_exact_power_sums_but_not_minimum(degree):
    a, b = limits.thue_morse(degree)
    assert set(a).isdisjoint(b) and sorted(a + b) == list(range(1 << (degree + 1)))
    assert limits.moments(a, degree) == limits.moments(b, degree)
    assert sum(x ** (degree + 1) for x in a) != sum(x ** (degree + 1) for x in b)
    assert min(a) == 0 and min(b) == 1
    assert tuple(row.bit_count() for row in limits.rows(a, max(a + b))) == a


def test_histogram_and_all_distance_only_moments_omit_ids():
    a, b = (0, 1, 2, 3), (3, 2, 1, 0)
    assert limits.moments(a, 8) == limits.moments(b, 8)
    assert limits.top(a) != limits.top(b)


def test_coverage_with_stable_ties_is_sufficient_against_every_completion():
    for lower in itertools.product(range(3), repeat=4):
        measured = {0: lower[0], 1: lower[1]}
        good = limits.coverage(lower, measured, k=2)
        for remaining in itertools.product(range(3), repeat=2):
            if any(remaining[j] < lower[j + 2] for j in range(2)):
                continue
            values = (measured[0], measured[1], *remaining)
            if good:
                assert limits.top(values, 2) == limits.top((measured[0], measured[1]), 2)
    assert not limits.coverage((2, 2, 2, 0), {0: 2, 1: 2, 2: 2})
    assert limits.coverage((0, 0, 0, 0), {0: 0, 1: 0, 2: 0})
    assert not limits.coverage((0, 0, 0, 0), {1: 0, 2: 0, 3: 0})


def test_invalid_inputs_are_not_exact_summary_claims():
    for degree in (0, 9, True):
        with pytest.raises(ValueError):
            limits.thue_morse(degree)
    with pytest.raises(ValueError):
        limits.rows((5,), 4)
    with pytest.raises(ValueError):
        limits.coverage((2, 2, 2), {0: 1, 1: 2, 2: 2})
    report = limits.describe()
    assert len(report["moment_collisions"]) == 3
