"""E38 exact allowed domains and root/range counterexamples."""

import pytest

from experiments.bfv_search_lab import schema_metric_oracles as schema
from experiments.bfv_search_lab import binary_fixtures as fixtures


def test_all_schema_pairs_fit_a_field_below_binary_dimension():
    result = schema.exhaustive((5, 5), 5)
    assert result["dimension"] == 10
    assert result["pairs"] == 625
    assert result["maximum_exact_distance"] == 4
    assert result["all_valid_pairs_exact"]


def test_unrestricted_query_is_not_covered_by_the_schema_proof():
    a = schema.word((5, 5), (0, 0))
    b = a ^ 31  # Invalid one-hot input, distance 5 aliases distance zero in F_5.
    assert (a ^ b).bit_count() == 5
    assert ((a ^ b).bit_count() % 5) == 0
    with pytest.raises(ValueError, match="One-hot"):
        schema.distance((5, 5), a, b, 5)


def test_constant_attributes_and_range_guard():
    assert schema.exhaustive((1, 3, 1), 3)["maximum_exact_distance"] == 2
    with pytest.raises(ValueError, match="diameter"):
        schema.exhaustive((3, 3), 3)


def test_real_mushroom_root_limit_and_large_raw_index_are_retained():
    widths = tuple(map(len, fixtures.MUSHROOM_CATEGORIES))
    model = schema.frontier(widths, slots=32)
    assert model["dimension"] == 126 and model["certified_diameter"] == 44
    assert model["minimum_score_prime"] == 47 and model["score_prime_root_slots"] == 1
    assert model["minimum_joint_score_root_prime"] == 193
    assert model["raw_scalar_index_body_bytes_model"] == 16515072
