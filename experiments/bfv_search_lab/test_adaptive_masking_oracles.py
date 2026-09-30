"""Exact adaptive ideal-pad controls; no probabilistic HE security claim."""

from collections import Counter
from fractions import Fraction
import itertools

import pytest

from experiments.bfv_search_lab import adaptive_masking_oracles as masks


@pytest.mark.parametrize("field", (3, 5, 7))
def test_every_small_query_is_a_bijection_of_the_fresh_pad(field):
    for dimension in (1, 2):
        vectors = tuple(itertools.product(range(field), repeat=dimension))
        expected = dict.fromkeys(vectors, 1)
        for query in vectors:
            assert masks.one_step(field, query) == expected


@pytest.mark.parametrize("field,dimension,requests", ((3, 2, 3), (5, 2, 2), (7, 1, 3)))
def test_full_adaptive_transcript_is_independent_of_reused_errors_in_ideal_model(field, dimension, requests):
    result = masks.joint(field, dimension, requests)
    assert result.independence_distance() == 0
    assert result.mass == 4 ** dimension * field ** (dimension * requests)
    marginal = Counter()
    for (_, ds), count in result.counts.items():
        marginal[ds] += count
    assert len(marginal) == field ** (dimension * requests)
    assert set(marginal.values()) == {4 ** dimension}


@pytest.mark.parametrize("mode", ("reuse", "early_linear", "select"))
def test_reuse_early_linear_disclosure_and_error_dependent_token_selection_fail(mode):
    result = masks.joint(5, 2, 1 if mode == "select" else 2, mode=mode)
    assert result.independence_distance() > Fraction(1, 20)
    if mode == "early_linear":
        for (error, transcript), _ in result.counts.items():
            sign = 1 if error[0] > 0 else -1 if error[0] < 0 else 0
            assert all(sum(ds) % 5 == sign % 5 for ds in transcript)


def test_scope_and_enumeration_limits():
    description = masks.describe(masks.joint())
    assert description["error_delta_independence_tv"] == "0/1"
    assert "no encrypted" in description["scope"]
    for kwargs in ({"field": 4}, {"dimension": 3}, {"requests": 0}, {"mode": "encrypted_proof"},
                   {"field": 7, "dimension": 2, "requests": 3}):
        with pytest.raises(ValueError):
            masks.joint(**kwargs)
