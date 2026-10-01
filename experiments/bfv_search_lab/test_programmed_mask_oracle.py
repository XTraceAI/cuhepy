"""E74 exact programmed products, clean-set counts and leakage controls."""

from itertools import combinations, product
from math import comb

import pytest

from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import programmed_mask_oracle as oracle
from experiments.bfv_search_lab.test_supported_decoder import CASES, inputs


def test_all_small_field_recombinations_independent_integer_product():
    q, code = 3, ((1,), (2,), (1,))
    matrix = ((1, 0, 2), (2, 1, 1))
    compiled = tuple(sum(a*b[0] for a, b in zip(row, code, strict=True)) % q for row in matrix)
    checked = 0
    for secret in range(q):
        for error in product(range(q), repeat=3):
            sample = oracle.mask(code, (secret,), error, q)
            direct = tuple(sum(a*b for a, b in zip(row, sample, strict=True)) % q for row in matrix)
            programmed = tuple((a*secret+sum(x*y for x, y in zip(row, error, strict=True))) % q
                               for a, row in zip(compiled, matrix, strict=True))
            assert programmed == direct
            checked += 1
    assert checked == 81


@pytest.mark.parametrize("descriptor", CASES)
@pytest.mark.parametrize("shared", (0, 1))
def test_actual_crt_coordinate_schedule_and_shared_forms(descriptor, shared):
    original, _, groups, _, _ = inputs(*descriptor)
    s = crt.space(original.layout, original.map_ids, shared=shared)
    code = tuple(((i+1) % 17, (i*i+3) % 17) for i in range(s.dimension))
    compiled = oracle.compile_scores(s, groups, code)
    for secret in ((0, 0), (1, 7), (16, 16)):
        error = tuple(3 if i % 3 == 0 else 0 for i in range(s.dimension))
        sample = oracle.mask(code, secret, error, 17)
        assert oracle.programmed_scores(s, groups, compiled, secret, error) == tuple(tuple(row) for row in crt.scores(s, groups, sample))


def test_noiseless_or_public_support_exposes_exact_query_syndrome():
    q, code, query = 17, ((1,),)*4, (3, 8, 2, 4)
    annihilator = (1, -1, 0, 0)
    for error in ((0, 0, 0, 0), (0, 0, 7, 5)):
        r = oracle.mask(code, (9,), error, q)
        delta = tuple((a-b) % q for a, b in zip(query, r, strict=True))
        assert sum(a*b for a, b in zip(annihilator, r, strict=True)) % q == 0
        assert sum(a*b for a, b in zip(annihilator, delta, strict=True)) % q == sum(a*b for a, b in zip(annihilator, query, strict=True)) % q


def test_clean_information_set_recovers_toy_pad_and_distinguishes_known_query_pair():
    code, q, secret = tuple((1, i) for i in range(12)), 17, (3, 7)
    error = (5,)+(0,)*11
    r = oracle.mask(code, secret, error, q)
    recovered = oracle.recover_tiny_sample(code, r, q, 1)
    assert recovered["secret"] == secret and recovered["error"] == error and recovered["sets_examined"] == 12
    # Given public delta and two known candidate queries, one candidate mask
    # decodes while the other has two errors, not the declared one. This is a
    # tiny public-code privacy control, never a production HE secret attack.
    wrong = (r[0], (r[1]+1) % q, *r[2:])
    assert oracle.recover_tiny_sample(code, wrong, q, 1) is None


def test_exact_clean_set_probability_including_rank_independent_geometry():
    for n, k, weight in ((6, 2, 1), (8, 3, 2), (12, 2, 1)):
        bad = frozenset(range(weight))
        clean = sum(not bad.intersection(c) for c in combinations(range(n), k))
        p = oracle.clean_set_probability(n, k, weight)
        assert p.numerator*comb(n, k) == p.denominator*clean
    assert oracle.clean_set_probability(8, 3, 7) == 0


def test_monotone_cost_frontier_matches_exhaustive_parameter_search():
    for n, f in ((8, 4), (12, 8), (16, 16)):
        result = oracle.saving_frontier(n, f, 17, target_bits=4)
        exhaustive = [(oracle.clean_set_probability(n, k, weight), k, weight)
                      for k in range(1, n) for weight in range(n-k+1)
                      if 5*(k*n+f*weight) <= 4*f*n]
        optimum = min(exhaustive)[0]
        best = result["largest_trial_exponent_saving_candidate"]
        assert oracle.clean_set_probability(n, best["k"], best["weight"]) == optimum
        passing = [(k*n+f*weight, k, weight) for k in range(1, n) for weight in range(n-k+1)
                   if 17**k >= 16 and comb(n, k) >= 16*comb(n-weight, k)]
        actual = result["cheapest_recipe_passing_both_incomplete_filters"]
        if passing:
            expected = min(passing)
            assert actual["expected_row_products"] == expected[0]/n
        else:
            assert actual is None


def test_bounded_oracle_rejects_noncanonical_dimensions_and_parameters():
    with pytest.raises(ValueError):
        oracle.mask(((1,),), (1,), (17,), 17)
    with pytest.raises(ValueError):
        oracle.saving_frontier(8, 9, 17)
    with pytest.raises(ValueError):
        oracle.clean_set_probability(8, 8, 0)
