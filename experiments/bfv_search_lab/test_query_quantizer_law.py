"""E114 independent tiny laws, ideal-mask premises and integer boundary tests."""

from collections import Counter
from fractions import Fraction
from itertools import product

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import compressed_query_bgv as codec
from experiments.bfv_search_lab.query_quantizer_law import (
    QuantizerLaw, cbd_mgf, cbd_pmf, ceil_div, joint_mgf, tail_certificate,
    terminal_radius, upward_dyadic,
)


@pytest.mark.parametrize("q,t,drop", [(23, 3, 3), (31, 5, 4), (127, 5, 5),
                                      (255, 17, 7), (17, 3, 1)])
def test_tiny_literal_codec_distribution_and_partial_cycle(q, t, drop):
    law = QuantizerLaw(q, t, drop)
    observed = Counter()
    for c in range(q):
        radix = 1 << drop
        word = (c // radix) * t + (c % radix) % t
        expanded = ((word // t) * radix + word % t
                    + t * (((radix - 1) // t) // 2)) % q
        centered = (expanded - c) % q
        if centered > q // 2:
            centered -= q
        assert centered % t == 0
        observed[centered // t] += 1
        assert law.literal_map(c) == (word, expanded)
        assert law.added_error(c) == centered
    assert observed == dict(law.pmf())
    assert sum(observed.values()) == q
    assert law.mean_units() == Fraction(sum(x * count for x, count in observed.items()), q)
    assert law.second_moment_units() == Fraction(sum(x*x * count for x, count in observed.items()), q)
    assert law.tail > 0  # Odd Q cannot be a multiple of the power-of-two radix.


@pytest.mark.parametrize("drop", [1, 7, 10])
def test_smallest_actual_codec_width_exhaustion(drop):
    q, t = 65521, 17
    admitted = codec.coefficient_encoding(mpz(q), t, drop)
    law = QuantizerLaw(q, t, drop)
    assert admitted.center == t * law.center_units
    assert admitted.added_bound == law.added_bound
    counts = Counter()
    largest_word = 0
    for c in range(q):
        word = (c >> drop) * t + ((c & ((1 << drop) - 1)) % t)
        high, residue = divmod(word, t)
        expanded = ((high << drop) + residue + admitted.center) % q
        added = (expanded - c + q // 2) % q - q // 2
        counts[added // t] += 1
        largest_word = max(largest_word, word)
    assert largest_word == admitted.max_word
    assert counts == dict(law.pmf())


@pytest.mark.parametrize("q,t,drop", [(23, 3, 3), (127, 5, 5), (17, 3, 1)])
@pytest.mark.parametrize("base", [Fraction(1), Fraction(3, 2), Fraction(2, 3)])
def test_exact_geometric_mgf_matches_literal_rational_sum(q, t, drop, base):
    law = QuantizerLaw(q, t, drop)
    expected = sum((base ** value * count / q for value, count in law.pmf()), Fraction())
    assert law.mgf(base) == expected


@pytest.mark.parametrize("eta", [1, 2, 3])
def test_cbd_coin_enumeration_mgf_and_moments(eta):
    coins = Counter()
    for literal in product((0, 1), repeat=2 * eta):
        coins[sum(literal[:eta]) - sum(literal[eta:])] += 1
    assert coins == dict(cbd_pmf(eta))
    assert sum(coins.values()) == 4 ** eta
    assert sum(x * count for x, count in coins.items()) == 0
    assert Fraction(sum(x*x * count for x, count in coins.items()), 4 ** eta) == Fraction(eta, 2)
    base = Fraction(5, 4)
    assert cbd_mgf(eta, base) == sum((base ** x * count / 4 ** eta
                                            for x, count in coins.items()), Fraction())


def test_joint_law_accounts_for_bias_and_independent_cbd():
    law, eta, base = QuantizerLaw(23, 3, 3), 2, Fraction(3, 2)
    assert law.mean_units() != 0
    joint = Counter()
    for value, count in law.pmf():
        for error, weight in cbd_pmf(eta):
            joint[value + error] += count * weight
    denominator = law.q * 4 ** eta
    assert sum(joint.values()) == denominator
    assert joint_mgf(law, eta, base) == sum((base ** x * count / denominator
                                                     for x, count in joint.items()), Fraction())
    assert joint_mgf(law, eta, base) != joint_mgf(law, eta, 1 / base)


def _ring_product2(left, right, q):
    return ((left[0] * right[0] - left[1] * right[1]) % q,
            (left[0] * right[1] + left[1] * right[0]) % q)


@pytest.mark.parametrize("secret", [(1, 0), (1, 1)])
def test_unit_mask_permutation_gives_full_joint_uniformity_independent_of_error(secret):
    q, t, message = 17, 3, (1, 2)
    # This exhausts the full ring R_17=X^2+1 rather than assuming independent
    # scalar products. Both supported ternary secrets are units (det=1 or 2).
    expected = Counter(product(range(q), repeat=2))
    laws = []
    for errors in ((0, 0), (-1, 1), (1, -1)):
        observed = Counter()
        for mask in product(range(q), repeat=2):
            multiplied = _ring_product2(mask, secret, q)
            observed[tuple((m + t * e - a) % q
                           for m, e, a in zip(message, errors, multiplied, strict=True))] += 1
        assert observed == expected
        laws.append(observed)
    assert laws[0] == laws[1] == laws[2]


def test_nonunit_supported_secret_does_not_give_uniform_or_error_independent_c0():
    q, t, secret = 17, 3, (0, 0)
    laws = []
    for error in ((0, 0), (-1, 1)):
        observed = Counter()
        for mask in product(range(q), repeat=2):
            multiplied = _ring_product2(mask, secret, q)
            observed[tuple((t * e - a) % q for e, a in zip(error, multiplied, strict=True))] += 1
        laws.append(observed)
    assert len(laws[0]) == len(laws[1]) == 1
    assert laws[0] != laws[1]


def test_query_chosen_after_mask_can_destroy_uniformity_even_with_unit_secret():
    q, secret = 17, (1, 0)
    observed = Counter()
    for mask in product(range(q), repeat=2):
        multiplied = _ring_product2(mask, secret, q)
        # A post-mask choice among signed binary messages, rather than an
        # unrestricted message that simply cancels the complete mask.
        message = (1 if multiplied[0] % 2 == 0 else -1, 1)
        observed[tuple((m - a) % q for m, a in zip(message, multiplied, strict=True))] += 1
    assert observed != Counter(product(range(q), repeat=2))
    assert len(observed) < q * q


def test_exact_endpoint_convexity_includes_signed_intermediate_weights():
    law, eta, base = QuantizerLaw(23, 3, 3), 1, Fraction(4)
    upper = max(joint_mgf(law, eta, base), joint_mgf(law, eta, 1 / base))
    # With W=2, a=-1/+1 gives exact rational bases 1/2 and 2.
    for weighted_base in (Fraction(1, 4), Fraction(1, 2), Fraction(1), Fraction(2), Fraction(4)):
        assert joint_mgf(law, eta, weighted_base) <= upper


@pytest.mark.parametrize("q,p,t,n", [(107, 29, 3, 2), (1049, 29, 17, 1), (37, 13, 3, 1)])
def test_terminal_integer_radius_is_the_greatest_sufficient_safe_bound(q, p, t, n):
    radius, rounding = terminal_radius(q, p, t, n)
    admitted = [b for b in range((q - 1) // 2 + 1)
                if ceil_div(p * b, q) + rounding <= (p - 1) // 2]
    assert radius == (max(admitted) if admitted else -1)
    if radius >= 0:
        assert ceil_div(p * radius, q) + rounding <= (p - 1) // 2
        if radius < (q - 1) // 2:
            assert ceil_div(p * (radius + 1), q) + rounding > (p - 1) // 2


def test_negative_terminal_allowance_is_not_a_positive_certificate():
    radius, rounding = terminal_radius(107, 29, 3, 16)
    assert radius == -1 and rounding > (29 - 1) // 2


@pytest.mark.parametrize("value", [Fraction(1), Fraction(1, 3), Fraction(5, 7), Fraction(9, 5)])
def test_dyadic_rounding_is_outward_not_nearest(value):
    rounded = upward_dyadic(value, 5)
    assert value <= rounded < value + Fraction(1, 32)
    assert rounded * 32 == int(rounded * 32)


def test_tail_sign_union_and_floor_accounting_are_exact():
    result = tail_certificate(n=3, threshold=7001, t=3, weight_bound=2,
                              plus=Fraction(11, 10), minus=Fraction(6, 5),
                              base=Fraction(2), lifetime_queries=4, output_coefficients=8)
    assert result["normalized_floor_threshold"] == 7001 // 6
    assert result["mgf_endpoint_upper"] == upward_dyadic(Fraction(6, 5))
    exact_a = (7001 // 6) * Fraction(1, 2) - 3 * (result["mgf_endpoint_upper"] - 1)
    assert result["log_exponent_lower"] == exact_a
    exponent = exact_a.numerator // exact_a.denominator
    assert result["per_output_two_sided_upper"] == Fraction(1, 1 << (exponent - 1))
    assert result["lifetime_union_factor"] == 32
    assert result["lifetime_upper"] == 32 * result["per_output_two_sided_upper"]


@pytest.mark.parametrize("threshold", [-1, 0, 1])
def test_unresolved_or_nonpositive_exponent_returns_trivial_one(threshold):
    result = tail_certificate(n=10, threshold=threshold, t=3, weight_bound=2,
                              plus=Fraction(2), minus=Fraction(1), base=Fraction(2),
                              lifetime_queries=4, output_coefficients=8)
    assert result["per_output_two_sided_upper"] == result["lifetime_upper"] == 1


def test_tiny_exact_random_tail_is_below_certificate():
    law, eta, base = QuantizerLaw(23, 3, 3), 1, Fraction(3, 2)
    joint = Counter()
    for a, count in law.pmf():
        for e, weight in cbd_pmf(eta):
            joint[a + e] += count * weight
    denominator = law.q * 4 ** eta
    # Two unequal signed weights, rather than repeated endpoints.
    for threshold in (3, 9, 24, 90):
        mass = sum(c * d for a, c in joint.items() for b, d in joint.items()
                   if abs(3 * (2 * a - b)) >= threshold)
        exact_tail = Fraction(mass, denominator ** 2)
        result = tail_certificate(n=2, threshold=threshold, t=3, weight_bound=2,
                                  plus=joint_mgf(law, eta, base),
                                  minus=joint_mgf(law, eta, 1 / base), base=base,
                                  lifetime_queries=1, output_coefficients=1)
        assert exact_tail <= result["per_output_two_sided_upper"]


@pytest.mark.parametrize("arguments", [(True, 3, 2), (23.0, 3, 2), (23, True, 2),
                                       (23, 3, True), (24, 3, 2), (23, 4, 2),
                                       (23, 3, 0), (23, 3, 5), (5, 3, 2)])
def test_quantizer_strict_grammar_and_unique_lift(arguments):
    with pytest.raises(ValueError):
        QuantizerLaw(*arguments)


@pytest.mark.parametrize("bad", [True, 1.5, -1, 23])
def test_original_coefficient_requires_exact_canonical_integer(bad):
    with pytest.raises(ValueError):
        QuantizerLaw(23, 3, 3).added_error(bad)


@pytest.mark.parametrize("base", [1.0, 2, Fraction(0), Fraction(-1)])
def test_mgf_requires_positive_fraction(base):
    with pytest.raises(ValueError):
        QuantizerLaw(23, 3, 3).mgf(base)


def test_tail_and_terminal_reject_numeric_aliases_and_wrong_context():
    with pytest.raises(ValueError):
        terminal_radius(107, 31, 3, 2)
    with pytest.raises(ValueError):
        terminal_radius(107, 29, 3, True)
    with pytest.raises(ValueError):
        tail_certificate(n=True, threshold=100, t=3, weight_bound=2,
                         plus=Fraction(1), minus=Fraction(1), base=Fraction(2),
                         lifetime_queries=1, output_coefficients=1)
    with pytest.raises(ValueError):
        tail_certificate(n=2, threshold=100, t=3, weight_bound=2,
                         plus=Fraction(1), minus=Fraction(1), base=Fraction(1),
                         lifetime_queries=1, output_coefficients=1)


def test_terminal_rejects_congruent_larger_modulus_outside_compact_v1():
    # P=113 and Q=107 are both 2 mod3, so the congruence-only guard does not
    # distinguish an upscaling map from the registered compact-P<Q relation.
    with pytest.raises(ValueError):
        terminal_radius(107, 113, 3, 2)
