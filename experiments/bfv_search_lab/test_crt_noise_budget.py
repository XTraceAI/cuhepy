"""Exact entropy/distribution, variance and violated-assumption controls."""

from collections import Counter
from dataclasses import replace
from decimal import Decimal, localcontext
from fractions import Fraction
import itertools
from math import comb

import pytest

from experiments.bfv_search_lab import crt_noise_budget as noise
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as crt
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import reduction_oracles as reduction


@pytest.mark.parametrize("eta", (1, 2, 3, 4))
def test_cbd_exact_counts_match_every_sampler_entropy_word(eta):
    width = (2 * eta + 7) // 8
    words = range(1 << (2 * eta))
    entropy = b"".join(x.to_bytes(width, "little") for x in words)
    actual = Counter(owner._errors_from_bytes(entropy, len(words), eta))
    assert actual == dict(noise.cbd_counts(eta))
    assert sum(actual.values()) == 1 << (2 * eta)


@pytest.mark.parametrize("weights,eta", (((1, -2, 0, 3), 1), ((1, 2, -3), 2), ((0, 0), 3)))
def test_weighted_distribution_against_every_independent_entropy_assignment(weights, eta):
    errors = [sum((word >> j) & 1 for j in range(eta)) - sum((word >> (eta + j)) & 1 for j in range(eta))
              for word in range(1 << (2 * eta))]
    actual = Counter(sum(a * b for a, b in zip(weights, es, strict=True))
                     for es in itertools.product(errors, repeat=len(weights)))
    assert actual == noise.weighted_counts(weights, eta)
    denominator = 1 << (2 * eta * len(weights))
    assert sum(actual.values()) == denominator
    assert sum(x * mass for x, mass in actual.items()) == 0
    assert Fraction(sum(x * x * mass for x, mass in actual.items()), denominator) == Fraction(eta, 2) * sum(x * x for x in weights)


def test_exact_mgf_and_subgaussian_inequality_numerical_sanity():
    # The proof is analytic. High-precision values independently sanity-check
    # its exact finite-distribution identity; these are not tail-probability MC.
    with localcontext() as ctx:
        ctx.prec = 80
        for eta, x in itertools.product((1, 3, 21), (Decimal("0"), Decimal("0.1"), Decimal("0.7"), Decimal("2"))):
            exact = sum(Decimal(mass) * (x * e).exp() for e, mass in noise.cbd_counts(eta)) / (1 << (2 * eta))
            cosh = ((x / 2).exp() + (-x / 2).exp()) / 2
            assert abs(exact - cosh ** (2 * eta)) <= Decimal("1e-65") * max(Decimal(1), exact)
            assert exact <= (Decimal(eta) * x * x / 4).exp()


def test_negacyclic_error_coefficients_have_predicted_exact_distribution():
    # One short correction in N=8: coefficient zero depends on distinct
    # e[0] and e[4], plus an independent fresh-answer error. Enumerate each.
    correction = (2, 0, 0, 0, -3, 0, 0, 0)
    actual = Counter()
    # CBD(1) outcomes counted from their four equally likely entropy words.
    errors = (0, 1, -1, 0)
    for saved, e0, e4 in itertools.product(errors, repeat=3):
        poly = (e0, 0, 0, 0, e4, 0, 0, 0)
        actual[saved + reduction.ring_product(poly, correction)[0]] += 1
    assert actual == noise.weighted_counts((1, 2, 3), 1)


def test_error_dependent_signs_and_reused_error_break_the_fixed_independent_bound():
    terms = 256
    # A fixed unit-weight sum has variance proxy terms/2 for CBD(1).
    tail = noise.ceil_root_ratio(terms * 7 * (32 + 5), 10)
    assert tail < terms // 2
    # If weights are chosen as sign(e_i), sum w_i*e_i=sum |e_i| is Binomial
    # (terms,1/2). This exceeds the claimed fixed-weight tail almost always.
    dependent_failure = Fraction(sum(comb(terms, k) for k in range(tail + 1, terms + 1)), 1 << terms)
    assert dependent_failure > Fraction(99, 100) > Fraction(1, 1 << 32)
    # Repeating ONE CBD error instead of independently sampling every term
    # also has large tails and a different variance, even with fixed weights.
    correlated_failure = Fraction(sum(m for e, m in noise.cbd_counts(1) if abs(terms * e) > tail), 4)
    assert correlated_failure == Fraction(1, 2)


def test_integer_union_budget_and_full_size_q32_projection():
    ctx = crt.context(16384, tuple(format(i, "05b") for i in range(32)), 1153)
    s = space.space(crt.layout(ctx, (32,) * 32, (1,) * 32), tuple(range(32)))
    profile = noise.Profile(s)
    cert = noise.certificate(profile)
    assert cert.message_bound == 339739200 and cert.tail_bound == 1011162134
    assert cert.total == 1350901334 and 2 * cert.total < 4294475777
    short = space.corrections(s, tuple((i * 37) % 1153 for i in range(s.dimension)))
    actual = noise.certificate(profile, short)
    assert actual.total <= cert.total
    assert actual.message_bound == (1153 // 2) * (1 + sum(abs(x) for row in short for x in row))
    for numerator, denominator in ((0, 10), (9, 1), (10, 1), (10001, 1000), ((1 << 180) + 1, 7)):
        root = noise.ceil_root_ratio(numerator, denominator)
        assert root * root * denominator >= numerator
        assert root == 0 or (root - 1) ** 2 * denominator < numerator
    assert noise.certificate(replace(profile, query_budget=65536)).tail_bound > cert.tail_bound
    assert profile.binding != replace(profile, correctness_bits=129).binding
    for p in (replace(profile, assumption="adaptive"), replace(profile, query_budget=True), replace(profile, eta=0)):
        with pytest.raises(ValueError):
            noise.certificate(p)
