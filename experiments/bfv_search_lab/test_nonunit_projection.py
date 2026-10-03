"""E118 small independent algebra and dependent-codec projection regressions.

These tests do not repeat the registered full finite panels or execute HE.
"""

from collections import Counter
from dataclasses import replace
from fractions import Fraction
from itertools import permutations, product

import pytest

from benchmarks import nonunit_projection_lab as oracle
from experiments.bfv_search_lab import nonunit_projection as lab
from experiments.bfv_search_lab.query_quantizer_law import QuantizerLaw, cbd_pmf, joint_mgf


def schoolbook(left, right):
    n = len(left)
    out = [0] * n
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            at = i + j
            out[at % n] += a * b * (1 if at < n else -1)
    return tuple(out)


def leibniz(matrix):
    total = 0
    for permutation in permutations(range(len(matrix))):
        term = -1 if sum(permutation[i] > permutation[j]
                         for i in range(len(matrix)) for j in range(i + 1, len(matrix))) % 2 else 1
        for i, column in enumerate(permutation):
            term *= matrix[i][column]
        total += term
    return total


@pytest.mark.parametrize("matrix", [((0, 1), (1, 0)), ((1, 2), (2, 4)),
                                     ((1, -2), (3, 5)),
                                     ((0, 1, 2, 3), (1, 0, 4, 5), (2, 4, 0, 6), (3, 5, 6, 0)),
                                     ((0, 0, 0, 0), (1, 2, 3, 4), (1, 0, 2, 5), (3, 1, 0, 4))])
def test_finite_oracle_bareiss_matches_independent_leibniz_including_pivots(matrix):
    assert oracle.bareiss(matrix) == leibniz(matrix)


def test_independent_field_rank_controls_match_all_small_two_by_two_matrices():
    for a, b, c, d in product((-1, 0, 1), repeat=4):
        matrix = ((a, b), (c, d))
        expected = 2 if (a*d - b*c) % 5 else int(any((a, b, c, d)))
        assert lab.rank_mod(matrix, 5) == oracle.gaussian_rank(matrix, 5) == expected


@pytest.mark.parametrize("secret", [(1, -1), (-2, 1, 0, 0), (-4, 0, 1, 0),
                                    (-1, 0, -1, 1, 0, 0, 0, 0)])
def test_signed_toeplitz_matrix_matches_independent_monomial_schoolbook(secret):
    matrix = lab.multiplication_matrix(secret)
    n = len(secret)
    for column in range(n):
        basis = tuple(int(i == column) for i in range(n))
        expected = schoolbook(secret, basis)
        assert tuple(row[column] for row in matrix) == expected
    vector = tuple(i - 2 for i in range(n))
    assert lab.apply_matrix(matrix, vector, 17) == tuple(x % 17 for x in schoolbook(secret, vector))


@pytest.mark.parametrize("secret,zeros,prefix", [((-2, 1, 0, 0), (2,), 3),
                                               ((-4, 0, 1, 0), (2, 15), 2)])
def test_exact_nonternary_determinants_nullity_and_fixed_prefix(secret, zeros, prefix):
    ctx = lab.Context(4, 17, 2)
    matrix = lab.multiplication_matrix(secret)
    determinant = leibniz(matrix)
    norm2 = sum(x*x for x in secret)
    certificate = lab.norm_certificate(4, 17, norm2)
    assert set(lab.zero_roots(secret, ctx)) == set(zeros)
    assert lab.rank_mod(matrix, 17) == 4 - len(zeros)
    assert determinant != 0 and determinant % (17 ** len(zeros)) == 0
    assert abs(determinant) <= norm2 ** 2
    assert certificate.prefix_length == prefix
    assert lab.projection_rank(secret, 17, tuple(range(prefix))) == prefix


def test_arbitrary_subset_is_not_guaranteed_and_has_explicit_field_dependence():
    secret = (-4, 0, 1, 0)
    assert lab.projection_rank(secret, 17, (0, 1)) == 2
    assert lab.projection_rank(secret, 17, (0, 2)) == 1
    matrix = lab.multiplication_matrix(secret)
    assert all((4 * a - b) % 17 == 0 for a, b in zip(matrix[0], matrix[2], strict=True))
    # A minor from the root-parity columns0,2 is singular, unlike consecutive
    # columns2,3. This falsifies every-subset/MDS rather than full-map injectivity.
    roots = (2, 15)
    arbitrary_minor = tuple(tuple(pow(alpha, i, 17) for i in (0, 2)) for alpha in roots)
    consecutive_minor = tuple(tuple(pow(alpha, i, 17) for i in (2, 3)) for alpha in roots)
    assert lab.rank_mod(arbitrary_minor, 17) == 1
    assert lab.rank_mod(consecutive_minor, 17) == 2


def test_zero_secret_is_explicitly_outside_nonzero_determinant_certificate():
    secret, ctx = (0,) * 8, lab.Context(8, 17, 3)
    assert len(lab.zero_roots(secret, ctx)) == 8
    assert lab.rank_mod(lab.multiplication_matrix(secret), 17) == 0
    certificate = lab.norm_certificate(8, 17, 8)
    assert certificate.nullity_cap == 2 and certificate.prefix_length == 6
    # The certificate's nonzero premise is essential; zero must not be
    # inferred to have a uniform six-coordinate projection.
    assert lab.projection_rank(secret, 17, tuple(range(6))) == 0


def test_explicit_ternary_nonunit_does_not_require_a_unit_secret():
    secret, ctx = (-1, 0, -1, 1, 0, 0, 0, 0), lab.Context(8, 17, 3)
    assert lab.zero_roots(secret, ctx) == (3,)
    certificate = lab.norm_certificate(8, 17, 3)
    assert certificate.nullity_cap == 1 and certificate.prefix_length == 7
    assert lab.projection_rank(secret, 17, tuple(range(7))) == 7


def test_correlated_tiny_codec_image_has_uniform_prefix_independent_of_all_errors():
    # Separate N2 public unit-test illustration, not another registered main
    # context or an admitted small-Q crypto parameter. Rank1 secret gives
    # a correlated full image; only its first coordinate is uniform.
    secret, q, t, law = (-4, 1), 17, 3, QuantizerLaw(17, 3, 3)
    matrix = lab.multiplication_matrix(secret)
    assert lab.rank_mod(matrix, q) == 1
    prefix_mgf = Fraction()
    joint_full = Counter()
    error_weights = dict(cbd_pmf(1))
    denominator = q*q * 16
    for e0, e1 in product(error_weights, repeat=2):
        counts = Counter()
        error_weight = error_weights[e0] * error_weights[e1]
        for mask in product(range(q), repeat=2):
            multiplied = schoolbook(secret, mask)
            c0 = ((1 + t*e0 - multiplied[0]) % q, (-1 + t*e1 - multiplied[1]) % q)
            deltas = tuple(law.added_error(c) // t for c in c0)
            counts[deltas[0]] += 1
            prefix_mgf += error_weight * Fraction(2) ** (e0 + deltas[0]) / denominator
            if (e0, e1) == (0, 0):
                joint_full[deltas] += 1
        assert counts == {value: mass * q for value, mass in law.pmf()}
    assert prefix_mgf == joint_mgf(law, 1, Fraction(2))
    first = Counter()
    second = Counter()
    for (a, b), count in joint_full.items():
        first[a] += count
        second[b] += count
    assert any(Fraction(joint_full[a, b], q*q) != Fraction(first[a] * second[b], q**4)
               for a in first for b in second)


@pytest.mark.parametrize("norm2,k,m", [(1, 0, 8), (3, 1, 7), (8, 2, 6)])
def test_public_norm_bound_is_exact_at_adjacent_Q_powers(norm2, k, m):
    certificate = lab.norm_certificate(8, 17, norm2)
    assert (certificate.nullity_cap, certificate.prefix_length) == (k, m)
    assert 17 ** k <= norm2 ** 4 < 17 ** (k + 1)
    certificate.validate()


@pytest.mark.parametrize("mutation", ["nullity", "prefix", "norm", "type"])
def test_forged_public_norm_certificate_is_rejected(mutation):
    certificate = lab.norm_certificate(8, 17, 8)
    changed = {"nullity": {"nullity_cap": 1}, "prefix": {"prefix_length": 7},
               "norm": {"squared_norm_cap": 0}, "type": {"nullity_cap": True}}[mutation]
    with pytest.raises(ValueError):
        replace(certificate, **changed).validate()


@pytest.mark.parametrize("value", [Fraction(1), Fraction(1, 81), Fraction(1, 256),
                                   Fraction(17, 257), Fraction(1, 3) + Fraction(1, 8)])
def test_simple_dyadic_upper_is_conservative_and_the_best_one_term_bound(value):
    bits, upper = lab.dyadic_upper(value)
    assert value <= upper
    assert value > upper / 2
    assert upper == Fraction(1, 1 << bits)


def test_suffix_charge_and_zero_setup_are_not_silently_repeated_per_query():
    model = lab.Model(4, 1, 3, 17, 11, 3, 1, 4, 3)
    result = lab.correctness_model(model)
    assert result["all_output_coefficients"] == 4
    assert result["same_complete_lifetime_union"] == (1 << 32) * 4
    assert result["actual_unconditioned_raw_secret_zero_mass"] == Fraction(1, 81)
    assert result["omitted_phase_cap"] == 0  # Nonzero ternary N4/Q17 is unit.
    assert result["retained_random_threshold"] == result["original_random_threshold"]
    assert result["good_nonzero_secret_lifetime_tail_upper"] == 1
    assert result["single_setup_plus_lifetime_exact_ideal_upper"] == 1
    assert result["single_setup_plus_lifetime_dyadic_upper"] == 1


@pytest.mark.parametrize("arguments", [(True, 17, 2), (4, 17.0, 2), (4, 17, True),
                                       (3, 17, 2), (1, 17, 2), (4, 25, 2),
                                       (4, 19, 2), (4, 17, 1), (4, 17, 17)])
def test_strict_split_context_and_root_admission(arguments):
    with pytest.raises(ValueError):
        lab.Context(*arguments).validate()


@pytest.mark.parametrize("value", [(True, 0), (1.0, 0), [1, 0], (0,), (0,) * 16,
                                   (1 << 20, 0)])
def test_tiny_public_matrix_oracle_rejects_aliases_and_large_secrets(value):
    with pytest.raises(ValueError):
        lab.multiplication_matrix(value)


@pytest.mark.parametrize("coordinates", [(0, 0), (0, True), (), [0, 1], (0, 4)])
def test_projection_coordinate_grammar(coordinates):
    with pytest.raises(ValueError):
        lab.projection_rank((-4, 0, 1, 0), 17, coordinates)


@pytest.mark.parametrize("changed", [{"n": True}, {"eta": False}, {"drop": 0},
                                     {"p": 19}, {"dimension": 2}, {"count": 0}])
def test_model_strict_inputs_and_complete_geometry(changed):
    model = lab.Model(4, 1, 3, 17, 11, 3, 1, 4, 3)
    with pytest.raises(ValueError):
        replace(model, **changed).validate()


def test_matrix_rank_and_application_reject_nonfield_or_malformed_values():
    with pytest.raises(ValueError):
        lab.rank_mod(((1, 0), (0, 1)), 15)
    with pytest.raises(ValueError):
        lab.rank_mod(((1, 0), (1,)), 17)
    with pytest.raises(ValueError):
        lab.apply_matrix(((1, 0), (0, 1)), (True, 0), 17)
    with pytest.raises(ValueError):
        lab.dyadic_upper(Fraction(0))
