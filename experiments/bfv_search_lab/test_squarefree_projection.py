"""E119 independent tiny algebra/admission regressions; no full cohort rerun."""

from dataclasses import replace
from itertools import permutations

import pytest

from benchmarks import squarefree_projection_lab as oracle
from experiments.bfv_search_lab import squarefree_projection as lab
from experiments.bfv_search_lab.query_quantizer_law import QuantizerLaw


def leibniz(matrix):
    total = 0
    for order in permutations(range(len(matrix))):
        odd = sum(order[i] > order[j] for i in range(len(matrix))
                  for j in range(i+1, len(matrix))) % 2
        term = -1 if odd else 1
        for row, column in enumerate(order):
            term *= matrix[row][column]
        total += term
    return total


@pytest.mark.parametrize("matrix", [((0, 1), (1, 0)), ((1, 2), (2, 4)),
                                     ((-2, -1), (1, -2)), ((-5, -1), (1, -5)),
                                     ((0, 1, 2, 3), (1, 0, 4, 5), (2, 4, 0, 6), (3, 5, 6, 0)),
                                     ((0, 0, 0, 0), (1, 2, 3, 4), (1, 0, 2, 5), (3, 1, 0, 4))])
def test_rational_and_fraction_free_determinants_match_leibniz_with_pivots(matrix):
    assert lab.determinant(matrix) == oracle.bareiss(matrix) == leibniz(matrix)


@pytest.mark.parametrize("secret", [(-2, 1), (-5, 1), (-1, 0, -1, 1, 0, 0, 0, 0)])
def test_negacyclic_matrix_columns_match_independent_literal_monomials(secret):
    matrix = lab.multiplication_matrix(secret)
    assert matrix == oracle.schoolbook_matrix(secret)
    for j in range(len(secret)):
        basis = tuple(int(i == j) for i in range(len(secret)))
        assert tuple(row[j] for row in matrix) == oracle.schoolbook(secret, basis)


@pytest.mark.parametrize("secret,expected", [((-2, 1), (1, 2)), ((-5, 1), (2, 1)),
                                             ((0, 0), (0, 0))])
def test_each_prime_limb_rank_is_field_rank_and_composite_is_rejected(secret, expected):
    matrix = lab.multiplication_matrix(secret)
    assert tuple(lab.rank_mod(matrix, p) for p in (5, 13)) == expected
    assert tuple(oracle.field_rank(matrix, p) for p in (5, 13)) == expected
    with pytest.raises(ValueError):
        lab.rank_mod(matrix, 65)


@pytest.mark.parametrize("residues,expected", [((0, 0), 0), ((3, 8), 8), ((0, 8), 60), ((4, 12), 64)])
def test_common_coefficient_crt_matches_independent_inventory(residues, expected):
    ctx = lab.Context(2, (5, 13), (2, 5))
    assert lab.crt_lift(residues, ctx) == oracle.literal_crt_table(ctx)[residues] == expected


@pytest.mark.parametrize("mask", [(0, 0), (1, 64), (64, 1), (8, 32)])
def test_complete_tiny_crt_product_matches_literal_wholeQ_product(mask):
    ctx = lab.Context(2, (5, 13), (2, 5))
    for secret in ((-2, 1), (-5, 1)):
        assert lab.multiply_via_crt(secret, mask, ctx) == tuple(
            c % 65 for c in oracle.schoolbook(secret, mask))


def test_genuine_ternary_defect_cannot_use_wholeQ_as_prime():
    ctx = lab.Context(8, (17, 97), (3, 8))
    secret = (-1, 0, -1, 1, 0, 0, 0, 0)
    matrix = lab.multiplication_matrix(secret)
    determinant = lab.determinant(matrix)
    zeros = lab.zero_roots(secret, ctx)
    assert zeros == oracle.literal_zero_roots(secret, ctx) == ((3,), ())
    nullities = tuple(8-lab.rank_mod(matrix, p) for p in ctx.primes)
    assert nullities == (1, 0)
    assert 0 < abs(determinant) <= 81 and determinant % lab.weighted_divisor(ctx, nullities) == 0
    assert determinant % 1649 != 0
    assert oracle.norm_cap_using_product_as_if_prime(8, 1649, 3) == 0
    assert lab.norm_certificate(8, ctx.primes, 3).prefix_length == 7
    assert lab.projection_ranks(secret, ctx, tuple(range(7))) == (7, 7)


@pytest.mark.parametrize("n,primes,norm2,caps,prefix", [
    (8, (17, 97), 1, (0, 0), 8),
    (8, (17, 97), 3, (1, 0), 7),
    (8, (17, 97), 8, (2, 1), 6),
    (2, (5, 13), 5, (1, 0), 1),
    (2, (5, 13), 26, (2, 1), 0),
])
def test_norm_only_caps_use_each_prime_and_exact_adjacent_integer_powers(n, primes, norm2, caps, prefix):
    certificate = lab.norm_certificate(n, primes, norm2)
    assert certificate.limb_nullity_caps == caps
    assert certificate.prefix_length == prefix
    for prime, cap in zip(primes, caps, strict=True):
        assert prime**cap <= norm2**(n//2)
        assert cap == n or prime**(cap+1) > norm2**(n//2)


def test_actual_public_rank_of_Xminus5_does_not_upgrade_the_norm_only_guarantee():
    ctx = lab.Context(2, (5, 13), (2, 5))
    secret = (-5, 1)
    certificate = lab.norm_certificate(2, ctx.primes, 26)
    assert certificate.prefix_length == 0
    assert lab.projection_ranks(secret, ctx, ()) == (0, 0)
    assert lab.projection_ranks(secret, ctx, (0,)) == (1, 1)
    assert lab.zero_roots(secret, ctx) == ((), (5,))
    assert lab.weighted_divisor(ctx, (0, 1)) == 13


def test_zero_is_explicitly_outside_nonzero_determinant_projection_promise():
    ctx = lab.Context(8, (17, 97), (3, 8))
    zero = (0,)*8
    assert lab.determinant(lab.multiplication_matrix(zero)) == 0
    assert tuple(map(len, lab.zero_roots(zero, ctx))) == (8, 8)
    certificate = lab.norm_certificate(8, ctx.primes, 8)
    assert certificate.prefix_length == 6
    assert lab.projection_ranks(zero, ctx, tuple(range(6))) == (0, 0)
    with pytest.raises(ValueError):
        lab.norm_certificate(8, ctx.primes, 0)


@pytest.mark.parametrize("mutation", ["caps", "common", "prefix", "cap_type", "cap_list", "zero_norm"])
def test_forged_public_norm_certificate_is_rejected(mutation):
    certificate = lab.norm_certificate(8, (17, 97), 8)
    changes = {"caps": {"limb_nullity_caps": (1, 1)}, "common": {"common_nullity_cap": 1},
               "prefix": {"prefix_length": 7}, "cap_type": {"limb_nullity_caps": (True, 1)},
               "cap_list": {"limb_nullity_caps": [2, 1]}, "zero_norm": {"squared_norm_cap": 0}}[mutation]
    with pytest.raises(ValueError):
        replace(certificate, **changes).validate()


@pytest.mark.parametrize("context", [
    lab.Context(True, (5, 13), (2, 5)), lab.Context(3, (5, 13), (2, 5)),
    lab.Context(2, [5, 13], (2, 5)), lab.Context(2, (5, 5), (2, 2)),
    lab.Context(2, (13, 5), (5, 2)), lab.Context(2, (5, 25), (2, 7)),
    lab.Context(2, (5, 65), (2, 8)), lab.Context(2, (5, 7), (2, 2)),
    lab.Context(2, (5, 13), [2, 5]), lab.Context(2, (5, 13), (1, 5)),
    lab.Context(2, (5, 13), (7, 5)), lab.Context(2, (5, 13), (2, True)),
    lab.Context(2, (5, 13), (2,)), lab.Context(2, (5.0, 13), (2, 5)),
])
def test_strict_squarefree_split_prime_root_and_exact_grammar_admission(context):
    with pytest.raises(ValueError):
        context.validate()


@pytest.mark.parametrize("value", [(True, 0), (1.0, 0), [1, 0], (1,), (0,)*16, (1 << 20, 0)])
def test_public_polynomial_oracle_rejects_numeric_aliases_and_large_secrets(value):
    with pytest.raises(ValueError):
        lab.multiplication_matrix(value)


@pytest.mark.parametrize("residues", [(True, 0), (1.0, 0), [0, 0], (5, 0), (-1, 0), (0,)])
def test_common_CRT_requires_canonical_exact_residues_in_fixed_limb_order(residues):
    with pytest.raises(ValueError):
        lab.crt_lift(residues, lab.Context(2, (5, 13), (2, 5)))


@pytest.mark.parametrize("mask", [(True, 0), (1.0, 0), [0, 0], (65, 0), (-1, 0), (0,)])
def test_wholeQ_mask_requires_canonical_exact_coefficients(mask):
    with pytest.raises(ValueError):
        lab.multiply_via_crt((-2, 1), mask, lab.Context(2, (5, 13), (2, 5)))


@pytest.mark.parametrize("coordinates", [(0, 0), (0, True), [0, 1], (0, 2)])
def test_common_projection_coordinate_grammar(coordinates):
    with pytest.raises(ValueError):
        lab.projection_ranks((-2, 1), lab.Context(2, (5, 13), (2, 5)), coordinates)


@pytest.mark.parametrize("nullities", [(True, 0), (1.0, 0), [1, 0], (3, 0), (-1, 0), (0,)])
def test_weighted_divisor_requires_one_exact_bounded_nullity_per_prime(nullities):
    with pytest.raises(ValueError):
        lab.weighted_divisor(lab.Context(2, (5, 13), (2, 5)), nullities)


def test_wholeQ_codec_partial_cycle_and_sign_and_unadmitted_limb_substitution():
    law = QuantizerLaw(65, 3, 2)
    assert law.pmf() == ((0, 49), (-1, 16))
    assert law.literal_map(3) == (0, 0) and law.added_error(3) == -3
    assert law.literal_map(64) == (48, 64) and law.added_error(64) == 0
    assert oracle.formal_coefficient_formula(8, 65, 3, 2) == (6, 8, 0)
    # A FORMAL arithmetic substitution only: never an admitted q5 codec.
    with pytest.raises(ValueError):
        QuantizerLaw(5, 3, 2)
    formal_limbs = tuple(oracle.formal_coefficient_formula(8 % p, p, 3, 2)[1] for p in (5, 13))
    assert formal_limbs == (0, 8)
    assert lab.crt_lift(formal_limbs, lab.Context(2, (5, 13), (2, 5))) == 60 != 8


def test_malformed_matrix_rank_determinant_and_wrong_context_reject():
    with pytest.raises(ValueError):
        lab.determinant(((1, 0),))
    with pytest.raises(ValueError):
        lab.rank_mod(((1, 0), (1,)), 5)
    with pytest.raises(ValueError):
        lab.rank_mod(((1, 0), (0, 1)), True)
    with pytest.raises(ValueError):
        lab.zero_roots((-2, 1), lab.Context(8, (17, 97), (3, 8)))
