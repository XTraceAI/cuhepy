"""All-error code tests and independently formed public operator controls."""

from dataclasses import replace
from itertools import product

import pytest

from experiments.bfv_search_lab import coded_operator_oracle as oracle


def test_rs_distance_exhausts_all_errors_not_only_basis_vectors():
    def encoder(e):
        return oracle.rs_encode(e, tuple(range(6)), 7)
    result = oracle.exhaustive_distance(3, 7, encoder)
    assert result["errors_checked"] == 342
    assert result["minimum_distance"] == 4  # n-k+1, including cancellation errors.


def test_negacirculant_encoder_preserves_signed_shift_generators():
    q, n, generators = 17, 4, ((1, 0, 0, 0), (3, 1, 4, 2))
    for values in product(range(3), repeat=n):
        encoded = oracle.quasi_encode(values, generators, q)
        for shift in range(n):
            left = oracle.quasi_encode(oracle.negashift(values, shift, q), generators, q)
            right = tuple(x for i in range(0, len(encoded), n)
                          for x in oracle.negashift(encoded[i:i + n], shift, q))
            assert left == right


def test_known_tensor_code_spreads_single_block_errors_and_keeps_exact_distance():
    multipliers = ((1, 0), (1, 1))
    inner = oracle.exhaustive_distance(2, 5, lambda e: oracle.quasi_encode(e, multipliers, 5))
    tensor = oracle.exhaustive_distance(4, 5, lambda e: oracle.tensor_encode(e, 2, multipliers, (0, 1, 2, 3), 5))
    assert inner["minimum_distance"] == 3 and inner["errors_checked"] == 24
    assert tensor["minimum_distance"] == 9 and tensor["errors_checked"] == 624
    assert tensor["code_length"] == 16


def test_bad_commuting_code_does_not_inherit_a_good_distance():
    result = oracle.exhaustive_distance(2, 5, lambda e: oracle.quasi_encode(e, ((1, 0), (0, 0)), 5))
    assert result["minimum_distance"] == 1
    assert result["minimum_distance"] / result["code_length"] == 0.25


def test_block_only_code_has_a_one_block_global_distance_loss():
    multipliers = ((1, 0), (1, 1))
    def encode(values):
        return oracle.quasi_encode(values[:2], multipliers, 5) + oracle.quasi_encode(values[2:], multipliers, 5)
    result = oracle.exhaustive_distance(4, 5, encode)
    assert result["minimum_distance"] == 3 and result["code_length"] == 8


def test_pure_ntt_has_distance_one_despite_spreading_basis_errors():
    # n=4, q=17, negacyclic roots of X^4+1. All basis errors encode densely.
    roots = (2, 8, 15, 9)
    def encoder(e):
        return oracle.rs_encode(e, roots, 17)
    assert all(pow(z, 4, 17) == 16 for z in roots)
    assert all(sum(bool(x) for x in encoder(tuple(int(j == i) for j in range(4)))) == 4 for i in range(4))
    result = oracle.exhaustive_distance(4, 17, encoder)
    assert result["minimum_distance"] == 1 and result["errors_checked"] == 83520


def test_implicit_coded_generators_equal_independent_dense_operator_and_all_query_values():
    q, base = 5, (1, 2)
    # Dense negacyclic multiplication by 1+2X: [[1,-2],[2,1]].
    matrix = ((1, 3), (2, 1))
    def encoder(e):
        return oracle.quasi_encode(e, ((1, 0), (1, 1)), q)
    coded = oracle.encode_matrix(matrix, q, encoder)
    transformed = oracle.ring_product((1, 1), base, q)
    expected = (matrix[0], matrix[1], (transformed[0], -transformed[1] % q),
                (transformed[1], transformed[0]))
    assert coded == expected
    for query in product(range(q), repeat=2):
        assert oracle.matvec(coded, query, q) == encoder(oracle.matvec(matrix, query, q))


def fixture():
    matrix, q = ((1, 3), (2, 1)), 5
    def encoder(e):
        return oracle.rs_encode(e, (0, 1, 2, 3), q)
    coded = oracle.encode_matrix(matrix, q, encoder)
    registration, layers = oracle.register(coded, q, "a" * 64)
    query = (1, 2)
    fixed = oracle.fix_answer(oracle.matvec(matrix, query, q), query, registration)
    openings = tuple(oracle.open_row(coded, layers, i) for i in range(4))
    return fixed, openings, encoder, matrix, coded, layers


def test_authentication_and_field_evaluation_are_both_required():
    fixed, openings, encoder, *_ = fixture()
    assert oracle.check_rows(fixed, tuple(range(4)), openings, encoder)
    wrong = replace(openings[0], row=(0, 0))
    assert not oracle.check_rows(fixed, tuple(range(4)), (wrong, *openings[1:]), encoder)
    bad_answer = replace(fixed, values=((fixed.values[0] + 1) % 5, fixed.values[1]))
    assert not oracle.check_rows(bad_answer, tuple(range(4)), openings, encoder)
    assert not oracle.check_rows(fixed, (1, 0, 2, 3), openings, encoder)
    assert not oracle.check_rows(fixed, (0,), (), encoder)


def test_true_answer_bad_path_and_epoch_are_rejected_publicly():
    fixed, openings, encoder, *_ = fixture()
    siblings = (b"\x00" * 32, *openings[0].siblings[1:])
    bad = replace(openings[0], siblings=siblings)
    assert not oracle.check_rows(fixed, (0,), (bad,), encoder)
    other_epoch = replace(fixed.registration, identity="b" * 64)
    assert not oracle.check_rows(replace(fixed, registration=other_epoch), (0,), (openings[0],), encoder)
    assert oracle.check_rows(fixed, (0,), (openings[0],), encoder)


def test_error_after_revealed_challenge_can_evade_a_single_code_row():
    fixed, openings, encoder, *_ = fixture()
    # At point 0 the checker observes coefficient 0 only. If that challenge
    # is given first, an adversary can change coefficient 1 undetected.
    changed = replace(fixed, values=(fixed.values[0], (fixed.values[1] + 1) % 5))
    assert oracle.check_rows(changed, (0,), (openings[0],), encoder)
    assert not oracle.check_rows(changed, (1,), (openings[1],), encoder)


def test_all_supported_components_and_rns_limbs_must_be_in_the_relation():
    values = (0, 0, 1, 0)  # Error occurs in the second output block only.
    full = oracle.tensor_encode(values, 2, ((1, 0), (1, 1)), (0, 1, 2, 3), 5)
    assert any(full)
    assert not any(oracle.quasi_encode(values[:2], ((1, 0), (1, 1)), 5))
    first_limb, second_limb = (0, 0), (0, 1)
    assert not any(oracle.rs_encode(first_limb, (0, 1, 2, 3), 17))
    assert any(oracle.rs_encode(second_limb, (0, 1, 2, 3), 97))
    # Multiplying soundness bounds as if this error affected both is invalid.


def test_caps_canonical_vectors_and_missing_coefficient_rejected():
    with pytest.raises(ValueError):
        oracle.exhaustive_distance(8, 17, lambda x: x)
    with pytest.raises(ValueError):
        oracle.rs_encode((1, 2), (1, 1), 5)
    with pytest.raises(ValueError):
        oracle.ring_product((True, 0), (1, 0), 5)
    with pytest.raises(ValueError):
        oracle.tensor_encode((1, 0, 0), 2, ((1, 0), (1, 1)), (0, 1), 5)
    fixed, openings, encoder, *_ = fixture()
    assert not oracle.check_rows(fixed, (0,), (replace(openings[0], row=(1,)),), encoder)
