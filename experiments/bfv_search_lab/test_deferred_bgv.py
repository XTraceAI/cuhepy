"""E20 algebra, operation-count, negative-shortcut and homemade encrypted checks."""

from dataclasses import replace
import random

import pytest

from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import deferred_bgv as delayed
from experiments.bfv_search_lab import reduction_oracles as oracle
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


@pytest.mark.parametrize("n", [4, 8, 16, 32])
def test_symbolic_secret_terms_match_direct_projection_for_all_tails(n):
    rng = random.Random(n)
    secret = tuple(rng.randrange(-1, 2) for _ in range(n))
    for padded in (1 << j for j in range(n.bit_length() - 1)):
        for tiles in range(1, padded + 1):
            forms = [{(1, j): tuple(rng.randrange(-3, 4) for _ in range(n))
                      for j in range(3)} for _ in range(tiles)]
            phases = [oracle.evaluate_form(form, secret) for form in forms]
            combined = oracle.expanded_butterfly(forms, padded)
            assert oracle.evaluate_form(combined, secret) == oracle.projected_phases(phases, padded)
            assert len(combined) == 1 + 2 * padded


@pytest.mark.parametrize("padded", [1, 2, 4, 8, 16, 32, 512])
def test_full_group_has_no_switch_count_saving_at_any_delay_depth(padded):
    n = 2 * padded
    for cut in range(padded.bit_length()):
        model = oracle.schedule_cost(n, padded, padded, cut)
        assert model.switch_calls == 2 * padded - 1
        assert model.product_bound_weight == padded**2
        assert model.distinct_keys == 2 * (1 << cut) - 1 + padded.bit_length() - 1 - cut
    eager = oracle.schedule_cost(n, padded, padded, 0)
    deferred = oracle.schedule_cost(n, padded, padded, padded.bit_length() - 1)
    assert eager.switch_error_weight == (4 * padded**2 - 1) // 3
    assert deferred.switch_error_weight == 2 * padded - 1


def test_eager_counts_match_existing_butterfly_for_every_tail():
    for padded in (1, 2, 4, 8, 16, 32):
        for tiles in range(1, padded + 1):
            expected_bound, rotations = butterfly.schedule(padded, [2] * tiles, 1)
            eager = oracle.schedule_cost(2 * padded, padded, tiles, 0)
            assert eager.switch_calls == tiles + rotations
            assert eager.product_bound_weight + eager.switch_error_weight == expected_bound
            for cut in range(padded.bit_length()):
                model = oracle.schedule_cost(2 * padded, padded, tiles, cut)
                assert model.switch_calls >= eager.switch_calls
                assert model.product_bound_weight == padded * tiles


def test_not_a_universal_lower_bound_same_secret_sum_can_save_relinearizations():
    # The obstruction concerns a packing butterfly, not arbitrary addition DAGs.
    n, secret = 8, (1, -1, 0, 1, 0, 0, 0, 0)
    a = {(1, j): tuple(i + j for i in range(n)) for j in range(3)}
    b = {(1, j): tuple(i - j for i in range(n)) for j in range(3)}
    combined = oracle.add_forms(a, b)
    assert set(combined) == {(1, 0), (1, 1), (1, 2)}
    assert oracle.evaluate_form(combined, secret) == tuple(
        x + y for x, y in zip(oracle.evaluate_form(a, secret), oracle.evaluate_form(b, secret), strict=True))


def test_rotating_coefficients_without_secret_basis_is_wrong():
    secret = (0, 1, 0, 0, 0, 0, 0, 0)
    form = {(1, 1): (1, 0, 0, 0, 0, 0, 0, 0)}
    correct = oracle.evaluate_form(oracle.transform_form(form, exponent=3), secret)
    wrong = oracle.evaluate_form({key: oracle.permute(poly, exponent=3) for key, poly in form.items()}, secret)
    assert correct == (0, 0, 0, 1, 0, 0, 0, 0)
    assert wrong != correct


def test_projection_and_digit_decomposition_are_not_ring_linear():
    x = (0, 1, 0, 0)
    def keep_even(a):
        return tuple(v if i % 2 == 0 else 0 for i, v in enumerate(a))
    assert keep_even(oracle.ring_product(x, x)) != oracle.ring_product(keep_even(x), keep_even(x))
    def digits(c):
        return (c % 4, c // 4)
    assert digits(3 + 1) != tuple(a + b for a, b in zip(digits(3), digits(1), strict=True))


@pytest.mark.parametrize("n,dimension", [(8, 1), (16, 3), (32, 8)])
def test_every_encrypted_delay_depth_matches_independent_trace_and_plaintext(n, dimension):
    pk, sk = bgv.key_gen(n, t=1031, q_bits=180, eta=2)
    rng = random.Random(n + dimension)
    padded = 1 << (dimension - 1).bit_length()
    query = [rng.randrange(2) for _ in range(dimension)]
    rows = [query, [1 - x for x in query]] + [
        [rng.randrange(2) for _ in range(dimension)] for _ in range(n + 1)]
    qp, plaintext_index = bgv.coefficient_inputs(query, rows, n)
    encrypted_query = bgv.encrypt(qp, pk)
    index = [bgv.encrypt(poly, pk) for poly in plaintext_index]
    reference_keys = trace.evaluation_keys(pk, sk, padded, digit_bits=12)
    capacity = n // padded
    for cut in range(padded.bit_length()):
        keys = delayed.evaluation_keys(pk, sk, padded, cut)
        for count in sorted({0, 1, capacity + 1, n - 1, n, n + 1, len(rows)}):
            chosen = index[:(count + capacity - 1) // capacity]
            output = delayed.search(encrypted_query, chosen, count, pk, keys)
            decoded = [bgv.decrypt(ct, pk, sk) for ct in output]
            assert decoded == [bgv.decrypt(ct, pk, sk) for ct in
                               trace.search(encrypted_query, chosen, count, pk, reference_keys)]
            assert trace.decode(decoded, count, dimension, pk) == [
                sum(a != b for a, b in zip(query, row, strict=True)) for row in rows[:count]]
            for group, ct in enumerate(output):
                tiles = min(padded, len(chosen) - group * padded)
                model = oracle.schedule_cost(n, padded, tiles, cut)
                assert ct.phase_bound == (model.product_bound_weight * n * pk.fresh_bound**2
                                          + model.switch_error_weight * keys.switch_error_bound)


def test_wrong_key_schedule_modulus_bound_and_input_shape_are_rejected():
    pk, sk = bgv.key_gen(16, q_bits=120)
    keys = delayed.evaluation_keys(pk, sk, 4, 2)
    cipher = bgv.encrypt([0] * 16, pk)
    for bad in (replace(keys, key_id="bad"), replace(keys, cut=1),
                replace(keys, sources=keys.sources[:-1]), replace(keys, sources=keys.sources[::-1]),
                replace(keys, switch_error_bound=0), replace(keys, digit_bits=True)):
        with pytest.raises(ValueError):
            delayed.search(cipher, [cipher], 1, pk, bad)
    for bad in (replace(cipher, key_id="bad"), replace(cipher, phase_bound=int(pk.q // 3)),
                replace(cipher, components=cipher.components + (cipher.components[0],))):
        with pytest.raises(ValueError):
            delayed.search(bad, [cipher], 1, pk, keys)
    with pytest.raises(ValueError):
        delayed.search(cipher, [], 1, pk, keys)


@pytest.mark.parametrize("args", [(16, 3, 1, 0), (16, 4, 0, 0), (16, 4, 5, 1),
                                  (16, 4, 1, 3), (16, 4, True, 0), (7, 2, 1, 0)])
def test_invalid_model_inputs(args):
    with pytest.raises(ValueError):
        oracle.schedule_cost(*args)
