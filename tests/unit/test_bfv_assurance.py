"""Checks on the conservative, public circuit bound, not a security certificate."""

from dataclasses import replace

import pytest

from cuhepy.hamming.bfv_assurance import bfv_review_policy, hamming_noise_bound
from cuhepy.hamming.bfv import BFVClient
from cuhepy.hamming.bfv_security import BFVExecutionPolicy
from cuhepy.bfv.scheme import BFV


@pytest.mark.parametrize("make_policy", [BFVExecutionPolicy, bfv_review_policy])
def test_full_supported_circuit_has_positive_worst_case_margin(make_policy):
    p = make_policy()
    smaller = hamming_noise_bound(p, 1)
    largest = hamming_noise_bound(p, p.max_vectors)
    assert smaller.sufficient and largest.sufficient
    assert smaller.merged <= largest.merged
    assert 2 * largest.terminal_rounding_error_numerator < largest.terminal_modulus


def test_reduced_q_is_not_approved_just_because_random_tests_work():
    original = BFVExecutionPolicy()
    reduced = replace(original, params=replace(original.params, coeff_modulus_bits=120))
    assert not hamming_noise_bound(reduced, reduced.max_vectors).sufficient


def test_bound_matches_observed_phases_through_packed_merge():
    client = BFVClient(3, 32, 193, 120, 15, response_modulus_bits=40, rns_modulus=True)
    policy = BFVExecutionPolicy(params=client.params, embed_len=3, response_modulus_bits=40)
    query = [0, 1, 0]
    vectors = ([[0, 0, 0], [0, 1, 0], [1, 0, 1], [1, 1, 1]] * 19)[:67]
    index = client.encrypt_vec_packed(vectors)
    responses = client.encode_hamming_server_packed(
        client.encrypt_vec_one(query), index, len(vectors), compact=False
    )
    bound = hamming_noise_bound(policy, len(vectors))
    assert bound.sufficient
    expected = [sum(a != b for a, b in zip(query, v, strict=True)) for v in vectors]
    n, t, q = client.params.poly_modulus_degree, client.params.plain_modulus, client._pk()["q"]
    for group, wire in enumerate(responses):
        slots = [0] * n
        for i, value in enumerate(expected[group * n : (group + 1) * n]):
            tile, lane = divmod(i, client.vectors_per_ciphertext)
            row, col = divmod(lane, client.lanes_per_row)
            slots[row * (n // 2) + tile * client.lanes_per_row + col] = value
        message = BFV.batch_encode(slots, client.params)
        ct = BFV.ciphertext_from_ints(wire, client._pk())
        phase = BFV._phase(ct, client._keys())
        actual = max(
            abs((value - (q // t) * m + q // 2) % q - q // 2)
            for value, m in zip(phase, message, strict=True)
        )
        assert actual <= bound.merged
        small = BFV.modulus_switch(ct, 40, client._pk())
        assert BFV.batch_decode(BFV.decrypt(small, client._keys()), client.params) == slots


@pytest.mark.parametrize("count", [0, -1, True, 65537])
def test_bound_rejects_invalid_counts(count):
    with pytest.raises(ValueError):
        hamming_noise_bound(BFVExecutionPolicy(), count)
