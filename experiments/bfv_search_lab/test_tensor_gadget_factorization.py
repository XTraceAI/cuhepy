"""Independent modular oracle for grouped integer lifts/composite corrections."""

import random

import pytest

from experiments.bfv_search_lab import native_boundary_oracle as oracle
from experiments.bfv_search_lab import propagated_gadget_bgv as gadget
from experiments.bfv_search_lab import tensor_gadget_factorization as factor
from experiments.bfv_search_lab import tensor_gadget_seed as seed


def trial(n, q, bits, rng):
    ell = (q.bit_length() + bits - 1) // bits
    relin_ell = (q.bit_length() + 29) // 30

    def pair():
        return tuple(tuple(rng.randrange(q) for _ in range(n)) for _ in range(2))

    query, indexed = pair(), (pair(), pair())
    relin_a = tuple(tuple(rng.randrange(q) for _ in range(n)) for _ in range(relin_ell))
    key = tuple(pair() for _ in range(ell))
    digits = tuple(
        gadget.canonical_digits(oracle.multiply(query[1], tile[1], q), q, 30)
        for tile in indexed
    )
    states = tuple(
        factor.grouped_seed(query, tile, d, relin_a, q, bits)
        for tile, d in zip(indexed, digits, strict=True)
    )
    bound = seed.seed_bound(n, q, bits)
    for tile, d, state in zip(indexed, digits, states, strict=True):
        assert state == seed.c1_seed(query, tile, d, relin_a, q, bits)
        assert max(abs(x) for row in state for x in row) <= bound
        expected = oracle.add(
            oracle.multiply(query[0], tile[1], q),
            oracle.multiply(query[1], tile[0], q),
            q,
        )
        for dc, a in zip(d, relin_a, strict=True):
            expected = oracle.add(expected, oracle.multiply(dc, a, q), q)
        assert gadget.recompose(state, bits, q) == expected
    shifted = tuple(
        tuple(gadget.permute(row, shift=1 - n // 2) for row in state)
        for state in states
    )
    for binary in (False, True):
        source = gadget.source_state(
            shifted[0], shifted[1] if binary else None, n // 4, 5
        )
        assert max(abs(x) for row in source for x in row) <= bound * (
            2 if binary else 1
        )
        actual = factor.fused_first_switch(
            (indexed[0], digits[0]),
            (indexed[1], digits[1]) if binary else None,
            query,
            relin_a,
            key,
            5,
            n // 4,
            1 - n // 2,
            q,
            bits,
        )
        expected = []
        for k in range(2):
            out = (0,) * n
            for row, column in zip(source, key, strict=True):
                out = oracle.add(out, oracle.multiply(row, column[k], q), q)
            expected.append(out)
        assert actual == tuple(expected) == gadget.switched(source, key, q)
    return {
        "N": n,
        "Q": q,
        "bits": bits,
        "seed_coefficients": 2 * ell * n,
        "switch_coefficients": 4 * n,
        "binary_and_unary_exact": True,
        "largest_seed_abs": max(
            abs(x) for state in states for row in state for x in row
        ),
        "public_bound": bound,
    }


@pytest.mark.parametrize(
    "n,q,bits",
    [
        (8, 65537, 3),
        (16, 65537, 3),
        (16, int("ffffffffffc00020000003bffc0001", 16), 14),
        (16, int("ffffffffffc00020000003bffc0001", 16), 18),
    ],
)
def test_factorized_seed_and_shared_correction(n, q, bits):
    assert trial(n, q, bits, random.Random(640701 + n + bits))["binary_and_unary_exact"]


def test_grouping_retains_off_diagonal_radix_terms():
    n, q, bits = 8, 65537, 3
    zero = (0,) * n
    query, indexed = ((8,) + zero[1:], zero), (zero, (1,) + zero[1:])
    digits = (zero,)
    state = factor.grouped_seed(query, indexed, digits, (zero,), q, bits)
    assert gadget.recompose(state, bits, q) == (8,) + zero[1:]
    dq = gadget.canonical_digits(query[0], q, bits)
    di = gadget.canonical_digits(indexed[1], q, bits)
    assert all(
        gadget.integer_product(a, b) == zero for a, b in zip(dq, di, strict=True)
    )


def test_power_rows_are_exact_not_independent_limb_gadgets():
    q, bits = int("ffffffffffc00020000003bffc0001", 16), 18
    rows = factor.power_rows(q, bits)
    for r, row in enumerate(rows):
        assert sum(x << (j * bits) for j, x in enumerate(row)) % q == pow(
            1 << bits, r, q
        )
    gamma = seed.power_digits(q, bits)
    assert all(
        gamma[a][b] == rows[a + b] for a in range(len(gamma)) for b in range(len(gamma))
    )


def test_sufficient_factorized_state_prices_streaming_and_cached_controls():
    geometry = {
        "N": 16384,
        "Q_hex": "ffffffffffc00020000003bffc0001",
        "P": 33548413,
        "t": 1031,
        "eta": 21,
        "D": 512,
        "vectors": [8192, 32768],
    }
    a, b = factor.resource_models(geometry, 18)
    assert a["all_guards_pass"] and b["all_guards_pass"]
    assert (
        b["cached_index_digit_RNS_word_bytes"]
        == 4 * a["cached_index_digit_RNS_word_bytes"]
    )
    assert a["shared_L_R_RNS_word_bytes"] == b["shared_L_R_RNS_word_bytes"] == 8912896
    assert (
        a["factorized_total_word_products_per_query"]
        > a["expanded_online_word_products_per_query"]
    )
    assert (
        a["streamed_index_pair_digit_RNS_word_bytes"] + a["shared_L_R_RNS_word_bytes"]
        < a["expanded_query_matrix_RNS_word_bytes"]
    )
