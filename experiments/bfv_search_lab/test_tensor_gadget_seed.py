"""Exact common tensor C1/source lift, including cross terms and binary plus."""

import random

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import native_boundary_oracle as oracle
from experiments.bfv_search_lab import propagated_gadget_bgv as gadget
from experiments.bfv_search_lab import tensor_gadget_seed as seed


def trial(n, rng, q=65537, bits=3, relin_bits=4):
    query, indexed = [
        tuple(tuple(rng.randrange(q) for _ in range(n)) for _ in range(2))
        for _ in range(2)
    ]
    relin_ell = (q.bit_length() + relin_bits - 1) // relin_bits
    a = tuple(tuple(rng.randrange(q) for _ in range(n)) for _ in range(relin_ell))
    tensor2 = oracle.multiply(query[1], indexed[1], q)
    relin_d = gadget.canonical_digits(tensor2, q, relin_bits)
    expected = oracle.add(
        oracle.multiply(query[0], indexed[1], q),
        oracle.multiply(query[1], indexed[0], q),
        q,
    )
    for d, poly in zip(relin_d, a, strict=True):
        expected = oracle.add(expected, oracle.multiply(d, poly, q), q)
    state = seed.c1_seed(query, indexed, relin_d, a, q, bits)
    assert gadget.recompose(state, bits, q) == expected
    bound = seed.seed_bound(n, q, bits, relin_bits)
    assert max(abs(v) for d in state for v in d) <= bound
    # A distinct right state supplies both plus and minus, unlike minus-only
    # anchoring. This copy has an independent cyclic shift and a known lift.
    right = tuple(gadget.permute(d, shift=1) for d in state)
    right_poly = oracle.monomial(expected, 1, q)
    source = gadget.source_state(state, right, n // 4, 5)
    expected_source = oracle.automorphism(
        oracle.add(expected, oracle.monomial(right_poly, n // 4, q), q, -1), 5, q
    )
    assert gadget.recompose(source, bits, q) == expected_source
    plus = tuple(
        tuple(x + y for x, y in zip(d, gadget.permute(r, shift=n // 4), strict=True))
        for d, r in zip(state, right, strict=True)
    )
    assert gadget.recompose(plus, bits, q) == oracle.add(
        expected, oracle.monomial(right_poly, n // 4, q), q
    )
    ell = len(source)
    key = tuple(
        tuple(tuple(mpz(rng.randrange(q)) for _ in range(n)) for _ in range(2))
        for _ in range(ell)
    )
    switched = gadget.switched(source, key, q)
    independent = tuple(
        tuple(
            sum(
                oracle.multiply(d, tuple(map(int, col[k])), q)[i]
                for d, col in zip(source, key, strict=True)
            )
            % q
            for i in range(n)
        )
        for k in range(2)
    )
    assert switched == independent
    return {
        "n": n,
        "C1_source_plus_relations": 3,
        "coefficients": 3 * n,
        "switch_coefficients": 2 * n,
        "maximum_digit_abs": max(abs(v) for d in state for v in d),
        "public_seed_bound": bound,
        "all_exact": True,
    }


@pytest.mark.parametrize("n", [8, 16])
def test_tensor_seed_common_lift_and_binary_source_switch(n):
    rng = random.Random(64069 + n)
    for _ in range(12):
        assert trial(n, rng)["all_exact"]


def test_scalar_radix_powers_use_all_mod_Q_cross_terms():
    q, bits = 65537, 3
    gamma, base = seed.power_digits(q, bits), 1 << bits
    for a, row in enumerate(gamma):
        for b, ds in enumerate(row):
            assert sum(d * base**j for j, d in enumerate(ds)) % q == pow(base, a + b, q)


def test_large_seed_and_mixed_models_keep_failed_guards_and_added_state():
    geometry = {
        "N": 16384,
        "Q_hex": "ffffffffffc00020000003bffc0001",
        "P": 33548413,
        "t": 1031,
        "eta": 21,
        "D": 512,
        "vectors": [8192, 32768],
    }
    models = [
        m for b in (8, 12, 13, 14, 18, 30) for m in seed.source_models(geometry, b)
    ]
    assert any(m["all_guards_pass"] and m["saving_fraction"] > 0.2 for m in models)
    assert any(not m["all_guards_pass"] for m in models)
    assert all(
        m["compiled_query_matrix_Q_body_bytes"] > 0
        for m in models
        if m["rule"].startswith("tensor")
    )
    assert all(not m["full_native_admission_implemented"] for m in models)
