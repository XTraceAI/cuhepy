"""Encrypted ring-trace projection and packing against a coefficient oracle."""

from dataclasses import replace
import random

import pytest

from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


@pytest.mark.parametrize("n,d,t", [(8, 1, 17), (16, 3, 1031), (64, 5, 1031)])
def test_encrypted_trace_full_polynomial_and_multi_response_search(n, d, t):
    pk, sk = bgv.key_gen(n, t)
    padded = 1 << (d - 1).bit_length()
    keys = trace.evaluation_keys(pk, sk, padded)
    rng = random.Random(n + d)
    query = [rng.randrange(2) for _ in range(d)]
    rows = [query, [1 - x for x in query]] + [
        [rng.randrange(2) for _ in range(d)] for _ in range(n + 3)
    ]
    qp, tiles = bgv.coefficient_inputs(query, rows, n)
    encrypted_query = bgv.encrypt(qp, pk)
    index = [bgv.encrypt(tile, pk) for tile in tiles]
    projected = trace.project_product(encrypted_query, index[0], pk, keys)
    expected_poly = [0] * n
    for lane, row in enumerate(rows[: n // padded]):
        expected_poly[lane * padded] = (
            padded * sum((1 - 2 * a) * (1 - 2 * b) for a, b in zip(query, row, strict=True)) % t
        )
    assert bgv.decrypt(projected, pk, sk) == expected_poly
    for count in sorted({0, 1, n // padded, n - 1, n, n + 1, len(rows)}):
        chosen = index[: (count + n // padded - 1) // (n // padded)]
        responses = trace.search(encrypted_query, chosen, count, pk, keys)
        assert len(responses) == (count + n - 1) // n
        for response in responses:
            assert response.phase_bound < pk.q // 2
        distances = trace.decode([bgv.decrypt(ct, pk, sk) for ct in responses], count, d, pk)
        assert distances == [
            sum(a != b for a, b in zip(query, row, strict=True)) for row in rows[:count]
        ]


def test_trace_context_shape_and_bound_rejection():
    pk, sk = bgv.key_gen(16, 1031)
    keys = trace.evaluation_keys(pk, sk, 4)
    ct = bgv.encrypt([0] * 16, pk)
    with pytest.raises(ValueError, match="evaluation keys"):
        trace.project_product(ct, ct, pk, replace(keys, key_id="bad"))
    for count in (-1, True, 9):
        with pytest.raises(ValueError):
            trace.search(ct, [ct], count, pk, keys)
    with pytest.raises(ValueError, match="bound"):
        trace.search(ct, [ct], 4, pk, replace(keys, switch_error_bound=int(pk.q)))
    for padded in (0, 3, 16, True):
        with pytest.raises(ValueError):
            trace.evaluation_keys(pk, sk, padded)
    with pytest.raises(ValueError, match="Wrong"):
        trace.evaluation_keys(pk, replace(sk, key_id="bad"), 4)
    for plaintexts, count, dimension in (([], 1, 3), ([[0] * 16], 1, 3), ([], 0, 0)):
        with pytest.raises(ValueError):
            trace.decode(plaintexts, count, dimension, pk)


def test_full_workload_conservative_bound_rejects_q90():
    # Bound-only public metadata: no ciphertext or secret key is constructed.
    # Independent expression accounts for one relinearization and nine trace
    # additions per tile, followed by packing 256 tiles in the full ring.
    from cuhepy.bfv.scheme import _coefficient_modulus

    n, t, eta, padded, tiles = 16384, 1031, 21, 512, 256
    for bits, fits in ((90, False), (96, True), (120, True)):
        pk = bgv.PublicKey(n, t, _coefficient_modulus(bits), eta, (), (), "bound-only")
        error = t * eta * n * ((bits + 29) // 30) * ((1 << 30) - 1)
        keys = trace.EvaluationKeys(pk.key_id, padded, 30, (), (), error)
        per_tile = n * pk.fresh_bound**2 + error
        for _ in range(9):
            per_tile = 2 * per_tile + error
        assert trace.projected_bound(pk, keys, tiles) == tiles * per_tile
        assert (2 * tiles * per_tile < pk.q) is fits
