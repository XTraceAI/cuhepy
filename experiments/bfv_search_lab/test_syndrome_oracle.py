"""Exhaustive lower-bound checks; no test is a remote coverage certificate."""

import random

import pytest

from experiments.bfv_search_lab import syndrome_oracle as oracle
from experiments.bfv_search_lab import reduction_oracles as reduction
from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


@pytest.mark.parametrize("width", [1, 2, 3, 4, 5, 6])
def test_all_queries_and_blocks_have_safe_monotonically_stronger_bounds(width):
    for rank in range(1, width + 1):
        code = oracle.make_code(width, rank, 10 + width)
        for query in range(1 << width):
            table = oracle.conditioned_table(code, query)
            for value in range(1 << width):
                weight, syndrome, parity_max, conditioned = oracle.block_bounds(code, query, value, table)
                exact = (query ^ value).bit_count()
                assert 0 <= max(weight, syndrome) <= parity_max <= conditioned <= exact
                assert conditioned % 2 == exact % 2
                if rank == width:
                    assert conditioned == syndrome == exact


def test_conditioning_can_be_stronger_than_separate_bounds_even_with_parity():
    code = oracle.make_code(8, 4, 20260927)
    improvements = []
    for query in range(1 << code.width):
        table = oracle.conditioned_table(code, query)
        for value in range(1 << code.width):
            _, _, simple, conditioned = oracle.block_bounds(code, query, value, table)
            if conditioned > simple:
                improvements.append((query, value, simple, conditioned))
    assert improvements


@pytest.mark.parametrize("dimension", [1, 7, 8, 9, 17, 32])
def test_disjoint_sum_tails_duplicates_and_radius_equality_preserve_stable_winners(dimension):
    rng = random.Random(dimension)
    codes = [oracle.make_code(min(8, dimension - i), min(4, dimension - i), i)
             for i in range(0, dimension, 8)]
    query = rng.getrandbits(dimension)
    rows = [query, query, query ^ 1] + [rng.getrandbits(dimension) for _ in range(50)]
    result = oracle.selectivity(query, rows, codes)
    assert all(row["exact_topk_preserved"] for row in result["filters"].values())
    assert result["oracle_kth_radius"] in (0, 1)
    assert result["filters"]["conditioned"]["survivors"] >= 3


def test_overlapping_bounds_cannot_be_summed_and_equal_radius_cannot_be_dropped():
    code = oracle.make_code(4, 4)
    bound = oracle.block_bounds(code, 0, 1)[-1]
    assert bound == 1
    assert bound + bound > (0 ^ 1).bit_count()  # The same coordinate counted twice.
    report = oracle.selectivity(0, [1, 2, 4, 8], [code])
    assert report["oracle_kth_radius"] == 1
    assert report["filters"]["conditioned"]["survivors"] == 4


@pytest.mark.parametrize("width,rank", [(0, 0), (11, 4), (8, 0), (8, 9), (True, 1)])
def test_invalid_toy_code_dimensions(width, rank):
    with pytest.raises(ValueError):
        oracle.make_code(width, rank)


def test_out_of_range_vectors_and_impossible_k_rejected():
    code = oracle.make_code(4, 2)
    for query, rows, k in ((16, [0], 1), (0, [16], 1), (0, [0], 0), (0, [0], 2)):
        with pytest.raises(ValueError):
            oracle.selectivity(query, rows, [code], k)


def test_onehot_cost_model_accounts_for_query_and_index_expansion():
    codes = [oracle.make_code(8, 4, 20260927 + i) for i in range(64)]
    model = oracle.lookup_expansion(codes, 8192)
    assert model["onehot_features"] == 6117
    assert model["onehot_input_tiles"] == 16 * model["original_input_tiles"]
    assert model["onehot_switches"] > 15 * model["original_switches"]


def test_onehot_filter_is_an_exact_depth_one_homemade_encrypted_dot_product():
    n, dimension = 128, 8
    codes = [oracle.make_code(4, 2, i) for i in range(2)]
    rng = random.Random(2709)
    pk, sk = bgv.key_gen(n, t=257, q_bits=180, eta=1)
    for count in (0, 1, 5, n + 1):
        query = rng.getrandbits(dimension)
        rows = [rng.getrandbits(dimension) for _ in range(count)]
        qp, tiles, padded = oracle.lookup_inputs(query, rows, codes, n)
        expected = oracle.vector_bounds(query, rows, codes)["conditioned"]
        # Plain integer product is an independent layout oracle.
        plain_products = [reduction.ring_product(tuple(qp), tuple(tile)) for tile in tiles]
        assert [plain_products[i // (n // padded)][(i % (n // padded)) * padded + padded - 1]
                for i in range(count)] == expected
        keys = trace.evaluation_keys(pk, sk, padded, 12)
        output = butterfly.search(bgv.encrypt(qp, pk), [bgv.encrypt(tile, pk) for tile in tiles], count, pk, keys)
        plaintexts = [bgv.decrypt(cipher, pk, sk) for cipher in output]
        decoded = []
        for position in range(count):
            group, within = divmod(position, n)
            tile, lane = divmod(within, n // padded)
            decoded.append(plaintexts[group][lane * padded + tile] * pow(padded, -1, pk.t) % pk.t)
        assert decoded == expected
