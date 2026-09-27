"""Independent integer identities and local encrypted pilots, not security proofs."""

from dataclasses import replace
import random

import pytest

from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import certified_lookup as certified
from experiments.bfv_search_lab import folded_filter as folded
from experiments.bfv_search_lab import linear_packing as packing
from experiments.bfv_search_lab import reduction_oracles as reduction
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import syndrome_oracle as syndrome


def encrypted_dots(qp, tiles, padded, count, pk, sk):
    keys = trace.evaluation_keys(pk, sk, padded, 12)
    output = butterfly.search(bgv.encrypt(qp, pk), [bgv.encrypt(p, pk) for p in tiles], count, pk, keys)
    return packing.unpack([bgv.decrypt(c, pk, sk) for c in output], count, padded, pk.n, pk.t)


@pytest.mark.parametrize("count", [0, 1, 7, 65])
def test_generic_layout_matches_independent_integer_negacyclic_product(count):
    rng = random.Random(2800 + count)
    query = [rng.randrange(-8, 9) for _ in range(5)]
    rows = [[rng.randrange(-100, 101) for _ in query] for _ in range(count)]
    qp, tiles, padded = packing.pack(query, rows, 64)
    products = [reduction.ring_product(tuple(qp), tuple(tile)) for tile in tiles]
    assert [products[i // 8][i % 8 * padded + padded - 1] for i in range(count)] == [
        sum(a * b for a, b in zip(query, row, strict=True)) for row in rows]


def test_packing_accounts_for_padding_and_partial_butterflies():
    assert packing.packing_cost(512, 8192).input_tiles == 256
    assert packing.packing_cost(512, 8192).switches == 767
    assert packing.packing_cost(48, 8192).input_tiles == 32
    assert packing.packing_cost(48, 8192).switches == 95
    # A single extra bias feature can double the padded dimension.
    assert packing.packing_cost(64, 8192).input_tiles * 2 == packing.packing_cost(65, 8192).input_tiles
    assert packing.packing_cost(3, 0).response_ciphertexts == 0
    for args in ((0, 1), (True, 1), (2, -1), (16384, 1)):
        with pytest.raises(ValueError):
            packing.packing_cost(*args)
    with pytest.raises(ValueError):
        packing.unpack([[0] * 32], 1, 3, 32, 257)
    with pytest.raises(ValueError):
        packing.pack([1], [[1, 2]], 32)


def structured_rows(count, dimension=16):
    rng = random.Random(2801)
    mapping = [(j % 3, rng.randrange(2)) for j in range(dimension)]
    return [sum((((i >> g) & 1) ^ c) << j for j, (g, c) in enumerate(mapping)) for i in range(count)]


@pytest.mark.parametrize("threshold", [0, 2, 6])
def test_folded_bounds_exhaustive_all_queries_with_complements_and_residuals(threshold):
    rows = structured_rows(12, 8)
    rows[-1] ^= 1 << 4
    plan = folded.prepare(rows, 8, threshold)
    features = folded.index_features(plan, rows)
    for query in range(256):
        exact = [(query ^ row).bit_count() for row in rows]
        weights = folded.query_features(plan, query)
        dots = [sum(a * b for a, b in zip(weights, row, strict=True)) for row in features]
        decoded = folded.decode(plan, [x % 17 for x in dots], 17)
        assert decoded == folded.lower_bounds(plan, query, rows)
        assert all(0 <= low <= high for low, high in zip(decoded, exact, strict=True))
        if plan.max_error == 0:
            assert decoded == exact


def test_exact_column_folding_can_keep_all_rows_distinct():
    rows = structured_rows(8)
    plan = folded.prepare(rows, 16)
    assert len(set(rows)) == len(rows)
    assert len(plan.representatives) == 3
    assert plan.max_error == 0
    assert any(c for _, c in plan.mapping)


def test_error_feature_is_charged_and_recomputed_for_new_rows():
    rows = [0, 255, 1]
    plan = folded.prepare(rows, 8, 1)
    assert len(plan.representatives) == 1 and plan.max_error == 7
    assert plan.features == 2
    with pytest.raises(ValueError, match="epoch"):
        folded.index_features(replace(plan, max_error=0), rows)
    # The encrypted dot 22 wraps mod 17; unwrapping a centered dot is wrong.
    assert folded.decode(plan, [22 % 17], 17) == [0]
    exact = folded.prepare([0, 255], 8)
    assert folded.decode(exact, [8 % 11], 11) == [0]
    with pytest.raises(ValueError, match="modulus"):
        folded.decode(plan, [0], 15)
    with pytest.raises(ValueError, match="outside"):
        folded.decode(exact, [1], 19)  # Odd-field division gives an impossible distance.


@pytest.mark.parametrize("count", [0, 1, 13, 129])
@pytest.mark.parametrize("perturb", [False, True])
def test_folded_homemade_bgv_handles_errors_tails_and_multiple_responses(count, perturb):
    training = structured_rows(max(16, count))
    if perturb:
        training[7] ^= 1 << 9
    plan = folded.prepare(training, 16, 2 if perturb else 0)
    rows = training[:count]
    query = 0xA56B
    pk, sk = bgv.key_gen(128, t=257, q_bits=180, eta=1)
    qp, tiles, padded = folded.inputs(plan, query, rows, pk.n)
    dots = encrypted_dots(qp, tiles, padded, count, pk, sk)
    assert folded.decode(plan, dots, pk.t) == folded.lower_bounds(plan, query, rows)


def test_folding_rejects_invalid_inputs_and_maps():
    for rows, dimension, threshold in (([], 8, 0), ([0], 0, 0), ([256], 8, 0), ([0], 8, 1), ([True], 8, 0)):
        with pytest.raises(ValueError):
            folded.prepare(rows, dimension, threshold)
    plan = folded.prepare([0, 255], 8)
    with pytest.raises(ValueError):
        folded.query_features(plan, 256)
    with pytest.raises(ValueError):
        folded.validate(replace(plan, mapping=((0, 1),) * 8))
    with pytest.raises(ValueError):
        folded.inputs(plan, 0, [256], 32)


@pytest.mark.parametrize("width", [2, 3, 4, 5])
@pytest.mark.parametrize("rank", [1, 3])
def test_svd_certificate_covers_all_queries_and_bucket_words(width, rank):
    code = syndrome.make_code(width, min(width, 3), 28)
    model = certified.svd_proposal(code, rank, 8)
    assert certified.verify(model)
    for query in range(1 << width):
        expected = syndrome.conditioned_table(code, query)
        for b, bucket in enumerate(model.buckets):
            raw = sum(a * x for a, x in zip(model.query[query], model.index[b], strict=True))
            bound = (raw + model.column_offsets[b] + model.row_offsets[query]) // model.scale
            assert bound <= expected[bucket]


def test_certificate_uses_unbounded_integers_and_detects_corruption():
    code = syndrome.make_code(3, 2, 28)
    buckets = syndrome._buckets(code)
    query = tuple((i * (1 << 80),) for i in range(8))
    index = tuple((i * (1 << 80),) for i in range(len(buckets)))
    model = certified.certify(code, query, index, 7, (0,) * 8)
    assert model.numerator_bound > 1 << 64
    assert certified.verify(model)
    assert not certified.verify(replace(model, column_offsets=tuple(x + 1 for x in model.column_offsets)))
    assert not certified.verify(replace(model, numerator_bound=0))
    assert not certified.verify(replace(model, query=model.query[:-1]))


@pytest.mark.parametrize("count", [0, 1, 17, 129])
def test_certified_lookup_is_a_homemade_encrypted_integer_dot_product(count):
    models = [certified.svd_proposal(syndrome.make_code(4, 2, j), 2, 4) for j in range(2)]
    rng = random.Random(2802)
    query, rows = rng.randrange(256), [rng.randrange(256) for _ in range(count)]
    pk, sk = bgv.key_gen(128, t=65537, q_bits=180, eta=1)
    qp, tiles, padded, offset = certified.inputs(models, query, rows, pk.n)
    dots = encrypted_dots(qp, tiles, padded, count, pk, sk)
    decoded = certified.decode(models, dots, offset, pk.t)
    assert decoded == certified.lower_bounds(models, query, rows)
    assert all(x <= (query ^ row).bit_count() for x, row in zip(decoded, rows, strict=True))
    with pytest.raises(ValueError, match="modulus"):
        certified.decode(models, [], offset, 3)


def test_certified_rejects_incompatible_scales_and_invalid_proposals():
    code = syndrome.make_code(3, 2)
    for rank, quant in ((0, 4), (100, 4), (1, 0), (True, 8)):
        with pytest.raises(ValueError):
            certified.svd_proposal(code, rank, quant)
    one = certified.svd_proposal(code, 1, 4)
    two = certified.svd_proposal(code, 1, 8)
    with pytest.raises(ValueError):
        certified.lower_bounds([one, two], 0, [0])
    with pytest.raises(ValueError):
        certified.lower_bounds([one], 8, [0])
    with pytest.raises(ValueError):
        certified.certify(code, (), (), 1, ())
