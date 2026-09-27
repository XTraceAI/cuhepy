"""Independent polynomial, binary-distance and homemade encrypted CRT oracles."""

from dataclasses import replace
import random

import pytest

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import crt_multiplex as crt
from experiments.bfv_search_lab import private_residual_lookup as lookup
from experiments.bfv_search_lab import reduction_oracles as reduction
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


@pytest.mark.parametrize("rows", [[0] * 5, [0, 255, 1, 254], list(range(16)), [1, 2, 4, 8]])
def test_affine_exact_for_every_binary_query_and_canonical_map(rows):
    plan = affine.prepare(rows, 8, 17)
    features = affine.index_features(plan, rows)
    assert len(affine.canonical_map(plan)) > 0
    for query in range(256):
        weights, offset = affine.query_features(plan, query)
        dots = [sum(a * b for a, b in zip(weights, row, strict=True)) % plan.prime for row in features]
        assert affine.decode(plan, dots, offset) == [(query ^ row).bit_count() for row in rows]
    if len(set(rows)) == 1:
        assert plan.rank == 0 and plan.features == 1


def test_affine_one_hot_rank_and_hidden_address_feature_obstruction():
    # Equality/bit lookup on all singleton addresses contains an identity matrix.
    rows = [1 << i for i in range(8)]
    plan = affine.prepare(rows, 8, 17)
    assert plan.rank == 7  # One query-only affine offset saves one feature.
    assert affine.prepare([0, *rows], 8, 17).rank == 8
    assert lookup.cost(8, 1, 1)["ciphertext_products"] == 8
    assert lookup.cost(8, 1, 1)["multiplicative_depth"] == 4


def test_affine_rejects_wrong_epoch_field_and_pivot_context():
    plan = affine.prepare([1, 2, 4, 8], 4, 17)
    with pytest.raises(ValueError, match="epoch"):
        affine.index_features(plan, [0])
    with pytest.raises(ValueError):
        affine.validate(replace(plan, pivots=(0, 0, 1)))
    for rows, d, p in (([], 4, 17), ([0], 4, 15), ([0], 4, 3), ([16], 4, 17)):
        with pytest.raises(ValueError):
            affine.prepare(rows, d, p)


@pytest.mark.parametrize("parts", [1, 2, 4, 8])
def test_crt_roundtrip_and_schoolbook_twisted_products(parts):
    ctx = crt.context(64, parts, 257)
    rng = random.Random(3001 + parts)
    a = [[rng.randrange(-1000, 1001) for _ in range(ctx.degree)] for _ in range(parts)]
    b = [[rng.randrange(-1000, 1001) for _ in range(ctx.degree)] for _ in range(parts)]
    pa, pb = crt.encode(ctx, a), crt.encode(ctx, b)
    assert crt.decode(ctx, [x % ctx.prime for x in pa]) == [[x % ctx.prime for x in row] for row in a]
    product = [x % ctx.prime for x in reduction.ring_product(tuple(pa), tuple(pb))]
    expected = []
    for left, right, root in zip(a, b, ctx.roots, strict=True):
        result = [0] * ctx.degree
        for i, x in enumerate(left):
            for j, y in enumerate(right):
                result[(i + j) % ctx.degree] += x * y * (root if i + j >= ctx.degree else 1)
        expected.append([x % ctx.prime for x in result])
    assert crt.decode(ctx, product) == expected


@pytest.mark.parametrize("parts,features,counts", [(1, (3,), (0,)), (2, (3, 5), (13, 7)),
                                                  (4, (1, 3, 5, 2), (1, 0, 39, 11)),
                                                  (8, (8,) * 8, (17,) * 8)])
def test_existing_butterfly_handles_components_tails_and_multiple_responses(parts, features, counts):
    ctx = crt.context(64, parts, 257)
    plan = crt.layout(ctx, features, counts)
    rng = random.Random(3002)
    queries = [[rng.randrange(-8, 9) for _ in range(f)] for f in features]
    rows = [[[rng.randrange(-15, 16) for _ in range(f)] for _ in range(count)]
            for f, count in zip(features, counts, strict=True)]
    qp, tiles = crt.query(plan, queries), crt.index(plan, rows)
    pk, sk = bgv.key_gen(64, t=257, q_bits=180, eta=1)
    keys = trace.evaluation_keys(pk, sk, plan.padded, 12)
    out = butterfly.search(bgv.encrypt(qp, pk), [bgv.encrypt(x, pk) for x in tiles], plan.virtual_count, pk, keys)
    plain = [bgv.decrypt(c, pk, sk) for c in out]
    decoded = crt.unpack(plan, plain)
    assert decoded == [[sum(a * b for a, b in zip(q, row, strict=True)) % ctx.prime for row in group]
                       for q, group in zip(queries, rows, strict=True)]
    # Independent integer coefficient projection, not another encryption helper.
    for group, start in enumerate(range(0, len(tiles), plan.padded)):
        products = [reduction.ring_product(tuple(qp), tuple(tile)) for tile in tiles[start:start + plan.padded]]
        projected = reduction.projected_phases(products, plan.padded)
        assert plain[group] == [x % ctx.prime for x in projected]


def test_exact_affine_search_all_distances_under_one_crt_query_and_response():
    groups = [[1, 2, 4, 8, 1], [0, 255, 0, 255], [42] * 3, [16, 32, 64, 128]]
    ctx = crt.context(128, 4, 257)
    plans = [affine.prepare(rows, 8, ctx.prime) for rows in groups]
    layout = crt.layout(ctx, tuple(p.features for p in plans), tuple(map(len, groups)))
    features = [affine.index_features(p, rows) for p, rows in zip(plans, groups, strict=True)]
    query = 0xAF
    transformations = [affine.query_features(p, query) for p in plans]
    qp = crt.query(layout, [q for q, _ in transformations])
    pk, sk = bgv.key_gen(ctx.n, t=ctx.prime, q_bits=180, eta=1)
    keys = trace.evaluation_keys(pk, sk, layout.padded, 12)
    out = butterfly.search(bgv.encrypt(qp, pk), [bgv.encrypt(x, pk) for x in crt.index(layout, features)],
                           layout.virtual_count, pk, keys)
    assert len(out) == 1
    dots = crt.unpack(layout, [bgv.decrypt(c, pk, sk) for c in out])
    for p, ds, (_, offset), rows in zip(plans, dots, transformations, groups, strict=True):
        assert affine.decode(p, ds, offset) == [(query ^ row).bit_count() for row in rows]


def test_crt_refuses_incompatible_prime_padding_and_corrupted_context():
    for args in ((64, 4, 1031), (64, 3, 257), (64, 4, 255), (63, 4, 257)):
        with pytest.raises(ValueError):
            crt.context(*args)
    ctx = crt.context(64, 4, 257)
    with pytest.raises(ValueError):
        crt.layout(ctx, (17,) * 4, (1,) * 4)
    with pytest.raises(ValueError):
        crt.encode(replace(ctx, roots=(1,) * 4), [[0] * 16] * 4)
    with pytest.raises(ValueError):
        crt.decode(ctx, [257] * 64)


@pytest.mark.parametrize("position,sign", [(0, -1), (3, 1), (7, -1), (5, 0)])
def test_encrypted_hidden_residual_position_and_padded_zero_sign(position, sign):
    pk, sk = bgv.key_gen(16, t=17, q_bits=180, eta=1)
    keys = trace.evaluation_keys(pk, sk, 1, 8)
    bits = [0, 1, 1, 0, 1, 1, 0, 1]

    def encrypted(value):
        return bgv.encrypt([value] + [0] * (pk.n - 1), pk)

    out = lookup.correction([encrypted(x) for x in bits], [encrypted((position >> j) & 1) for j in range(3)],
                            encrypted(sign), encrypted(1), pk, keys)
    plain = bgv.decrypt(out, pk, sk)
    assert plain == [sign * (1 - 2 * bits[position]) % pk.t] + [0] * (pk.n - 1)


def test_bounded_maps_and_scores_do_not_authenticate_a_response():
    plan = affine.prepare([0, 1], 3, 17)
    # Correctly shaped, plausible field output can still lie about a distance.
    assert affine.decode(plan, [1, 1], 0) == [1, 1]
    assert affine.decode(plan, [1, 1], 0) != [0, 1]
