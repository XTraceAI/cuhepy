"""Independent factor projections and homemade encrypted unequal CRT layouts."""

from dataclasses import replace
import random

import pytest

from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import crt_multiplex as flat
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import reduction_oracles as reduction
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


def project(poly, degree, root, prime):
    result = [0] * degree
    for i, value in enumerate(poly):
        result[i % degree] += value * pow(root, i // degree, prime)
    return [x % prime for x in result]


@pytest.mark.parametrize("paths", [("",), ("0", "1"), ("0", "10", "110", "111"),
                                   ("00", "01", "10", "110", "111")])
def test_unequal_crt_matches_direct_polynomial_remainders_and_products(paths):
    ctx = tree.context(64, paths, 257)
    rng = random.Random(3101)
    components = [[rng.randrange(-1000, 1001) for _ in range(leaf.degree)] for leaf in ctx.leaves]
    encoded = tree.encode(ctx, components)
    expected = [[x % ctx.prime for x in row] for row in components]
    assert tree.decode(ctx, [x % ctx.prime for x in encoded]) == expected
    assert [project(encoded, leaf.degree, leaf.root, ctx.prime) for leaf in ctx.leaves] == expected
    right = [rng.randrange(-100, 100) for _ in range(ctx.n)]
    product = reduction.ring_product(tuple(encoded), tuple(right))
    for leaf, values in zip(ctx.leaves, expected, strict=True):
        b = project(right, leaf.degree, leaf.root, ctx.prime)
        direct = [0] * leaf.degree
        for i, x in enumerate(values):
            for j, y in enumerate(b):
                direct[(i + j) % leaf.degree] += x * y * (leaf.root if i + j >= leaf.degree else 1)
        assert project(product, leaf.degree, leaf.root, ctx.prime) == [x % ctx.prime for x in direct]


@pytest.mark.parametrize("parts", [1, 2, 4, 8, 16])
def test_uniform_tree_is_exactly_flat_crt_after_root_permutation(parts):
    depth = parts.bit_length() - 1
    paths = tuple(format(i, f"0{depth}b") for i in range(parts)) if depth else ("",)
    ctx, old = tree.context(128, paths, 257), flat.context(128, parts, 257)
    rng = random.Random(3102)
    components = [[rng.randrange(257) for _ in range(leaf.degree)] for leaf in ctx.leaves]
    by_root = {leaf.root: row for leaf, row in zip(ctx.leaves, components, strict=True)}
    assert tree.encode(ctx, components) == flat.encode(old, [by_root[root] for root in old.roots])


@pytest.mark.parametrize("paths,features,counts", [
    (("",), (3,), (0,)),
    (("0", "10", "110", "111"), (5, 3, 7, 1), (19, 8, 37, 0)),
    (("00", "01", "1"), (1, 3, 4), (33, 17, 7)),
])
def test_unchanged_bgv_butterfly_scores_unequal_components_with_full_polynomial_oracle(paths, features, counts):
    ctx = tree.context(128, paths, 257)
    plan = tree.layout(ctx, features, counts)
    rng = random.Random(3103)
    queries = [[rng.randrange(-8, 9) for _ in range(f)] for f in features]
    rows = [[[rng.randrange(-15, 16) for _ in range(f)] for _ in range(c)]
            for f, c in zip(features, counts, strict=True)]
    qp, tiles = tree.query(plan, queries), tree.index(plan, rows)
    assert len(tiles) == max((c + leaf.degree // plan.padded - 1) // (leaf.degree // plan.padded)
                             for c, leaf in zip(counts, ctx.leaves, strict=True))
    pk, sk = bgv.key_gen(128, t=257, q_bits=180, eta=1)
    keys = trace.evaluation_keys(pk, sk, plan.padded, 12)
    out = butterfly.search(bgv.encrypt(qp, pk), [bgv.encrypt(p, pk) for p in tiles], plan.virtual_count, pk, keys)
    plain = [bgv.decrypt(c, pk, sk) for c in out]
    assert tree.unpack(plan, plain) == [[sum(a * b for a, b in zip(q, row, strict=True)) % pk.t for row in group]
                                      for q, group in zip(queries, rows, strict=True)]
    for group, start in enumerate(range(0, len(tiles), plan.padded)):
        products = [reduction.ring_product(tuple(qp), tuple(p)) for p in tiles[start:start + plan.padded]]
        assert plain[group] == [x % pk.t for x in reduction.projected_phases(products, plan.padded)]


@pytest.mark.parametrize("paths", [("0",), ("", "0"), ("0", "10"), ("0", "0", "1"), ("1", "0"), ("2",)])
def test_incomplete_overlapping_and_noncanonical_trees_rejected(paths):
    with pytest.raises(ValueError):
        tree.context(64, paths, 257)


def test_context_schedule_shape_and_plaintext_boundaries():
    with pytest.raises(ValueError):
        tree.context(64, ("0", "1"), 1031)
    ctx = tree.context(64, ("0", "10", "11"), 257)
    with pytest.raises(ValueError):
        tree.layout(ctx, (17, 1, 1), (1, 1, 1))
    with pytest.raises(ValueError):
        tree.validate(replace(ctx, leaves=(replace(ctx.leaves[0], root=1), *ctx.leaves[1:])))
    plan = tree.layout(ctx, (3, 2, 1), (2, 1, 0))
    with pytest.raises(ValueError):
        tree.query(plan, [[1, 2, 3], [1], [0]])
    with pytest.raises(ValueError):
        tree.index(plan, [[[1, 2, 3]], [[1, 2]], []])
    with pytest.raises(ValueError):
        tree.decode(ctx, [257] * 64)
    with pytest.raises(ValueError):
        tree.unpack(plan, [])
    with pytest.raises(ValueError):
        tree.validate_layout(replace(plan, padded=8))
