"""Independent small-space oracles and complete encrypted E31 execution."""

from contextlib import closing
from dataclasses import asdict, replace
from functools import cache
import hashlib
import itertools
import json
import random

import pytest

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as crt
from experiments.bfv_search_lab import hierarchical_query_basis as hierarchy
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import reduction_oracles as reduction
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_basis as shared
from experiments.bfv_search_lab.test_crt_masked_bgv import EPOCH, SEED
from benchmarks.hierarchical_query_basis_lab import uniform_candidate
from experiments.bfv_search_lab import rank_partition as partition


def all_plane_subspaces(t):
    # Independent enumeration: zero, every projective line, and the full plane.
    rows = [(), ((0, 1),)] + [((1, j),) for j in range(t)] + [((1, 0), (0, 1))]
    plans, sets = [], []
    for basis in rows:
        pivots = tuple(next(i for i, x in enumerate(row) if x) for row in basis)
        plans.append(affine.Plan(2, t, 0, pivots, tuple(basis)))
        sets.append(frozenset(tuple(sum(c * row[j] for c, row in zip(weights, basis, strict=True)) % t
                                    for j in range(2)) for weights in itertools.product(range(t), repeat=len(basis))))
    return tuple(plans), tuple(sets)


def test_exact_intersections_against_all_small_subspace_point_sets():
    plans, sets = all_plane_subspaces(5)
    for a, b in itertools.product(range(len(plans)), repeat=2):
        common = hierarchy.intersection(plans[a], plans[b])
        actual = {tuple(sum(c * row[j] for c, row in zip(weights, common.basis, strict=True)) % 5 for j in range(2))
                  for weights in itertools.product(range(5), repeat=common.rank)}
        assert actual == sets[a] & sets[b]
        # Exhaustive choices of a common subspace: minimum laminar coordinates.
        optimum = min(plans[a].rank + plans[b].rank - p.rank
                      for p, points in zip(plans, sets, strict=True) if points <= sets[a] & sets[b])
        assert optimum == plans[a].rank + plans[b].rank - common.rank
    a = affine.Plan(3, 7, 0, (0, 1), ((1, 0, 1), (0, 1, 1)))
    b = affine.Plan(3, 7, 0, (0, 1), ((1, 0, 2), (0, 1, 3)))
    assert hierarchy.intersection(a, b).basis == ((1, 3, 4),)
    assert all((1, 3, 4) not in p.basis for p in (a, b))


def test_four_leaf_laminar_coordinate_bound_matches_exhaustive_subspace_choices():
    plans, sets = all_plane_subspaces(17)
    ctx = crt.context(32, ("00", "01", "10", "11"), 17)

    @cache
    def optimum(leaves, ancestor):
        if len(leaves) == 1:
            return plans[leaves[0]].rank - plans[ancestor].rank
        common = frozenset.intersection(*(sets[i] for i in leaves))
        return min(plans[i].rank - plans[ancestor].rank
                   + optimum(leaves[:len(leaves) // 2], i) + optimum(leaves[len(leaves) // 2:], i)
                   for i, points in enumerate(sets) if sets[ancestor] <= points <= common)

    # 625 tuples of zero/e0/e1/diagonal/full spaces; each oracle considers ALL
    # 20 possible F17^2 common subspaces, not just our candidate basis rows.
    for ids in itertools.product((0, 1, 2, 3, len(plans) - 1), repeat=4):
        p = hierarchy.prepare(ctx, tuple(plans[i] for i in ids))
        h_laminar = sum(node.basis.rank for node in p.nodes)
        assert h_laminar == optimum(ids, 0)
        assert p.features == tuple(plans[i].features for i in ids)
    # This is a fixed-tree coordinate optimum without cross-tree equality
    # deduplication or rank expansion. It is NOT a map-size/W/global optimum.


def fixture(repeat=1):
    axes = ((0, 1, 3), (0, 1, 4), (0, 2, 5), (0, 2, 6))
    words = [[sum(((i >> j) & 1) << bit for j, bit in enumerate(bits)) for i in range(8)] * repeat for bits in axes]
    maps = tuple(affine.prepare(rows, 7, 97) for rows in words)
    ctx = crt.context(32, ("00", "01", "10", "11"), 97)
    p = hierarchy.prepare(ctx, maps)
    ids, _ = hierarchy.schedule(p)
    s = space.space(crt.layout(ctx, p.features, tuple(map(len, words))), (0, 1, 2, 3), coordinate_ids=ids)
    groups = [hierarchy.index_features(p, i, rows) for i, rows in enumerate(words)]
    return words, maps, p, s, groups


def test_all_binary_queries_and_independent_row_reconstruction():
    words, maps, p, s, groups = fixture()
    assert s.dimension == 7 and s.columns == 3 and s.column_degrees == (1, 2, 4)
    compiled = hierarchy.compile_bits(p)
    for q in range(128):
        w, offsets = compiled.query(q)
        scores = space.scores(s, groups, w)
        assert [affine.decode(m, row, off) for m, row, off in zip(maps, scores, offsets, strict=True)] == [
            [(x ^ q).bit_count() for x in rows] for rows in words]
    for leaf, anchor, rows, features in zip(p.context.leaves, p.anchors, words, groups, strict=True):
        basis = [row for node in p.chain(leaf.path) for row in node.basis]
        for x, cs in zip(rows, features, strict=True):
            assert all((sum(c * row[j] for c, row in zip(cs, basis, strict=True)) + ((anchor >> j) & 1)) % 97
                       == (x >> j) & 1 for j in range(7))


@pytest.mark.parametrize("repeat", (0, 1, 3))
def test_short_corrections_equal_full_crt_and_schoolbook_products(repeat):
    _, _, _, s, _ = fixture()
    counts = tuple(8 * repeat for _ in range(4))
    s = space.space(crt.layout(s.layout.context, (3,) * 4, counts), s.map_ids, coordinate_ids=s.coordinate_ids)
    rng = random.Random(8101)
    rows = [[[rng.randrange(-48, 49) for _ in range(3)] for _ in range(n)] for n in counts]
    for _ in range(5):
        values = tuple(rng.randrange(97) for _ in range(s.dimension))
        weights = space.split(s, values)
        corrections = space.corrections(s, values)
        assert tuple(map(len, corrections)) == (1, 2, 4)
        actual = [[0] * 32 for _ in range(s.layout.cost.response_ciphertexts)]
        for j, (column, short) in enumerate(zip(space.columns(s, rows), corrections, strict=True)):
            full = space.expand(s, short)
            assert full == crt.encode(s.layout.context, [[w[j]] + [0] * 7 for w in weights])
            for output, poly in zip(actual, column, strict=True):
                output[:] = [(a + b) % 97 for a, b in zip(output, reduction.ring_product(tuple(full), tuple(poly)), strict=True)]
        assert actual == [[x % 97 for x in row] for row in space.outputs(s.layout, space.scores(s, rows, values))]


def test_three_native_degrees_noisy_search_check_before_decryption_and_tail_mutation():
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    words, maps, p, s, rows = fixture(3)
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    compiled = hierarchy.compile_bits(p)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, rows, EPOCH, client)
        evaluator = native.NativeIndex(index, pk)
        gate = check.EpochCheck(index, pk, budget=6, rng=random.Random(8102))
        assert len(evaluator._handles) == 3
        # Independent shift fingerprints, including intermediate degree two.
        for rho, hints in zip(gate._challenges(), gate._fingerprints, strict=True):
            for column, hs in zip(index.columns, hints, strict=True):
                for k, h in enumerate(hs):
                    monomial = tuple(int(j == k * pk.n // len(hs)) for j in range(pk.n))
                    value = sum(a * b for cipher, pair in zip(column, rho, strict=True)
                                for poly, weights in zip(cipher.components, pair, strict=True)
                                for a, b in zip(reduction.ring_product(tuple(poly), monomial), weights, strict=True))
                    assert value % pk.q == h
        for i, q in enumerate((0, 1, 31, 64, 127, 7)):
            ticket, answer, _ = masked.prepare(s, rows, EPOCH, i.to_bytes(16, "little"), SEED, client)
            gate.prepare_answer(answer)
            weights, offsets = compiled.query(q)
            request = ticket.consume(weights, EPOCH)
            output = evaluator.evaluate(answer, request)
            assert output == masked.evaluate(index, answer, request, pk)
            if i == 5:
                components = [list(poly) for poly in output[-1].components]
                components[1][-1] = (components[1][-1] + 1) % pk.q
                bad = (*output[:-1], replace(output[-1], components=tuple(tuple(poly) for poly in components)))
                assert not gate.verify_once(request, bad)
                continue
            assert gate.verify_once(request, output)
            dots = crt.unpack(s.layout, [bgv.decrypt(c, pk, sk) for c in output])
            actual = [affine.decode(m, ds, off) for m, ds, off in zip(maps, dots, offsets, strict=True)]
            assert actual == [[(x ^ q).bit_count() for x in group] for group in words]
            for cipher in output:
                product = reduction.ring_product(tuple(map(int, cipher.components[1])), tuple(map(int, sk.s)))
                phase = [(a + b) % int(pk.q) for a, b in zip(cipher.components[0], product, strict=True)]
                assert max(abs(int(x if x <= pk.q // 2 else x - pk.q)) for x in phase) <= cipher.phase_bound


def test_unequal_leaves_dummy_and_equal_directions_across_disconnected_nodes():
    ctx = crt.context(32, ("0", "10", "11"), 97)
    words = ([0, 1], [0], [2, 3])
    maps = tuple(affine.prepare(list(rows), 3, 97) for rows in words)
    p = hierarchy.prepare(ctx, maps)
    ids, directions = hierarchy.schedule(p)
    assert ids == ((0,), (1,), (0,)) and directions == ((1, 0, 0), (0, 0, 0))
    s = space.space(crt.layout(ctx, p.features, (2, 1, 2)), (0, 1, 2), coordinate_ids=ids)
    assert s.dimension == 2 and s.column_degrees == (4,)
    rows = [hierarchy.index_features(p, i, list(xs)) for i, xs in enumerate(words)]
    for q in range(8):
        weights, offsets = hierarchy.compile_bits(p).query(q)
        assert [affine.decode(m, ds, off) for m, ds, off in zip(maps, space.scores(s, rows, weights), offsets, strict=True)] == [
            [(x ^ q).bit_count() for x in group] for group in words]
    assert hierarchy.index_features(p, 0, []) == []
    with pytest.raises(ValueError, match="envelope"):
        hierarchy.index_features(p, 1, [1])
    assert hierarchy.canonical_map(p) == hierarchy.canonical_map(p)


def test_schedule_validation_canonical_field_binding_and_legacy_digests():
    _, _, p, s, rows = fixture()
    for shared_count in (0, 1):
        old = space.space(s.layout, s.map_ids, shared=shared_count)
        body = asdict(old)
        del body["coordinate_ids"]
        if not shared_count:
            del body["shared"]
        assert old.binding == hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).digest()
    for ids in (((0, 1, 2),) * 3, ((0, 0, 1),) * 4, ((1, 2, 3),) * 4, ((0, 1, True),) * 4):
        with pytest.raises(ValueError):
            space.space(s.layout, s.map_ids, coordinate_ids=ids)
    with pytest.raises(ValueError):
        space.space(s.layout, s.map_ids, shared=1, coordinate_ids=s.coordinate_ids)
    with pytest.raises(ValueError):
        hierarchy.validate(replace(p, nodes=tuple(reversed(p.nodes))))
    # Same column count and coordinate count; a different dependency schedule.
    ids = list(s.coordinate_ids)
    ids[-1] = (ids[-1][1], ids[-1][0], ids[-1][2])
    changed = space.space(s.layout, s.map_ids, coordinate_ids=tuple(ids))
    assert changed.dimension == s.dimension and changed.binding != s.binding
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, rows, EPOCH, client)
        ticket, answer, _ = masked.prepare(s, rows, EPOCH, bytes(16), SEED, client)
    request = ticket.consume((0,) * s.dimension, EPOCH)
    output = masked.evaluate(index, answer, request, pk)
    substitute = replace(request, space=changed)
    gate = check.EpochCheck(index, pk)
    gate.prepare_answer(answer)
    assert not gate.verify_once(substitute, output)
    with pytest.raises(ValueError):
        masked.evaluate(index, answer, substitute, pk)


def test_overlap_grouping_capacity_coverage_and_tiny_permutation_optimum():
    # Identical subspaces start on opposite branches. Enumerate every four-leaf
    # ordering independently before trusting the greedy geometry on this case.
    a = affine.prepare([0, 1, 2, 3], 3, 97)
    b = affine.prepare([0, 4], 3, 97)
    maps = (a, b, a, b)
    ctx = crt.context(32, ("00", "01", "10", "11"), 97)
    order = hierarchy.overlap_order(maps)
    assert sorted(order) == list(range(4))
    p = hierarchy.prepare(ctx, tuple(maps[i] for i in order))
    optimum = min(sum(node.basis.rank for node in hierarchy.prepare(ctx, tuple(maps[i] for i in perm)).nodes)
                  for perm in itertools.permutations(range(4)))
    assert sum(node.basis.rank for node in p.nodes) == optimum == 3
    assert sum(node.basis.rank for node in hierarchy.prepare(ctx, maps).nodes) == 6
    with pytest.raises(ValueError):
        hierarchy.overlap_order((a, b, a))

    # Unequal original leaves, a rounding remainder and an empty block.
    rows = [0, 1, 2, 3, 0, 1, 2, 0, 4]
    blocks = (partition.Block("0", tuple(range(7)), a), partition.Block("10", (), a),
              partition.Block("11", (7, 8), b))
    ctx = crt.context(32, ("0", "10", "11"), 97)
    layout = crt.layout(ctx, tuple(x.mapping.features for x in blocks), (7, 0, 2))
    source = partition.Candidate(layout, blocks, (), partition.epoch_digest(rows, 3), 3, partition.map_body_bytes(blocks), None)
    for regroup in (False, True):
        c, perm = uniform_candidate(source, rows, regroup=regroup)
        assert c.source_digest == source.source_digest and sorted(perm) == list(range(4))
        assert sorted(i for block in c.blocks for i in block.positions) == list(range(len(rows)))
        p = hierarchy.prepare(c.layout.context, tuple(block.mapping for block in c.blocks))
        schedule, _ = hierarchy.schedule(p)
        s = space.space(c.layout, tuple(range(4)), coordinate_ids=schedule)
        coords = [hierarchy.index_features(p, i, [rows[j] for j in block.positions]) for i, block in enumerate(c.blocks)]
        for q in range(8):
            values, offsets = hierarchy.compile_bits(p).query(q)
            actual = sorted((i, score) for block, scores, off in zip(c.blocks, space.scores(s, coords, values), offsets, strict=True)
                            for i, score in zip(block.positions, affine.decode(block.mapping, scores, off), strict=True))
            assert actual == [(i, (x ^ q).bit_count()) for i, x in enumerate(rows)]
