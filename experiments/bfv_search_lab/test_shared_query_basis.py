"""Exact common/local algebra, encrypted execution and failed shortcuts."""

from contextlib import closing
from dataclasses import asdict, replace
import hashlib
import itertools
import json
import random

import numpy as np
import pytest

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import reduction_oracles as reduction
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_basis as shared
from experiments.bfv_search_lab.test_crt_masked_bgv import EPOCH, SEED


def fixture(k=1):
    words = ([0, 1, 6, 7] * 5, [8, 9, 10, 11] * 3, [16] * 4)
    maps = tuple(affine.prepare(list(row), 5, 97) for row in words)
    curve = shared.trajectory(maps)
    p = curve[k]
    layout = tree.layout(tree.context(32, ("0", "10", "11"), 97), p.features, tuple(map(len, words)))
    s = space.space(layout, (0, 1, 2), shared=p.shared)
    rows = [shared.index_features(p, i, list(row)) for i, row in enumerate(words)]
    return words, p, s, rows


@pytest.mark.parametrize("strategy", ("overlap", "raw"))
def test_exact_shared_affine_hamming_for_all_binary_queries_and_curve_points(strategy):
    words, _, _, _ = fixture()
    maps = tuple(affine.prepare(list(row), 5, 97) for row in words)
    curve = shared.trajectory(maps, strategy=strategy)
    for k, p in enumerate(curve):
        assert p.shared == k
        compiled = shared.compile_bits(p)
        coordinates = [shared.index_features(p, i, list(row)) for i, row in enumerate(words)]
        s = space.space(tree.layout(tree.context(32, ("0", "10", "11"), 97), p.features, tuple(map(len, words))),
                        (0, 1, 2), shared=p.shared)
        for query in range(32):
            weights, offsets = compiled.query(query)
            assert len(weights) == p.dimension == s.dimension
            scores = space.scores(s, coordinates, weights)
            actual = [v for i, row in enumerate(scores) for v in affine.decode(p.residuals[i], row, offsets[i])]
            assert actual == [(x ^ query).bit_count() for row in words for x in row]
        for g, rows in enumerate(coordinates):
            # Independent reconstruction of every original bit from BOTH bases.
            basis = (*p.common.basis, *p.residuals[g].basis)
            for x, coordinates in zip(words[g], rows, strict=True):
                if basis:
                    assert all((sum(a * b[j] for a, b in zip(coordinates, basis, strict=True))
                                + ((p.residuals[g].anchor >> j) & 1)) % 97 == (x >> j) & 1 for j in range(5))
                else:
                    assert x == p.residuals[g].anchor
    assert not any(p.rank for p in curve[-1].residuals)


def test_direction_sharing_beats_raw_coordinate_stripping_on_correlated_bits():
    m = affine.prepare([1, 2], 2, 97)
    overlap = shared.trajectory((m, m), limit=1)[-1]
    raw = shared.trajectory((m, m), limit=1, strategy="raw")[-1]
    assert (overlap.shared, overlap.dimension, max(overlap.features)) == (1, 1, 1)
    assert (raw.shared, raw.dimension, max(raw.features)) == (1, 3, 2)


def test_candidate_pool_can_miss_a_better_non_basis_intersection():
    a = affine.Plan(3, 7, 0, (0, 1), ((1, 0, 1), (0, 1, 1)))
    b = affine.Plan(3, 7, 0, (0, 1), ((1, 0, 2), (0, 1, 3)))
    greedy = shared.trajectory((a, b), limit=1)[-1]
    better = shared.factor((a, b), affine.Plan(3, 7, 0, (0,), ((1, 3, 4),)))
    assert max(greedy.features) == 3 and greedy.dimension == 4
    assert max(better.features) == 2 and better.dimension == 3


def test_single_full_rank_group_offers_no_query_or_index_dimension_saving():
    m = affine.prepare([0, 1, 2, 4, 8], 4, 97)
    assert all(p.dimension == max(p.features) == 4 for p in shared.trajectory((m,)))


@pytest.mark.parametrize("k", (0, 1, 3))
def test_shared_scalar_and_crt_corrections_match_full_schoolbook_polynomials(k):
    words, p, s, rows = fixture(k)
    rng = random.Random(7501)
    for _ in range(4):
        weights = tuple(rng.randrange(97) for _ in range(s.dimension))
        corrections = space.corrections(s, weights)
        assert tuple(map(len, corrections)) == s.column_degrees
        output = [[0] * 32 for _ in range(s.layout.cost.response_ciphertexts)]
        for column, short in zip(space.columns(s, rows), corrections, strict=True):
            poly = space.expand(s, short)
            for acc, values in zip(output, column, strict=True):
                product = reduction.ring_product(tuple(values), tuple(poly))
                acc[:] = [(a + b) % 97 for a, b in zip(acc, product, strict=True)]
        expected = space.outputs(s.layout, space.scores(s, rows, weights))
        assert output == [[x % 97 for x in poly] for poly in expected]


@pytest.mark.parametrize("k", (0, 1, 3))
def test_noisy_shared_search_all_distances_with_checker_before_decryption(k):
    words, p, s, rows = fixture(k)
    compiled = shared.compile_bits(p)
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, rows, EPOCH, client)
        gate = check.EpochCheck(index, pk, budget=32, rng=random.Random(7502))
        assert sum(map(len, gate._fingerprints[0])) == sum(s.column_degrees)
        pool = [masked.prepare(s, rows, EPOCH, i.to_bytes(16, "little"), SEED, client) for i in range(32)]
        for _, answer, _ in pool:
            gate.prepare_answer(answer)
        for q, (ticket, answer, _) in enumerate(pool):
            weights, offsets = compiled.query(q)
            request = ticket.consume(weights, EPOCH)
            result = masked.evaluate(index, answer, request, pk)
            assert gate.verify_once(request, result)
            dots = tree.unpack(s.layout, [bgv.decrypt(c, pk, sk) for c in result])
            actual = [v for i, row in enumerate(dots) for v in affine.decode(p.residuals[i], row, offsets[i])]
            expected = [(x ^ q).bit_count() for row in words for x in row]
            assert actual == expected
            assert sorted(zip(actual, range(len(actual)), strict=True))[:3] == sorted(zip(expected, range(len(expected)), strict=True))[:3]
            # Independent schoolbook phase bound, including scalar additions.
            for cipher in result:
                product = reduction.ring_product(tuple(map(int, cipher.components[1])), tuple(map(int, sk.s)))
                phase = [(a + b) % int(pk.q) for a, b in zip(cipher.components[0], product, strict=True)]
                assert max(abs(int(x if x <= pk.q // 2 else x - pk.q)) for x in phase) <= cipher.phase_bound


@pytest.mark.parametrize("k", (0, 1, 3))
def test_native_mixed_buffers_match_independent_gmp(k):
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    _, p, s, rows = fixture(k)
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, rows, EPOCH, client)
        evaluator = native.NativeIndex(index, pk)
        for i in range(4):
            ticket, answer, _ = masked.prepare(s, rows, EPOCH, i.to_bytes(16, "little"), SEED, client)
            request = ticket.consume(shared.compile_bits(p).query(i)[0], EPOCH)
            assert evaluator.evaluate(answer, request) == masked.evaluate(index, answer, request, pk)


def test_changed_shared_prefix_context_rejected_and_e29_bindings_preserved():
    _, _, s, rows = fixture(1)
    old = space.space(s.layout, s.map_ids)
    body = asdict(old)
    del body["shared"]
    del body["coordinate_ids"]
    assert old.binding == hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).digest()
    assert old.binding != s.binding and old.dimension > s.dimension
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, rows, EPOCH, client)
        ticket, answer, _ = masked.prepare(s, rows, EPOCH, bytes(16), SEED, client)
    request = ticket.consume((0,) * s.dimension, EPOCH)
    output = masked.evaluate(index, answer, request, pk)
    gate = check.EpochCheck(index, pk)
    gate.prepare_answer(answer)
    substitute = replace(request, space=old, delta=(0,) * old.dimension)
    assert not gate.verify_once(substitute, output)
    with pytest.raises(ValueError):
        masked.evaluate(index, answer, substitute, pk)
    for invalid in (-1, True, min(s.dimensions) + 1):
        with pytest.raises(ValueError):
            space.space(s.layout, s.map_ids, shared=invalid)


def test_restricting_masks_to_private_query_image_discloses_a_relation():
    # A private 3x2 query transform has image (a,b,a+b). Sampling masks from
    # this image reveals its relation in EVERY delta, even for a fixed query.
    # Full declared-coordinate masks instead give every delta exactly once.
    t, w = 5, (1, 3, 4)
    narrow = [(a, b, (a + b) % t) for a, b in itertools.product(range(t), repeat=2)]
    full = list(itertools.product(range(t), repeat=3))
    def deltas(masks):
        return [tuple((a - b) % t for a, b in zip(w, r, strict=True)) for r in masks]
    assert all((d[0] + d[1] - d[2]) % t == 0 for d in deltas(narrow))
    assert len(set(deltas(full))) == t ** 3
    assert sum((d[0] + d[1] - d[2]) % t == 0 for d in deltas(full)) == t ** 2


def test_private_factor_validation_and_outside_envelope_rows():
    _, p, _, _ = fixture(1)
    assert shared.index_features(p, 0, []) == []
    with pytest.raises(ValueError, match="envelope"):
        shared.index_features(p, 0, [16])
    with pytest.raises(ValueError):
        shared.trajectory((), limit=1)
    with pytest.raises(ValueError):
        shared.trajectory(p.residuals, limit=-1)
    with pytest.raises(ValueError):
        shared.validate(replace(p, common=replace(p.common, anchor=1)))
    with pytest.raises(ValueError):
        shared.index_features(p, 4, [])


@pytest.mark.parametrize("counts", ((0, 0, 0), (17, 11, 19)))
def test_replicated_maps_shared_prefix_and_empty_or_multiple_replies(counts):
    layout = tree.layout(tree.context(32, ("0", "10", "11"), 97), (2, 2, 3), counts)
    s = space.space(layout, (0, 0, 1), shared=1)
    assert s.dimension == 4 and s.column_degrees == (1, 4, 4)
    rows = [[[int((i + j) % 3 - 1) for j in range(f)] for i in range(c)]
            for f, c in zip(layout.features, counts, strict=True)]
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, rows, EPOCH, client)
        ticket, answer, _ = masked.prepare(s, rows, EPOCH, bytes(16), SEED, client)
    request = ticket.consume((9, 11, 21, 7), EPOCH)
    result = masked.evaluate(index, answer, request, pk)
    gate = check.EpochCheck(index, pk, rng=random.Random(7503))
    # Compare scalar AND subring hints with independent coefficient shifts.
    for rho, hints in zip(gate._challenges(), gate._fingerprints, strict=True):
        for column, hs in zip(index.columns, hints, strict=True):
            for k, h in enumerate(hs):
                monomial = tuple(int(j == k * pk.n // len(hs)) for j in range(pk.n))
                value = sum(a * b for cipher, pair in zip(column, rho, strict=True)
                            for poly, weights in zip(cipher.components, pair, strict=True)
                            for a, b in zip(reduction.ring_product(tuple(poly), monomial), weights, strict=True))
                assert value % pk.q == h
    gate.prepare_answer(answer)
    assert gate.verify_once(request, result)
    assert tree.unpack(layout, [bgv.decrypt(c, pk, sk) for c in result]) == space.scores(s, rows, (9, 11, 21, 7))
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    assert native.NativeIndex(index, pk).evaluate(answer, request) == result
