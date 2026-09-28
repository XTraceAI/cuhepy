"""Exact masked-query identities and local lifecycle limits, not a security audit."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import random

import pytest

from experiments.bfv_search_lab import matrix_bgv_oracle as matrix
from experiments.bfv_search_lab import matrix_masked_query as masked

EPOCH, TOKEN, SEED = b"e" * 32, b"i" * 16, b"s" * 32


def fixture(t=97):
    ctx, rng = matrix.Context(n=4, rank=2, t=t), random.Random(412)
    secret = matrix.sample_matrix(ctx, 2, 2, rng, small=True)
    out_secret = matrix.sample_matrix(ctx, 1, 2, rng, small=True)[0]
    rows = tuple(tuple(matrix.simd_encode(ctx, tuple((word >> bit) & 1 for word in range(4)))
                       for bit in range(2)) for _ in range(2))
    index = matrix.encrypt(ctx, secret, rows, rng)
    forms = masked.index_conversion_forms(ctx, index)
    sources = {s for row in forms for form in row for s, _ in form.terms}
    key = matrix.mask_sources(ctx, matrix.source_values(ctx, secret, sources), out_secret, rng)
    converted = masked.convert_index(ctx, index, key, EPOCH)
    return ctx, rng, secret, out_secret, index, converted


@pytest.mark.parametrize("t", [17, 97, 257])
@pytest.mark.parametrize("space", ["full", "constant"])
def test_offline_plus_online_matches_all_binary_queries(t, space):
    ctx, rng, secret, out_secret, index, converted = fixture(t)
    for query in range(4):
        token_id = query.to_bytes(16, "little")
        ticket, packet = masked.prepare(ctx, secret, out_secret, SEED, EPOCH, token_id, rng, mask_space=space)
        offline = masked.evaluate_offline(ctx, index, packet)
        weights = tuple(ctx.constant(1 - 2 * ((query >> bit) & 1)) for bit in range(2))
        request = ticket.consume(weights, EPOCH)
        assert len(request.coefficient_body()) == (ctx.n if space == "full" else 1) * ctx.rank * ((t.bit_length() + 7) // 8)
        result = masked.evaluate_online(converted, offline, request)
        for cipher in result:
            scores = matrix.simd_decode(ctx, matrix.decrypt(ctx, cipher, out_secret))
            assert [(x + query.bit_count()) % t for x in scores] == [(i ^ query).bit_count() for i in range(4)]
        with pytest.raises(RuntimeError, match="consumed"):
            ticket.consume(weights, EPOCH)


def test_uniform_mask_difference_has_identical_marginal_distribution():
    # Exact finite-field enumeration; says nothing about the joint HE transcript.
    for t in (3, 5, 17):
        for w in range(t):
            assert Counter((w - r) % t for r in range(t)) == Counter(range(t))


def test_reused_mask_exposes_query_difference_even_across_ticket_objects():
    ctx = matrix.Context()
    first = masked.MaskTicket(ctx, SEED, EPOCH, TOKEN)
    # Deliberately bypass the lease by recreating private state: rollback is not
    # solved by an in-memory flag. Preserve this as an explicit failure control.
    clone = masked.MaskTicket(ctx, SEED, EPOCH, TOKEN)
    w1, w2 = (ctx.constant(1), ctx.constant(-1)), (ctx.constant(-1), ctx.constant(1))
    r1, r2 = first.consume(w1, EPOCH), clone.consume(w2, EPOCH)
    leaked = tuple(tuple((a - b) % ctx.t for a, b in zip(p, q, strict=True))
                   for p, q in zip(r1.delta, r2.delta, strict=True))
    expected = tuple(tuple((a - b) % ctx.t for a, b in zip(ctx.centered(p), ctx.centered(q), strict=True))
                     for p, q in zip(w1, w2, strict=True))
    assert leaked == expected


def test_ticket_is_consumed_at_most_once_under_concurrency():
    ctx = matrix.Context()
    ticket = masked.MaskTicket(ctx, SEED, EPOCH, TOKEN)

    def attempt(_):
        try:
            ticket.consume((ctx.constant(1), ctx.constant(-1)), EPOCH)
            return True
        except RuntimeError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(attempt, range(16))) == 1


def test_epoch_id_range_and_consumption_rejections():
    ctx, rng, secret, out_secret, index, converted = fixture()
    ticket, packet = masked.prepare(ctx, secret, out_secret, SEED, EPOCH, TOKEN, rng)
    offline = masked.evaluate_offline(ctx, index, packet)
    with pytest.raises(ValueError, match="epoch"):
        ticket.consume((ctx.constant(1),) * 2, b"x" * 32)
    request = ticket.consume((ctx.constant(1),) * 2, EPOCH)
    for bad in (replace(request, epoch=b"x" * 32), replace(request, token_id=b"x" * 16),
                replace(request, context=replace(ctx, t=17)),
                replace(request, delta=((ctx.t,) * ctx.n,) * ctx.rank)):
        with pytest.raises(ValueError, match="mismatch"):
            masked.evaluate_online(converted, offline, bad)
    # A failed submission does not make its secret mask reusable.
    with pytest.raises(RuntimeError, match="consumed"):
        ticket.consume((ctx.constant(-1),) * 2, EPOCH)
    huge = replace(offline, results=tuple(replace(c, phase_bound=ctx.q) for c in offline.results))
    with pytest.raises(ValueError, match="bound"):
        masked.evaluate_online(converted, huge, request)


def test_expansion_binds_context_epoch_and_token():
    ctx = matrix.Context()
    baseline = masked.expand_mask(ctx, SEED, EPOCH, TOKEN)
    assert masked.expand_mask(ctx, SEED, b"x" * 32, TOKEN) != baseline
    assert masked.expand_mask(ctx, SEED, EPOCH, b"x" * 16) != baseline
    assert masked.expand_mask(replace(ctx, t=17), SEED, EPOCH, TOKEN) != baseline
    with pytest.raises(ValueError):
        masked.expand_mask(ctx, b"short", EPOCH, TOKEN)


def test_constant_masks_reject_queries_outside_their_space():
    ctx, rng, secret, out_secret, index, converted = fixture()
    ticket, packet = masked.prepare(ctx, secret, out_secret, SEED, EPOCH, TOKEN, rng, mask_space="constant")
    outside = (ctx.poly([0, 1, 0, 0]), ctx.constant(1))
    with pytest.raises(ValueError, match="subspace"):
        ticket.consume(outside, EPOCH)
    request = ticket.consume((ctx.constant(1),) * ctx.rank, EPOCH)
    answer = masked.evaluate_offline(ctx, index, packet)
    bad_delta = replace(request, delta=((0, 1, 0, 0), (0, 0, 0, 0)))
    with pytest.raises(ValueError, match="subspace"):
        masked.evaluate_online(converted, answer, bad_delta)
    with pytest.raises(ValueError, match="space"):
        bad_delta.coefficient_body()
    with pytest.raises(ValueError, match="mismatch"):
        masked.evaluate_online(converted, answer, replace(request, mask_space="full"))
    # A mask in span(e0) hides shifts along e0, but reveals the other coordinate.
    t = 3
    for w in range(t):
        assert {(w - r) % t for r in range(t)} == set(range(t))
    assert {(r, 0) for r in range(t)}.isdisjoint({(r, 1) for r in range(t)})


def test_constant_online_path_uses_no_polynomial_products(monkeypatch):
    ctx, rng, secret, out_secret, index, converted = fixture()
    ticket, packet = masked.prepare(ctx, secret, out_secret, SEED, EPOCH, TOKEN, rng, mask_space="constant")
    answer = masked.evaluate_offline(ctx, index, packet)
    request = ticket.consume((ctx.constant(1), ctx.constant(-1)), EPOCH)

    def forbidden(*args):
        raise AssertionError("Constant query should only scale coefficients")

    with monkeypatch.context() as patch:
        patch.setattr(matrix.Context, "mul", forbidden)
        results = masked.evaluate_online(converted, answer, request)
    assert len(results) == len(converted.entries)
    for cipher in results:
        scores = matrix.simd_decode(ctx, matrix.decrypt(ctx, cipher, out_secret))
        assert [(s + 1) % ctx.t for s in scores] == [(w ^ 2).bit_count() for w in range(4)]
