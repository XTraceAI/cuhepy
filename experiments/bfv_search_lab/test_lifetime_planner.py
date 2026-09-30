"""Hindsight DP, exhaustive schedules, rank-state trap and mandatory rebasing."""

from contextlib import closing
from dataclasses import replace
import random
import secrets

import pytest

from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import crt_linear_check as checks
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import dyadic_crt as crt
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import lifetime_planner as life
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import representation_updates as updates
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def small_problem():
    w = Workload((0, 1), (100, 9), 3)
    entries = tuple(life.reserve(w, directions, 17, name=name) for name, directions in (
        ("fit", ()), ("reserve-bit1", (1,)), ("reserve-bit2", (2,)), ("reserve-both", (1, 2))))
    trace = life.Trace((w, replace(w, rows=(0, 3)), replace(w, rows=(0, 7))), (1, 2, 1), 6)
    return life.Problem(trace, entries, Profile(32, 17, eta=1))


def test_exact_dp_equals_complete_schedule_frontier_and_all_query_scores():
    p = small_problem()
    expected, counts = life.exhaustive(p)
    actual, dp_counts = life.dynamic_program(p)
    assert {x.cost for x in actual} == {x.cost for x in expected}
    assert counts[-1] > dp_counts[-1]
    for revision in p.plans:
        for plan in revision:
            if plan is None:
                continue
            for word in range(8):
                values, offsets = oracle.query(plan.client_view(), word)
                field_scores = space.scores(plan.query_space, [[list(row) for row in g] for g in plan.groups], values)
                plain = [[x % 17 for x in poly] for poly in space.outputs(plan.candidate.layout, field_scores)]
                assert oracle.decode(plan.client_view(), plain, offsets) == plan.workload.expected(word)
                assert crt.unpack(plan.candidate.layout, plain) == field_scores


def test_same_rank_and_static_vector_do_not_determine_future_span():
    p = small_problem()
    left, right = p.plans[0][1:3]
    assert left.maps[0].rank == right.maps[0].rank == 2
    assert left.resources.static_vector == right.resources.static_vector
    assert p.plans[1][1] is not None
    assert p.plans[1][2] is None
    # No rank-only merge may silently identify these boundary states.
    start = {x.entry: x for x in p.starts()}
    assert any(a.actions[-1][1] == "repair" and a.entry == 1 for a in p.successors(1, start[1]))
    assert not any(a.entry == 2 for a in p.successors(1, start[2]))


def test_all_initial_tokens_including_unspent_are_charged_and_no_consume_reuse():
    p = small_problem()
    one = life.Problem(replace(p.trace, revisions=(p.trace.revisions[0],), queries=(1,)), p.entries, p.profile)
    first = one.starts()[0]
    plan = one.plans[0][0]
    assert first.cost.fresh_ciphertext_coefficients == 2 * p.profile.n * plan.resources.replies * (plan.resources.columns + 6)
    assert first.cost.private_dot_terms == 6 * sum(len(g) * f for g, f in zip(plan.groups, plan.candidate.layout.features, strict=True))
    assert first.cost.response_body_bytes == plan.resources.response_body_bytes
    second = p._cost(1, 1, "repair")
    assert second.fresh_ciphertext_coefficients == 2 * p.profile.n * (p.plans[1][1].resources.columns + 5)
    with pytest.raises(ValueError, match="token trace"):
        life.Problem(replace(p.trace, queries=(1, 2, 4)), p.entries, p.profile)


def test_universal_accumulated_noise_forces_refresh_before_second_use():
    rows = (0, *(1 << i for i in range(32)))
    w = Workload(rows, tuple(range(33)), 32)
    raw = oracle.Choice((oracle.Piece("", tuple(range(33)), oracle.raw_map(32, 1153), "raw"),))
    entries = (life.Entry("raw", raw, (1,)),)
    changed = replace(w, rows=rows[:-1] + ((1 << 31) | (1 << 30),))
    p = life.Problem(life.Trace((w, changed), (1, 1), 2), entries, Profile(128, 1153, eta=64))
    assert p.plans[0][0] is not None
    assert 2 * p.plans[0][0].resources.phase_bound < p.profile.q
    assert 4 * p.plans[0][0].resources.phase_bound >= p.profile.q
    result, _ = life.dynamic_program(p)
    assert result and all(x.actions[-1] == ("raw", "refresh", 1) for x in result)


def test_many_bounded_random_traces_match_unpruned_enumeration():
    rng = random.Random(5201)
    for _ in range(12):
        w = Workload((0, 1, 0, 1), (8, 2, 11, 13), 3)
        entries = tuple(life.reserve(w, bits, 17, name=str(i)) for i, bits in enumerate(((), (1,), (2,), (1, 2))))
        revisions = (w, *(replace(w, rows=tuple(rng.randrange(8) for _ in w.rows)) for _ in range(2)))
        p = life.Problem(life.Trace(revisions, (1, 1, 1), 4), entries, Profile(32, 17, eta=1))
        a, _ = life.dynamic_program(p)
        b, _ = life.exhaustive(p)
        assert {x.cost for x in a} == {x.cost for x in b}


def test_reserved_zero_column_supports_real_encrypted_repair_and_every_token():
    p = small_problem().plans[0][1]
    # Reserved pivot starts unused, but its encrypted column/pads still exist.
    assert all(row[1] == 0 for group in p.groups for row in group)
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        pool = updates.RepairPool(p, client)
        tokens = [pool.prepare(i.to_bytes(16, "little")) for i in range(6)]
        word = 0
        for revision in range(3):
            if revision:
                rows = (0, 3) if revision == 1 else (2, 1)
                pool.edit(dict(zip(p.ids, rows, strict=True)))
            phase = audit.Audit(pool.index, pk, sk, maximum_answer_bound=max(
                c.phase_bound for token in tokens if token._pad is not None for c in token.answer.ciphertexts))
            server, gate = native.NativeIndex(pool.index, pk), checks.EpochCheck(pool.index, pk, budget=6)
            for token in tokens[2 * revision:2 * revision + 2]:
                gate.prepare_answer(token.answer)
                values, offsets = oracle.query(pool.plan.client_view(), word)
                request = token.consume(values, pool.index.epoch)
                result = server.evaluate(token.answer, request)
                assert result == masked.evaluate(pool.index, token.answer, request, pk)
                assert gate.verify_once(request, result)
                assert phase.measure(request, token.answer, result)["all_integer_phase_coefficients_match_ciphertext"]
                scores = oracle.decode(pool.plan.client_view(), [bgv.decrypt(c, pk, sk) for c in result], offsets)
                assert scores == pool.plan.workload.expected(word)
                word = (pool.plan.workload.top_k(scores)[0][1] + revision) % 8
        assert all(token._pad is None for token in tokens)
        before = pool.index
        with pytest.raises(ValueError, match="outside"):
            pool.edit({p.ids[1]: 4})  # Unreserved bit 2 must not become plausible data.
        assert pool.index == before
        with pytest.raises(RuntimeError, match="consumed"):
            tokens[0].consume(oracle.query(pool.plan.client_view(), 0)[0], pool.index.epoch)


def test_work_limit_rejects_instead_of_silently_beaming():
    p = small_problem()
    for method in (life.dynamic_program, life.exhaustive):
        with pytest.raises(ValueError, match="work limit"):
            method(p, work_limit=1)
