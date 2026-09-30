"""E41 complete layouts against exhaustive binary and integer-ring oracles."""

from contextlib import closing
from dataclasses import replace
import itertools

import pytest

from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.representation_contract import Budget, Profile, Workload


def fixture():
    return Workload((0, 1, 2, 3, 8, 9, 10, 11), (8, 4, 9, 2, 100, 50, 30, 20), 4)


def test_all_tiny_representations_geometries_and_binary_queries():
    w = fixture()
    plans, rejected = oracle.enumerate_plans(w, oracle.median_tree(w),
                                            (Profile(8, 17, eta=1), Profile(16, 17, eta=1), Profile(32, 17, eta=1)),
                                            slots=(1, 2, 4), limit=3000)
    assert plans and rejected  # Geometry restrictions are exercised, not bypassed.
    for plan in plans:
        for query in range(1 << w.dimension):
            expected = tuple((row ^ query).bit_count() for row in w.rows)
            assert oracle.exact_scores(plan, query) == expected
        # Independent pigeonhole lower bound, before CRT-specific restrictions.
        assert plan.resources.replies >= (len(w.rows) + plan.profile.n - 1) // plan.profile.n
        assert sum(len(b.positions) for b in plan.candidate.blocks) == len(w.rows)
        assert all(len(b.positions) <= plan.resources.replies * leaf.degree
                   for b, leaf in zip(plan.candidate.blocks, plan.candidate.layout.context.leaves, strict=True))


def test_positive_compositions_equal_independent_small_cartesian_search():
    for total in (1, 2, 4, 8):
        for groups in range(1, min(4, total) + 1):
            expected = {x for x in itertools.product(range(1, total + 1), repeat=groups) if sum(x) == total}
            assert set(oracle.allocations(total, groups)) == expected
    with pytest.raises(ValueError, match="work limit"):
        oracle.allocations(64, 32)
    with pytest.raises(ValueError, match="work limit"):
        oracle.enumerate_plans(fixture(), oracle.median_tree(fixture()), (Profile(32, 17),), limit=1)


def test_online_view_drops_plaintext_and_stable_ids_resolve_ties(monkeypatch):
    w = Workload((0, 0, 1, 1), (100, 5, 50, 2), 1)
    choice = oracle.choices(w, oracle.median_tree(w), 17)[1]
    plan = oracle.compile_choice(w, choice, Profile(16, 17, eta=1), (1,))
    view = plan.client_view()
    assert not hasattr(view, "workload") and not hasattr(view, "groups")
    assert w.top_k(w.expected(0)) == ((0, 5), (0, 100), (1, 2))
    # Query compilation must never scan the enrolled rows for an expected result.
    monkeypatch.setattr(Workload, "expected", lambda *args: pytest.fail("plaintext scan in query"))
    assert oracle.query(view, 0) == oracle.query(plan, 0)
    assert replace(w, ids=(5, 100, 50, 2)).digest != w.digest
    with pytest.raises(ValueError, match="binary dimension"):
        oracle.query(view, True)


@pytest.mark.parametrize("mutation", ("duplicate_id", "missing", "duplicate_row_position", "field", "unsupported"))
def test_invalid_or_stale_contracts(mutation):
    w = fixture()
    choice = oracle.choices(w, oracle.median_tree(w), 17)[1]
    profile = Profile(32, 17, eta=1)
    if mutation == "duplicate_id":
        w = replace(w, ids=(8,) * 8)
    elif mutation == "missing":
        choice = replace(choice, pieces=(replace(choice.pieces[0], positions=(0, 1)),))
    elif mutation == "duplicate_row_position":
        choice = replace(choice, pieces=(replace(choice.pieces[0], positions=(0,) * 8),))
    elif mutation == "field":
        profile = replace(profile, prime=97)
    else:
        with pytest.raises(ValueError, match="production assurance"):
            profile.require_production()
        return
    with pytest.raises(ValueError):
        oracle.compile_choice(w, choice, profile, (1,))


def test_joint_private_form_sharing_and_budget_are_explicit():
    w = fixture()
    choice = oracle.choices(w, oracle.median_tree(w, 1), 17)[-1]
    plans = [oracle.compile_choice(w, choice, Profile(32, 17, eta=1), (1, 1), equal_forms=share)
             for share in (False, True)]
    assert plans[1].resources.query_coordinates < plans[0].resources.query_coordinates
    assert plans[1].binding != plans[0].binding
    assert Budget(max_replies=0).rejection(plans[0].resources) == ("replies exceeds budget",)
    for q in range(16):
        assert oracle.exact_scores(plans[0], q) == oracle.exact_scores(plans[1], q) == w.expected(q)


def test_adaptive_encrypted_response_is_checked_then_matches_integer_oracle():
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    w = fixture()
    choice = oracle.choices(w, oracle.median_tree(w, 1), 17)[-1]
    plan = oracle.compile_choice(w, choice, Profile(32, 17, eta=1), (1, 1))
    view = plan.client_view()
    pk, sk = masked.key_gen(plan.query_space, q_bits=32, eta=1)
    epoch = bytes.fromhex(plan.binding)
    with closing(owner.OwnerClient(pk, sk)) as client:
        groups = [[list(row) for row in g] for g in plan.groups]
        index, _ = masked.enroll(plan.query_space, groups, epoch, client)
        evaluator, phase = native.NativeIndex(index, pk), audit.Audit(index, pk, sk)
        gate = check.EpochCheck(index, pk, rounds=fields.rounds(int(pk.q)), budget=32)
        pool = [masked.prepare(plan.query_space, groups, epoch, i.to_bytes(16, "little"), bytes([i]) * 32, client)
                for i in range(17)]
        for _, answer, _ in pool:
            gate.prepare_answer(answer)
        word = 0
        for i, (ticket, answer, _) in enumerate(pool):
            weights, offsets = oracle.query(view, word)
            request = ticket.consume(weights, epoch)
            result = evaluator.evaluate(answer, request)
            assert result == masked.evaluate(index, answer, request, pk)
            assert gate.verify_once(request, result)
            assert phase.measure(request, answer, result)["all_integer_phase_coefficients_match_ciphertext"]
            actual = oracle.decode(view, [bgv.decrypt(c, pk, sk) for c in result], offsets)
            assert actual == w.expected(word) == oracle.exact_scores(plan, word)
            word = (w.top_k(actual)[0][1] + i) % 16  # Chosen after authenticated previous output.
            with pytest.raises(RuntimeError, match="consumed"):
                ticket.consume(weights, epoch)
