"""Frozen-map edits, pending-pad transitions and complete encrypted controls."""

from contextlib import closing
from dataclasses import replace

import pytest

from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import representation_updates as updates
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def plan():
    w = Workload(tuple(range(8)), tuple(range(8)), 4)
    choice = oracle.choices(w, oracle.median_tree(w, 0), 17)[1]
    return oracle.compile_choice(w, choice, Profile(32, 17, eta=1), (1,))


@pytest.mark.parametrize("method", ("sparse_delta", "full_reencrypt"))
@pytest.mark.parametrize("arithmetic", ("python", "numpy"))
def test_pending_repairs_preserve_all_scores_and_consumed_pads_never_return(method, arithmetic):
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    p = plan()
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        pool = updates.RepairPool(p, client, arithmetic=arithmetic)
        assert pool.coordinate_array_bytes == (24 if arithmetic == "numpy" else 0)
        tokens = [pool.prepare(i.to_bytes(16, "little")) for i in range(20)]
        word = 0
        for revision, edits in enumerate(({0: 3}, {7: 2}, {3: 0})):
            old_epoch = pool.index.epoch
            consumed = tokens[revision]
            values, _ = oracle.query(pool.plan.client_view(), word)
            old_request = consumed.consume(values, old_epoch)
            assert "_pad=" not in repr(consumed)
            consumed_answer = consumed.answer
            old_index = pool.index
            report = pool.edit(edits, method=method)
            assert pool.index.epoch != old_epoch
            assert report["repaired_unused_tokens"] == 19 - 2 * revision
            assert report["owner_arithmetic"] == arithmetic
            assert consumed.answer is consumed_answer and consumed._pad is None
            with pytest.raises(RuntimeError, match="consumed"):
                consumed.consume(values, pool.index.epoch)
            view = pool.plan.client_view()
            gate = check.EpochCheck(pool.index, pk, rounds=fields.rounds(int(pk.q)), budget=64)
            token = tokens[19 - revision]
            gate.prepare_answer(token.answer)
            values, offsets = oracle.query(view, word)
            with pytest.raises(ValueError, match="Stale"):
                token.consume(values, old_epoch)
            request = token.consume(values, pool.index.epoch)
            result = native.NativeIndex(pool.index, pk).evaluate(token.answer, request)
            assert result == masked.evaluate(pool.index, token.answer, request, pk)
            assert gate.verify_once(request, result)
            actual = oracle.decode(view, [bgv.decrypt(c, pk, sk) for c in result], offsets)
            assert actual == pool.plan.workload.expected(word) == oracle.exact_scores(pool.plan, word)
            with pytest.raises(ValueError, match="mismatch"):
                masked.evaluate(old_index, consumed_answer, request, pk)
            word = (pool.plan.workload.top_k(actual)[0][1] + revision + 1) % 16
            # An old request cannot be used against the new ciphertext target.
            with pytest.raises(ValueError, match="mismatch"):
                masked.evaluate(pool.index, consumed_answer, old_request, pk)


def test_outside_frozen_span_and_phase_exhaustion_leave_epoch_and_pads_unchanged():
    p = plan()
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        pool = updates.RepairPool(p, client)
        token = pool.prepare(bytes(16))
        before, pad = pool.index, token._pad
        with pytest.raises(ValueError, match="outside"):
            pool.edit({0: 8})  # The fourth bit is outside the old rank-3 affine span.
        assert pool.index is before and token._pad == pad
        cipher = replace(pool.index.columns[0][0], phase_bound=int(pk.q // 2) - 1)
        pool.index = replace(pool.index, columns=((cipher,), *pool.index.columns[1:]))
        high_index, answer = pool.index, token.answer
        with pytest.raises(ValueError, match="phase budget"):
            pool.edit({0: 1})
        assert pool.index is high_index and token.answer is answer and token._pad == pad
        pool.edit({0: 1}, method="full_reencrypt")  # Full rebase refreshes noise.
        assert pool.index is not high_index and token._pad == pad


def test_reusing_an_exposed_pad_would_reveal_query_difference():
    t, pad = 17, (4, 9, 2)
    a, b = (1, 0, 1), (0, 1, 1)
    delta_a = tuple((w - r) % t for w, r in zip(a, pad, strict=True))
    delta_b = tuple((w - r) % t for w, r in zip(b, pad, strict=True))
    assert tuple((x - y) % t for x, y in zip(delta_a, delta_b, strict=True)) == tuple((x - y) % t for x, y in zip(a, b, strict=True))


def test_repair_phase_oracle_covers_accumulated_input_and_answer_bounds():
    p = plan()
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        pool = updates.RepairPool(p, client)
        token = pool.prepare(bytes(16))
        for edit in ({0: 1}, {0: 2}, {0: 3}):
            pool.edit(edit)
        bound = max(c.phase_bound for c in token.answer.ciphertexts)
        old_fresh_oracle = audit.Audit(pool.index, pk, sk)
        current_oracle = audit.Audit(pool.index, pk, sk, maximum_answer_bound=bound)
        assert current_oracle.modulus > old_fresh_oracle.modulus
        values, _ = oracle.query(pool.plan.client_view(), 0)
        request = token.consume(values, pool.index.epoch)
        output = masked.evaluate(pool.index, token.answer, request, pk)
        with pytest.raises(ValueError, match="declared phase budget"):
            old_fresh_oracle.measure(request, token.answer, output)
        measured = current_oracle.measure(request, token.answer, output)
        assert measured["all_integer_phase_coefficients_match_ciphertext"]
        assert measured["maximum_unreduced_integer_phase"] <= measured["maximum_deterministic_response_bound"]


def test_vectorized_failed_update_is_atomic_and_failed_preparation_burns_id(monkeypatch):
    p = plan()
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        pool = updates.RepairPool(p, client, arithmetic="numpy")
        token = pool.prepare(bytes(16))
        before = pool.index, pool.plan, pool._coordinates, token.answer, token._pad
        def fail(*args):
            raise ValueError("injected encryption failure")
        monkeypatch.setattr(client, "encrypt", fail)
        with pytest.raises(ValueError, match="injected"):
            pool.edit({0: 3, 7: 2})
        assert (pool.index, pool.plan, pool._coordinates, token.answer, token._pad) == before
        identifier = (1).to_bytes(16, "little")
        with pytest.raises(ValueError, match="injected"):
            pool.prepare(identifier)
        with pytest.raises(ValueError, match="Duplicate"):
            pool.prepare(identifier)
        assert identifier in pool._issued and identifier not in pool._tokens


def test_batched_sparse_products_include_negative_and_zero_deltas():
    p = plan()
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        pool = updates.RepairPool(p, client, arithmetic="numpy")
        changes = ((0, 0, (1, -1, 0)), (0, 7, (-2, 0, 2)), (0, 1, (0, 0, 0)))
        pads = ((16, 16, 16), (0, 1, 16), (8, 9, 10))
        actual = pool._sparse_scores(changes, pads)
        for ordinal, pad in enumerate(pads):
            for _, row, difference in changes:
                assert actual[ordinal][0][row] == sum(a * b for a, b in zip(difference, pad, strict=True)) % 17
        assert pool._sparse_scores(changes, ()) == []
