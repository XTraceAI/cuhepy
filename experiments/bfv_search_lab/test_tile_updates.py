"""Selective refresh must preserve full scores, untouched noise and spent pads."""

from contextlib import closing
from dataclasses import replace

import pytest

from experiments.bfv_search_lab import coordinate_factory
from experiments.bfv_search_lab import crt_linear_check as checks
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import representation_updates as updates
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def plan():
    workload = Workload(tuple(i % 8 for i in range(80)), tuple(100 + i for i in range(80)), 4)
    choice = oracle.choices(workload, oracle.median_tree(workload, 0), 17)[1]
    return oracle.compile_choice(workload, choice, Profile(32, 17, eta=1), (1,))


@pytest.mark.parametrize("arithmetic", ("python", "numpy"))
def test_selective_tiles_preserve_all_scores_and_never_resurrect_spent_pad(arithmetic):
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    p = plan()
    assert p.query_space.layout.cost.response_ciphertexts == 3
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        pool = updates.RepairPool(p, client, arithmetic=arithmetic)
        tokens = [pool.prepare(i.to_bytes(16, "little")) for i in range(6)]
        values, _ = oracle.query(p.client_view(), 0)
        tokens[0].consume(values, pool.index.epoch)
        consumed = tokens[0].answer
        old_index, old_answer = pool.index, tokens[1].answer
        report = pool.edit({100: 3, 164: 5}, method="tile_reencrypt")
        assert report["public_reply_tiles_rebuilt"] == (0, 2)
        assert report["ciphertexts_freshly_encrypted"] == (p.query_space.columns + 5) * 2
        for old, new in zip(old_index.columns, pool.index.columns, strict=True):
            assert new[1] is old[1] and new[0] is not old[0] and new[2] is not old[2]
        assert tokens[1].answer.ciphertexts[1] is old_answer.ciphertexts[1]
        assert tokens[0]._pad is None and tokens[0].answer is consumed
        with pytest.raises(RuntimeError, match="consumed"):
            tokens[0].consume(values, pool.index.epoch)
        gate = checks.EpochCheck(pool.index, pk, rounds=5)
        phase = audit.Audit(pool.index, pk, sk)
        evaluator = native.NativeIndex(pool.index, pk)
        for token, word in zip(tokens[1:], (0, 1, 7, 8, 15), strict=True):
            gate.prepare_answer(token.answer)
            values, offsets = oracle.query(pool.plan.client_view(), word)
            with pytest.raises(ValueError, match="Stale"):
                token.consume(values, old_index.epoch)
            request = token.consume(values, pool.index.epoch)
            output = evaluator.evaluate(token.answer, request)
            assert output == masked.evaluate(pool.index, token.answer, request, pk)
            assert gate.verify_once(request, output)
            scores = oracle.decode(pool.plan.client_view(), [bgv.decrypt(c, pk, sk) for c in output], offsets)
            assert scores == pool.plan.workload.expected(word)
            assert pool.plan.workload.top_k(scores) == pool.plan.workload.top_k(pool.plan.workload.expected(word))
            assert phase.measure(request, token.answer, output)["all_integer_phase_coefficients_match_ciphertext"]


def test_untouched_tile_phase_age_is_not_refreshed_and_failures_are_atomic(monkeypatch):
    p = plan()
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        pool = updates.RepairPool(p, client, arithmetic="numpy")
        token = pool.prepare(bytes(16))
        old = pool.index.columns[0]
        high = replace(old[1], phase_bound=int(pk.q // 2) - 1)
        pool.index = replace(pool.index, columns=((old[0], high, old[2]), *pool.index.columns[1:]))
        before = pool.index, pool.plan, pool._coordinates, token.answer, token._pad
        with pytest.raises(ValueError, match="phase budget"):
            pool.edit({100: 3}, method="tile_reencrypt")
        assert (pool.index, pool.plan, pool._coordinates, token.answer, token._pad) == before
        pool.edit({132: 3}, method="tile_reencrypt")  # The old high-age tile itself is refreshed.
        before = pool.index, pool.plan, pool._coordinates, token.answer, token._pad
        def fail(*args):
            raise ValueError("injected tile encryption failure")
        monkeypatch.setattr(client, "encrypt", fail)
        with pytest.raises(ValueError, match="injected"):
            pool.edit({100: 3, 164: 5}, method="tile_reencrypt")
        assert (pool.index, pool.plan, pool._coordinates, token.answer, token._pad) == before


def test_selected_products_and_polynomials_match_full_reference():
    p = plan()
    s, groups = p.query_space, [[list(row) for row in g] for g in p.groups]
    pads = ((0, 1, 16), (16, 9, 2))
    factory = coordinate_factory.Coordinates(s, groups)
    full, selected = factory.scores_many(pads), factory.scores_many(pads, replies=(0, 2))
    for complete, subset in zip(full, selected, strict=True):
        assert subset[0][:32] == complete[0][:32]
        assert subset[0][32:64] == [0] * 32
        assert subset[0][64:] == complete[0][64:]
        whole = space.outputs(s.layout, complete)
        assert space.outputs(s.layout, subset, replies=(0, 2)) == [whole[0], whole[2]]
    for invalid in ((), (1, 0), (0, 0), (True,), ([0],), (3,)):
        with pytest.raises(ValueError, match="tile selection"):
            space.reply_selection(s.layout, invalid)
