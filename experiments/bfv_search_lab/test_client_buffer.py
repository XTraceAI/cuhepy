"""Dynamic coverage/IDs and complete immutable encrypted-base validation."""

from contextlib import closing
from dataclasses import replace
import secrets

import pytest

from experiments.bfv_search_lab import client_buffer as buffer
from experiments.bfv_search_lab import client_delta as delta
from experiments.bfv_search_lab import coordinate_factory as coordinates
from experiments.bfv_search_lab import crt_linear_check as checks
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import verification_lifetime as lifetime
from experiments.bfv_search_lab.test_client_delta import plan


def check(snapshot, base, current, word):
    result = snapshot.correct(base.workload.expected(word), word, epoch=snapshot.epoch, verified_base_epoch=snapshot.base_epoch)
    assert set(result.ids) == set(current) and len(result.ids) == len(current)
    assert dict(zip(result.ids, result.scores, strict=True)) == {i: (row ^ word).bit_count() for i, row in current.items()}
    assert result.top3 == tuple(sorted(((row ^ word).bit_count(), i) for i, row in current.items())[:3])


def test_arbitrary_private_edits_inserts_deletes_and_empty_exact_results():
    p = plan()
    ledger = buffer.Ledger(p, secrets.token_bytes(32))
    current = dict(zip(p.ids, p.workload.rows, strict=True))
    old = ledger.snapshot
    for mutation in (dict(edits={99: 15}, inserts={8: 15, 0: 15}, delete_ids=(1,)),
                     dict(edits={8: 0, 5: 9}, inserts={100: 7}, delete_ids=(33,)),
                     dict(edits={99: 0}, delete_ids=(0, 8)),
                     dict(delete_ids=(99, 5, 100))):
        ledger.transact(**mutation)
        current.update(mutation.get("edits", {}))
        current.update(mutation.get("inserts", {}))
        for identifier in mutation.get("delete_ids", ()):
            del current[identifier]
        for word in range(16):
            check(ledger.snapshot, p, current, word)
    assert not current and ledger.snapshot.correct(p.workload.expected(0), 0, epoch=ledger.snapshot.epoch,
                                                   verified_base_epoch=ledger.base_epoch) == buffer.Result((), (), ())
    check(old, p, dict(zip(p.ids, p.workload.rows, strict=True)), 7)
    assert "inserted" not in repr(ledger.snapshot) and ledger.owner_historical_id_body_bytes_model == 7 * 8


def test_invalid_transactions_never_commit_or_reuse_any_historical_id():
    p = plan()
    ledger = buffer.Ledger(p, secrets.token_bytes(32))
    ledger.transact(inserts={8: 15}, delete_ids=(1,))
    ledger.transact(delete_ids=(8,))
    before = ledger.snapshot, dict(ledger._rows), set(ledger._ever_ids)
    for mutation in ({}, dict(inserts={1: 1}), dict(inserts={8: 3}), dict(inserts={99: 0}),
                     dict(edits={8: 3}), dict(edits={True: 0}), dict(delete_ids=(5, 5)),
                     dict(delete_ids=(88,)), dict(edits={99: 1}, delete_ids=(99,)),
                     dict(inserts={200: 16}), dict(delete_ids=[5])):
        with pytest.raises(ValueError, match="transaction"):
            ledger.transact(**mutation)
        assert (ledger.snapshot, ledger._rows, ledger._ever_ids) == before


def test_snapshot_and_full_base_input_checks():
    p = plan()
    ledger = buffer.Ledger(p, secrets.token_bytes(32))
    s = ledger.snapshot
    for scores, word, epoch, base_epoch in ((p.workload.expected(0), 0, secrets.token_bytes(32), s.base_epoch),
                                         (p.workload.expected(0), 0, s.epoch, secrets.token_bytes(32)),
                                         ((0, 0, 0), 0, s.epoch, s.base_epoch),
                                         ((0, 0, 0, -1), 0, s.epoch, s.base_epoch),
                                         (p.workload.expected(0), 16, s.epoch, s.base_epoch)):
        with pytest.raises(ValueError):
            s.correct(scores, word, epoch=epoch, verified_base_epoch=base_epoch)
    for wrong in (replace(s, deleted_positions=(1, 1)), replace(s, inserted=((99, 1),)),
                  replace(s, inserted=((88, 16),)), replace(s, inserted=((8, 1), (8, 2))),
                  replace(s, deleted_positions=(0,), patches=(delta.Patch(0, 1, 0),))):
        with pytest.raises(ValueError):
            wrong.validate()


def test_mutations_do_not_change_encrypted_geometry_or_bypass_complete_gate():
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    p = plan()
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    groups = [[list(row) for row in g] for g in p.groups]
    epoch = secrets.token_bytes(32)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(p.query_space, groups, epoch, client)
        factory = coordinates.Factory(p.query_space, groups, epoch, client, budget=16)
        server, phase = native.NativeIndex(index, pk), audit.Audit(index, pk, sk)
        budget = lifetime.AttemptBudget(16)
        checker = checks.EpochCheck(index, pk, budget=16)
        gate = budget.bind(checker)
        ledger = buffer.Ledger(p, epoch)
        current = dict(zip(p.ids, p.workload.rows, strict=True))
        word = 0
        for revision in range(8):
            identifier, row = 1000 + revision, 15 ^ revision
            deletes = (p.ids[revision],) if revision < len(p.ids) else ()
            ledger.transact(inserts={identifier: row}, delete_ids=deletes)
            current[identifier] = row
            for old in deletes:
                del current[old]
            token, answer, _ = factory.prepare(revision.to_bytes(16, "little"))
            gate.prepare_answer(answer)
            values, offsets = oracle.query(ledger.snapshot.base, word)
            request = token.consume(values, epoch)
            output = server.evaluate(answer, request)
            assert output == masked.evaluate(index, answer, request, pk) and gate.verify_once(request, output)
            assert phase.measure(request, answer, output)["all_integer_phase_coefficients_match_ciphertext"]
            base = oracle.decode(ledger.snapshot.base, [bgv.decrypt(c, pk, sk) for c in output], offsets)
            result = ledger.snapshot.correct(base, word, epoch=ledger.snapshot.epoch, verified_base_epoch=server.epoch)
            assert dict(zip(result.ids, result.scores, strict=True)) == {i: (row ^ word).bit_count() for i, row in current.items()}
            assert result.top3 == tuple(sorted(((row ^ word).bit_count(), i) for i, row in current.items())[:3])
            with pytest.raises(RuntimeError, match="consumed"):
                token.consume(values, epoch)
            word = (result.top3[0][1] + revision) % 16
        assert budget.used == 8 and server.epoch == checker.epoch == ledger.base_epoch == epoch
