"""Exact deltas, epoch binding and a genuine encrypted base/one-use gate."""

from contextlib import closing
from dataclasses import replace
import secrets

import pytest

from experiments.bfv_search_lab import client_delta as delta
from experiments.bfv_search_lab import coordinate_factory as coordinates
from experiments.bfv_search_lab import crt_linear_check as checks
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def plan():
    w = Workload((0, 1, 2, 3), (99, 1, 5, 33), 4)
    choice = oracle.choices(w, oracle.median_tree(w, 0), 17)[1]
    return oracle.compile_choice(w, choice, Profile(32, 17, eta=1), (1,))


def test_exhaustive_corrections_use_base_difference_across_repeated_edits():
    p = plan()
    ledger = delta.Ledger(p, secrets.token_bytes(32))
    old = ledger.snapshot
    for edits in ({99: 15, 1: 8}, {99: 7, 5: 13}, {99: 0, 1: 1, 5: 2}):
        ledger.edit(edits)
        for word in range(16):
            expected = ledger.workload.expected(word)
            actual = ledger.snapshot.correct(p.workload.expected(word), word, epoch=ledger.snapshot.epoch)
            assert actual == expected
            assert ledger.workload.top_k(actual) == ledger.workload.top_k(expected)
        with pytest.raises(ValueError, match="Stale"):
            ledger.snapshot.correct(p.workload.expected(0), 0, epoch=old.epoch)
    assert not ledger.snapshot.patches and ledger.snapshot.private_body_bytes == 64
    assert old.correct(p.workload.expected(0), 0, epoch=old.epoch) == p.workload.expected(0)
    assert "positive" not in repr(ledger.snapshot)


def test_invalid_edits_and_overlapping_masks_reject_without_commit():
    p = plan()
    ledger = delta.Ledger(p, secrets.token_bytes(32))
    before = ledger.snapshot, ledger.workload
    for edits in ({88: 1}, {99: -1}, {99: 16}, {True: 1}, {}):
        with pytest.raises(ValueError, match="fixed-ID"):
            ledger.edit(edits)
        assert (ledger.snapshot, ledger.workload) == before
    with pytest.raises(ValueError, match="snapshot"):
        replace(ledger.snapshot, patches=(delta.Patch(0, 1, 1),)).validate()


def test_encrypted_base_remains_frozen_with_arbitrary_out_of_span_edits():
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    p = plan()
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    groups = [[list(row) for row in g] for g in p.groups]
    epoch = secrets.token_bytes(32)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(p.query_space, groups, epoch, client)
        producer = coordinates.Factory(p.query_space, groups, epoch, client, budget=16)
        server = native.NativeIndex(index, pk)
        gate = checks.EpochCheck(index, pk, budget=16)
        phase = audit.Audit(index, pk, sk)
        ledger = delta.Ledger(p, epoch)
        word = 0
        for revision in range(8):
            ledger.edit({99: 15 ^ revision, 1: 8 | revision})  # Old rank-2 span does not contain these.
            ticket, answer, _ = producer.prepare(revision.to_bytes(16, "little"))
            gate.prepare_answer(answer)
            values, offsets = oracle.query(ledger.snapshot.base, word)
            request = ticket.consume(values, epoch)
            output = server.evaluate(answer, request)
            assert output == masked.evaluate(index, answer, request, pk)
            assert gate.verify_once(request, output)
            assert phase.measure(request, answer, output)["all_integer_phase_coefficients_match_ciphertext"]
            base_scores = oracle.decode(ledger.snapshot.base, [bgv.decrypt(c, pk, sk) for c in output], offsets)
            scores = ledger.snapshot.correct(base_scores, word, epoch=ledger.snapshot.epoch)
            assert scores == ledger.workload.expected(word)
            with pytest.raises(RuntimeError, match="consumed"):
                ticket.consume(values, epoch)
            word = (ledger.workload.top_k(scores)[0][1] + revision) % 16
        assert server.epoch == gate.epoch == ledger.base_epoch == epoch
