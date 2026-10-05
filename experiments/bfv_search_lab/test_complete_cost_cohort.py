"""Public source/accounting units; opaque packets, no valid HE or native work.

Only the two existing Q77 public UNIT-ONLY signing contexts are reconstructed.
All key/group bytes below are public grammar fixtures, not a cryptographic
example or a declaration of honest sampled encryption. Mock budget consumption
does not generate an HE key. These small tests are not timing observations.
"""

import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import pickle

import pytest

from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_cohort as cohort
from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab import shared_query_certificate as cert
from experiments.bfv_search_lab import test_complete_cost_protocol as public
from experiments.bfv_search_lab.shared_query_bounds import Profile

owners = public.owners


@pytest.fixture
def data(tmp_path, owners):
    made = []

    def make(groups=1):
        geometry = cert.geometry(0)
        p = Profile(
            geometry.n,
            geometry.dimension,
            geometry.q,
            geometry.p,
            geometry.t,
            geometry.eta,
            "owner",
            "canonical30",
        )
        count = 5 if groups == 1 else p.n + 1
        m = native.PublicMetadata(
            p,
            geometry.primes,
            public.token("public-key-label").hex(),
            tuple((1 << 64) - 1 - i for i in range(count)),
        )
        arc = cohort.PublicArchive(
            tmp_path / ("public-archive-" + str(len(made))), byte_limit=300_000
        )
        keys = bytes((p.levels + 1) * 8 * p.n * native.COMMON_WIDTH)
        key_ref = arc.put(keys, kind="evaluation-keys")
        packets = tuple(
            tuple(
                ("public-group" + str(g) + "-feature" + str(i)).encode() for i in range(p.dimension)
            )
            for g in range(groups)
        )
        refs = tuple(arc.put_group(batch, n=p.n, dimension=p.dimension) for batch in packets)
        record = cohort.sign_record(
            arc,
            m,
            key_ref,
            refs,
            epoch=1,
            policy_digest=public.token("public-policy"),
            signing_owner=owners[0],
        )
        result = (arc, m, keys, packets, record)
        made.append(result)
        return result

    return make


@pytest.mark.parametrize("groups", [1, 2])
def test_reconstructed_signed_enrollment_is_byte_exact_existing_wire(data, owners, groups):
    arc, m, keys, batches, record = data(groups)
    packets = tuple(packet for group in batches for packet in group)
    expected = auth.sign_enrollment(m, keys, packets, 1, record.policy_digest, owners[0])
    got = arc.materialize(record, label="current", owner_anchor=record.owner_anchor)
    body = Path(got["file"]).read_bytes()
    assert body == expected and len(body) == record.packet_bytes == got["bytes"]
    assert hashlib.sha256(body).hexdigest() == record.packet_sha256 == got["sha256"]
    payload = auth._unpack(expected, limit=native.PACKET_CAP, array_cap=3)[1]
    assert hashlib.sha256(payload).hexdigest() == record.payload_sha256
    assert (
        hashlib.sha256(auth.ENROLL_TAG + record.owner_anchor + payload).hexdigest()
        == record.snapshot_id
    )


def test_new_group_reuses_exact_unaffected_group_and_evaluation_keys(data, owners):
    arc, m, keys, batches, old = data(2)
    changed = tuple(b"changed-public-feature-" + bytes([i]) for i in range(m.profile.dimension))
    ref = arc.put_group(changed, n=m.profile.n, dimension=m.profile.dimension)
    new = cohort.sign_record(
        arc,
        m,
        old.keys,
        (ref, old.groups[1]),
        epoch=2,
        policy_digest=old.policy_digest,
        signing_owner=owners[0],
    )
    expected = auth.sign_enrollment(m, keys, changed + batches[1], 2, old.policy_digest, owners[0])
    actual = b"".join(block for _, block in new.packet_chunks(arc))
    assert actual == expected and new.snapshot_id != old.snapshot_id
    assert new.keys == old.keys and new.groups[1] == old.groups[1]
    assert arc.inventory()["blob_count"] == 6  # keys, three groups, two records


def test_binary_and_array_header_boundaries_match_canonical_msgpack():
    for size in (0, 1, 255, 256, 65535, 65536):
        assert cohort._bin_header(size) + bytes(size) == auth._pack(bytes(size))
    for size in (0, 3, 15, 16, 512):
        assert cohort._array_header(size) + b"\xc0" * size == auth._pack([None] * size)


def test_public_blob_deduplication_charges_once_and_refuses_oversize_before_write(tmp_path):
    arc = cohort.PublicArchive(tmp_path / "bounded", byte_limit=3)
    one = arc.put(b"abc", kind="descriptor")
    two = arc.put(b"abc", kind="query")
    assert arc.read(one) == arc.read(two) == b"abc"
    assert arc.inventory()["retained_bytes"] == 3 and arc.inventory()["blob_count"] == 1
    with pytest.raises(RuntimeError):
        arc.put(b"d", kind="query")
    assert len(list((arc.root / "blobs").iterdir())) == 1


def test_complete_scratch_can_retire_and_reconstruct_without_losing_public_inputs(data):
    arc, _, _, _, record = data()
    pin = arc.materialize(record, label="first", owner_anchor=record.owner_anchor)
    original = Path(pin["file"]).read_bytes()
    retained = arc.inventory()["retained_bytes"]
    arc.retire("first")
    assert arc.inventory()["live_scratch_bytes"] == 0
    assert arc.inventory()["retained_bytes"] == retained and not os.path.exists(pin["file"])
    again = arc.materialize(record, label="second", owner_anchor=record.owner_anchor)
    assert Path(again["file"]).read_bytes() == original
    with pytest.raises(RuntimeError):
        arc.materialize(record, label="first", owner_anchor=record.owner_anchor)


@pytest.mark.parametrize("fault", ["length", "content"])
def test_changed_public_source_blob_cannot_be_signed_or_reconstructed(data, owners, fault):
    arc, m, _, _, record = data()
    path = arc.root / "blobs" / record.groups[0].sha256
    body = path.read_bytes()
    path.write_bytes(body + b"x" if fault == "length" else body[:-1] + bytes([body[-1] ^ 1]))
    with pytest.raises(ValueError):
        cohort.sign_record(
            arc,
            m,
            record.keys,
            record.groups,
            epoch=2,
            policy_digest=record.policy_digest,
            signing_owner=owners[0],
        )
    with pytest.raises(ValueError):
        arc.materialize(record, label="bad", owner_anchor=record.owner_anchor)
    assert arc.inventory()["scratch"]["bad"]["status"] == "partial"


def test_signed_digest_does_not_allow_modified_unsigned_record_metadata(data):
    arc, _, _, _, record = data()
    changed = replace(record, epoch=2)
    changed.verify_owner(record.owner_anchor)  # Signature still covers original digest.
    with pytest.raises(ValueError):
        arc.materialize(changed, label="bad-epoch", owner_anchor=record.owner_anchor)
    assert arc.inventory()["scratch"]["bad-epoch"]["status"] == "partial"
    with pytest.raises(ValueError):
        arc.retire("bad-epoch")


def test_foreign_anchor_or_bad_signature_fails_before_scratch_reservation(data, owners):
    arc, _, _, _, record = data()
    foreign = owners[1].public_key().public_bytes_raw()
    with pytest.raises(ValueError):
        arc.materialize(record, label="foreign", owner_anchor=foreign)
    with pytest.raises(ValueError):
        arc.materialize(
            replace(record, signature=bytes(64)), label="bad-sig", owner_anchor=record.owner_anchor
        )
    assert arc.inventory()["scratch"] == {} and arc.inventory()["live_scratch_bytes"] == 0


def test_false_declared_payload_length_cannot_write_past_reserved_byte_bound(data):
    arc, _, _, _, record = data()
    short = replace(record, payload_bytes=1)
    with pytest.raises(ValueError):
        arc.materialize(short, label="short", owner_anchor=record.owner_anchor)
    partial = arc.inventory()["scratch"]["short"]
    assert os.path.getsize(partial["file"]) <= partial["bytes"] == short.packet_bytes


def test_mock_attempt_is_persisted_before_caller_work_and_not_refunded(tmp_path):
    ledger = cohort.ResourceLedger(tmp_path / "mock-budget.jsonl", {"HE_keys": 2})
    try:
        event = ledger.take("HE_keys", 1, label="public-mock-key0")
        observed = [json.loads(line) for line in ledger.path.read_text().splitlines()]
        assert observed[-1] == event and ledger.inventory()["used"]["HE_keys"] == 1
        # No actual key generator is called by this fixture.
        with pytest.raises(RuntimeError):
            raise RuntimeError("public mock caller failure")
        with pytest.raises(RuntimeError):
            ledger.take("HE_keys", 1, label="public-mock-key0")
        assert ledger.inventory()["used"]["HE_keys"] == 1
    finally:
        ledger.close()


def test_mock_resource_exhaustion_is_not_a_replacement_budget(tmp_path):
    ledger = cohort.ResourceLedger(tmp_path / "mock-budget.jsonl", {"feature_encryptions": 512})
    try:
        ledger.take("feature_encryptions", 512, label="mock-group0")
        with pytest.raises(RuntimeError):
            ledger.take("feature_encryptions", 1, label="mock-retry")
        assert ledger.inventory()["used"]["feature_encryptions"] == 512
    finally:
        ledger.close()


@pytest.mark.parametrize("amount", [True, 0, -1])
def test_invalid_mock_amount_cannot_consume_a_resource(tmp_path, amount):
    ledger = cohort.ResourceLedger(tmp_path / "mock-budget.jsonl", {"HE_keys": 2})
    try:
        with pytest.raises(ValueError):
            ledger.take("HE_keys", amount, label="invalid")
        assert ledger.inventory()["used"]["HE_keys"] == 0
    finally:
        ledger.close()


def test_persistence_failure_disables_holder_before_return_to_caller(tmp_path, monkeypatch):
    ledger = cohort.ResourceLedger(tmp_path / "mock-budget.jsonl", {"HE_keys": 2})

    def failure(_fd):
        raise OSError("public fsync fixture failure")

    monkeypatch.setattr(cohort.os, "fsync", failure)
    with pytest.raises(OSError):
        ledger.take("HE_keys", 1, label="mock-key0")
    assert ledger.inventory()["closed"] and ledger.inventory()["used"]["HE_keys"] == 1
    with pytest.raises(RuntimeError):
        ledger.take("HE_keys", 1, label="mock-key1")


def test_existing_archive_or_budget_cannot_be_recreated_as_fresh(tmp_path):
    path = tmp_path / "mock-budget.jsonl"
    ledger = cohort.ResourceLedger(path, {"HE_keys": 1})
    ledger.close()
    with pytest.raises(FileExistsError):
        cohort.ResourceLedger(path, {"HE_keys": 1})
    root = tmp_path / "archive"
    cohort.PublicArchive(root, byte_limit=100)
    with pytest.raises(FileExistsError):
        cohort.PublicArchive(root, byte_limit=100)


def test_live_archive_and_budget_reject_forked_copy_or_serialization(tmp_path):
    archive = cohort.PublicArchive(tmp_path / "archive", byte_limit=100)
    ledger = cohort.ResourceLedger(tmp_path / "mock-budget.jsonl", {"HE_keys": 1})
    try:
        for handle in (archive, ledger):
            with pytest.raises(TypeError):
                copy.copy(handle)
            with pytest.raises(TypeError):
                pickle.dumps(handle)
            pid = handle._pid
            handle._pid += 1
            try:
                with pytest.raises(RuntimeError):
                    handle.inventory()
            finally:
                handle._pid = pid
    finally:
        ledger.close()


def test_noncanonical_incomplete_or_trailing_group_never_enters_signed_payload(data, owners):
    arc, m, _, _, record = data()
    good = arc.read(record.groups[0])
    for number, bad in enumerate((b"\xdc\x00\x03" + good[1:], good[:-1], good + b"x")):
        ref = arc.put(bad, kind="index-group")
        with pytest.raises(ValueError):
            cohort.sign_record(
                arc,
                m,
                record.keys,
                (ref,),
                epoch=number + 2,
                policy_digest=record.policy_digest,
                signing_owner=owners[0],
            )


def test_wrong_source_coverage_is_rejected_before_signing(data, owners):
    arc, m, _, _, record = data()
    for keys, groups in (
        (replace(record.keys, bytes=1), record.groups),
        (record.keys, ()),
        (record.keys, (replace(record.groups[0], kind="query"),)),
    ):
        with pytest.raises(ValueError):
            cohort.sign_record(
                arc,
                m,
                keys,
                groups,
                epoch=2,
                policy_digest=record.policy_digest,
                signing_owner=owners[0],
            )


def test_changed_complete_scratch_is_preserved_as_forensic_evidence(data):
    arc, _, _, _, record = data()
    pin = arc.materialize(record, label="current", owner_anchor=record.owner_anchor)
    path = arc.root / "scratch/current.packet"
    body = path.read_bytes()
    path.write_bytes(body[:-1] + bytes([body[-1] ^ 1]))
    with pytest.raises(ValueError):
        arc.retire("current")
    assert path.exists() and arc.inventory()["live_scratch_bytes"] == pin["bytes"]


def test_readonly_recovery_reconstructs_public_inputs_without_private_material(data):
    arc, _, _, _, original = data(2)
    fields = json.loads(json.dumps(original.fields()))
    record = cohort.EnrollmentRecord.from_fields(fields)
    assert record == original
    reader = cohort.PublicArchive.recover(arc.root, (record.keys, *record.groups))
    record.verify_owner(record.owner_anchor)
    got = b"".join(block for _, block in record.packet_chunks(reader))
    assert hashlib.sha256(got).hexdigest() == record.packet_sha256
    with pytest.raises(RuntimeError):
        reader.put(b"new", kind="query")
    with pytest.raises(RuntimeError):
        reader.materialize(record, label="new", owner_anchor=record.owner_anchor)
    for change in (
        {"secret_key": "not-an-allowed-field"},
        {"schema_version": True},
        {"groups": []},
    ):
        with pytest.raises(ValueError):
            cohort.EnrollmentRecord.from_fields(dict(fields, **change))
