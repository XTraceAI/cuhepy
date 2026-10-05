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
import sys
import time
from types import SimpleNamespace

import pytest

from benchmarks import complete_cost_owner_lab as runtime
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_cohort as cohort
from experiments.bfv_search_lab import complete_cost_cohort_relay as cohort_relay
from experiments.bfv_search_lab import complete_cost_network as network
from experiments.bfv_search_lab import complete_cost_relay as relay
from experiments.bfv_search_lab import complete_cost_supervisor as supervisor
from experiments.bfv_search_lab import complete_cost_transport as transport
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


@pytest.fixture
def relay_files(tmp_path, owners):
    """Pinned opaque public deliveries; the worker never receives a secret."""
    freeze_path = os.environ.get("Q77_COHORT_RELAY_PUBLIC_FREEZE")
    if not freeze_path:
        raise RuntimeError("This separately registered public gate needs its source freeze")
    namespace = public.token("cohort-relay-UNIT-ONLY-lifetime")
    anchor = owners[0].public_key().public_bytes_raw()
    snapshot, descriptor = tmp_path / "snapshot", tmp_path / "descriptor"
    snapshot.write_bytes(b"opaque public authenticated-cache packet grammar")
    descriptor.write_bytes(b"opaque public cache signature grammar")
    routing = {
        "role": "frontend",
        "service": "shared-client-relay",
        "search_port": None,
        "cap": 8192,
        "timeout_ns": 10_000_000_000,
        "client_link": {"bytes_per_second": 100_000, "one_way_delay_ns": 100_000},
        "upload": None,
        "snapshot": {
            "packet": supervisor.pinned(snapshot),
            "descriptor": supervisor.pinned(descriptor),
        },
        "patch": None,
    }
    routing_path, config_path = tmp_path / "routing.json", tmp_path / "cohort.json"
    routing_path.write_text(json.dumps(routing))
    cfg = {
        "role": "frontend",
        "service": "owner-bound-cohort-relay",
        "routing_config": str(routing_path),
        "owner_anchor": anchor.hex(),
        "namespace": namespace.hex(),
        "uploads": [
            {"phase": "initial", "file": str(tmp_path / "initial.packet"), "max_bytes": 4096},
            {"phase": "update", "file": str(tmp_path / "update.packet"), "max_bytes": 4096},
        ],
    }
    config_path.write_text(json.dumps(cfg))
    return config_path, Path(freeze_path), cfg, namespace, anchor


def test_cohort_relay_exact_two_phases_are_consumed_without_replacement(relay_files, owners):
    config, freeze, cfg, namespace, _ = relay_files
    service = cohort_relay.CohortRelay(config, freeze)
    assert service.download_budget is service._base.download_budget
    for phase, body in ((b"initial", b"public-initial-body"), (b"update", b"public-update-body")):
        packet = cohort_relay.sign_upload(namespace, phase, body, owners[0])
        answer = service.execute(packet, deadline_ns=time.perf_counter_ns() + service.timeout_ns)
        assert auth._unpack(answer, limit=service.cap, array_cap=4) == [
            relay.OK_TAG,
            phase,
            len(body),
            hashlib.sha256(body).digest(),
        ]
        target = cfg["uploads"][cohort_relay.PHASES.index(phase)]["file"]
        assert Path(target).read_bytes() == body
        with pytest.raises(ValueError):
            service.execute(packet, deadline_ns=time.perf_counter_ns() + service.timeout_ns)
    inventory = service.inventory()
    assert [p["status"] for p in inventory["upload_phases"]] == ["complete", "complete"]
    assert not inventory["upload_failed"] and len(inventory["upload_stages"]) == 2
    assert inventory["private_authorization_or_attestation"] is False


def test_cohort_relay_rejects_foreign_roots_namespace_order_and_config(relay_files, owners):
    config, freeze, cfg, namespace, _ = relay_files
    service = cohort_relay.CohortRelay(config, freeze)
    for packet in (
        cohort_relay.sign_upload(namespace, b"initial", b"data", owners[1]),
        cohort_relay.sign_upload(public.token("foreign-cohort"), b"initial", b"data", owners[0]),
        cohort_relay.sign_upload(namespace, b"update", b"data", owners[0]),
        auth._pack([b"upload", b"legacy unsigned input"]),
        auth._pack([b"cohort-upload", {"file": "/tmp/not-an-upload-target"}]),
    ):
        with pytest.raises(ValueError):
            service.execute(packet, deadline_ns=time.perf_counter_ns() + service.timeout_ns)
    assert [p["status"] for p in service.inventory()["upload_phases"]] == ["unused", "unused"]
    assert all(not Path(p["file"]).exists() for p in cfg["uploads"])
    changed = dict(cfg, namespace=public.token("modified-root").hex())
    config.write_text(json.dumps(changed))
    with pytest.raises(ValueError):
        service.execute(
            cohort_relay.sign_upload(namespace, b"initial", b"data", owners[0]),
            deadline_ns=time.perf_counter_ns() + service.timeout_ns,
        )
    config.write_text(json.dumps(cfg))
    bad = dict(
        cfg, uploads=[cfg["uploads"][0], dict(cfg["uploads"][1], file=cfg["uploads"][0]["file"])]
    )
    config.write_text(json.dumps(bad))
    with pytest.raises(ValueError):
        cohort_relay.CohortRelay(config, freeze)


@pytest.mark.parametrize("failure", ["signed-digest", "fsync"])
def test_cohort_relay_failed_owner_phase_is_consumed_and_partial_retained(
    relay_files, owners, monkeypatch, failure
):
    config, freeze, cfg, namespace, _ = relay_files
    service = cohort_relay.CohortRelay(config, freeze)
    body = b"public body retained on disk failure"
    if failure == "signed-digest":
        payload = auth._pack([namespace, b"initial", len(body), bytes(32), body])
        packet = auth._pack(
            [b"cohort-upload", auth._sign(cohort_relay.UPLOAD_TAG, payload, owners[0])]
        )
    else:
        packet = cohort_relay.sign_upload(namespace, b"initial", body, owners[0])
        monkeypatch.setattr(
            cohort_relay.os, "fsync", lambda _: (_ for _ in ()).throw(OSError("UNIT failure"))
        )
    with pytest.raises((ValueError, OSError)):
        service.execute(packet, deadline_ns=time.perf_counter_ns() + service.timeout_ns)
    inventory = service.inventory()
    assert inventory["upload_failed"] and inventory["upload_phases"][0]["status"] == "failed"
    if failure == "fsync":
        assert Path(cfg["uploads"][0]["file"]).read_bytes() == body
    else:
        assert not Path(cfg["uploads"][0]["file"]).exists()
    for phase in cohort_relay.PHASES:
        with pytest.raises(ValueError):
            service.execute(
                cohort_relay.sign_upload(namespace, phase, body, owners[0]),
                deadline_ns=time.perf_counter_ns() + service.timeout_ns,
            )
    assert not Path(cfg["uploads"][1]["file"]).exists()


def test_cohort_relay_deadline_process_and_copy_guards_precede_writes(
    relay_files, owners, monkeypatch
):
    config, freeze, cfg, namespace, _ = relay_files
    service = cohort_relay.CohortRelay(config, freeze)
    packet = cohort_relay.sign_upload(namespace, b"initial", b"data", owners[0])
    with pytest.raises(transport.TransportError):
        service.execute(packet, deadline_ns=time.perf_counter_ns() - 1)
    for clone in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            clone(service)
    monkeypatch.setattr(service._base, "_pid", os.getpid() + 1)
    with pytest.raises(RuntimeError):
        service.execute(packet, deadline_ns=time.perf_counter_ns() + service.timeout_ns)
    assert all(not Path(p["file"]).exists() for p in cfg["uploads"])


def test_cohort_relay_supervised_worker_shares_setup_cache_update_download_lane(
    relay_files, owners, tmp_path
):
    config, freeze, cfg, namespace, _ = relay_files
    manager = supervisor.PublicSupervisor(
        tmp_path / "manager-result.json",
        source_pin=supervisor.pinned(supervisor.__file__),
        python_pin=supervisor.pinned(os.sys.executable),
        timeout_ns=30_000_000_000,
    )
    endpoint, done = None, tmp_path / "relay-result.json"
    try:
        spec = supervisor.WorkerSpec(
            "cohort-public-relay",
            supervisor.pinned(cohort_relay.__file__),
            str(config),
            str(freeze),
            str(done),
            min(os.sched_getaffinity(0)),
        )
        ready = manager.start((spec,))[spec.label]
        assert ready["process"] != os.getpid() and ready["process"] != manager.process_id
        assert ready["local_verifier_public_key"] is None
        # Public process ancestry, not an attestation or a real HE custody claim.
        stat = Path("/proc" + "/" + str(ready["process"]) + "/stat").read_text()
        assert int(stat[stat.rfind(")") + 2 :].split()[1]) == manager.process_id
        endpoint = relay.OwnerEndpoint(
            ready["port"],
            upload_budget=network.DirectionBudget(transport.Link(**cfg_link(config))),
            cap=8192,
            timeout_ns=10_000_000_000,
        )
        for phase, body in (
            (b"initial", b"public-initial" * 40),
            (b"update", b"public-update" * 40),
        ):
            response = endpoint.rpc(cohort_relay.sign_upload(namespace, phase, body, owners[0]))
            assert auth._unpack(response, limit=8192, array_cap=4)[1] == phase
            delivery = endpoint.rpc(auth._pack([b"snapshot"]))
            assert len(auth._unpack(delivery, limit=8192, array_cap=2)) == 2
        endpoint.close()
        manager.stop((spec.label,))
        report = json.loads(done.read_text())
        assert report["owned_handlers_complete"]
        assert [p["status"] for p in report["upload_phases"]] == ["complete", "complete"]
        # Each small message reserves its actual frame header and body.
        assert len(report["download_credits"]) == 10
        uploads = endpoint.inventory()["upload_credits"]
        assert len(uploads) == 8
        assert sum(r["wire_bytes"] for r in report["download_credits"]) == sum(
            r["wire_bytes"] for r in report["transfers"] if r["direction"] == "send"
        )
        assert all(r["completed"] for r in report["transfers"])
    finally:
        if endpoint is not None:
            endpoint.close()
        manager.close()
    summary = json.loads((tmp_path / "manager-result.json").read_text())
    assert len(summary["attempts"]) == 1
    assert summary["attempts"][0]["status"] == "stopped"
    assert summary["attempts"][0]["exit_code"] == 0
    assert not Path("/proc" + "/" + str(ready["process"])).exists()


def cfg_link(config):
    fields = json.loads(Path(config).read_text())
    return json.loads(Path(fields["routing_config"]).read_text())["client_link"]


def test_cohort_runtime_native_calls_preserve_cached_paths_and_separate_waits():
    """Configured-call public stubs exercise proxies, not HE/native arithmetic."""

    class PublicCall:
        def __init__(self):
            self.argtypes, self.restype = [object], object
            self.returned, self.arguments = object(), []
            self.error = None

        def __call__(self, *args):
            self.arguments.append(args)
            time.sleep(0.002)
            if self.error is not None:
                raise self.error
            return self.returned

    for mode, role in (
        (cert.MODES[0], "frontend"),
        (cert.MODES[0], "protected"),
        (cert.MODES[1], "protected"),
        (cert.MODES[2], "frontend"),
    ):
        symbols = runtime.NATIVE_SYMBOLS + tuple(s for _, s in runtime.CACHED_SYMBOLS[mode])
        originals = {symbol: PublicCall() for symbol in symbols}
        dll = SimpleNamespace(**originals)
        arithmetic = SimpleNamespace(**{a: originals[s] for a, s in runtime.CACHED_SYMBOLS[mode]})
        factory, library = SimpleNamespace(_arithmetic=arithmetic), SimpleNamespace(_lib=dll)
        clocks = runtime.NativeClocks(role, mode)
        clocks.install(library, factory)
        for attr, symbol in runtime.CACHED_SYMBOLS[mode]:
            assert getattr(arithmetic, attr) is getattr(dll, symbol)
        argument = object()
        with clocks.phase("initial-preparation"):
            assert dll.cuhepy_shared_create(argument) is originals["cuhepy_shared_create"].returned
        with clocks.phase("run"):
            assert dll.cuhepy_shared_query(argument) is originals["cuhepy_shared_query"].returned
            if mode == cert.MODES[0]:
                dll.cuhepy_shared_produce(argument)
                dll.cuhepy_shared_terminal(argument)
            elif mode == cert.MODES[1]:
                assert arithmetic._run(argument) is originals["cuhepy_shared_replay"].returned
            else:
                assert (
                    arithmetic._produce(argument)
                    is originals["cuhepy_shared_aggregate_produce"].returned
                )
            dll.cuhepy_shared_check(argument)
            time.sleep(0.03)  # Public simulated RPC wait, deliberately outside native calls.
            dll.cuhepy_shared_query_destroy(argument)
        report = clocks.inventory()
        projection = report["computational_projection"]
        run = next(p for p in report["phases"] if p["phase"] == "run")
        assert run["end_ns"] - run["start_ns"] - projection["wall_ns"] >= 20_000_000
        assert projection["not_independently_executed_unverified_evaluator"]
        assert projection["not_whole_owner_completion_latency"]
        assert all(originals[c["symbol"]].arguments for c in report["calls"])
        assert all(
            c["end_ns"] >= c["start_ns"] and c["thread_cpu_ns"] >= 0 for c in report["calls"]
        )
        assert not any(k in c for c in report["calls"] for k in ("arguments", "result", "pointer"))
        dll.cuhepy_shared_query.argtypes = [int]
        dll.cuhepy_shared_query.restype = int
        assert originals["cuhepy_shared_query"].argtypes == [int]
        assert originals["cuhepy_shared_query"].restype is int
        failure = ValueError("UNIT-ONLY diagnostic message must not be logged")
        originals["cuhepy_shared_check"].error = failure
        with pytest.raises(ValueError) as caught, clocks.phase("run"):
            dll.cuhepy_shared_check(argument)
        assert caught.value is failure
        assert clocks.inventory()["calls"][-1]["status"] == "raised"
        assert clocks.inventory()["calls"][-1]["error_class"] == "ValueError"
        assert "diagnostic message" not in json.dumps(clocks.inventory())
        before = len(originals["cuhepy_shared_query"].arguments)
        with pytest.raises(RuntimeError):
            dll.cuhepy_shared_query(argument)  # Unscoped work is forbidden before delegation.
        assert len(originals["cuhepy_shared_query"].arguments) == before
        with pytest.raises(RuntimeError):
            clocks.install(library, factory)
        for item in (clocks, dll.cuhepy_shared_query):
            with pytest.raises(TypeError):
                copy.copy(item)
            with pytest.raises(TypeError):
                pickle.dumps(item)
        clocks._pid += 1
        try:
            with pytest.raises(RuntimeError):
                clocks.inventory()
        finally:
            clocks._pid -= 1
    # A stale cached pointer fails before replacing any public function.
    originals = {name: PublicCall() for name in runtime.NATIVE_SYMBOLS + ("cuhepy_shared_replay",)}
    dll = SimpleNamespace(**originals)
    bad = SimpleNamespace(_arithmetic=SimpleNamespace(_run=PublicCall()))
    with pytest.raises(ValueError):
        runtime.NativeClocks("protected", cert.MODES[1]).install(SimpleNamespace(_lib=dll), bad)
    assert all(getattr(dll, name) is fn for name, fn in originals.items())


@pytest.fixture
def runtime_files(tmp_path):
    freeze = os.environ.get("Q77_RUNTIME_PUBLIC_FREEZE")
    if not freeze:
        raise RuntimeError("The registered public runtime gate requires its source freeze")

    def make(label, **changes):
        root = tmp_path / label
        root.mkdir()
        identity = runtime.process_counters(os.getpid())
        registry = root / "registry.json"
        registry.write_text(
            json.dumps(
                [{"label": "owner", "pid": os.getpid(), "birth_ticks": identity["birth_ticks"]}]
            )
        )
        cfg = {
            "role": "frontend",
            "service": "public-resource-telemetry",
            "registry": str(registry),
            "samples": str(root / "samples.jsonl"),
            "guard": str(root / "guard.json"),
            "interval_ns": 100_000_000,
            "max_samples": 100,
            "max_bytes": 131072,
            "deadline_ns": time.perf_counter_ns() + 10_000_000_000,
            "min_available_bytes": 0,
        }
        cfg.update(changes)
        config = root / "config.json"
        config.write_text(json.dumps(cfg))
        return config, Path(freeze), cfg

    return make


def test_cohort_runtime_telemetry_birth_binding_limits_and_persistence_failure(
    runtime_files, monkeypatch
):
    config, freeze, cfg = runtime_files("wrong-birth")
    registry = json.loads(Path(cfg["registry"]).read_text())
    registry[0]["birth_ticks"] += 1
    Path(cfg["registry"]).write_text(json.dumps(registry))
    service = runtime.PublicTelemetry(config, freeze)
    try:
        limit = time.perf_counter_ns() + 2_000_000_000
        while service.inventory()["samples_consumed"] < 1 and time.perf_counter_ns() < limit:
            time.sleep(0.01)
        with pytest.raises(ValueError):
            service.execute(
                auth._pack([b"sample", {"pid": 1, "file": "/tmp/not-a-telemetry-target"}])
            )
        service.close()
        rows = [json.loads(line) for line in Path(cfg["samples"]).read_text().splitlines()]
        assert rows and all(
            r["processes"][0]["observation"] == "birth_mismatch_no_process_followed" for r in rows
        )
        assert all("memory_bytes" not in r["processes"][0] for r in rows)
        inv = service.inventory()
        assert inv["closed"] and not inv["sampler_thread_alive"] and inv["failure"] is None
        assert (
            inv["no_processes_killed"] and not inv["process_memory_argv_environment_or_keys_read"]
        )
        consumed = inv["samples_consumed"]
        with pytest.raises(RuntimeError):
            service.sample()
        assert service.inventory()["samples_consumed"] == consumed
        with pytest.raises(TypeError):
            copy.copy(service)
        with pytest.raises(TypeError):
            pickle.dumps(service)
    finally:
        service.close()
    assert runtime.system_counters()["memory_bytes"]["MemAvailable"] < 1 << 40
    config, freeze, cfg = runtime_files("memory-guard", min_available_bytes=1 << 40)
    service = runtime.PublicTelemetry(config, freeze)
    try:
        service._thread.join(timeout=2)
        service.close()
        inv = service.inventory()
        assert inv["failure"]["reason"] == "available_memory_below_frozen_minimum"
        assert inv["guard_record_persistence_completed"] and service.stopping
        assert json.loads(Path(cfg["guard"]).read_text())["samples_consumed"] == 1
    finally:
        service.close()
    config, freeze, cfg = runtime_files("sample-cap", max_samples=1)
    service = runtime.PublicTelemetry(config, freeze)
    try:
        service._thread.join(timeout=2)
        service.close()
        assert service.inventory()["failure"]["reason"] == "sample_attempt_cap_exhausted"
        assert service.inventory()["samples_consumed"] == 1
    finally:
        service.close()
    # The fixed host's real public CPU counters exceed this tiny artifact cap.
    assert len(json.dumps(runtime.system_counters())) > 1024
    config, freeze, cfg = runtime_files("byte-cap", max_bytes=1024)
    service = runtime.PublicTelemetry(config, freeze)
    try:
        service._thread.join(timeout=2)
        service.close()
        assert service.inventory()["failure"]["reason"] == "sample_byte_cap_exhausted"
        assert service.inventory()["sample_bytes"] == Path(cfg["samples"]).stat().st_size == 0
    finally:
        service.close()
    config, freeze, cfg = runtime_files("guard-fsync-failure", min_available_bytes=1 << 40)
    with monkeypatch.context() as patch:

        def failed_fsync(_fd):
            raise OSError("UNIT-ONLY simulated guard persistence failure")

        patch.setattr(runtime.os, "fsync", failed_fsync)
        service = runtime.PublicTelemetry(config, freeze)
        service._thread.join(timeout=2)
    try:
        service.close()
        inv = service.inventory()
        assert service.stopping and inv["failure"] is not None
        assert inv["guard_record_persistence_completed"] is False
        assert Path(cfg["guard"]).exists()  # Partial failure is retained, never replaced.
    finally:
        service.close()


def test_cohort_runtime_clean_supervised_telemetry_is_public_and_owned(runtime_files, tmp_path):
    config, freeze, cfg = runtime_files("supervised")
    manager = supervisor.PublicSupervisor(
        tmp_path / "runtime-manager.json",
        source_pin=supervisor.pinned(Path(supervisor.__file__)),
        python_pin=supervisor.pinned(sys.executable),
        timeout_ns=10_000_000_000,
    )
    done = tmp_path / "runtime-worker.json"
    cpu = 7 if 7 in os.sched_getaffinity(0) else min(os.sched_getaffinity(0))
    spec = supervisor.WorkerSpec(
        "telemetry",
        supervisor.pinned(Path(runtime.__file__)),
        str(config),
        str(freeze),
        str(done),
        cpu,
    )
    try:
        ready = manager.start((spec,))[spec.label]
        assert ready["local_verifier_public_key"] is None
        assert runtime.process_counters(ready["process"])["parent"] == manager.process_id
        entries = []
        for label, pid in (
            ("owner", os.getpid()),
            ("manager", manager.process_id),
            ("telemetry", ready["process"]),
        ):
            entries.append(
                {
                    "label": label,
                    "pid": pid,
                    "birth_ticks": runtime.process_counters(pid)["birth_ticks"],
                }
            )
        pending_registry = tmp_path / "next-runtime-registry.json"
        pending_registry.write_text(json.dumps(entries))
        pending_registry.replace(Path(cfg["registry"]))
        time.sleep(0.15)
        manager.stop((spec.label,))
        result = json.loads(done.read_text())
        assert result["failure"] is None and result["closed"] and not result["sampler_thread_alive"]
        assert (
            result["no_processes_killed"]
            and not result["process_memory_argv_environment_or_keys_read"]
        )
        rows = [json.loads(line) for line in Path(cfg["samples"]).read_text().splitlines()]
        assert rows and all(row["sampler_cpu_affinity"] == [cpu] for row in rows)
        assert any(
            {p["label"] for p in row["processes"]} == {"owner", "manager", "telemetry"}
            for row in rows
        )
        assert all(row["system"]["VM_counters"]["pswpin"] >= 0 for row in rows)
        assert not Path("/proc/" + str(ready["process"])).exists()
    finally:
        manager.close()
    summary = json.loads((tmp_path / "runtime-manager.json").read_text())
    assert len(summary["attempts"]) == 1
    assert summary["attempts"][0]["status"] == "stopped"
    assert summary["attempts"][0]["exit_code"] == 0
