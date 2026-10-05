"""Public orchestration gates; arithmetic uses the existing labelled stubs."""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import threading
import time
from types import SimpleNamespace

import pytest

from experiments.bfv_search_lab import authenticated_cache as cache
from experiments.bfv_search_lab import complete_cost_coordinator as coordinator
from experiments.bfv_search_lab import complete_cost_supervisor as supervisor
from experiments.bfv_search_lab import shared_query_certificate as cert
from experiments.bfv_search_lab import test_complete_cost_supervisor as echo
from experiments.bfv_search_lab import test_complete_cost_trace as public_trace
from experiments.bfv_search_lab import test_complete_cost_cohort as public_cohort
from experiments.bfv_search_lab import complete_cost_cohort as cohort
from experiments.bfv_search_lab import authenticated_shared_query as auth
from benchmarks import complete_cost_owner_cohort as assembly
from benchmarks import complete_cost_owner_study as study
from experiments.bfv_search_lab import complete_cost_tenant as tenant_module
from experiments.bfv_search_lab import complete_cost_cohort_relay as cohort_relay
from experiments.bfv_search_lab import shared_query_client_context as context
from experiments.bfv_search_lab import test_complete_cost_owner as public_owner

# Re-export the existing labelled fixtures for pytest discovery.
make_trace, owners = public_trace.make_trace, public_trace.owners
data = public_cohort.data
deadline, reference = public_trace.deadline, public_trace.reference


def cpu():
    return min(os.sched_getaffinity(0))


def race(f, *, label="race"):
    return f.trace.race_query(
        0, label=label, arrival_ns=time.perf_counter_ns(), deadline_ns=deadline(), remote_cpu=cpu()
    )


def test_cache_publication_can_win_an_inflight_remote_query(make_trace):
    f = make_trace()
    f.block_snapshot = f.block_search = True
    job = f.trace.start_acquisition(deadline_ns=deadline(), cpu=cpu())
    assert f.snapshot_entered.wait(1)

    def publish():
        assert f.search_entered.wait(1)
        f.snapshot_release.set()

    publisher = threading.Thread(target=publish)
    publisher.start()
    result = race(f)
    publisher.join(1)
    assert result.distances == reference(f.rows, 3, 0)
    item = f.trace.inventory()["races"][0]
    assert item["winner"] == "cache" and item["remote_thread_alive"]
    assert f.private_entries == 0 and len(f.encrypted) == 1
    f.search_release.set()
    job.join(deadline_ns=deadline())
    f.trace.join_races(deadline_ns=deadline())
    assert f.private_entries == 1  # Losing work remains paid and authenticated.
    item = f.trace.inventory()["races"][0]
    assert item["remote_end_ns"] > item["end_ns"] and not item["remote_thread_alive"]


def test_remote_can_win_before_cache_publication_and_settlement_is_explicit(make_trace):
    f = make_trace()
    f.block_snapshot = True
    job = f.trace.start_acquisition(deadline_ns=deadline(), cpu=cpu())
    assert f.snapshot_entered.wait(1)
    assert race(f).distances == reference(f.rows, 3, 0)
    assert f.trace.inventory()["races"][0]["winner"] == "remote"
    assert not f.trace.cache_ready()
    f.snapshot_release.set()
    job.join(deadline_ns=deadline())
    f.trace.join_races(deadline_ns=deadline())
    f.trace.stop_remote()
    assert f.query(label="cached-after-settlement", policy="cache").distances == (0, 0, 1, 2, 3)


def test_failed_losing_remote_cannot_be_hidden_by_a_cache_win(make_trace):
    f = make_trace()
    f.block_snapshot = f.block_search = True
    f.reply_fault = "signature"
    job = f.trace.start_acquisition(deadline_ns=deadline(), cpu=cpu())
    assert f.snapshot_entered.wait(1)
    publisher = threading.Thread(
        target=lambda: (f.search_entered.wait(1), f.snapshot_release.set())
    )
    publisher.start()
    assert race(f).distances == (0, 0, 1, 2, 3)
    publisher.join(1)
    f.search_release.set()
    job.join(deadline_ns=deadline())
    with pytest.raises(RuntimeError):
        f.trace.join_races(deadline_ns=deadline())
    assert f.trace.inventory()["failed"] and f.private_entries == 0


def test_query_global_attempt_precedes_arithmetic_and_original_is_retained(make_trace):
    f = make_trace()
    records = []
    f.source._attempt_observer = lambda i: records.append(("attempt", i, len(f.encrypted)))
    f.source._packet_observer = lambda packet, i: records.append(("packet", i, packet))
    f.query()
    assert records[0] == ("attempt", 0, 0)
    assert records[1][0:2] == ("packet", 0) and type(records[1][2]) is bytes
    assert f.source.inventory()["actual_packet_observer"]
    assert f.source.inventory()["global_attempt_observer"]


@pytest.mark.parametrize("boundary", ("attempt", "packet"))
def test_query_persistence_failure_is_consumed_and_never_sent(make_trace, boundary):
    f = make_trace()

    def fail(*_args):
        raise OSError("UNIT-ONLY persistence diagnostic")

    if boundary == "attempt":
        f.source._attempt_observer = fail
    else:
        f.source._packet_observer = fail
    with pytest.raises(OSError):
        f.query()
    assert f.source.inventory()["issued"] == 1
    assert len(f.encrypted) == (boundary == "packet")
    assert f.rpc_calls == [] and f.private_entries == 0
    assert f.trace.inventory()["failed"]


def test_cache_control_survives_closed_HE_descriptor_without_HE_work(make_trace):
    f = make_trace(mode=None)
    raw = coordinator.CacheOwnerTrace(f.cache, f.endpoint, f.log)
    f.descriptor.close()
    f.keys.close()
    raw.acquire(deadline_ns=deadline())
    result = raw.query(
        0, label="direct-cache", arrival_ns=time.perf_counter_ns(), deadline_ns=deadline()
    )
    assert result.distances == (0, 0, 1, 2, 3)
    assert tuple(m.identifier for m in result.nearest) == f.metadata.ids[:3]
    assert not raw.inventory()["requires_HE_descriptor_key_index_or_certificate"]
    assert len(f.encrypted) == f.private_entries == 0


@pytest.mark.parametrize("policy", coordinator.POLICIES)
def test_complete_actual_trajectory_with_update_and_full_oracles(
    make_trace,
    owners,
    tmp_path,
    policy,
):
    f = make_trace(mode=None if policy.endswith("cache") else cert.MODES[0])
    path = (
        f.trace
        if policy in ("remote", "prefetch")
        else coordinator.CacheOwnerTrace(f.cache, f.endpoint, f.log)
    )
    calls, words = [], (0, 1, 2, 3, 4, 5, 6, 7)

    def setup(_deadline):
        calls.append("setup")

    def update(selected_deadline):
        calls.append("update")
        changed = tuple(words[i % 2] ^ 1 for i in range(len(f.rows)))
        delivery, _metadata, current = f.update()
        f.patch = cache.seal_update(
            tuple(enumerate(changed)),
            f.key,
            owners[0],
            f.snapshot.context,
            snapshot_id=current.snapshot_id,
        )
        f.rows = changed
        if policy == "remote":
            f.trace.advance(
                delivery.pin, delivery.packet, cache_context=current, deadline_ns=selected_deadline
            )
            target = f.trace
        else:
            target = (
                path
                if policy != "prefetch"
                else coordinator.CacheOwnerTrace(f.cache, f.endpoint, f.log)
            )
            target.advance(current, deadline_ns=selected_deadline)
            target.patch(deadline_ns=selected_deadline)
        return target, changed

    def warmup(_deadline):
        calls.append("cache-code-warmup")
        assert not f.cache.inventory()["active"]

    runner = coordinator.TrajectoryRunner(
        path,
        policy=policy,
        label="public-trajectory",
        words=words,
        rows=f.rows,
        ids=f.metadata.ids,
        output=tmp_path / "result.json",
        guard=lambda: None,
        operation_timeout_ns=1_500_000_000,
        setup=setup,
        update=update,
        close_workers=lambda: calls.append("cleanup"),
        cache_warmup=warmup,
        stop_remote=lambda _deadline: calls.append("remote-stopped"),
        remote_cpu=cpu(),
        background_cpu=cpu(),
    )
    result = runner.run()
    assert result["status"] == "complete", result
    assert calls[0] == "setup" and calls[-1] == "cleanup"
    assert len(result["observations"]) == 8
    assert len(result["complete_oracle_checks"]) == (9 if policy == "fresh-cache" else 10)
    assert all(
        x["owner_latency_ns"] == x["completion_ns"] - x["arrival_ns"]
        for x in result["observations"]
    )
    assert result["owner_inventory"]["closed"]
    assert json.loads((tmp_path / "result.json.attempt.json").read_text())["status"] == "starting"
    if policy == "prefetch":
        assert calls.index("remote-stopped") < calls.index("update")
    if policy.endswith("cache"):
        assert not f.encrypted and f.private_entries == 0
    with pytest.raises(RuntimeError):
        runner.run()


def test_failed_trajectory_retains_attempt_trace_and_cleanup(make_trace, tmp_path):
    f = make_trace(with_cache=False)
    f.reply_fault = "signature"
    closed = []
    runner = coordinator.TrajectoryRunner(
        f.trace,
        policy="remote",
        label="failed-trajectory",
        words=(0,) * 8,
        rows=f.rows,
        ids=f.metadata.ids,
        output=tmp_path / "failure.json",
        guard=lambda: None,
        operation_timeout_ns=1_500_000_000,
        setup=lambda _deadline: None,
        update=lambda _deadline: pytest.fail("no update after failure"),
        close_workers=lambda: closed.append(True),
    )
    result = runner.run()
    assert result["status"] == "failed" and result["error_class"] == "ValueError"
    assert closed == [True] and f.private_entries == 0
    assert result["owner_inventory"]["failed"]
    assert result["observations"] == []
    assert any(x["status"] == "failed" for x in result["owner_inventory"]["trace"]["events"])


def test_manager_affinity_does_not_remove_other_worker_CPUs(tmp_path):
    available = sorted(os.sched_getaffinity(0))
    assert len(available) >= 2
    pool = supervisor.PublicSupervisor(
        tmp_path / "supervisor.json",
        source_pin=supervisor.pinned(supervisor.__file__),
        python_pin=supervisor.pinned(os.sys.executable),
        timeout_ns=3_000_000_000,
        manager_cpu=available[0],
    )
    item = replace(echo.spec(tmp_path), cpu=available[1])
    try:
        pool.start((item,))
        pool.stop((item.label,))
    finally:
        pool.close()
    summary = echo.summary(tmp_path)
    assert summary["manager_cpu"] == available[0]
    assert summary["startup_available_cpus"] == available
    assert json.loads(Path(item.output).read_text())["cpu"] == [available[1]]


@pytest.mark.parametrize("fault", ("bytes", "sticky-telemetry", "deadline"))
def test_whole_artifact_resource_guard_is_sticky(tmp_path, fault):
    guard_file = tmp_path / "guard.json"
    (tmp_path / "body").write_bytes(b"a" * 2048)
    if fault == "sticky-telemetry":
        guard_file.write_text("{}")
    guard = coordinator.ResourceGuard(
        tmp_path,
        guard_file,
        artifact_limit=1024 if fault == "bytes" else 4096,
        min_available_bytes=0,
        deadline_ns=time.perf_counter_ns() + (1_000_000_000 if fault != "deadline" else -1),
    )
    with pytest.raises((RuntimeError, TimeoutError)):
        guard.check()
    (tmp_path / "body").unlink()
    guard_file.unlink(missing_ok=True)
    with pytest.raises(RuntimeError):
        guard.check()
    assert guard.inventory()["failure_class"] is not None


def assembly_files(tmp_path, data, owners, *, groups=2):
    arc, metadata, keys, batches, record = data(groups)
    original = b"".join(chunk for _, chunk in record.packet_chunks(arc))
    root = tmp_path / "assembly"
    root.mkdir()
    initial = tmp_path / "initial.upload"
    initial.write_bytes(
        assembly.upload_body(record, b"public initial descriptor fixture", original)
    )
    cfg = {
        "role": "frontend",
        "service": "public-cohort-enrollment-assembly",
        "owner_anchor": owners[0].public_key().public_bytes_raw().hex(),
        "root": str(root),
        "initial": supervisor.pinned(initial),
        "update": None,
    }
    config = tmp_path / "assembly.config.json"
    config.write_text(json.dumps(cfg))
    freeze = tmp_path / "assembly.freeze.json"
    entry = supervisor.pinned(assembly.__file__)
    freeze.write_text(
        json.dumps({"new_sources": [entry], "preserved_runtime_sources": [], "dependencies": []})
    )
    changed = tuple(b"new public feature " + bytes([i]) for i in range(metadata.profile.dimension))
    ref = arc.put_group(changed, n=metadata.profile.n, dimension=metadata.profile.dimension)
    update = cohort.sign_record(
        arc,
        metadata,
        record.keys,
        (ref, *record.groups[1:]),
        epoch=2,
        policy_digest=record.policy_digest,
        signing_owner=owners[0],
    )
    expected = b"".join(chunk for _, chunk in update.packet_chunks(arc))
    return config, cfg, freeze, record, update, original, expected, changed


@pytest.mark.parametrize("groups", (1, 2))
def test_public_assembly_reuses_unchanged_keys_and_group_byte_exact(tmp_path, data, owners, groups):
    config, cfg, freeze, old, new, original, expected, changed = assembly_files(
        tmp_path, data, owners, groups=groups
    )
    role = assembly.PublicEnrollmentAssembler(config, freeze)
    prior = dict(role.enrollment)
    assert Path(prior["file"]).read_bytes() == original
    uploaded = tmp_path / "update.upload"
    uploaded.write_bytes(
        assembly.upload_body(new, b"public updated descriptor fixture", auth._pack(list(changed)))
    )
    cfg["update"] = supervisor.pinned(uploaded)
    config.write_text(json.dumps(cfg))
    assert role.execute(auth._pack([b"refresh"]))
    assert Path(role.enrollment["file"]).read_bytes() == expected
    assert not Path(prior["file"]).exists() and role.retired == [prior]
    assert new.keys == old.keys and new.groups[1:] == old.groups[1:]
    assert Path(role.descriptor["file"]).read_bytes() == b"public updated descriptor fixture"
    with pytest.raises(ValueError):
        role.execute(auth._pack([b"refresh"]))
    assert role.inventory()["phases_consumed"] == 2


@pytest.mark.parametrize("fault", ("changed-group", "immutable-root", "pin"))
def test_public_assembly_failure_is_consumed_before_publication(tmp_path, data, owners, fault):
    config, cfg, freeze, _old, new, _original, _expected, changed = assembly_files(
        tmp_path, data, owners
    )
    role = assembly.PublicEnrollmentAssembler(config, freeze)
    uploaded = tmp_path / "update.upload"
    body = auth._pack(list(changed)) if fault != "changed-group" else b"invalid group coverage"
    uploaded.write_bytes(assembly.upload_body(new, b"public updated descriptor fixture", body))
    cfg["update"] = supervisor.pinned(uploaded)
    if fault == "immutable-root":
        cfg["owner_anchor"] = owners[1].public_key().public_bytes_raw().hex()
    if fault == "pin":
        cfg["update"]["sha256"] = "00" * 32
    config.write_text(json.dumps(cfg))
    with pytest.raises(ValueError):
        role.execute(auth._pack([b"refresh"]))
    assert role.inventory()["failed"] and role.inventory()["phases_consumed"] == 2
    assert not (Path(cfg["root"]) / "update.enrollment").exists()
    assert Path(role.enrollment["file"]).exists()  # Failed validation retains old input.
    with pytest.raises(ValueError):
        role.execute(auth._pack([b"refresh"]))


def test_clean_public_assembly_worker_is_owned_and_uses_no_native_path(tmp_path, data, owners):
    config, cfg, freeze, _old, _new, original, _expected, _changed = assembly_files(
        tmp_path, data, owners
    )
    pool = echo.start(tmp_path)
    item = supervisor.WorkerSpec(
        "assembly",
        supervisor.pinned(assembly.__file__),
        str(config),
        str(freeze),
        str(tmp_path / "assembly.result.json"),
        cpu(),
    )
    try:
        ready = pool.start((item,))[item.label]
        assert ready["local_verifier_public_key"] is None
        assert (Path(cfg["root"]) / "initial.enrollment").read_bytes() == original
        pool.stop((item.label,))
    finally:
        pool.close()
    result = json.loads(Path(item.output).read_text())
    assert not result["HE_private_key_present_or_private_HE_work"]
    assert not result["cryptographic_query_result_admission_or_attestation"]
    assert result["stages"][0]["status"] == "complete"


@pytest.mark.parametrize("fault", (False, True))
def test_worker_preparation_is_inside_consumed_owner_attempt(make_trace, tmp_path, fault):
    f = make_trace()
    output = tmp_path / "prepared.result.json"

    def setup(_deadline):
        assert output.with_suffix(".json.attempt.json").exists()
        assert f.log.inventory()["events"][-1]["label"] == "trajectory-setup"
        if fault:
            raise RuntimeError("UNIT-ONLY failed role preparation")
        return f.trace

    runner = coordinator.TrajectoryRunner(
        None,
        policy="remote",
        label="deferred-preparation",
        words=(0,) * 8,
        rows=f.rows,
        ids=f.metadata.ids,
        output=output,
        guard=lambda: None,
        operation_timeout_ns=1_500_000_000,
        setup=setup,
        # Deliberately stop at the update boundary; this fixture tests setup
        # lifetime and error retention, not another cryptographic experiment.
        update=lambda _deadline: (_ for _ in ()).throw(RuntimeError("UNIT-ONLY update stop")),
        close_workers=lambda: None,
        log=f.log,
        dimension=3,
    )
    result = runner.run()
    assert result["status"] == "failed"
    if fault:
        assert result["owner_inventory"]["owner_trace_preparation_unfinished"]
        assert not f.encrypted and not result["observations"]
    else:
        assert len(result["observations"]) == 8 and len(f.encrypted) == 9
        assert result["owner_inventory"]["closed"]


def public_tenant(tmp_path, monkeypatch, owners):
    """Existing public roots and invalid HE material; every HE operation is stubbed."""
    g, pk, sk = public_owner.material(0)
    ledger = cohort.ResourceLedger(tmp_path / "resources.jsonl", dict(study.LIMITS))
    state = SimpleNamespace(ready=False, calls=[], encryptions=[], fail_feature=None, nonce=0)
    key = hashlib.sha256(b"Q76.4c public unit AES fixture").digest()

    def used(name):
        return ledger.inventory()["used"][name]

    def signing_stub():
        assert used("owner_signing_keys") == 1
        state.calls.append("owner-signing-key-predebited")
        return owners[0]

    def entropy_stub(size):
        if size == 32:
            assert used("cache_AES_keys") == 1
            state.calls.append("cache-key-predebited")
            return key
        assert size == 12
        state.nonce += 1
        return state.nonce.to_bytes(12, "little")

    def key_stub(n, t, bits, eta, *, rns_modulus):
        assert (n, t, bits, eta, rns_modulus) == (g.n, g.t, 120, g.eta, True)
        assert used("HE_keys") == 1
        state.calls.append("HE-key-predebited-PUBLIC-STUB")
        return pk, sk

    def evaluation_stub(selected_pk, selected_sk, dimension):
        assert (selected_pk, selected_sk, dimension) == (pk, sk, g.dimension)
        state.calls.append("evaluation-keys-PUBLIC-STUB")
        zero = (0,) * g.n
        switch = ((zero, zero),) * 4
        return tenant_module.shared.Keys(pk.key_id, 4, switch, ((9, switch), (5, switch)))

    def encryption_stub(message, selected_pk, selected_sk):
        assert (selected_pk, selected_sk) == (pk, sk)
        assert len(message) == g.n and set(message) <= {-1, 0, 1}
        attempt = used("feature_encryptions")
        assert attempt == len(state.encryptions) + 1
        state.encryptions.append(tuple(message))
        if attempt == state.fail_feature:
            raise OSError("UNIT-ONLY failed feature persistence boundary")
        return b"UNIT-ONLY opaque feature packet " + str(attempt).encode()

    monkeypatch.setattr(tenant_module.Ed25519PrivateKey, "generate", staticmethod(signing_stub))
    monkeypatch.setattr(tenant_module.secrets, "token_bytes", entropy_stub)
    monkeypatch.setattr(tenant_module.bgv, "key_gen", key_stub)
    monkeypatch.setattr(tenant_module.shared, "evaluation_keys", evaluation_stub)
    monkeypatch.setattr(tenant_module.seeded, "encrypt", encryption_stub)
    p = tenant_module.TenantProvisioner(
        tmp_path / "tenants",
        ledger,
        geometry=g,
        guard=lambda: state.calls.append("public-guard"),
        ready=lambda: state.ready,
        byte_limit=300_000,
    )

    def builder(_anchor):
        return (
            tuple(hashlib.sha256(x.encode()).digest() for x in cert.MODES),
            hashlib.sha256(b"UNIT-ONLY public code identity").digest(),
        )

    return SimpleNamespace(p=p, state=state, ledger=ledger, builder=builder, key=key)


def test_honest_tenant_readiness_and_key_attempts_precede_stub_work(tmp_path, monkeypatch, owners):
    f = public_tenant(tmp_path, monkeypatch, owners)
    with pytest.raises(RuntimeError, match="telemetry"):
        f.p.create(0, policy_builder=f.builder)
    assert not any(f.ledger.inventory()["used"].values())
    f.state.ready = True
    tenant = f.p.create(0, policy_builder=f.builder)
    assert [x for x in f.state.calls if x != "public-guard"] == [
        "owner-signing-key-predebited",
        "cache-key-predebited",
        "HE-key-predebited-PUBLIC-STUB",
        "evaluation-keys-PUBLIC-STUB",
    ]
    view = tenant.initial((0, 1, 3, 7, 0), (9, 8, 7, 6, 5))
    assert len(view.records) == 3 and len(f.state.encryptions) == 3
    assert all(len(word) == 16 for word in f.state.encryptions)
    assert not list(f.p.root.glob("*.partial-group"))
    assert not tenant.inventory()["private_keys_serialized"]
    assert not tenant.inventory()["secure_zeroization_claim"]
    with pytest.raises(RuntimeError):
        f.p.create(0, policy_builder=f.builder)
    f.p.close()
    f.ledger.close()


def test_honest_tenant_failed_feature_keeps_prefix_and_consumes_attempt(
    tmp_path, monkeypatch, owners
):
    f = public_tenant(tmp_path, monkeypatch, owners)
    f.state.ready, f.state.fail_feature = True, 2
    tenant = f.p.create(0, policy_builder=f.builder)
    with pytest.raises(OSError):
        tenant.initial((0, 1, 3, 7, 0), (9, 8, 7, 6, 5))
    prefix = next(f.p.root.glob("*.partial-group"))
    retained = prefix.read_bytes()
    assert b"UNIT-ONLY opaque feature packet 1" in retained
    assert b"UNIT-ONLY opaque feature packet 2" not in retained
    assert f.ledger.inventory()["used"]["feature_encryptions"] == 2
    with pytest.raises(RuntimeError):
        tenant.initial((0, 1, 3, 7, 0), (9, 8, 7, 6, 5))
    assert prefix.read_bytes() == retained and len(f.state.encryptions) == 2
    f.p.close()
    f.ledger.close()


def test_tenant_modes_share_rows_and_updates_reuse_keys_and_unaffected_group(
    tmp_path,
    monkeypatch,
    owners,
):
    f = public_tenant(tmp_path, monkeypatch, owners)
    f.state.ready = True
    tenant = f.p.create(0, policy_builder=f.builder)
    old = tenant.initial(tuple(i % 8 for i in range(17)), tuple(range(17)))
    words = tuple(range(8))
    new = tenant.update(old, words, label="remote-update", encrypted=True)
    assert new.rows == tuple(words[i % 2] ^ 1 for i in range(17))
    metadata = context.verify_descriptor(new.descriptor.packet, tenant.anchor, new.descriptor.pin)
    for mode in cert.MODES:
        before, after = old.record(mode), new.record(mode)
        after.verify_owner(tenant.anchor)
        assert after.keys == before.keys and after.groups[1:] == before.groups[1:]
        assert after.groups[0] != before.groups[0] and after.epoch == 2
        assert metadata.mode(mode).snapshot_id.hex() == after.snapshot_id
    assert metadata.cache.snapshot_id == new.cache_delivery.context.snapshot_id
    consumed = f.ledger.inventory()["used"]["feature_encryptions"]
    delivery, rows = tenant.update(old, words, label="cache-update", encrypted=False)
    assert type(delivery) is cache.PatchDelivery and rows == new.rows
    assert f.ledger.inventory()["used"]["feature_encryptions"] == consumed == 9
    assert delivery.previous_context == old.cache_delivery.context
    with pytest.raises(RuntimeError):
        tenant.update(old, words, label="cache-update", encrypted=False)
    f.p.close()
    f.ledger.close()


def test_study_has_fixed_calibration_first_order_caps_and_rejects_uncommitted_execution(
    tmp_path,
    monkeypatch,
):
    order = study.cohort_order()
    assert len(order) == 18 and all(x["phase"] == "calibration" for x in order[:6])
    assert all(x["phase"] == "held-out" for x in order[6:])
    assert len({(x["key"], x["count"], x["block"]) for x in order}) == 18
    assert all(set(x["trajectories"]) == set(study.TRAJECTORIES) for x in order)
    assert study.LIMITS["query_encryptions"] == 3 * 18 * 10 + 18 * 9 == 702
    assert study.LIMITS["protected_signing_keys"] == (3 + 1) * 18 == 72
    assert study.LIMITS["feature_encryptions"] == 2 * (512 + 512 + 1024) + 3 * 18 * 512
    assert study.query_bytes()[:2] == (bytes.fromhex("55" * 64), bytes.fromhex("a3" * 64))
    called = []
    monkeypatch.setattr(study.OwnerStudy, "_bootstrap", lambda _self: called.append("forbidden"))
    path = tmp_path / "uncommitted.json"
    path.write_text("{}")
    with pytest.raises(ValueError, match="committed"):
        study.OwnerStudy(path, tmp_path / "output")
    assert not called and not (tmp_path / "output").exists()


def calibration_rows(tmp_path):
    results = []
    for key in range(2):
        for count in study.SIZES:
            for label in study.TRAJECTORIES:
                packet = tmp_path / f"public-calibration-{key}-{count}-{label}.json"
                packet.write_text(json.dumps({"UNIT-ONLY logical scheduler fixture": label}))
                rank = {"m0": 3, "m1": 1, "m2": 2}.get(label, 4)
                results.append(
                    {
                        "key": key,
                        "count": count,
                        "trajectory": label,
                        "block": 0,
                        "status": "complete",
                        "result_pin": supervisor.pinned(packet),
                        "observations": [{"owner_latency_ns": rank} for _ in range(8)],
                        "evaluator_projection_ns": [4 - rank] * 8,
                    }
                )
    return results


def test_policy_freeze_uses_complete_calibration_only_and_cannot_be_replaced(tmp_path):
    results = calibration_rows(tmp_path)
    for bad in (results[:-1], [dict(x, block=1) for x in results], [results[0]] * 36):
        with pytest.raises(ValueError):
            study.select_policies(bad, tmp_path / "must-not-exist.json")
        assert not (tmp_path / "must-not-exist.json").exists()
    target = tmp_path / "policy.json"
    selected = study.select_policies(results, target)
    frozen = target.read_bytes()
    assert set(selected["client_remote"].values()) == {"m1"}
    assert set(selected["evaluator_projection_remote"].values()) == {"m0"}
    assert selected["generic_same_information_remote"] == selected["client_remote"]
    assert not selected["held_out_inputs"] and len(selected["calibration_inputs"]) == 36
    with pytest.raises(FileExistsError):
        study.select_policies(results, target)
    assert target.read_bytes() == frozen


def test_actual_cache_only_session_uses_shared_tcp_upload_update_without_HE_work(
    tmp_path,
    monkeypatch,
    owners,
):
    f = public_tenant(tmp_path, monkeypatch, owners)
    f.state.ready = True
    tenant = f.p.create(0, policy_builder=f.builder)
    view = tenant.initial((0, 1, 3, 7, 0), (9, 8, 7, 6, 5))
    before = f.ledger.inventory()["used"]
    native = object.__new__(cache.NativePopcount)
    native._initialize_owner()

    def scan_stub(_self, rows, count, dimension, query):
        width, word = (dimension + 7) // 8, int.from_bytes(query, "little")
        values = tuple(
            (int.from_bytes(rows[i : i + width], "little") ^ word).bit_count()
            for i in range(0, len(rows), width)
        )
        assert len(values) == count
        return values, tuple(sorted(range(count), key=lambda i: (values[i], i))[:3])

    monkeypatch.setattr(cache.NativePopcount, "scan", scan_stub)
    monkeypatch.setattr(study, "CPUS", dict.fromkeys(study.CPUS, cpu()))
    freeze = tmp_path / "public-session-freeze.json"
    freeze.write_text(
        json.dumps(
            {
                "new_sources": [
                    supervisor.pinned(assembly.__file__),
                    supervisor.pinned(cohort_relay.__file__),
                ],
                "preserved_runtime_sources": [],
                "dependencies": [],
            }
        )
    )
    pool = echo.start(tmp_path, timeout=4_000_000_000)
    holder = object.__new__(study.OwnerStudy)
    holder.root, holder.addendum = tmp_path, freeze
    holder.freeze = {
        "guard": {"operation_timeout_ns": 1_500_000_000},
        "client_link": study.asdict(study.roles.CLIENT_LINK),
    }
    holder.guard = SimpleNamespace(check=lambda: None)
    holder.manager, holder.provisioner, holder.ledger = pool, f.p, f.ledger
    holder.native_cache, holder.active, holder.history, holder.policy = native, {}, [], None
    holder._pid, holder.registry = os.getpid(), tmp_path / "owned-pids.json"
    try:
        for label in ("returning", "fresh"):
            result = holder._trajectory(
                {"key": 0, "count": 5, "block": 0}, label, tenant, view, tuple(range(8))
            )
            assert result["status"] == "complete" and len(result["observations"]) == 8
            assert len(result["complete_oracle_checks"]) == (9 if label == "fresh" else 10)
            inv = result["owner_inventory"]
            assert not inv["requires_HE_descriptor_key_index_or_certificate"]
            assert not list((tmp_path / f"k0_n5_b0_{label}").glob("*.enrollment"))
            uploads = [x for x in inv["endpoint"]["transfers"] if "send" in x["direction"]]
            assert uploads  # Actual shaped sockets, not a modeled byte subtraction.
        after = f.ledger.inventory()["used"]
        for name in (
            "HE_keys",
            "feature_encryptions",
            "query_encryptions",
            "protected_signing_keys",
        ):
            assert after[name] == before[name]
        assert holder.active == {}
    finally:
        pool.close()
        f.p.close()
        f.ledger.close()


def test_combined_assembly_cache_update_preserves_HE_base_and_rejects_mismatched_coverage(
    tmp_path,
    data,
    owners,
    monkeypatch,
):
    nonce = [0]

    def nonce_stub(size):
        assert size == 12
        nonce[0] += 1
        return nonce[0].to_bytes(12, "little")

    monkeypatch.setattr(cache.secrets, "token_bytes", nonce_stub)
    arc, metadata, _keys, _batches, record = data(2)
    key = hashlib.sha256(b"Q76.4c public unit AES fixture").digest()
    rows = tuple(i % 8 for i in metadata.ids)
    delivery = cache.seal_snapshot(
        rows,
        metadata.ids,
        3,
        key,
        owners[0],
        namespace=b"N" * 32,
        key_id=b"K" * 32,
        snapshot_id=b"S" * 32,
        epoch=1,
    )
    full = b"".join(chunk for _, chunk in record.packet_chunks(arc))
    freeze = tmp_path / "combined.freeze.json"
    freeze.write_text(
        json.dumps(
            {
                "new_sources": [supervisor.pinned(assembly.__file__)],
                "preserved_runtime_sources": [],
                "dependencies": [],
            }
        )
    )

    def prepare(name, value, extra=False):
        root = tmp_path / name
        root.mkdir()
        packet = assembly.combined_body(record, b"UNIT-ONLY HE descriptor", full, value)
        if extra:
            packet = auth._pack([*auth._unpack(packet, limit=300_000, array_cap=4), b"trailing"])
        upload = root / "initial.upload"
        upload.write_bytes(packet)
        cfg = {
            "role": "frontend",
            "service": "public-cohort-combined-assembly",
            "owner_anchor": owners[0].public_key().public_bytes_raw().hex(),
            "root": str(root),
            "initial": supervisor.pinned(upload),
            "update": None,
            "cache_initial_context": assembly.context_fields(value.context),
            "cache_update_context": None,
        }
        path = root / "config.json"
        path.write_text(json.dumps(cfg))
        return path, cfg

    config, cfg = prepare("valid", delivery)
    role = assembly.PublicEnrollmentAssembler(config, freeze)
    old = dict(role.enrollment)
    patch = cache.seal_update(((0, 1),), key, owners[0], delivery.context, snapshot_id=b"T" * 32)
    upload = Path(cfg["root"]) / "update.upload"
    upload.write_bytes(assembly.cache_body(patch))
    cfg.update(
        update=supervisor.pinned(upload),
        cache_update_context=assembly.context_fields(patch.context),
    )
    config.write_text(json.dumps(cfg))
    role.execute(auth._pack([b"refresh"]))
    assert role.enrollment == old and role.record == record
    assert Path(old["file"]).read_bytes() == full
    assert role.cache_context == patch.context
    assert not role.inventory()["stages"][-1]["HE_index_or_descriptor_updated"]
    foreign = cache.seal_snapshot(
        rows,
        tuple(reversed(metadata.ids)),
        3,
        key,
        owners[0],
        namespace=b"N" * 32,
        key_id=b"K" * 32,
        snapshot_id=b"X" * 32,
        epoch=1,
    )
    for name, value, extra in (("wrong-IDs", foreign, False), ("wrong-grammar", delivery, True)):
        path, failed_cfg = prepare(name, value, extra)
        with pytest.raises(ValueError):
            assembly.PublicEnrollmentAssembler(path, freeze)
        assert not (Path(failed_cfg["root"]) / "initial.enrollment").exists()


def test_full_cohort_public_scheduler_freezes_once_before_held_out_and_stops_failures(
    tmp_path,
    monkeypatch,
):
    corpus = tmp_path / "public-zero-rows.bin"
    corpus.write_bytes(bytes(32768 * 64))

    def run_stub_cohort(root, fail_at=None):
        root.mkdir()
        holder = object.__new__(study.OwnerStudy)
        holder.root, holder.addendum = root, corpus
        holder.freeze = {"corpus": supervisor.pinned(corpus)}
        holder._pid, holder._consumed = os.getpid(), False
        holder.manager = holder.provisioner = holder.ledger = holder.native_cache = None
        holder.active, holder.history, holder.results, holder.policy = {}, [], [], None
        holder.guard = SimpleNamespace(check=lambda: None, inventory=lambda: {"public_stub": True})
        events = []

        def bootstrap():
            assert (root / "attempt.json").exists()
            events.append("UNIT-ONLY logical bootstrap; no actual manager/telemetry/key")

            def create(slot, **_kwargs):
                events.append(("public-key-slot-stub", slot))
                return SimpleNamespace(initial=lambda rows, ids: (rows, ids))

            holder.provisioner = SimpleNamespace(
                create=create, close=lambda: events.append("closed")
            )

        def trajectory(block, label, _tenant, _view, _words):
            index = len(holder.results)
            assert (holder.policy is None) == (index < 36)
            if index >= 36:
                assert (root / "policy-freeze.json").exists()
            packet = root / f"public-logical-row-{index}.json"
            packet.write_text(json.dumps({"UNIT-ONLY scheduler stub": index}))
            return {
                "key": block["key"],
                "count": block["count"],
                "block": block["block"],
                "trajectory": label,
                "status": "failed" if index == fail_at else "complete",
                "observations": [{"owner_latency_ns": 1} for _ in range(8)],
                "evaluator_projection_ns": [1] * 8,
                "result_pin": supervisor.pinned(packet),
            }

        holder._bootstrap, holder._trajectory, holder._stop = (
            bootstrap,
            trajectory,
            lambda _labels: None,
        )
        result = holder.run()
        with pytest.raises(RuntimeError):
            holder.run()
        assert events[-1] == "closed"
        return result

    success = run_stub_cohort(tmp_path / "public-complete")
    assert success["status"] == "complete" and len(success["results"]) == 108
    assert sum(x["block"] == 0 for x in success["results"]) == 36
    assert len(success["policy"]["calibration_inputs"]) == 36
    failed = run_stub_cohort(tmp_path / "public-failed", fail_at=36)
    assert failed["status"] == "failed" and len(failed["results"]) == 37
    assert failed["results"][-1]["status"] == "failed"
    assert failed["keys_blocks_or_retries_not_replaced"]
