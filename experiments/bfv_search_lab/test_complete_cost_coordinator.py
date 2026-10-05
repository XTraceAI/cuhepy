"""Public orchestration gates; arithmetic uses the existing labelled stubs."""

from dataclasses import replace
import json
import os
from pathlib import Path
import threading
import time

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
