"""Opaque public relay fixtures; no HE/native/AES or fresh signing keys.

The echo backend is not a cryptographically valid result. Tests cover actual
TCP contention, fixed routing/files, deadlines and clean subprocess ownership.
Their elapsed time is never a large-search benchmark sample.
"""

# ruff: noqa: E402 -- subprocess guard entry adds its repository root.
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
import os
from pathlib import Path
import pickle
import signal
import socket
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import pytest

from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_network as network
from experiments.bfv_search_lab import complete_cost_relay as relay
from experiments.bfv_search_lab import complete_cost_supervisor as supervisor
from experiments.bfv_search_lab import complete_cost_transport as transport

CAP = 300_000
TIMEOUT = 2_000_000_000
LINK = transport.Link(10_000_000, 0)


class Echo:
    """One deterministic public backend, with explicitly owned socket/thread."""

    def __init__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.done = threading.Event()
        self.requests = []
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        while not self.done.is_set():
            try:
                sock, _ = self.listener.accept()
            except TimeoutError:
                continue
            stream = transport.BoundedStream(
                sock, cap=CAP, link=relay.LOCAL_DISPATCH, timeout_ns=TIMEOUT
            )
            try:
                packet = stream.receive(kind="public-unit-backend")
                self.requests.append(packet)
                stream.send(auth._pack([b"public-echo", packet]), kind="public-unit-echo")
            finally:
                stream.close()

    def close(self):
        self.done.set()
        self.thread.join(2)
        assert not self.thread.is_alive()
        self.listener.close()


def public_file(tmp_path, name, body):
    path = tmp_path / name
    path.write_bytes(body)
    return supervisor.pinned(path)


def specification(tmp_path, *, port=None, upload=None):
    entry = supervisor.pinned(relay.__file__)
    test_entry = supervisor.pinned(__file__)
    cfg = {
        "role": "frontend",
        "service": "shared-client-relay",
        "search_port": port,
        "cap": CAP,
        "timeout_ns": TIMEOUT,
        "client_link": {"bytes_per_second": LINK.bytes_per_second, "one_way_delay_ns": 0},
        "upload": upload,
        "snapshot": {
            "packet": public_file(tmp_path, "opaque-snapshot.bin", b"opaque" * 12_000),
            "descriptor": public_file(tmp_path, "opaque-snapshot.descriptor", b"public-descriptor"),
        },
        "patch": {
            "packet": public_file(tmp_path, "opaque-patch.bin", b"patch-body"),
            "descriptor": public_file(tmp_path, "opaque-patch.descriptor", b"patch-descriptor"),
        },
    }
    config, freeze = tmp_path / "config.json", tmp_path / "freeze.json"
    config.write_text(json.dumps(cfg))
    freeze.write_text(
        json.dumps(
            {
                "new_sources": [entry, test_entry],
                "preserved_runtime_sources": [],
                "dependencies": [],
            }
        )
    )
    return cfg, config, freeze


class Harness:
    def __init__(self, tmp_path, *, upload=None):
        self.echo = Echo()
        self.cfg, self.config, self.freeze = specification(
            tmp_path, port=self.echo.port, upload=upload
        )
        self.role = relay.PublicRelay(self.config, self.freeze)
        self.output = tmp_path / "relay-result.json"
        readiness, ready = {}, threading.Event()

        def publish(value):
            readiness.update(value)
            ready.set()

        self.thread = threading.Thread(
            target=relay.serve, args=(self.role, self.output), kwargs={"ready": publish}
        )
        self.thread.start()
        assert ready.wait(2)
        self.port = readiness["port"]
        self.budget = network.DirectionBudget(LINK)
        self.endpoint = self.new_endpoint()

    def new_endpoint(self):
        return relay.OwnerEndpoint(
            self.port, upload_budget=self.budget, cap=CAP, timeout_ns=TIMEOUT
        )

    def close(self):
        try:
            with_endpoint = self.new_endpoint()
            try:
                with_endpoint.rpc(auth._pack([b"stop"]))
            finally:
                with_endpoint.close()
        finally:
            self.endpoint.close()
            self.thread.join(3)
            self.echo.close()
        assert not self.thread.is_alive()
        assert json.loads(self.output.read_text())["owned_handlers_complete"]


@pytest.fixture
def harness(tmp_path):
    item = Harness(tmp_path)
    try:
        yield item
    finally:
        item.close()


def test_exact_search_forward_and_separate_link_accounting(harness):
    original = auth._pack([b"run", b"opaque-original-context"])
    request = auth._pack([b"search", original])
    reply = harness.endpoint.rpc(request)
    assert auth._unpack(reply, limit=CAP, array_cap=2) == [b"public-echo", original]
    assert harness.echo.requests == [original]
    owner, public = harness.endpoint.inventory(), harness.role.inventory()
    assert sum(r["wire_bytes"] for r in owner["upload_credits"]) == len(request) + 8
    assert sum(r["wire_bytes"] for r in public["download_credits"]) == len(reply) + 8
    assert {r["kind"] for r in public["transfers"]} == {
        "client-upload",
        "client-download",
        "unshaped-backend-dispatch",
        "unshaped-backend-return",
    }
    assert public["private_authorization_or_attestation"] is False


@pytest.mark.parametrize("verb", [b"snapshot", b"patch"])
def test_public_store_packet_and_descriptor_are_complete(harness, verb):
    reply = harness.endpoint.rpc(auth._pack([verb]))
    fields = auth._unpack(reply, limit=CAP, array_cap=2)
    pins = harness.cfg[verb.decode()]
    assert fields == [
        Path(pins["packet"]["file"]).read_bytes(),
        Path(pins["descriptor"]["file"]).read_bytes(),
    ]
    assert harness.echo.requests == []


def test_concurrent_search_and_acquisition_share_each_direction(harness):
    barrier = threading.Barrier(2)
    commands = [auth._pack([b"search", b"Q" * 80_000]), auth._pack([b"snapshot"])]

    def call(command):
        barrier.wait(timeout=1)
        return harness.endpoint.rpc(command)

    with ThreadPoolExecutor(max_workers=2) as pool:
        replies = list(pool.map(call, commands))
    up, down = harness.budget.history(), harness.role.download_budget.history()
    assert sum(r.wire_bytes for r in up) == sum(len(c) + 8 for c in commands)
    assert sum(r.wire_bytes for r in down) == sum(len(r) + 8 for r in replies)
    for lane in (up, down):
        assert all(a.finished_ns <= b.started_ns for a, b in zip(lane, lane[1:], strict=False))
        assert [r.ordinal for r in lane] == list(range(len(lane)))
    assert harness.endpoint.inventory()["active_connections"] == 0


def test_two_cache_downloads_share_single_budget(harness):
    with ThreadPoolExecutor(max_workers=2) as pool:
        replies = list(pool.map(harness.endpoint.rpc, [auth._pack([b"snapshot"])] * 2))
    assert replies[0] == replies[1]
    credits = harness.role.download_budget.history()
    assert sum(r.wire_bytes for r in credits) == 2 * (len(replies[0]) + 8)
    assert sum(r.wire_bytes for r in credits if r.wire_bytes == 8) == 16


def test_fixed_public_upload_is_paid_written_once_and_preserved(tmp_path):
    body = b"opaque-public-enrollment" * 20
    target = tmp_path / "server-owned-public.bin"
    upload = {"file": str(target), "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
    item = Harness(tmp_path, upload=upload)
    try:
        command = auth._pack([b"upload", body])
        reply = item.endpoint.rpc(command)
        assert auth._unpack(reply, limit=CAP, array_cap=3) == [
            relay.OK_TAG,
            len(body),
            hashlib.sha256(body).digest(),
        ]
        assert target.read_bytes() == body and item.role.inventory()["upload_consumed"]
        assert sum(r.wire_bytes for r in item.budget.history()) == len(command) + 8
        with pytest.raises(RuntimeError, match="relay rejected"):
            item.endpoint.rpc(command)
        assert target.read_bytes() == body and item.cfg["upload"] == upload
    finally:
        item.close()


def test_wrong_upload_cannot_create_or_choose_a_file(tmp_path):
    target = tmp_path / "fixed-server-owned.bin"
    upload = {"file": str(target), "bytes": 3, "sha256": hashlib.sha256(b"yes").hexdigest()}
    _, config, freeze = specification(tmp_path, upload=upload)
    item = relay.PublicRelay(config, freeze)
    with pytest.raises(ValueError, match="differs"):
        item.execute(
            auth._pack([b"upload", b"bad"]), deadline_ns=time.perf_counter_ns() + TIMEOUT // 2
        )
    assert not target.exists() and not item.inventory()["upload_consumed"]


@pytest.mark.parametrize(
    "command",
    [
        [b"search", 42],
        [b"search", b"query", b"foreign-mode"],
        [b"load-library", b"/tmp/user-library.so"],
        [b"snapshot", b"/tmp/foreign-file"],
        [1],
        {"exec": "/tmp/foreign-code"},
    ],
)
def test_received_data_cannot_choose_routing_code_or_files(harness, command):
    with pytest.raises(RuntimeError, match="relay rejected"):
        harness.endpoint.rpc(auth._pack(command))
    assert harness.echo.requests == []


@pytest.mark.parametrize("field", ["cap", "service", "client_link"])
def test_trusted_root_change_rejects_before_dispatch(harness, field):
    cfg = json.loads(harness.config.read_text())
    cfg[field] = 1 if field != "service" else "other-service"
    harness.config.write_text(json.dumps(cfg))
    try:
        with pytest.raises(RuntimeError, match="relay rejected"):
            harness.endpoint.rpc(auth._pack([b"search", b"original"]))
        assert harness.echo.requests == []
    finally:
        harness.config.write_text(json.dumps(harness.cfg))


@pytest.mark.parametrize("part", ["packet", "descriptor"])
def test_changed_public_file_rejected_by_its_owner_pin(harness, part):
    Path(harness.cfg["snapshot"][part]["file"]).write_bytes(b"changed-public-bytes")
    with pytest.raises(RuntimeError, match="relay rejected"):
        harness.endpoint.rpc(auth._pack([b"snapshot"]))


def test_backend_can_be_bound_once_only_by_trusted_config(tmp_path):
    _, config, freeze = specification(tmp_path)
    item = relay.PublicRelay(config, freeze)
    with pytest.raises(ValueError, match="not been bound"):
        item.execute(
            auth._pack([b"search", b"query"]), deadline_ns=time.perf_counter_ns() + TIMEOUT // 2
        )
    echo = Echo()
    try:
        cfg = json.loads(config.read_text())
        cfg["search_port"] = echo.port
        config.write_text(json.dumps(cfg))
        reply = item.execute(
            auth._pack([b"search", b"query"]), deadline_ns=time.perf_counter_ns() + TIMEOUT // 2
        )
        assert auth._unpack(reply, limit=CAP, array_cap=2) == [b"public-echo", b"query"]
        cfg["search_port"] = 1 if echo.port != 1 else 2
        config.write_text(json.dumps(cfg))
        with pytest.raises(ValueError, match="backend changed"):
            item.execute(
                auth._pack([b"search", b"query"]), deadline_ns=time.perf_counter_ns() + TIMEOUT // 2
            )
    finally:
        echo.close()


@pytest.mark.parametrize("kind", ["endpoint", "relay"])
def test_pid_rejection_precedes_held_lock(harness, kind):
    item = harness.endpoint if kind == "endpoint" else harness.role
    old = item._pid
    item._pid = -1
    item._lock.acquire()
    try:
        with pytest.raises(RuntimeError, match="Inherited"):
            item.inventory()
    finally:
        item._lock.release()
        item._pid = old


@pytest.mark.parametrize("kind", ["endpoint", "relay"])
def test_process_owned_endpoints_cannot_be_copied_or_pickled(harness, kind):
    item = harness.endpoint if kind == "endpoint" else harness.role
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(item)


def test_expired_owner_deadline_sends_no_packet(harness):
    with pytest.raises(ValueError, match="deadline"):
        harness.endpoint.rpc(auth._pack([b"snapshot"]), deadline_ns=time.perf_counter_ns() - 1)
    assert harness.budget.history() == () and harness.role.inventory()["stages"] == []


def test_relay_deadline_cannot_be_extended_by_caller(harness):
    with pytest.raises(ValueError, match="deadline"):
        harness.role.execute(
            auth._pack([b"snapshot"]), deadline_ns=time.perf_counter_ns() + 2 * TIMEOUT
        )
    assert harness.role.inventory()["stages"] == []


def test_closed_owner_endpoint_cannot_issue_another_request(harness):
    harness.endpoint.close()
    with pytest.raises(RuntimeError, match="Closed"):
        harness.endpoint.rpc(auth._pack([b"snapshot"]))
    assert harness.budget.history() == ()


def test_oversized_wire_header_rejects_before_body(harness):
    sock = socket.create_connection(("127.0.0.1", harness.port), timeout=1)
    sock.sendall(transport.HEADER.pack(CAP + 1))
    assert sock.recv(1) == b""
    sock.close()
    assert harness.role.inventory()["stages"] == []


def test_clean_supervisor_starts_real_public_relay_worker(tmp_path):
    _, config, freeze = specification(tmp_path)
    pool = supervisor.PublicSupervisor(
        tmp_path / "supervisor.json",
        source_pin=supervisor.pinned(supervisor.__file__),
        python_pin=supervisor.pinned(sys.executable),
        timeout_ns=5_000_000_000,
    )
    output = tmp_path / "child-relay.json"
    spec = supervisor.WorkerSpec(
        "relay",
        supervisor.pinned(__file__),
        str(config),
        str(freeze),
        str(output),
        min(os.sched_getaffinity(0)),
    )
    endpoint = None
    try:
        ready = pool.start((spec,))["relay"]
        assert ready["process"] not in (os.getpid(), pool.process_id)
        endpoint = relay.OwnerEndpoint(
            ready["port"], upload_budget=network.DirectionBudget(LINK), cap=CAP, timeout_ns=TIMEOUT
        )
        received = auth._unpack(endpoint.rpc(auth._pack([b"snapshot"])), limit=CAP, array_cap=2)
        assert received[0] == b"opaque" * 12_000
        pool.stop(("relay",))
    finally:
        if endpoint is not None:
            endpoint.close()
        pool.close()
    assert json.loads(output.read_text())["owned_handlers_complete"]
    observed = json.loads(Path(str(output) + ".private-observation.json").read_text())
    assert observed["private_work_attempts"] == 0 and observed["blocked_private_entries"] == []


if __name__ == "__main__":
    private_calls = []

    def guard(frame, event, arg):
        if event == "call" and (
            frame.f_code.co_name
            in {
                "key_gen",
                "encrypt",
                "decrypt",
                "evaluation_keys",
                "_ring_product",
                "_small_poly",
                "_ternary_poly",
            }
            and frame.f_code.co_filename.startswith((str(ROOT / "src"), str(ROOT / "experiments")))
            or frame.f_code.co_filename == str(ROOT / "experiments/bfv_search_lab/private_bgv.py")
            and frame.f_code.co_name in {"__init__", "decode", "decode_packed", "close"}
        ):
            private_calls.append(frame.f_code.co_name)
            raise RuntimeError("Public relay unit forbids HE/private work")
        if event == "c_call" and str(getattr(arg, "__module__", "")).endswith("_bgv_private"):
            private_calls.append(getattr(arg, "__name__", "?"))
            raise RuntimeError("Public relay unit forbids native private work")

    def terminate(_signal, _frame):
        raise SystemExit(143)

    signal.signal(signal.SIGTERM, terminate)
    sys.setprofile(guard)
    threading.setprofile(guard)
    try:
        relay.main()
    finally:
        sys.setprofile(None)
        threading.setprofile(None)
        output = Path(sys.argv[sys.argv.index("--output") + 1] + ".private-observation.json")
        with output.open("x") as saved:
            json.dump(
                {
                    "process": os.getpid(),
                    "private_work_attempts": len(private_calls),
                    "blocked_private_entries": private_calls,
                    "scope": "Real public relay entry; imports precede function/thread guard",
                },
                saved,
            )
            saved.write("\n")
