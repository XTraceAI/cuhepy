"""Public echo subprocess fixtures only; no native, HE or fresh crypto keys."""

# ruff: noqa: E402 -- standalone public subprocess fixture adds its repository root.
from __future__ import annotations

import argparse
import copy
from dataclasses import replace
import json
import os
from pathlib import Path
import pickle
import signal
import socket
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import pytest

from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_supervisor as supervisor
from experiments.bfv_search_lab import complete_cost_transport as transport


def start(tmp_path, *, timeout=3_000_000_000):
    return supervisor.PublicSupervisor(
        tmp_path / "supervisor.json",
        source_pin=supervisor.pinned(supervisor.__file__),
        python_pin=supervisor.pinned(sys.executable),
        timeout_ns=timeout,
    )


def spec(tmp_path, *, label="echo", fault="none"):
    entry = supervisor.pinned(__file__)
    config, freeze = tmp_path / (label + ".config.json"), tmp_path / (label + ".freeze.json")
    config.write_text(json.dumps({"role": "frontend", "fault": fault}))
    freeze.write_text(json.dumps({"new_sources": [entry], "preserved_runtime_sources": []}))
    return supervisor.WorkerSpec(
        label,
        entry,
        str(config),
        str(freeze),
        str(tmp_path / (label + ".result.json")),
        min(os.sched_getaffinity(0)),
    )


def summary(tmp_path):
    return json.loads((tmp_path / "supervisor.json").read_text())


def test_clean_supervisor_spawn_and_owned_child_roundtrip(tmp_path, monkeypatch):
    # Public marker, not any real credential/key. Arbitrary owner environment is absent.
    monkeypatch.setenv("Q77_PUBLIC_UNIT_OWNER_MARKER", "must-not-reach-worker")
    pool = start(tmp_path)
    item = spec(tmp_path)
    try:
        ready = pool.start((item,))[item.label]
        assert ready["process"] not in (os.getpid(), pool.process_id)
        sock = socket.create_connection(("127.0.0.1", ready["port"]), timeout=1)
        stream = transport.BoundedStream(
            sock, cap=4096, link=supervisor.UNSHAPED, timeout_ns=1_000_000_000
        )
        try:
            stream.send(auth._pack([b"public"]), kind="unit-public-echo")
            assert stream.receive(kind="unit-public-reply") == auth._pack([b"public"])
        finally:
            stream.close()
        pool.stop((item.label,))
    finally:
        pool.close()
    value = summary(tmp_path)
    assert value["process"] == pool.process_id and value["attempts"][0]["exit_code"] == 0
    child = json.loads(Path(item.output).read_text())
    assert child["parent"] == pool.process_id and not child["owner_environment_marker_present"]
    assert child["cpu"] == [item.cpu] and child["HE_private_calls"] == 0
    observation = json.loads(Path(item.output + ".private-observation.json").read_text())
    assert observation["private_work_attempts"] == 0


def test_consumed_label_cannot_spawn_replacement(tmp_path):
    pool = start(tmp_path)
    first = spec(tmp_path)
    try:
        pool.start((first,))
        pool.stop((first.label,))
        other = spec(tmp_path, label="other")
        other = replace(other, label=first.label)
        with pytest.raises(RuntimeError):
            pool.start((other,))
        with pytest.raises(RuntimeError):
            pool.start((spec(tmp_path, label="third"),))
    finally:
        pool.close()
    assert len(summary(tmp_path)["attempts"]) == 1


@pytest.mark.parametrize("fault", ("wrong-pid", "no-ready"))
def test_startup_failure_retains_and_terminates_exact_owned_child(tmp_path, fault):
    pool = start(tmp_path, timeout=500_000_000)
    item = spec(tmp_path, fault=fault)
    try:
        with pytest.raises(RuntimeError):
            pool.start((item,))
    finally:
        pool.close()
    attempts = summary(tmp_path)["attempts"]
    assert len(attempts) == 1 and attempts[0]["status"] == "startup-failed"
    assert attempts[0]["exit_code"] is not None
    assert Path(item.output + ".stdout.log").exists() and Path(item.output + ".stderr.log").exists()


def test_changed_frozen_entry_rejected_before_child_creation(tmp_path):
    pool = start(tmp_path)
    item = spec(tmp_path)
    changed = replace(item, entry={**item.entry, "sha256": "0" * 64})
    try:
        with pytest.raises(ValueError):
            pool.start((changed,))
    finally:
        pool.close()
    assert summary(tmp_path)["attempts"] == []


def test_supervisor_handle_rejects_copy_and_inherited_use_before_lock(tmp_path):
    pool = start(tmp_path)
    try:
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError):
                operation(pool)
        old = pool._pid
        pool._pid = old + 1
        pool._lock.acquire()
        try:
            with pytest.raises(RuntimeError):
                pool.stop(("public",))
        finally:
            pool._pid = old
            pool._lock.release()
    finally:
        pool.close()


def unit_worker():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("worker",))
    parser.add_argument("--config", type=Path)
    parser.add_argument("--freeze", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cpu", type=int)
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text())
    os.sched_setaffinity(0, {args.cpu})
    if cfg["fault"] == "no-ready":
        time.sleep(5)
        return
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    print(
        json.dumps(
            {
                "port": listener.getsockname()[1],
                "process": os.getpid() + int(cfg["fault"] == "wrong-pid"),
                "local_verifier_public_key": None,
            }
        ),
        flush=True,
    )
    try:
        while True:
            sock, _ = listener.accept()
            stream = transport.BoundedStream(
                sock, cap=4096, link=supervisor.UNSHAPED, timeout_ns=1_000_000_000
            )
            try:
                request = stream.receive(kind="unit-public-command")
                stream.send(request, kind="unit-public-echo")
                if auth._unpack(request, limit=4096, array_cap=1) == [b"stop"]:
                    break
            finally:
                stream.close()
    finally:
        listener.close()
        with args.output.open("x") as saved:
            saved.write(
                json.dumps(
                    {
                        "parent": os.getppid(),
                        "cpu": sorted(os.sched_getaffinity(0)),
                        "owner_environment_marker_present": "Q77_PUBLIC_UNIT_OWNER_MARKER"
                        in os.environ,
                        "HE_private_calls": 0,
                    }
                )
                + "\n"
            )


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
            raise RuntimeError("Public subprocess unit forbids private HE work")
        if event == "c_call" and str(getattr(arg, "__module__", "")).endswith("_bgv_private"):
            private_calls.append(getattr(arg, "__name__", "?"))
            raise RuntimeError("Public subprocess unit forbids native private work")

    def terminate(_signal, _frame):
        raise SystemExit(143)

    signal.signal(signal.SIGTERM, terminate)
    sys.setprofile(guard)
    try:
        unit_worker()
    finally:
        sys.setprofile(None)
        output = Path(sys.argv[sys.argv.index("--output") + 1] + ".private-observation.json")
        with output.open("x") as saved:
            saved.write(
                json.dumps(
                    {
                        "process": os.getpid(),
                        "private_work_attempts": len(private_calls),
                        "blocked_private_entries": private_calls,
                        "scope": "Public echo entry only; imports precede this function guard",
                    }
                )
                + "\n"
            )
