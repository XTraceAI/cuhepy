"""Filesystem and process-isolation contracts for the follow-up phase runner.

These tests start only short synthetic Python workers. They use real file locks,
process sessions, signals and receipts; environmental telemetry is replaced at
its boundary so a GPU or an idle host is not required. They do not test resource
qualification or claim that the synthetic receipts are measurement evidence.
"""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest


pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="The phase runner uses Linux /proc, affinity and POSIX process groups",
)

PHASE_DIRECTORY = Path(__file__).resolve().parents[1] / "benchmarks"

# Keep the production lock, worker lifecycle and result checks intact. Replace
# only the host/GPU sampler: real nvidia-smi availability and concurrent desktop
# programs should not determine whether a process-safety test can execute.
BOOTSTRAP = r"""
import json
from pathlib import Path
import sys
import threading

sys.path.insert(0, sys.argv.pop(1))
import revalidation_phase as phase

class NeutralTelemetry:
    def __init__(self, path):
        self.path = path
        self.thread = threading.Thread(target=self.record_boundary)

    def record_boundary(self):
        self.path.write_text(json.dumps({'test_fixture': 'neutral telemetry boundary'}) + '\n')

    def conditions(self, *args):
        return {'qualified_by_conditions': False, 'test_fixture': True}

    def finish(self):
        self.thread.join(timeout=5)
        assert not self.thread.is_alive()

phase.Telemetry = NeutralTelemetry
raise SystemExit(phase.main())
"""


def phase_attempt(tmp_path, worker_code, required, timeout_s=10):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "evidence"
    lock = tmp_path / "serial.lock"
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"jobs": [{
        "id": "synthetic", "command": [sys.executable, "-c", worker_code],
        "cwd": str(source), "environment": {}, "timeout_s": timeout_s,
        "required_outputs": [str(path) for path in required],
    }]}))
    command = [sys.executable, "-c", BOOTSTRAP, str(PHASE_DIRECTORY),
               "--plan", str(plan), "--id", "synthetic", "--output", str(output),
               "--lock", str(lock), "--preflight-s", "0"]
    return command, output, lock


def launch(command):
    # Test teardown may signal only this deliberately created session.
    return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)


def wait_json(path, process, predicate=lambda value: True, timeout_s=10):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            value = json.loads(path.read_text())
            if predicate(value):
                return value
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        if process.poll() is not None:
            pytest.fail(f"Phase exited before expected evidence appeared: {path}")
        time.sleep(.02)
    pytest.fail(f"Timed out waiting for test-owned evidence: {path}")


def stop_created_session(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=5)


def process_is_running(pid):
    try:
        # A killed orphan may remain a zombie until the host reaps it. It cannot
        # compute or retain a live worker; do not confuse it with failed cleanup.
        stat = Path(f"/proc/{pid}/stat").read_text()
        return stat[stat.rindex(")") + 2:].split()[0] != "Z"
    except FileNotFoundError:
        return False


def test_artifact_created_while_waiting_for_lock_is_preserved(tmp_path):
    import fcntl

    required = tmp_path / "result.json"
    ran = tmp_path / "worker-ran"
    worker = ("from pathlib import Path; "
              f"Path({str(ran)!r}).write_text('executed'); "
              f"Path({str(required)!r}).write_text('overwritten')")
    command, output, lock_path = phase_attempt(tmp_path, worker, [required])
    process = None
    with lock_path.open("a") as held_lock:
        fcntl.flock(held_lock, fcntl.LOCK_EX)
        try:
            process = launch(command)
            wait_json(output / "receipt.json", process,
                      lambda receipt: receipt["state"] == "waiting_for_serial_lock")
            existing = b'{"belongs_to":"other completed phase"}\n'
            required.write_bytes(existing)
            fcntl.flock(held_lock, fcntl.LOCK_UN)
            stdout, stderr = process.communicate(timeout=15)
            receipt = json.loads((output / "receipt.json").read_text())
            assert process.returncode != 0, (stdout, stderr)
            assert receipt["state"] == "failed"
            assert receipt["error"]["type"] == "FileExistsError"
            assert required.read_bytes() == existing
            assert not ran.exists(), "A stale-output collision must prevent worker launch"
            assert not (output / "stdout.log").exists()
        finally:
            fcntl.flock(held_lock, fcntl.LOCK_UN)
            if process is not None:
                stop_created_session(process)


def test_successful_worker_without_required_artifact_is_failed(tmp_path):
    required = tmp_path / "missing-result.json"
    ran = tmp_path / "worker-ran"
    worker = f"from pathlib import Path; Path({str(ran)!r}).write_text('executed')"
    command, output, _ = phase_attempt(tmp_path, worker, [required])
    process = launch(command)
    try:
        stdout, stderr = process.communicate(timeout=15)
        receipt = json.loads((output / "receipt.json").read_text())
        assert ran.is_file()
        assert process.returncode != 0, (stdout, stderr)
        assert receipt["returncode"] == 0
        assert receipt["state"] == "failed"
        assert receipt["required_outputs"][str(required)] is None
        assert not required.exists()
    finally:
        stop_created_session(process)


@pytest.mark.parametrize("termination", ["normal_exit", "timeout", "sigterm"])
def test_owned_children_are_stopped_and_unrelated_session_survives(tmp_path, termination):
    import fcntl

    child_record = tmp_path / "owned-child.json"
    cleanup_started = tmp_path / "owned-child-received-term"
    required = tmp_path / "result.json"
    # The child deliberately survives SIGTERM so the real helper must exercise
    # bounded SIGKILL cleanup. It never detaches from the worker's session.
    child = r"""
import json, os, signal, sys, time
from pathlib import Path
signal.signal(signal.SIGTERM, lambda *_: Path(sys.argv[3]).write_text('TERM observed'))
Path(sys.argv[1]).write_text(json.dumps({'pid': os.getpid(), 'group': os.getpgrp(),
                                      'worker_pid': int(sys.argv[2])}))
time.sleep(120)
"""
    worker = f"""
import os, subprocess, sys, time
from pathlib import Path
subprocess.Popen([sys.executable, '-c', {child!r}, {str(child_record)!r},
                  str(os.getpid()), {str(cleanup_started)!r}])
deadline = time.monotonic() + 5
while not Path({str(child_record)!r}).exists():
    assert time.monotonic() < deadline, 'Child did not start'
    time.sleep(.01)
Path({str(required)!r}).write_text('synthetic worker reached its boundary')
if {termination!r} != 'normal_exit':
    time.sleep(120)
"""
    command, output, lock_path = phase_attempt(
        tmp_path, worker, [required], timeout_s=2 if termination == "timeout" else 30)
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
    process = None
    owned = None
    try:
        process = launch(command)
        owned = wait_json(child_record, process)
        assert owned["group"] == owned["worker_pid"]
        assert owned["group"] not in {os.getpgrp(), unrelated.pid, process.pid}
        if termination == "sigterm":
            # Signal only our phase. Its registered handler must route this
            # cancellation through worker-group cleanup, then release the lock.
            process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=25)
        receipt = json.loads((output / "receipt.json").read_text())
        assert cleanup_started.is_file(), "The owned child never received cleanup"
        assert not process_is_running(owned["pid"])
        assert unrelated.poll() is None, "Cleanup terminated an unrelated session"
        os.kill(unrelated.pid, 0)
        if termination == "normal_exit":
            assert process.returncode == 0, (stdout, stderr)
            assert receipt["state"] == "completed"
        else:
            assert process.returncode != 0, (stdout, stderr)
            assert receipt["state"] == "failed"
            assert receipt["error"]["type"] == (
                "TimeoutExpired" if termination == "timeout" else "KeyboardInterrupt")
        # The next task can acquire the lock only after its predecessor has
        # finished and its owned worker group has stopped.
        with lock_path.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(lock, fcntl.LOCK_UN)
    finally:
        if process is not None:
            stop_created_session(process)
        if owned is not None:
            # Bound test teardown to the recorded session of the worker this
            # test launched. Never enumerate or signal other host processes.
            try:
                os.killpg(owned["group"], signal.SIGKILL)
            except ProcessLookupError:
                pass
        stop_created_session(unrelated)
