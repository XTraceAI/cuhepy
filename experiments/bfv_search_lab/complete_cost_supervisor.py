"""Q77 clean public supervisor and fixed local worker ownership.

Launch this supervisor before the owner generates either HE key. Subsequent
public workers are children of its HE-secret-free process, not the HE owner.
The trusted local control channel conveys explicit pinned public specifications;
it is not an untrusted RPC or attestation channel. Actual HE custody, shared
relay topology and whole owner event DAG remain execution-freeze obligations.
"""

# ruff: noqa: E402 -- standalone subprocess entry point adds its repository root.
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_transport as transport

CONTROL_CAP = 65536
HEADER = struct.Struct("!I")
UNSHAPED = transport.Link(1 << 40, 0)


def pinned(path):
    path = Path(path).resolve(strict=True)
    data = path.read_bytes()
    return {"file": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def check_pin(entry):
    if (
        type(entry) is not dict
        or set(entry) != {"file", "bytes", "sha256"}
        or type(entry["file"]) is not str
        or not Path(entry["file"]).is_absolute()
        or type(entry["bytes"]) is not int
        or entry["bytes"] < 0
        or type(entry["sha256"]) is not str
        or pinned(entry["file"]) != entry
    ):
        raise ValueError("Exact trusted public source/runtime pin required")


def public_environment():
    # Do not inherit arbitrary owner environment variables into public workers.
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(ROOT),
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
    }


def _read(sock, size, deadline):
    result = bytearray(size)
    at = 0
    while at < size:
        remaining = deadline - time.perf_counter_ns()
        if remaining <= 0:
            raise TimeoutError("Public control deadline exhausted")
        if not select.select([sock], [], [], min(remaining / 1e9, 0.1))[0]:
            continue
        got = sock.recv_into(memoryview(result)[at:])
        if got == 0:
            raise EOFError("Public control peer closed")
        at += got
    return bytes(result)


def _receive(sock, deadline):
    size = HEADER.unpack(_read(sock, HEADER.size, deadline))[0]
    if not 1 <= size <= CONTROL_CAP:
        raise ValueError("Public control frame exceeds its bound")
    data = _read(sock, size, deadline)
    value = json.loads(data)
    if json.dumps(value, separators=(",", ":"), sort_keys=True).encode() != data:
        raise ValueError("Noncanonical bounded public control JSON")
    return value


def _send(sock, value, deadline):
    data = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    if not 1 <= len(data) <= CONTROL_CAP:
        raise ValueError("Public control frame exceeds its bound")
    view, at = memoryview(HEADER.pack(len(data)) + data), 0
    while at < len(view):
        remaining = deadline - time.perf_counter_ns()
        if remaining <= 0:
            raise TimeoutError("Public control deadline exhausted")
        if not select.select([], [sock], [], min(remaining / 1e9, 0.1))[1]:
            continue
        wrote = sock.send(view[at:])
        if wrote == 0:
            raise EOFError("Public control peer closed")
        at += wrote


@dataclass(frozen=True)
class WorkerSpec:
    label: str
    entry: dict
    config: str
    freeze: str
    output: str
    cpu: int

    def validate(self, *, available_cpus=None):
        if (
            type(self.label) is not str
            or not 1 <= len(self.label) <= 64
            or any(
                c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                for c in self.label
            )
            or type(self.cpu) is not int
            or not 0 <= self.cpu < (os.cpu_count() or 1)
            or available_cpus is not None
            and self.cpu not in available_cpus
        ):
            raise ValueError("Explicit public worker label/available affinity required")
        check_pin(self.entry)
        for name in ("config", "freeze", "output"):
            value = getattr(self, name)
            if type(value) is not str or not Path(value).is_absolute() or len(value) > 4096:
                raise ValueError("Explicit absolute public worker paths required")
        config = json.loads(Path(self.config).read_text())
        if config["role"] not in ("frontend", "protected"):
            raise ValueError("Explicit fixed public/protected role required")
        freeze = json.loads(Path(self.freeze).read_text())
        if self.entry not in freeze["new_sources"] + freeze["preserved_runtime_sources"]:
            raise ValueError("Worker entry is absent from its execution freeze")
        for path in (self.output, self.output + ".stdout.log", self.output + ".stderr.log"):
            if Path(path).exists():
                raise ValueError("Never replace a consumed worker artifact")
        return config["role"]

    def fields(self, *, available_cpus=None):
        self.validate(available_cpus=available_cpus)
        return [self.label, self.entry, self.config, self.freeze, self.output, self.cpu]


def _terminate(process):
    # Affect only the exact process handle owned by this supervisor.
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def _terminate_manager(process):
    # Manager owns a fresh session; all its fixed workers remain in this group.
    # This also cleans children if the manager itself becomes unresponsive.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=2)


def _ready(process, spec, role, deadline):
    path = Path(spec.output + ".stdout.log")
    while time.perf_counter_ns() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Public worker ended before readiness")
        with path.open("rb") as stream:
            data = stream.read(4097)
        if len(data) > 4096:
            raise ValueError("Public worker readiness exceeded its bound")
        if b"\n" in data:
            record = json.loads(data.split(b"\n", 1)[0])
            if (
                type(record) is not dict
                or set(record) != {"port", "process", "local_verifier_public_key"}
                or type(record["process"]) is not int
                or record["process"] != process.pid
                or type(record["port"]) is not int
                or not 1 <= record["port"] <= 65535
            ):
                raise ValueError("Public worker readiness differs from its owned process")
            key = record["local_verifier_public_key"]
            if role == "frontend":
                if key is not None:
                    raise ValueError("Frontend cannot provision a verifier anchor")
            elif type(key) is not str or len(key) != 64 or len(bytes.fromhex(key)) != 32:
                raise ValueError("Complete separately provisioned verifier public key required")
            return record
        time.sleep(0.01)
    raise TimeoutError("Public worker readiness deadline exhausted")


def _stop(process, ready, deadline):
    if process.poll() is not None:
        return
    try:
        sock = socket.create_connection(
            ("127.0.0.1", ready["port"]),
            timeout=min(1, max(0.001, (deadline - time.perf_counter_ns()) / 1e9)),
        )
        stream = transport.BoundedStream(
            sock, cap=4096, link=UNSHAPED, timeout_ns=max(1, deadline - time.perf_counter_ns())
        )
        try:
            stream.send(auth._pack([b"stop"]), kind="supervisor-stop")
            stream.receive(kind="supervisor-stop-reply")
        finally:
            stream.close()
        process.wait(timeout=max(0.001, (deadline - time.perf_counter_ns()) / 1e9))
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        _terminate(process)


def _supervise(sock, summary, timeout_ns):
    processes, attempts, seen = {}, [], set()
    stopping = False
    try:
        _send(sock, ["ready", os.getpid()], time.perf_counter_ns() + timeout_ns)
        while not stopping:
            # Idle lifetime is controlled by the owner; each command has a deadline.
            if not select.select([sock], [], [], 0.25)[0]:
                continue
            deadline = time.perf_counter_ns() + timeout_ns
            command = _receive(sock, deadline)
            try:
                if type(command) is not list or not command:
                    raise ValueError("Public supervisor command required")
                if (
                    command[0] == "start"
                    and len(command) == 2
                    and type(command[1]) is list
                    and 1 <= len(command[1]) <= 6
                ):
                    result = []
                    for fields in command[1]:
                        if type(fields) is not list or len(fields) != 6:
                            raise ValueError("Complete public worker specification required")
                        spec = WorkerSpec(*fields)
                        role = spec.validate(available_cpus=os.sched_getaffinity(0))
                        if spec.label in seen:
                            raise ValueError("Worker attempt already consumed")
                        seen.add(spec.label)
                        attempt = {
                            "label": spec.label,
                            "role": role,
                            "started_ns": time.perf_counter_ns(),
                            "status": "starting",
                        }
                        attempts.append(attempt)
                        with (
                            Path(spec.output + ".stdout.log").open("xb") as stdout,
                            Path(spec.output + ".stderr.log").open("xb") as stderr,
                        ):
                            argv = [
                                sys.executable,
                                "-u",
                                spec.entry["file"],
                                "worker",
                                "--config",
                                spec.config,
                                "--freeze",
                                spec.freeze,
                                "--output",
                                spec.output,
                                "--cpu",
                                str(spec.cpu),
                            ]
                            process = subprocess.Popen(
                                argv,
                                cwd=ROOT,
                                env=public_environment(),
                                stdin=subprocess.DEVNULL,
                                stdout=stdout,
                                stderr=stderr,
                                close_fds=True,
                            )
                        processes[spec.label] = (process, None, spec, attempt)
                        attempt["process"] = process.pid
                        ready = _ready(process, spec, role, deadline)
                        processes[spec.label] = (process, ready, spec, attempt)
                        attempt.update(
                            status="ready", ready_ns=time.perf_counter_ns(), announcement=ready
                        )
                        result.append([spec.label, ready])
                    _send(sock, ["ok", result], deadline)
                elif (
                    command[0] == "stop"
                    and len(command) == 2
                    and type(command[1]) is list
                    and command[1]
                    and len(set(command[1])) == len(command[1])
                ):
                    for label in command[1]:
                        process, ready, _spec, attempt = processes[label]
                        _stop(process, ready, deadline)
                        attempt.update(
                            status="stopped",
                            exit_code=process.returncode,
                            stopped_ns=time.perf_counter_ns(),
                        )
                    _send(sock, ["ok", []], deadline)
                elif command == ["close"]:
                    stopping = True
                    _send(sock, ["ok", []], deadline)
                else:
                    raise ValueError("Unsupported public supervisor command")
            except (OSError, ValueError, RuntimeError, KeyError, TypeError, TimeoutError):
                _send(sock, ["error"], time.perf_counter_ns() + min(timeout_ns, 1_000_000_000))
                break  # Fail the whole manager; never replace a consumed child.
    except (EOFError, OSError, ValueError, TimeoutError):
        pass
    finally:
        for process, ready, spec, attempt in processes.values():
            if process.poll() is None:
                if ready is None:
                    _terminate(process)
                else:
                    _stop(process, ready, time.perf_counter_ns() + 2_000_000_000)
            attempt.update(exit_code=process.returncode, finished_ns=time.perf_counter_ns())
            if attempt["status"] == "starting":
                attempt["status"] = "startup-failed"
            attempt["stdout"] = pinned(spec.output + ".stdout.log")
            attempt["stderr"] = pinned(spec.output + ".stderr.log")
        with Path(summary).open("x") as saved:
            saved.write(
                json.dumps(
                    {
                        "process": os.getpid(),
                        "attempts": attempts,
                        "public_specification_only_interface": True,
                        "actual_HE_custody_assurance_pending": True,
                    },
                    indent=2,
                )
                + "\n"
            )
        sock.close()


class PublicSupervisor:
    """Trusted-owner handle; construct before HE key generation and retain it.

    It imports no owner key, carries no arbitrary environment, and launches
    future workers from the clean manager. This API cannot prove that its caller
    has no key already; real cohort order/custody must be inspected and frozen.
    """

    def __init__(self, summary, *, source_pin, python_pin, timeout_ns):
        check_pin(source_pin)
        check_pin(python_pin)
        if source_pin != pinned(__file__) or python_pin != pinned(sys.executable):
            raise ValueError("Pinned supervisor and actual Python executable required")
        if type(timeout_ns) is not int or not 1_000_000 <= timeout_ns <= 900_000_000_000:
            raise ValueError("Explicit public process deadline required")
        self._pid, self._closed = os.getpid(), False
        self._available_cpus = tuple(os.sched_getaffinity(0))
        self._lock, self._timeout = threading.RLock(), timeout_ns
        self.summary = Path(summary).resolve()
        if self.summary.exists():
            raise ValueError("Never replace a supervisor result")
        self._control, child = socket.socketpair()
        try:
            self._process = subprocess.Popen(
                [
                    sys.executable,
                    "-u",
                    str(Path(__file__).resolve()),
                    "supervisor",
                    "--control-fd",
                    str(child.fileno()),
                    "--summary",
                    str(self.summary),
                    "--timeout-ns",
                    str(timeout_ns),
                ],
                cwd=ROOT,
                env=public_environment(),
                pass_fds=(child.fileno(),),
                close_fds=True,
                start_new_session=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            ready = _receive(self._control, time.perf_counter_ns() + timeout_ns)
            if ready != ["ready", self._process.pid]:
                raise RuntimeError("Public supervisor readiness differs from owned process")
        except BaseException:
            self._control.close()
            if hasattr(self, "_process"):
                _terminate_manager(self._process)
            self._closed = True
            raise
        finally:
            child.close()

    @property
    def process_id(self):
        return self._process.pid

    def _owned(self):
        if os.getpid() != self._pid:
            raise RuntimeError("Inherited public supervisor handle")
        if self._closed:
            raise RuntimeError("Closed public supervisor handle")

    def _request(self, command):
        self._owned()
        with self._lock:
            self._owned()
            try:
                deadline = time.perf_counter_ns() + self._timeout
                _send(self._control, command, deadline)
                reply = _receive(self._control, deadline)
                if type(reply) is not list or len(reply) != 2 or reply[0] != "ok":
                    raise RuntimeError("Public supervisor rejected the task")
                return reply[1]
            except BaseException:
                self._closed = True
                self._control.close()
                try:
                    self._process.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    _terminate_manager(self._process)
                raise RuntimeError("Public supervisor task failed") from None

    def start(self, specs):
        if (
            type(specs) is not tuple
            or not 1 <= len(specs) <= 6
            or any(type(x) is not WorkerSpec for x in specs)
        ):
            raise ValueError("Complete tuple of pinned public specifications required")
        return dict(
            self._request(
                ["start", [spec.fields(available_cpus=self._available_cpus) for spec in specs]]
            )
        )

    def stop(self, labels):
        if type(labels) is not tuple or not labels or any(type(x) is not str for x in labels):
            raise ValueError("Owned public labels required")
        self._request(["stop", list(labels)])

    def close(self):
        if os.getpid() != self._pid:
            raise RuntimeError("Inherited public supervisor handle")
        with self._lock:
            if self._closed:
                return
            try:
                self._request(["close"])
            finally:
                self._closed = True
                self._control.close()
                try:
                    self._process.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    _terminate_manager(self._process)

    def __copy__(self):
        raise TypeError("Public supervisors cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Public supervisors cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Public supervisors cannot be serialized")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("supervisor", "worker"))
    parser.add_argument("--control-fd", type=int)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--timeout-ns", type=int)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--freeze", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cpu", type=int)
    args = parser.parse_args()
    if args.action == "supervisor":
        if (
            args.control_fd is None
            or args.summary is None
            or args.summary.exists()
            or type(args.timeout_ns) is not int
        ):
            raise ValueError("Explicit new supervisor control and result required")
        _supervise(socket.socket(fileno=args.control_fd), args.summary, args.timeout_ns)
    else:
        if (
            args.config is None
            or args.freeze is None
            or args.output is None
            or args.output.exists()
            or type(args.cpu) is not int
        ):
            raise ValueError("Explicit fresh pinned role inputs required")
        from benchmarks.complete_cost_shared_query_lab import LocalRole, serve

        os.sched_setaffinity(0, {args.cpu})
        role = LocalRole(args.config, args.freeze)
        # Shared client directions are charged by the relay, once. The
        # protected role's internal link remains shaped inside LocalRole.
        serve(
            role,
            args.output,
            cpu=args.cpu,
            link=UNSHAPED if role.role == "frontend" else transport.Link(1_250_000_000, 100_000),
        )


if __name__ == "__main__":
    main()
