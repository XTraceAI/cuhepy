"""Q77 shared client endpoint and fixed public search/cache/setup relay.

One owner endpoint owns the upload lane; one relay owns the download lane.
All competing connections share those budgets. The relay/backend hop is an
explicit unshaped local dispatch, with its copies/work/bytes recorded. These
declared loopback conditions are not a deployed network or authenticated TEE.
Only public opaque packets and separately trusted local configuration belong
here. The relay neither holds an owner secret nor authorizes private work.
"""

# ruff: noqa: E402 -- public worker entry adds the repository root.
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import resource
import socket
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_network as network
from experiments.bfv_search_lab import complete_cost_transport as transport
from experiments.bfv_search_lab import complete_cost_supervisor as supervisor

ERROR_TAG = b"cuhepy/Q77/public-worker-failure/v1"
OK_TAG = b"cuhepy/Q77/public-worker-ok/v1"
LOCAL_DISPATCH = transport.Link(1 << 40, 0)
MAX_CONNECTIONS = 4


def _port(value, *, absent=False):
    if absent and value is None:
        return
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("Trusted fixed loopback backend port required")


def _remaining(deadline_ns):
    if type(deadline_ns) is not int:
        raise ValueError("Absolute task deadline required")
    remaining = deadline_ns - time.perf_counter_ns()
    if remaining <= 0:
        raise transport.TransportError("Public task deadline exhausted")
    return min(remaining, 3_600_000_000_000)


def _read_pin(entry, cap):
    supervisor.check_pin(entry)
    if not 1 <= entry["bytes"] <= cap:
        raise ValueError("Public store packet exceeds fixed cap")
    # check_pin rehashes through a bounded file reader. A read is verified too,
    # so a change between that check and the actual read cannot enter a reply.
    data = Path(entry["file"]).read_bytes()
    if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError("Pinned public packet changed during read")
    return data


class OwnerEndpoint:
    """One process-owned upload lane for all owner threads/connections.

    The caller performs the existing descriptor/receipt/cache authentication.
    This transport cannot choose a decoder or replace that authorization. A
    failed connection is consumed and closed; this class never retries it.
    """

    def __init__(self, port, *, upload_budget, cap, timeout_ns):
        _port(port)
        if (
            type(upload_budget) is not network.DirectionBudget
            or type(cap) is not int
            or not 1 <= cap <= transport.MAX_FRAME
            or type(timeout_ns) is not int
            or not 1 <= timeout_ns <= 3_600_000_000_000
        ):
            raise ValueError("Explicit shared upload lane and trusted bounds required")
        upload_budget._process()
        self.port, self.cap, self.timeout_ns = port, cap, timeout_ns
        self.upload_budget, self._pid = upload_budget, os.getpid()
        self._lock, self._closed = threading.Lock(), False
        self._streams, self._transfers = set(), []

    def _process(self):
        if self._pid != os.getpid():
            raise RuntimeError("Inherited owner endpoint")

    def _record(self, record):
        with self._lock:
            self._transfers.append(record)

    def rpc(self, packet, *, deadline_ns=None):
        self._process()
        if type(packet) is not bytes or not 1 <= len(packet) <= self.cap:
            raise ValueError("Immutable bounded owner command required")
        start = time.perf_counter_ns()
        deadline = start + self.timeout_ns if deadline_ns is None else deadline_ns
        if type(deadline) is not int or not start < deadline <= start + self.timeout_ns:
            raise ValueError("Explicit bounded absolute owner deadline required")
        with self._lock:
            if self._closed:
                raise RuntimeError("Closed owner endpoint")
        sock = socket.create_connection(
            ("127.0.0.1", self.port), timeout=min(_remaining(deadline) / 1e9, 5)
        )
        try:
            stream = network.BudgetedStream(
                sock,
                budget=self.upload_budget,
                cap=self.cap,
                timeout_ns=_remaining(deadline),
                observer=self._record,
            )
        except BaseException:
            sock.close()
            raise
        with self._lock:
            if self._closed:
                stream.close()
                raise RuntimeError("Owner endpoint closed during connection")
            self._streams.add(stream)
        try:
            stream.send(packet, kind="client-upload")
            stream.timeout_ns = _remaining(deadline)
            reply = stream.receive(kind="client-download")
            fields = auth._unpack(reply, limit=self.cap, array_cap=9)
            if type(fields) is list and fields and fields[0] == ERROR_TAG:
                raise RuntimeError("Public relay rejected the task")
            return reply
        finally:
            stream.close()
            with self._lock:
                self._streams.discard(stream)

    def inventory(self):
        self._process()
        with self._lock:
            return {
                "process": self._pid,
                "active_connections": len(self._streams),
                "transfers": [r.as_dict() for r in self._transfers],
                "upload_credits": [asdict(r) for r in self.upload_budget.history()],
                "role": "owner-client-link-endpoint",
                "private_authority": False,
            }

    def close(self):
        self._process()
        with self._lock:
            self._closed = True
            streams = tuple(self._streams)
        for stream in streams:
            stream.close()

    def __copy__(self):
        raise TypeError("Owner endpoint cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Owner endpoint cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Owner endpoint cannot be serialized")


class PublicRelay:
    """Fixed routing and owner-controlled public packets; no private capability.

    Mutable configuration is a trusted local owner input. It can advance the
    stored signed cache packets and bind an initially absent backend once.
    Received commands cannot supply paths, ports, libraries or configuration.
    An upload targets exactly one preregistered immutable public file and may
    not replace an already consumed target, even after a partial failure.
    """

    def __init__(self, config_path, freeze_path):
        self.config_path = Path(config_path).resolve(strict=True)
        freeze = json.loads(Path(freeze_path).read_text())
        for item in (
            freeze["new_sources"] + freeze["preserved_runtime_sources"] + freeze["dependencies"]
        ):
            supervisor.check_pin(item)
        cfg = json.loads(self.config_path.read_text())
        required = {
            "role",
            "service",
            "search_port",
            "cap",
            "timeout_ns",
            "client_link",
            "upload",
            "snapshot",
            "patch",
        }
        if (
            set(cfg) != required
            or cfg["role"] != "frontend"
            or cfg["service"] != "shared-client-relay"
        ):
            raise ValueError("Fixed public relay configuration required")
        _port(cfg["search_port"], absent=True)
        cap, timeout_ns = cfg["cap"], cfg["timeout_ns"]
        if (
            type(cap) is not int
            or not 1 <= cap <= transport.MAX_FRAME
            or type(timeout_ns) is not int
            or not 1 <= timeout_ns <= 900_000_000_000
        ):
            raise ValueError("Bounded relay cap and deadline required")
        if set(cfg["client_link"]) != {"bytes_per_second", "one_way_delay_ns"}:
            raise ValueError("Explicit directional link conditions required")
        self.cap, self.timeout_ns = cap, timeout_ns
        self.download_budget = network.DirectionBudget(transport.Link(**cfg["client_link"]))
        self._immutable = {k: cfg[k] for k in required - {"search_port", "snapshot", "patch"}}
        self._backend, self._pid = cfg["search_port"], os.getpid()
        self._lock, self._stopping = threading.Lock(), False
        self._transfers, self._stages = [], []
        self._upload_consumed = False
        if cfg["upload"] is not None:
            entry = cfg["upload"]
            if (
                type(entry) is not dict
                or set(entry) != {"file", "bytes", "sha256"}
                or type(entry["file"]) is not str
                or not Path(entry["file"]).is_absolute()
                or type(entry["bytes"]) is not int
                or not 1 <= entry["bytes"] <= cap
                or type(entry["sha256"]) is not str
                or len(entry["sha256"]) != 64
            ):
                raise ValueError("One fixed future public upload required")
            if bytes.fromhex(entry["sha256"]).hex() != entry["sha256"]:
                raise ValueError("Canonical public upload digest required")
            if Path(entry["file"]).exists():
                raise ValueError("Public upload target already consumed")
            Path(entry["file"]).parent.resolve(strict=True)

    def _process(self):
        if self._pid != os.getpid():
            raise RuntimeError("Inherited public relay")

    @property
    def stopping(self):
        self._process()
        with self._lock:
            return self._stopping

    def record(self, transfer):
        self._process()
        with self._lock:
            self._transfers.append(transfer)

    def _config(self):
        cfg = json.loads(self.config_path.read_text())
        if set(cfg) != set(self._immutable) | {"search_port", "snapshot", "patch"}:
            raise ValueError("Trusted relay configuration grammar changed")
        if {k: cfg[k] for k in self._immutable} != self._immutable:
            raise ValueError("Trusted relay roots/bounds changed")
        _port(cfg["search_port"], absent=True)
        with self._lock:
            if self._backend is None:
                self._backend = cfg["search_port"]
            elif self._backend != cfg["search_port"]:
                raise ValueError("Fixed relay backend changed")
        return cfg

    def execute(self, packet, *, deadline_ns):
        self._process()
        if _remaining(deadline_ns) > self.timeout_ns:
            raise ValueError("Bounded absolute relay deadline required")
        fields = auth._unpack(packet, limit=self.cap, array_cap=3)
        if type(fields) is not list or not fields or type(fields[0]) is not bytes:
            raise ValueError("Bounded relay command required")
        if fields[0] not in (b"search", b"snapshot", b"patch", b"upload", b"stop"):
            raise ValueError("Unsupported fixed public relay command")
        cfg = self._config()
        verb, start, cpu = fields[0], time.perf_counter_ns(), time.thread_time_ns()
        completed = False
        try:
            if verb == b"stop" and len(fields) == 1:
                with self._lock:
                    self._stopping = True
                reply = auth._pack([OK_TAG])
            elif verb == b"search" and len(fields) == 2 and type(fields[1]) is bytes:
                if self._backend is None:
                    raise ValueError("Public backend has not been bound by the owner")
                sock = socket.create_connection(
                    ("127.0.0.1", self._backend), timeout=min(_remaining(deadline_ns) / 1e9, 5)
                )
                try:
                    stream = transport.BoundedStream(
                        sock,
                        cap=self.cap,
                        link=LOCAL_DISPATCH,
                        timeout_ns=_remaining(deadline_ns),
                        observer=self.record,
                    )
                except BaseException:
                    sock.close()
                    raise
                try:
                    stream.send(fields[1], kind="unshaped-backend-dispatch")
                    stream.timeout_ns = _remaining(deadline_ns)
                    reply = stream.receive(kind="unshaped-backend-return")
                finally:
                    stream.close()
            elif verb in (b"snapshot", b"patch") and len(fields) == 1:
                delivery = cfg[verb.decode("ascii")]
                if type(delivery) is not dict or set(delivery) != {"packet", "descriptor"}:
                    raise ValueError("Owner has not installed this public delivery")
                reply = auth._pack(
                    [
                        _read_pin(delivery["packet"], self.cap),
                        _read_pin(delivery["descriptor"], self.cap),
                    ]
                )
            elif verb == b"upload" and len(fields) == 2 and type(fields[1]) is bytes:
                entry, body = cfg["upload"], fields[1]
                if (
                    entry is None
                    or len(body) != entry["bytes"]
                    or hashlib.sha256(body).hexdigest() != entry["sha256"]
                ):
                    raise ValueError("Public upload differs from the fixed owner input")
                with self._lock:
                    if self._upload_consumed:
                        raise ValueError("Public upload attempt already consumed")
                    self._upload_consumed = True
                with Path(entry["file"]).open("xb") as out:
                    out.write(body)
                    out.flush()
                    os.fsync(out.fileno())
                reply = auth._pack([OK_TAG, entry["bytes"], bytes.fromhex(entry["sha256"])])
            else:
                raise ValueError("Unsupported fixed public relay command")
            _remaining(deadline_ns)
            if not 1 <= len(reply) <= self.cap:
                raise ValueError("Complete relay reply exceeds trusted cap")
            completed = True
            return reply
        finally:
            with self._lock:
                self._stages.append(
                    {
                        "verb": verb.decode("ascii", errors="replace"),
                        "started_ns": start,
                        "finished_ns": time.perf_counter_ns(),
                        "thread_cpu_ns": time.thread_time_ns() - cpu,
                        "completed": completed,
                    }
                )

    def inventory(self):
        self._process()
        with self._lock:
            return {
                "role": "shared-public-relay",
                "process": self._pid,
                "backend_port": self._backend,
                "upload_consumed": self._upload_consumed,
                "transfers": [r.as_dict() for r in self._transfers],
                "stages": list(self._stages),
                "download_credits": [asdict(r) for r in self.download_budget.history()],
                "process_high_water_RSS_bytes_not_stage_peak": resource.getrusage(
                    resource.RUSAGE_SELF
                ).ru_maxrss
                * 1024,
                "uplink_shaped_at_shared_owner_endpoint": True,
                "backend_dispatch_is_separate_unshaped_local_control": True,
                "private_authorization_or_attestation": False,
            }

    def __copy__(self):
        raise TypeError("Public relay cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Public relay cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Public relay cannot be serialized")


def serve(relay, output, *, ready=None):
    """Bounded concurrent public worker, compatible with the clean supervisor."""
    output = Path(output)
    if output.exists():
        raise ValueError("Never overwrite a public relay result")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(MAX_CONNECTIONS)
    listener.settimeout(0.1)
    slots, active, lock = threading.BoundedSemaphore(MAX_CONNECTIONS), set(), threading.Lock()

    def handle(sock):
        stream = None
        deadline = time.perf_counter_ns() + relay.timeout_ns
        try:
            stream = network.BudgetedStream(
                sock,
                budget=relay.download_budget,
                cap=relay.cap,
                timeout_ns=_remaining(deadline),
                observer=relay.record,
            )
            packet = stream.receive(kind="client-upload")
            try:
                reply = relay.execute(packet, deadline_ns=deadline)
            except (ValueError, RuntimeError, OSError, MemoryError):
                reply = auth._pack([ERROR_TAG])
            stream.timeout_ns = _remaining(deadline)
            stream.send(reply, kind="client-download")
        except (OSError, transport.TransportError):
            pass  # Transfer records retain the failed connection; no retry.
        finally:
            if stream is not None:
                stream.close()
            else:
                sock.close()
            with lock:
                active.discard(threading.current_thread())
            slots.release()

    readiness = {
        "port": listener.getsockname()[1],
        "process": os.getpid(),
        "local_verifier_public_key": None,
    }
    if ready is None:
        print(json.dumps(readiness), flush=True)
    else:
        ready(readiness)
    try:
        while not relay.stopping:
            try:
                sock, _ = listener.accept()
            except TimeoutError:
                continue
            if not slots.acquire(blocking=False):
                sock.close()
                continue
            worker = threading.Thread(target=handle, args=(sock,))
            with lock:
                active.add(worker)
            worker.start()
    finally:
        listener.close()
        deadline = time.perf_counter_ns() + relay.timeout_ns
        with lock:
            workers = tuple(active)
        for worker in workers:
            worker.join(timeout=max(0, deadline - time.perf_counter_ns()) / 1e9)
        with lock:
            incomplete = any(worker.is_alive() for worker in active)
        value = relay.inventory()
        value["owned_handlers_complete"] = not incomplete
        with output.open("x") as out:
            json.dump(value, out, indent=2)
            out.write("\n")
        if incomplete:
            raise RuntimeError("Owned relay handlers did not finish before deadline")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("worker",))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu", type=int, required=True)
    args = parser.parse_args()
    os.sched_setaffinity(0, {args.cpu})
    serve(PublicRelay(args.config, args.freeze), args.output)


if __name__ == "__main__":
    main()
