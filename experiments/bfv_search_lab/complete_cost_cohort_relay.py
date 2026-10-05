"""Q77 owner-bound initial/update uploads on the existing shared relay.

Two destinations and one public lifetime namespace are trusted local inputs.
An owner signature binds the namespace, phase and complete body. A valid owner
phase is consumed before any write, including failure; it cannot be replaced.
The existing relay still owns exactly one shared download lane, while all owner
threads share its upload endpoint. Received packets cannot choose paths, keys,
ports, code, policies or current epochs.

This is experiment transport/accounting, not admission, attestation, rollback
protection or proof that an encrypted input was honestly generated. The whole
cohort runner and committed execution addendum remain required before HE work.
"""

# ruff: noqa: E402 -- public worker entry adds the repository root.
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_relay as relay

UPLOAD_TAG = b"cuhepy/Q77/owner-cohort-upload/v1"
PHASES = (b"initial", b"update")
OVERHEAD_RESERVE = 1024


def _phase(value):
    if type(value) is not bytes or value not in PHASES:
        raise ValueError("Fixed initial or update phase required")
    return value


def _digest(value):
    if type(value) is not str or len(value) != 64:
        raise ValueError("Canonical trusted public digest required")
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise ValueError("Canonical trusted public digest required") from None
    if raw.hex() != value:
        raise ValueError("Canonical trusted public digest required")
    return raw


def sign_upload(namespace, phase, body, signing_owner):
    """Owner-side fixed packet; uses the existing SHA256/Ed25519 signing law."""
    auth._fixed(namespace, 32, "trusted cohort namespace")
    _phase(phase)
    if (
        type(body) is not bytes
        or not 1 <= len(body) <= relay.transport.MAX_FRAME - OVERHEAD_RESERVE
        or not isinstance(signing_owner, Ed25519PrivateKey)
    ):
        raise ValueError("Bounded immutable public body and owner signing context required")
    payload = auth._pack([namespace, phase, len(body), hashlib.sha256(body).digest(), body])
    return auth._pack([b"cohort-upload", auth._sign(UPLOAD_TAG, payload, signing_owner)])


class CohortRelay:
    """Composition with the existing public router; never a second traffic lane.

    Configuration files and their directories are trusted owner inputs. Phase
    state is process-local. The runner must reject an existing cohort/lifetime;
    a fresh process does not supply durable anti-replay or remote freshness.
    """

    def __init__(self, config_path, freeze_path):
        self.config_path = Path(config_path).resolve(strict=True)
        cfg = json.loads(self.config_path.read_text())
        required = {"role", "service", "routing_config", "owner_anchor", "namespace", "uploads"}
        if (
            type(cfg) is not dict
            or set(cfg) != required
            or cfg["role"] != "frontend"
            or cfg["service"] != "owner-bound-cohort-relay"
            or type(cfg["routing_config"]) is not str
            or not Path(cfg["routing_config"]).is_absolute()
            or type(cfg["uploads"]) is not list
            or len(cfg["uploads"]) != 2
        ):
            raise ValueError("Fixed trusted cohort relay configuration required")
        anchor, self.namespace = _digest(cfg["owner_anchor"]), _digest(cfg["namespace"])
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        self._anchor = Ed25519PublicKey.from_public_bytes(anchor)
        self._base = relay.PublicRelay(cfg["routing_config"], freeze_path)
        if self._base._immutable["upload"] is not None:
            raise ValueError("Cohort uploads cannot coexist with a second legacy upload target")
        self.cap, self.timeout_ns = self._base.cap, self._base.timeout_ns
        self.download_budget = self._base.download_budget
        targets = []
        for phase, entry in zip(PHASES, cfg["uploads"], strict=True):
            if (
                type(entry) is not dict
                or set(entry) != {"phase", "file", "max_bytes"}
                or type(entry["phase"]) is not str
                or entry["phase"] != phase.decode("ascii")
                or type(entry["file"]) is not str
                or not Path(entry["file"]).is_absolute()
                or type(entry["max_bytes"]) is not int
                or not 1 <= entry["max_bytes"] <= self.cap - OVERHEAD_RESERVE
            ):
                raise ValueError("Fixed bounded initial/update destinations required")
            path = Path(entry["file"])
            path.parent.resolve(strict=True)
            if path.exists() or path.is_symlink():
                raise ValueError("Public upload destination already consumed")
            targets.append(path.resolve())
        if targets[0] == targets[1]:
            raise ValueError("Distinct fixed upload destinations required")
        self._immutable = cfg
        self._lock = threading.Lock()
        self._next, self._failed = 0, False
        self._phases = [{"phase": phase.decode("ascii"), "status": "unused"} for phase in PHASES]
        self._stages = []

    @property
    def stopping(self):
        return self._base.stopping

    def record(self, transfer):
        self._base.record(transfer)

    def _config(self):
        if json.loads(self.config_path.read_text()) != self._immutable:
            raise ValueError("Trusted cohort destinations/namespace/root changed")
        # The old router separately validates its mutable delivery/backend path.
        self._base._config()

    def execute(self, packet, *, deadline_ns):
        self._base._process()
        if relay._remaining(deadline_ns) > self.timeout_ns:
            raise ValueError("Bounded absolute cohort deadline required")
        self._config()
        fields = auth._unpack(packet, limit=self.cap, array_cap=2)
        if type(fields) is not list or not fields or type(fields[0]) is not bytes:
            raise ValueError("Bounded cohort relay command required")
        if fields[0] != b"cohort-upload":
            return self._base.execute(packet, deadline_ns=deadline_ns)
        if len(fields) != 2 or type(fields[1]) is not bytes:
            raise ValueError("Owner-signed complete cohort upload required")
        payload = auth._verify(fields[1], self._anchor, UPLOAD_TAG, self.cap)
        values = auth._unpack(payload, limit=self.cap, array_cap=5)
        if type(values) is not list or len(values) != 5:
            raise ValueError("Complete signed upload declaration required")
        namespace, phase, size, digest, body = values
        auth._fixed(namespace, 32, "signed cohort namespace")
        _phase(phase)
        if namespace != self.namespace:
            raise ValueError("Foreign cohort upload lifetime")
        with self._lock:
            if self._failed or self._next >= len(PHASES) or phase != PHASES[self._next]:
                raise ValueError("Failed, consumed or out-of-order cohort upload")
            index = self._next
            if self._phases[index]["status"] != "unused":
                raise ValueError("Cohort upload phase already consumed")
            self._phases[index]["status"] = "consumed"
        start, cpu, complete = time.perf_counter_ns(), time.thread_time_ns(), False
        try:
            entry = self._immutable["uploads"][index]
            if (
                type(size) is not int
                or not 1 <= size <= entry["max_bytes"]
                or type(body) is not bytes
                or len(body) != size
                or type(digest) is not bytes
                or len(digest) != 32
                or hashlib.sha256(body).digest() != digest
            ):
                raise ValueError("Signed upload differs from its complete bounded declaration")
            relay._remaining(deadline_ns)
            path = Path(entry["file"])
            with path.open("xb") as out:
                out.write(body)
                out.flush()
                os.fsync(out.fileno())
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            relay._remaining(deadline_ns)
            with self._lock:
                self._phases[index].update(status="complete", bytes=size, sha256=digest.hex())
                self._next += 1
            complete = True
            return auth._pack([relay.OK_TAG, phase, size, digest])
        finally:
            with self._lock:
                if not complete:
                    self._failed = True
                    self._phases[index]["status"] = "failed"
                self._stages.append(
                    {
                        "phase": phase.decode("ascii"),
                        "started_ns": start,
                        "finished_ns": time.perf_counter_ns(),
                        "thread_cpu_ns": time.thread_time_ns() - cpu,
                        "completed": complete,
                    }
                )

    def inventory(self):
        self._base._process()
        value = self._base.inventory()
        with self._lock:
            value.update(
                role="owner-bound-shared-cohort-relay",
                namespace=self.namespace.hex(),
                upload_phases=[dict(x) for x in self._phases],
                upload_failed=self._failed,
                upload_stages=[dict(x) for x in self._stages],
                upload_phase_state_is_process_local_not_anti_rollback=True,
            )
        return value

    def __copy__(self):
        raise TypeError("Cohort relay cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Cohort relay cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Cohort relay cannot be serialized")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("worker",))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu", type=int, required=True)
    args = parser.parse_args()
    os.sched_setaffinity(0, {args.cpu})
    relay.serve(CohortRelay(args.config, args.freeze), args.output)


if __name__ == "__main__":
    main()
