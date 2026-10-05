"""Q77 real local public/protected role executor, with fixed trusted inputs.

The role path is implemented here; the owner cohort coordinator and exact
execution addendum are still required before fresh HE keys or timing panels.
No CLI option substitutes a stage-cost model for an absent execution path.
This is not an enclave. Config files, runtime, journal and local verifier-key
provisioning are trusted prototype inputs, never attestation evidence.
"""

# ruff: noqa: E402 -- standalone research runner adds its repository root.
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
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experiments.bfv_search_lab import aggregate_shared_query as aggregate
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_protocol as result
from experiments.bfv_search_lab import complete_cost_transport as transport
from experiments.bfv_search_lab import lifecycle_shared_query as life
from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab import replay_shared_query as replay
from experiments.bfv_search_lab import shared_query_certificate as cert
from experiments.bfv_search_lab import shared_query_client_context as context

CLIENT_LINK = transport.Link(12_500_000, 10_000_000)
INTERNAL_LINK = transport.Link(1_250_000_000, 100_000)
TIMEOUT_NS = 900_000_000_000
ERROR_TAG = b"cuhepy/Q77/public-worker-failure/v1"
OK_TAG = b"cuhepy/Q77/public-worker-ok/v1"
FACTORIES = (auth.OwnerFactory, replay.ReplayFactory, aggregate.AggregateFactory)


def pinned_bytes(entry):
    path = Path(entry["file"]).resolve(strict=True)
    data = path.read_bytes()
    if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError("Pinned public input changed")
    return data


def verify_freeze(path):
    freeze = json.loads(Path(path).read_text())
    for entry in (
        freeze["new_sources"] + freeze["preserved_runtime_sources"] + freeze["dependencies"]
    ):
        pinned_bytes(entry)
    return freeze


def rpc(port, packet, *, link, cap, observer=None, timeout_ns=TIMEOUT_NS):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Trusted explicit local role port required")
    sock = socket.create_connection(("127.0.0.1", port), timeout=min(timeout_ns / 1e9, 5))
    stream = transport.BoundedStream(
        sock, cap=cap, link=link, timeout_ns=timeout_ns, observer=observer
    )
    try:
        stream.send(packet, kind="RPC-request")
        reply = stream.receive(kind="RPC-response")
        # Worker errors are public and deliberately carry no exception text.
        fields = auth._unpack(reply, limit=cap, array_cap=9)
        if type(fields) is list and fields and fields[0] == ERROR_TAG:
            raise RuntimeError("Public local worker rejected the task")
        return reply
    finally:
        stream.close()


class LocalRole:
    """Actual complete runtime path for one fixed public/protected mode.

    The owner controls the config path and its current pin out of band. RPC
    cannot select a library, mode, graph, anchor, config path or current pin.
    Refresh reads only that trusted path and requires one owner-pin advance.
    A replay frontend is a forwarding proxy; it creates no native preparation
    and computes no unnecessary producer result.
    """

    def __init__(self, config_path, freeze_path, *, signer=None, internal_link=INTERNAL_LINK):
        self.config_path = Path(config_path).resolve(strict=True)
        self.freeze = verify_freeze(freeze_path)
        cfg = json.loads(self.config_path.read_text())
        if cfg["role"] not in ("frontend", "protected") or cfg["mode"] not in cert.MODES:
            raise ValueError("Trusted fixed local role and mode required")
        self.role, self.mode = cfg["role"], cfg["mode"]
        self._immutable = {
            key: cfg[key]
            for key in ("role", "mode", "library", "owner_anchor", "journal", "protected_port")
        }
        if cfg["library"] not in self.freeze["executed_public_libraries"]:
            raise ValueError("Role library is absent from the explicit execution freeze")
        pinned_bytes(cfg["library"])
        self.owner_anchor = bytes.fromhex(cfg["owner_anchor"])
        auth._fixed(self.owner_anchor, 32, "trusted owner")
        self.library = self.factory = self.enrollment = None
        if self.role == "protected" or self.mode != cert.MODES[1]:
            self.library = native.NativeLibrary(cfg["library"]["file"])
            self.factory = FACTORIES[cert.MODES.index(self.mode)](self.owner_anchor, self.library)
        self._internal_link, self._journal_path = internal_link, Path(cfg["journal"])
        self._descriptor = self.journal = self._signer = None
        self._signing_key = signer
        self._pid, self._closed, self.stopping = os.getpid(), False, False
        self.transfers, self.stages = [], []
        self.refresh(initial=True)

    def _process(self):
        if self._pid != os.getpid():
            raise RuntimeError("Inherited local role")

    def _open(self):
        self._process()
        if self._closed:
            raise RuntimeError("Closed local role")

    @staticmethod
    def _pin(fields):
        if set(fields) != {"namespace", "revision", "epoch", "payload_digest"}:
            raise ValueError("Complete separately trusted owner pin required")
        return context.CurrentPin(
            bytes.fromhex(fields["namespace"]),
            bytes.fromhex(fields["revision"]),
            fields["epoch"],
            bytes.fromhex(fields["payload_digest"]),
        )

    def refresh(self, *, initial=False):
        self._open()
        start, cpu = time.perf_counter_ns(), time.process_time_ns()
        cfg = json.loads(self.config_path.read_text())
        if {key: cfg[key] for key in self._immutable} != self._immutable:
            raise ValueError("Trusted role code/root configuration changed")
        current = self._pin(cfg["current_pin"])
        if initial:
            self._descriptor = context.DescriptorClient(self.owner_anchor, current)
        elif current == self._descriptor._current:
            return  # An untrusted redundant refresh cannot reset the epoch.
        else:
            self._descriptor.advance_current(current)
        descriptor = pinned_bytes(cfg["descriptor"])
        metadata = self._descriptor.acquire(descriptor)
        selected = metadata.mode(self.mode)
        if selected.code_digest.hex() != cfg["library"]["sha256"]:
            raise ValueError("Owner mode does not bind the selected library")
        if self.factory is not None:
            if selected.policy_digest != self.factory.policy_digest:
                raise ValueError("Owner mode differs from fixed factory policy")
            new = self.factory.enroll(pinned_bytes(cfg["enrollment"]))
            p, g = new.metadata.profile, metadata.geometry
            matches = (
                (p.n, p.dimension, p.t, p.eta, p.q, p.p, new.metadata.primes)
                == (g.n, g.dimension, g.t, g.eta, g.q, g.p, g.primes)
                and new.metadata.ids == metadata.ids
                and bytes.fromhex(new.metadata.key_id) == metadata.key_id
                and new.snapshot_id == selected.snapshot_id
                and new.epoch == selected.epoch
            )
            if not matches:
                new.close()
                raise ValueError("Native enrollment differs from complete owner descriptor")
            old, self.enrollment = self.enrollment, new
            if old is not None:
                old.close()
        if self.role == "protected":
            if self.journal is None:
                self.journal = life.LocalJournal(
                    self._journal_path, self.owner_anchor, selected.policy_digest, current.namespace
                )
            self.journal.install(self.enrollment)
            if self._signer is None:
                # Public tests inject one of their two deterministic fixture
                # contexts. Actual workers create a new standard signing key;
                # neither path serializes a production signing secret.
                key = (
                    self._signing_key
                    if self._signing_key is not None
                    else Ed25519PrivateKey.generate()
                )
                self._signer = result.LocalResultSigner(self.journal, key, self._descriptor)
                self._signing_key = None
        self.stages.append(
            {
                "stage": "initial-preparation" if initial else "refresh",
                "started_ns": start,
                "finished_ns": time.perf_counter_ns(),
                "process_cpu_ns": time.process_time_ns() - cpu,
            }
        )

    def execute(self, packet):
        self._open()
        fields = auth._unpack(packet, limit=native.PACKET_CAP, array_cap=3)
        if type(fields) is not list or not fields or type(fields[0]) is not bytes:
            raise ValueError("Bounded public role command required")
        verb = fields[0]
        if verb == b"descriptor" and len(fields) == 1:
            return pinned_bytes(json.loads(self.config_path.read_text())["descriptor"])
        if verb == b"refresh" and len(fields) == 1:
            self.refresh()
            return auth._pack([OK_TAG])
        if verb == b"stop" and len(fields) == 1:
            self.stopping = True
            return auth._pack([OK_TAG])
        if verb != b"run" or type(fields[1] if len(fields) > 1 else None) is not bytes:
            raise ValueError("Unsupported public role command")
        original = fields[1]
        start, cpu = time.perf_counter_ns(), time.process_time_ns()
        if self.role == "frontend":
            if len(fields) != 2:
                raise ValueError("Frontend takes only the signed original")
            if self.mode == cert.MODES[1]:
                delegated = auth._pack([b"run", original])
            else:
                with self.enrollment.request(original) as request:
                    delegated = auth._pack([b"run", original, request.produce_packet()])
            reply = rpc(
                self._immutable["protected_port"],
                delegated,
                link=self._internal_link,
                cap=native.PACKET_CAP,
                observer=self.transfers.append,
            )
        else:
            metadata = self._descriptor.metadata()
            if self.mode == cert.MODES[1]:
                if len(fields) != 2:
                    raise ValueError("Prepared replay takes no proposed result")
                _, authorization = replay.PreparedReplayAuthorizer(self.journal).execute(
                    self.enrollment, original
                )
            else:
                if len(fields) != 3 or type(fields[2]) is not bytes:
                    raise ValueError("Complete deterministic result is required")
                authorization = life.LocalAuthorizer(self.journal).admit(
                    self.enrollment, original, fields[2]
                )
                if authorization is None:
                    raise ValueError("Complete public admission rejected")
            if authorization.binding != result.original_binding(
                original, self.owner_anchor, metadata, self.mode
            ):
                raise RuntimeError("Protected lifecycle and owner original differ")
            reply = self._signer.issue(authorization, self.mode)
        self.stages.append(
            {
                "stage": "produce-forward" if self.role == "frontend" else "admit-claim-sign",
                "started_ns": start,
                "finished_ns": time.perf_counter_ns(),
                "process_cpu_ns": time.process_time_ns() - cpu,
            }
        )
        return reply

    def inventory(self):
        self._open()
        return {
            "role": self.role,
            "mode": self.mode,
            "process": os.getpid(),
            "native_stats": asdict(self.enrollment.stats) if self.enrollment is not None else None,
            "native_preparation_exists": self.enrollment is not None,
            "journal": self.journal.summary() if self.journal is not None else None,
            "local_verifier_public_key": self._signer.public_key.hex()
            if self._signer is not None
            else None,
            "process_high_water_RSS_bytes_not_stage_peak": resource.getrusage(
                resource.RUSAGE_SELF
            ).ru_maxrss
            * 1024,
            "transfers": [record.as_dict() for record in self.transfers],
            "stages": self.stages,
            "HE_private_key_present_or_private_HE_work": False,
            "actual_attestation_or_nonrollback_host_assurance": False,
        }

    def close(self):
        self._process()
        if self._closed:
            return
        self._closed = True
        if self._signer is not None:
            self._signer.close()
        if self.journal is not None:
            self.journal.close()
        if self.enrollment is not None:
            self.enrollment.close()
        if self._descriptor is not None:
            self._descriptor.close()

    def __copy__(self):
        raise TypeError("Local role ownership cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Local role ownership cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Local role cannot be serialized")


def serve(role, output, *, cpu, link, timeout_ns=TIMEOUT_NS):
    os.sched_setaffinity(0, {cpu})
    output = Path(output)
    if output.exists():
        raise ValueError("Never overwrite a worker result")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(0.25)
    # This announcement is trusted only by the local owner that spawned this
    # exact pinned process. A remote server announcement is not a trust root.
    print(
        json.dumps(
            {
                "port": listener.getsockname()[1],
                "process": os.getpid(),
                "local_verifier_public_key": role._signer.public_key.hex()
                if role._signer
                else None,
            }
        ),
        flush=True,
    )
    try:
        while not role.stopping:
            try:
                sock, _ = listener.accept()
            except TimeoutError:
                continue
            stream = transport.BoundedStream(
                sock,
                cap=native.PACKET_CAP,
                link=link,
                timeout_ns=timeout_ns,
                observer=role.transfers.append,
            )
            try:
                packet = stream.receive(kind="role-request")
                try:
                    reply = role.execute(packet)
                except (ValueError, RuntimeError, OverflowError, MemoryError):
                    reply = auth._pack([ERROR_TAG])
                stream.send(reply, kind="role-response")
            finally:
                stream.close()
    finally:
        listener.close()
        value = role.inventory()
        with output.open("x") as saved:
            saved.write(json.dumps(value, indent=2) + "\n")
        role.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["worker"])
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu", type=int, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("Never overwrite a worker result or consume its signing context again")
    # Pin role affinity before preparation, not just after its NTT setup.
    os.sched_setaffinity(0, {args.cpu})
    role = LocalRole(args.config, args.freeze)
    serve(
        role,
        args.output,
        cpu=args.cpu,
        link=CLIENT_LINK if role.role == "frontend" else INTERNAL_LINK,
    )


if __name__ == "__main__":
    main()
