"""Public enrollment assembly worker for the complete owner cohort.

Initial upload carries the complete selected enrollment. An update carries
only the changed feature group, its signed recovery record and the descriptor.
This worker reuses the old evaluation keys and unaffected group, reconstructs
the existing owner-signed enrollment, and publishes distinct fixed files.
No signature, sampled error, HE key or private operation is generated here.

This is the public preparation part of the owner-run path. The full tenant
provisioning, cohort launcher and exact execution addendum remain required.
"""

# ruff: noqa: E402 -- standalone public worker adds the repository root.
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks import complete_cost_shared_query_lab as roles
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_cohort as cohort
from experiments.bfv_search_lab import complete_cost_supervisor as supervisor


def upload_body(record, descriptor, body):
    """Fixed owner-side public data; outer upload is signed by CohortRelay's law."""
    if (
        type(record) is not cohort.EnrollmentRecord
        or type(descriptor) is not bytes
        or not descriptor
        or type(body) is not bytes
        or not body
    ):
        raise ValueError("Complete public record, descriptor and upload body required")
    fields = json.dumps(record.fields(), sort_keys=True, separators=(",", ":")).encode()
    return auth._pack([fields, descriptor, body])


class PublicEnrollmentAssembler:
    """Fixed-path initial/update reconstruction, never cryptographic admission.

    Config and public-file pins are trusted owner control inputs. Upload phase
    authentication belongs to CohortRelay; actual query/result admission still
    belongs to the existing protected role. Consumed assembly failures cannot
    be retried. Retired inputs remain reconstructible from the owner's archive.
    """

    def __init__(self, config_path, freeze_path):
        roles.verify_freeze(freeze_path)
        self.config_path = Path(config_path).resolve(strict=True)
        cfg = json.loads(self.config_path.read_text())
        required = {"role", "service", "owner_anchor", "root", "initial", "update"}
        if (
            type(cfg) is not dict
            or set(cfg) != required
            or cfg["role"] != "frontend"
            or cfg["service"] != "public-cohort-enrollment-assembly"
            or type(cfg["root"]) is not str
            or not Path(cfg["root"]).is_absolute()
            or type(cfg["owner_anchor"]) is not str
        ):
            raise ValueError("Fixed owner-controlled public assembly config required")
        anchor = bytes.fromhex(cfg["owner_anchor"])
        auth._fixed(anchor, 32, "owner anchor")
        if anchor.hex() != cfg["owner_anchor"]:
            raise ValueError("Canonical fixed public anchor required")
        self.root = Path(cfg["root"]).resolve(strict=True)
        for name in ("initial", "update"):
            entry = cfg[name]
            if name == "update" and entry is None:
                continue  # The honest owner pins fresh update bytes later.
            if (
                type(entry) is not dict
                or set(entry) != {"file", "bytes", "sha256"}
                or type(entry["file"]) is not str
                or not Path(entry["file"]).is_absolute()
                or type(entry["bytes"]) is not int
                or not 1 <= entry["bytes"] <= roles.native.PACKET_CAP
                or type(entry["sha256"]) is not str
                or len(entry["sha256"]) != 64
            ):
                raise ValueError("Fixed complete future public upload pins required")
        self._cfg, self._anchor = cfg, Ed25519PublicKey.from_public_bytes(anchor)
        self._pid, self._failed, self._next = os.getpid(), False, 0
        self._signer, self.stopping = None, False
        self.transfers, self.stages, self.retired = [], [], []
        self.enrollment = self.descriptor = self.record = None
        self._assemble("initial")

    def _process(self):
        if os.getpid() != self._pid:
            raise RuntimeError("Inherited public assembly worker")

    @staticmethod
    def _equal_blob(data, reference):
        return len(data) == reference.bytes and hashlib.sha256(data).hexdigest() == reference.sha256

    def _enrollment_fields(self, packet, record):
        payload = auth._verify(packet, self._anchor, auth.ENROLL_TAG, roles.native.PACKET_CAP)
        p, m = record.metadata.profile, record.metadata
        fields = auth._unpack(
            payload, limit=roles.native.PACKET_CAP, array_cap=max(8, m.groups * p.dimension)
        )
        prefix = [
            auth._profile_fields(p),
            list(m.primes),
            bytes.fromhex(m.key_id),
            b"".join(x.to_bytes(8, "little") for x in m.ids),
            record.epoch,
            record.policy_digest,
        ]
        if type(fields) is not list or len(fields) != 8 or fields[:6] != prefix:
            raise ValueError("Complete signed enrollment metadata differs from recovery record")
        if type(fields[6]) is not bytes or not self._equal_blob(fields[6], record.keys):
            raise ValueError("Evaluation keys differ from the signed recovery record")
        packets = fields[7]
        if type(packets) is not list or len(packets) != m.groups * p.dimension:
            raise ValueError("Incomplete feature group coverage")
        for i, group in enumerate(record.groups):
            body = auth._pack(packets[i * p.dimension : (i + 1) * p.dimension])
            if not self._equal_blob(body, group):
                raise ValueError("Feature group differs from its complete recovery record")
        if (
            len(packet) != record.packet_bytes
            or hashlib.sha256(packet).hexdigest() != record.packet_sha256
        ):
            raise ValueError("Reconstructed enrollment packet differs from owner record")
        if hashlib.sha256(payload).hexdigest() != record.payload_sha256:
            raise ValueError("Signed payload differs from owner record")
        snapshot = hashlib.sha256(auth.ENROLL_TAG + record.owner_anchor + payload).hexdigest()
        if snapshot != record.snapshot_id:
            raise ValueError("Signed snapshot differs from owner record")
        return fields

    def _assemble(self, phase):
        self._process()
        if self._failed or self._next >= 2 or phase != ("initial", "update")[self._next]:
            raise ValueError("Failed or consumed public assembly phase")
        self._next += 1  # Consume before reads/parsing/public writes.
        start, cpu = time.perf_counter_ns(), time.process_time_ns()
        item = {"phase": phase, "started_ns": start, "status": "consumed"}
        self.stages.append(item)
        try:
            cfg = json.loads(self.config_path.read_text())
            immutable = set(self._cfg) - {"update"}
            if set(cfg) != set(self._cfg) or any(cfg[k] != self._cfg[k] for k in immutable):
                raise ValueError("Trusted assembly inputs or roots changed")
            entry = cfg[phase]
            if (
                type(entry) is not dict
                or set(entry) != {"file", "bytes", "sha256"}
                or type(entry["file"]) is not str
                or not Path(entry["file"]).is_absolute()
                or type(entry["bytes"]) is not int
                or not 1 <= entry["bytes"] <= roles.native.PACKET_CAP
                or type(entry["sha256"]) is not str
                or len(entry["sha256"]) != 64
            ):
                raise ValueError("Honest owner must pin the actual complete upload before assembly")
            raw = roles.pinned_bytes(entry)
            fields = auth._unpack(raw, limit=roles.native.PACKET_CAP, array_cap=3)
            if (
                type(fields) is not list
                or len(fields) != 3
                or any(type(x) is not bytes for x in fields)
            ):
                raise ValueError("Complete fixed public upload grammar required")
            if len(fields[0]) > 2 << 20 or not fields[1]:
                raise ValueError("Bounded record and nonempty descriptor required")
            decoded = json.loads(fields[0])
            if json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode() != fields[0]:
                raise ValueError("Noncanonical public recovery record")
            record = cohort.EnrollmentRecord.from_fields(decoded)
            record.verify_owner(bytes.fromhex(self._cfg["owner_anchor"]))
            if phase == "initial":
                packet = fields[2]
            else:
                old = self.record
                if (
                    record.metadata != old.metadata
                    or record.epoch != old.epoch + 1
                    or record.policy_digest != old.policy_digest
                    or record.keys != old.keys
                    or record.groups[1:] != old.groups[1:]
                ):
                    raise ValueError(
                        "Update changes the frozen key/shape/policy or unaffected group"
                    )
                original = self._enrollment_fields(roles.pinned_bytes(self.enrollment), old)
                p = record.metadata.profile
                changed = auth._unpack(
                    fields[2], limit=roles.native.PACKET_CAP, array_cap=p.dimension
                )
                if (
                    type(changed) is not list
                    or len(changed) != p.dimension
                    or any(type(x) is not bytes for x in changed)
                    or not self._equal_blob(fields[2], record.groups[0])
                ):
                    raise ValueError("Complete changed feature group required")
                original[4] = record.epoch
                original[7][: p.dimension] = changed
                packet = auth._pack([auth.ENROLL_TAG, auth._pack(original), record.signature])
            self._enrollment_fields(packet, record)
            # Old scratch is recoverable from its retained owner record/blobs.
            # Retire before publishing the new full packet to bound disk peak.
            if phase == "update":
                self.retired.append(self.enrollment)
                Path(self.enrollment["file"]).unlink()
            target = self.root / (phase + ".enrollment")
            descriptor = self.root / (phase + ".descriptor")
            for path, body in ((target, packet), (descriptor, fields[1])):
                with path.open("xb") as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(stream.fileno())
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            self.record = record
            self.enrollment, self.descriptor = (
                supervisor.pinned(target),
                supervisor.pinned(descriptor),
            )
            item.update(
                status="complete",
                public_upload_bytes=len(raw),
                enrollment=self.enrollment,
                descriptor=self.descriptor,
                snapshot_id=record.snapshot_id,
            )
        except BaseException as error:
            self._failed = True
            item.update(status="failed", error_class=type(error).__name__)
            raise
        finally:
            item.update(
                finished_ns=time.perf_counter_ns(), process_cpu_ns=time.process_time_ns() - cpu
            )

    def execute(self, packet):
        self._process()
        fields = auth._unpack(packet, limit=4096, array_cap=1)
        if fields == [b"stop"]:
            self.stopping = True
        elif fields == [b"refresh"]:
            self._assemble("update")
        else:
            raise ValueError("Only fixed public assembly refresh/stop commands accepted")
        return auth._pack([roles.OK_TAG])

    def inventory(self):
        self._process()
        return {
            "role": "public-enrollment-assembly",
            "process": self._pid,
            "failed": self._failed,
            "phases_consumed": self._next,
            "stages": self.stages,
            "retired_recoverable_enrollments": self.retired,
            "transfers": [x.as_dict() for x in self.transfers],
            "HE_private_key_present_or_private_HE_work": False,
            "cryptographic_query_result_admission_or_attestation": False,
        }

    def close(self):
        self._process()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("worker",))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu", type=int, required=True)
    args = parser.parse_args()
    os.sched_setaffinity(0, {args.cpu})
    role = PublicEnrollmentAssembler(args.config, args.freeze)
    roles.serve(role, args.output, cpu=args.cpu, link=supervisor.UNSHAPED)


if __name__ == "__main__":
    main()
