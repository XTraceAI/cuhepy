"""Q77 public source preservation and preconsumed resource accounting.

Every fresh encrypted feature group is retained once. Immutable references
reconstruct the exact existing owner-signed enrollment bytes, including old
unaffected groups and evaluation keys, without a private key or sampled error.
This avoids keeping a complete duplicate index for every mode/update while
preserving the actual inputs needed to reproduce public native computations.

These are local experiment controls, not a new encryption scheme, admission
predicate, durable remote authority or proof of honest encryption. Actual HE
and the complete owner coordinator require a committed execution addendum.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import msgpack

from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_owner as owner
from experiments.bfv_search_lab import complete_cost_trace as trace
from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab.shared_query_bounds import Profile

BLOCK = 1 << 16
KINDS = frozenset(
    (
        "index-group",
        "evaluation-keys",
        "public-key",
        "query",
        "cache",
        "descriptor",
        "witness",
        "record",
    )
)
HISTORICAL_LIMITS = {
    "HE_keys": 2,
    "feature_encryptions": 31744,
    "query_encryptions": 540,
    "owner_signing_keys": 2,
    "cache_AES_keys": 2,
    "protected_signing_keys": 54,
}


def _hex(value, size):
    if type(value) is not str or len(value) != 2 * size:
        raise ValueError("Canonical public digest required")
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise ValueError("Canonical public digest required") from None
    if raw.hex() != value:
        raise ValueError("Canonical public digest required")
    return raw


def _bin_header(size):
    if type(size) is not int or not 0 <= size < 1 << 32:
        raise ValueError("Bounded binary field required")
    if size < 1 << 8:
        return b"\xc4" + struct.pack("!B", size)
    if size < 1 << 16:
        return b"\xc5" + struct.pack("!H", size)
    return b"\xc6" + struct.pack("!I", size)


def _array_header(size):
    return msgpack.Packer(use_bin_type=True).pack_array_header(size)


class ResourceLedger(owner._Owned):
    """Owner-local fsynced attempt accounting, consumed before expensive work.

    No refund, replacement or resume operation exists. A persistence failure
    disables this holder before returning to its caller. This is not anti-rollback
    storage; the execution runner must additionally reject an existing cohort and
    enforce the externally committed registration. Public unit limits may be
    smaller than HE limits, but cannot activate HE in the guarded public gate.
    """

    def __init__(self, path, limits):
        if (
            type(limits) is not dict
            or not limits
            or set(limits) - HISTORICAL_LIMITS.keys()
            or any(type(v) is not int or not 0 <= v <= 1 << 32 for v in limits.values())
        ):
            raise ValueError("Explicit finite registered resource limits required")
        self._initialize()
        self._limits, self._used, self._labels, self._events = (
            dict(limits),
            dict.fromkeys(limits, 0),
            set(),
            [],
        )
        self.path = Path(path).resolve()
        self.path.parent.resolve(strict=True)
        self._stream = self.path.open("x")
        try:
            self._persist({"kind": "start", "limits": self._limits, "process": self._pid})
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            self._closed = True
            self._stream.close()
            raise

    def _persist(self, event):
        self._stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        self._stream.flush()
        os.fsync(self._stream.fileno())

    def take(self, resource, amount, *, label):
        self._process()
        trace._label(label)
        with self._lock:
            self._open()
            if (
                type(resource) is not str
                or resource not in self._limits
                or type(amount) is not int
                or amount <= 0
            ):
                raise ValueError("Named positive registered attempt required")
            identity = (resource, label)
            if identity in self._labels or self._used[resource] + amount > self._limits[resource]:
                raise RuntimeError("Consumed or exhausted experiment resource")
            self._labels.add(identity)
            self._used[resource] += amount
            event = {
                "kind": "consume",
                "sequence": len(self._events),
                "resource": resource,
                "amount": amount,
                "label": label,
                "monotonic_ns": time.perf_counter_ns(),
                "used": self._used[resource],
            }
            self._events.append(event)
            try:
                self._persist(event)
            except BaseException:
                self._closed = True
                self._stream.close()
                raise
            return dict(event)

    def inventory(self):
        self._process()
        with self._lock:
            return {
                "process": self._pid,
                "closed": self._closed,
                "limits": dict(self._limits),
                "used": dict(self._used),
                "events": [dict(e) for e in self._events],
                "rollback_resistance": False,
            }

    def close(self):
        self._process()
        with self._lock:
            if not self._closed:
                self._closed = True
                self._stream.close()


@dataclass(frozen=True)
class Blob:
    kind: str
    bytes: int
    sha256: str

    def __post_init__(self):
        if (
            type(self.kind) is not str
            or self.kind not in KINDS
            or type(self.bytes) is not int
            or not 1 <= self.bytes <= native.PACKET_CAP
        ):
            raise ValueError("Bounded public blob reference required")
        _hex(self.sha256, 32)


def _group_data(data, n, dimension):
    """Validate canonical binary entries without unpacking a second whole copy."""
    header = _array_header(dimension)
    if (
        type(data) is not bytes
        or not data.startswith(header)
        or len(data) > dimension * (n * native.COMMON_WIDTH + 261) + len(header)
    ):
        raise ValueError("Bounded canonical feature-group array required")
    at = len(header)
    for _ in range(dimension):
        if at >= len(data):
            raise ValueError("Incomplete public feature-group coverage")
        size_of_size = {0xC4: 1, 0xC5: 2, 0xC6: 4}.get(data[at])
        if size_of_size is None or at + 1 + size_of_size > len(data):
            raise ValueError("Canonical binary feature packet required")
        size = int.from_bytes(data[at + 1 : at + 1 + size_of_size], "big")
        if (
            not 1 <= size <= n * native.COMMON_WIDTH + 256
            or _bin_header(size) != data[at : at + 1 + size_of_size]
        ):
            raise ValueError("Noncanonical feature-group entry")
        at += 1 + size_of_size + size
        if at > len(data):
            raise ValueError("Truncated feature-group entry")
    if at != len(data):
        raise ValueError("Trailing public feature-group bytes")
    return len(header)


class PublicArchive(owner._Owned):
    """One process-owned immutable public blob store and bounded live scratch.

    The byte ceiling covers retained blobs and live/partial materializations.
    Successful scratch may be removed after its inputs/signature remain recorded.
    Failed writes stay consumed and present for inspection. Digest-addressed
    filenames come from validated fixed-width digests, never received paths. The
    caller must publish only the specifically public outputs of fixed owner code;
    this API cannot prove that arbitrary caller bytes contain no secret.
    """

    def __init__(self, root, *, byte_limit):
        if type(byte_limit) is not int or not 1 <= byte_limit <= 8 << 30:
            raise ValueError("Explicit additional-artifact ceiling required")
        self._initialize()
        self.root = Path(root).resolve()
        self.root.mkdir()
        (self.root / "blobs").mkdir()
        (self.root / "scratch").mkdir()
        self.byte_limit = byte_limit
        self._readonly = False
        self._blobs, self._scratch, self._retained, self._live, self._peak = {}, {}, 0, 0, 0

    @classmethod
    def recover(cls, root, references):
        """Read-only public recovery in a fresh process; never resume HE budgets."""
        if type(references) is not tuple or any(type(r) is not Blob for r in references):
            raise ValueError("Explicit public reconstruction references required")
        root = Path(root)
        if root.is_symlink() or (root / "blobs").is_symlink():
            raise ValueError("Direct preserved public archive required")
        result = object.__new__(cls)
        result._initialize()
        result.root, result._readonly = root.resolve(strict=True), True
        result._blobs, result._scratch = {}, {}
        for ref in references:
            prior = result._blobs.get(ref.sha256)
            item = {"bytes": ref.bytes, "status": "complete"}
            if prior is not None and prior != item:
                raise ValueError("Inconsistent public reconstruction references")
            result._blobs[ref.sha256] = item
        result._retained = sum(item["bytes"] for item in result._blobs.values())
        result._live, result._peak, result.byte_limit = 0, result._retained, result._retained
        for ref in references:
            for _ in result.stream(ref):
                pass
        return result

    def _reserve(self, size, *, scratch=False):
        if self._retained + self._live + size > self.byte_limit:
            raise RuntimeError("Registered additional-artifact ceiling exhausted")
        if scratch:
            self._live += size
        else:
            self._retained += size
        self._peak = max(self._peak, self._retained + self._live)

    def _path(self, ref):
        if type(ref) is not Blob:
            raise ValueError("Exact public blob reference required")
        return self.root / "blobs" / ref.sha256

    def put(self, data, *, kind):
        self._process()
        if type(data) is not bytes:
            raise ValueError("Immutable public bytes required")
        ref = Blob(kind, len(data), hashlib.sha256(data).hexdigest())
        with self._lock:
            self._open()
            if self._readonly:
                raise RuntimeError("Public recovery archive is read-only")
            if ref.sha256 in self._blobs:
                if self.read(ref) != data:
                    raise ValueError("Retained public blob differs from its digest")
                return ref
            self._reserve(len(data))
            self._blobs[ref.sha256] = {"bytes": len(data), "status": "partial"}
            path = self._path(ref)
            with path.open("xb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            self._blobs[ref.sha256]["status"] = "complete"
            return ref

    def put_group(self, packets, *, n, dimension):
        self._process()
        if (
            type(n) is not int
            or not 8 <= n <= 16384
            or n & (n - 1)
            or type(dimension) is not int
            or not 3 <= dimension <= min(512, n // 2)
            or type(packets) is not tuple
            or len(packets) != dimension
            or any(
                type(p) is not bytes or not 1 <= len(p) <= n * native.COMMON_WIDTH + 256
                for p in packets
            )
        ):
            raise ValueError("Complete bounded immutable feature group required")
        return self.put(auth._pack(list(packets)), kind="index-group")

    def stream(self, ref):
        self._process()
        path = self._path(ref)
        with self._lock:
            self._open()
            stored = self._blobs.get(ref.sha256)
            if stored != {"bytes": ref.bytes, "status": "complete"}:
                raise ValueError("Public reference is not a completely retained blob")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        digest, total = hashlib.sha256(), 0
        with os.fdopen(fd, "rb") as source:
            if os.fstat(source.fileno()).st_size != ref.bytes:
                raise ValueError("Retained public blob length changed")
            for block in iter(lambda: source.read(BLOCK), b""):
                total += len(block)
                if total > ref.bytes:
                    raise ValueError("Retained public blob grew during read")
                digest.update(block)
                yield block
        if total != ref.bytes or digest.hexdigest() != ref.sha256:
            raise ValueError("Retained public blob changed during read")

    def read(self, ref):
        return b"".join(self.stream(ref))

    def materialize(self, record, *, label, owner_anchor):
        self._process()
        trace._label(label)
        if type(record) is not EnrollmentRecord:
            raise ValueError("Complete signed public enrollment record required")
        record.verify_owner(owner_anchor)
        with self._lock:
            self._open()
            if self._readonly:
                raise RuntimeError("Public recovery cannot create a new execution lifetime")
            if label in self._scratch:
                raise RuntimeError("Consumed public scratch lifetime")
            self._reserve(record.packet_bytes, scratch=True)
            path = self.root / "scratch" / (label + ".packet")
            self._scratch[label] = {
                "file": str(path),
                "bytes": record.packet_bytes,
                "status": "partial",
            }
        payload, packet, snapshot = (
            hashlib.sha256(),
            hashlib.sha256(),
            hashlib.sha256(auth.ENROLL_TAG + owner_anchor),
        )
        written = 0
        with path.open("xb") as out:
            for kind, block in record.packet_chunks(self):
                if written + len(block) > record.packet_bytes:
                    raise ValueError("Materialized public enrollment exceeded declared coverage")
                out.write(block)
                written += len(block)
                packet.update(block)
                if kind == "payload":
                    payload.update(block)
                    snapshot.update(block)
            out.flush()
            os.fsync(out.fileno())
        if (
            written != record.packet_bytes
            or packet.hexdigest() != record.packet_sha256
            or payload.hexdigest() != record.payload_sha256
            or snapshot.hexdigest() != record.snapshot_id
        ):
            raise ValueError("Materialized enrollment differs from the complete signed record")
        with self._lock:
            self._scratch[label]["status"] = "complete"
            self._scratch[label]["sha256"] = packet.hexdigest()
        return {"file": str(path), "bytes": written, "sha256": packet.hexdigest()}

    def retire(self, label):
        """Retire only a complete exact owned scratch, retaining its record/blobs."""
        self._process()
        with self._lock:
            self._open()
            item = self._scratch.get(label)
            if item is None or item["status"] != "complete":
                raise ValueError("Complete owned public scratch required")
            path = Path(item["file"])
            if path.is_symlink() or path.stat().st_size != item["bytes"]:
                raise ValueError("Owned scratch changed before retirement")
            digest = hashlib.sha256()
            with path.open("rb") as source:
                for block in iter(lambda: source.read(BLOCK), b""):
                    digest.update(block)
            if digest.hexdigest() != item["sha256"]:
                raise ValueError("Owned scratch content changed before retirement")
            # The caller must retain the record before making this call. It
            # contains only public metadata/signature/input references.
            path.unlink()
            item["status"] = "retired"
            self._live -= item["bytes"]

    def inventory(self):
        self._process()
        with self._lock:
            return {
                "process": self._pid,
                "byte_limit": self.byte_limit,
                "retained_bytes": self._retained,
                "live_scratch_bytes": self._live,
                "peak_retained_plus_scratch_bytes": self._peak,
                "blob_count": len(self._blobs),
                "blobs": {k: dict(v) for k, v in self._blobs.items()},
                "scratch": {k: dict(v) for k, v in self._scratch.items()},
                "qualification": "Logical additional file bytes, not filesystem block allocation or process RSS",
            }


@dataclass(frozen=True)
class EnrollmentRecord:
    metadata: native.PublicMetadata
    epoch: int
    policy_digest: bytes
    owner_anchor: bytes
    keys: Blob
    groups: tuple[Blob, ...]
    payload_bytes: int
    payload_sha256: str
    packet_sha256: str
    snapshot_id: str
    signature: bytes

    def __post_init__(self):
        if type(self.metadata) is not native.PublicMetadata:
            raise ValueError("Complete existing public metadata required")
        p = self.metadata.profile
        auth._epoch(self.epoch)
        auth._fixed(self.policy_digest, 32, "policy")
        auth._fixed(self.owner_anchor, 32, "owner anchor")
        auth._fixed(self.signature, 64, "owner signature")
        if (
            type(self.keys) is not Blob
            or self.keys.kind != "evaluation-keys"
            or self.keys.bytes != (p.levels + 1) * 8 * p.n * native.COMMON_WIDTH
            or type(self.groups) is not tuple
            or len(self.groups) != self.metadata.groups
            or any(type(g) is not Blob or g.kind != "index-group" for g in self.groups)
            or type(self.payload_bytes) is not int
            or not 1 <= self.payload_bytes <= native.PACKET_CAP - 128
        ):
            raise ValueError("Complete bounded enrolled source coverage required")
        for value in (self.payload_sha256, self.packet_sha256, self.snapshot_id):
            _hex(value, 32)

    @property
    def packet_bytes(self):
        return (
            len(_array_header(3) + auth._pack(auth.ENROLL_TAG) + _bin_header(self.payload_bytes))
            + self.payload_bytes
            + len(auth._pack(self.signature))
        )

    def verify_owner(self, owner_anchor):
        auth._fixed(owner_anchor, 32, "separately trusted owner anchor")
        if owner_anchor != self.owner_anchor:
            raise ValueError("Foreign public enrollment record")
        try:
            Ed25519PublicKey.from_public_bytes(owner_anchor).verify(
                self.signature,
                auth._pack([auth.SIGN_DOMAIN, auth.ENROLL_TAG, _hex(self.payload_sha256, 32)]),
            )
        except InvalidSignature:
            raise ValueError("Unsigned or modified enrollment record") from None

    def payload_chunks(self, archive):
        m, p = self.metadata, self.metadata.profile
        yield _array_header(8)
        fields = (
            auth._profile_fields(p),
            list(m.primes),
            bytes.fromhex(m.key_id),
            b"".join(x.to_bytes(8, "little") for x in m.ids),
            self.epoch,
            self.policy_digest,
        )
        for field in fields:
            yield auth._pack(field)
        yield _bin_header(self.keys.bytes)
        yield from archive.stream(self.keys)
        yield _array_header(m.groups * p.dimension)
        for ref in self.groups:
            raw = archive.read(ref)
            start = _group_data(raw, p.n, p.dimension)
            view = memoryview(raw)
            for at in range(start, len(raw), BLOCK):
                yield view[at : at + BLOCK]

    def packet_chunks(self, archive):
        yield (
            "envelope",
            _array_header(3) + auth._pack(auth.ENROLL_TAG) + _bin_header(self.payload_bytes),
        )
        for block in self.payload_chunks(archive):
            yield "payload", block
        yield "signature", auth._pack(self.signature)

    def fields(self):
        """Public recovery data only; no owner secret or ciphertext expansion."""
        return {
            "schema_version": 1,
            "profile": asdict(self.metadata.profile),
            "primes": list(self.metadata.primes),
            "key_id": self.metadata.key_id,
            "ids": list(self.metadata.ids),
            "epoch": self.epoch,
            "policy_digest": self.policy_digest.hex(),
            "owner_anchor": self.owner_anchor.hex(),
            "keys": asdict(self.keys),
            "groups": [asdict(g) for g in self.groups],
            "payload_bytes": self.payload_bytes,
            "payload_sha256": self.payload_sha256,
            "packet_sha256": self.packet_sha256,
            "snapshot_id": self.snapshot_id,
            "signature": self.signature.hex(),
        }

    @classmethod
    def from_fields(cls, fields):
        """Parse public recovery declarations; authorization remains separate."""
        required = {
            "schema_version",
            "profile",
            "primes",
            "key_id",
            "ids",
            "epoch",
            "policy_digest",
            "owner_anchor",
            "keys",
            "groups",
            "payload_bytes",
            "payload_sha256",
            "packet_sha256",
            "snapshot_id",
            "signature",
        }
        if (
            type(fields) is not dict
            or set(fields) != required
            or type(fields["schema_version"]) is not int
            or fields["schema_version"] != 1
            or type(fields["profile"]) is not dict
            or type(fields["primes"]) is not list
            or type(fields["ids"]) is not list
            or type(fields["groups"]) is not list
            or type(fields["keys"]) is not dict
            or len(fields["primes"]) != 2
            or not 1 <= len(fields["ids"]) <= 32768
            or not 1 <= len(fields["groups"]) <= 2
            or any(type(g) is not dict for g in fields["groups"])
        ):
            raise ValueError("Complete public record fields required")
        try:
            metadata = native.PublicMetadata(
                Profile(**fields["profile"]),
                tuple(fields["primes"]),
                fields["key_id"],
                tuple(fields["ids"]),
            )
            return cls(
                metadata,
                fields["epoch"],
                _hex(fields["policy_digest"], 32),
                _hex(fields["owner_anchor"], 32),
                Blob(**fields["keys"]),
                tuple(Blob(**g) for g in fields["groups"]),
                fields["payload_bytes"],
                fields["payload_sha256"],
                fields["packet_sha256"],
                fields["snapshot_id"],
                _hex(fields["signature"], 64),
            )
        except (TypeError, KeyError, OverflowError):
            raise ValueError("Malformed public reconstruction fields") from None


def sign_record(archive, metadata, keys, groups, *, epoch, policy_digest, signing_owner):
    """Stream the existing SHA256/Ed25519 enrollment law over public inputs.

    No cryptographic scheme or signature domain changes. Exact byte comparison
    against auth.sign_enrollment is a required public unit gate. Signatures bind
    bytes, not key validity, plaintext origin/noise, current state or execution.
    """
    if type(archive) is not PublicArchive or not isinstance(signing_owner, Ed25519PrivateKey):
        raise ValueError("Owner archive and signing context required")
    archive._process()
    anchor = signing_owner.public_key().public_bytes_raw()
    # Placeholder public digests/signature only permit construction of the
    # validated shape; this object is never returned or materialized.
    shape = EnrollmentRecord(
        metadata,
        epoch,
        policy_digest,
        anchor,
        keys,
        groups,
        1,
        "00" * 32,
        "00" * 32,
        "00" * 32,
        bytes(64),
    )
    p = metadata.profile
    size = 1 + sum(
        len(auth._pack(field))
        for field in (
            auth._profile_fields(p),
            list(metadata.primes),
            bytes.fromhex(metadata.key_id),
            b"".join(x.to_bytes(8, "little") for x in metadata.ids),
            epoch,
            policy_digest,
        )
    )
    size += (
        len(_bin_header(keys.bytes))
        + keys.bytes
        + len(_array_header(metadata.groups * p.dimension))
    )
    size += sum(g.bytes - len(_array_header(p.dimension)) for g in groups)
    if not 1 <= size <= native.PACKET_CAP - 128:
        raise ValueError("Enrollment payload exceeds the existing wire cap")
    payload, packet = hashlib.sha256(), hashlib.sha256()
    snapshot = hashlib.sha256(auth.ENROLL_TAG + anchor)
    packet.update(_array_header(3) + auth._pack(auth.ENROLL_TAG) + _bin_header(size))
    total = 0
    for block in shape.payload_chunks(archive):
        total += len(block)
        if total > size:
            raise ValueError("Source groups exceed their canonical enrollment coverage")
        payload.update(block)
        packet.update(block)
        snapshot.update(block)
    if total != size:
        raise ValueError("Source groups differ from canonical enrollment coverage")
    signature = signing_owner.sign(
        auth._pack([auth.SIGN_DOMAIN, auth.ENROLL_TAG, payload.digest()])
    )
    packet.update(auth._pack(signature))
    record = EnrollmentRecord(
        metadata,
        epoch,
        policy_digest,
        anchor,
        keys,
        groups,
        size,
        payload.hexdigest(),
        packet.hexdigest(),
        snapshot.hexdigest(),
        signature,
    )
    archive.put(
        json.dumps(record.fields(), sort_keys=True, separators=(",", ":")).encode(), kind="record"
    )
    return record
