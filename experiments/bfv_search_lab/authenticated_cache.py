"""Q76.4c: permitted authenticated mutable owner cache, not a novel scheme.

The honest owner may keep all plaintext. A separately trusted current pin,
AES-256-GCM-SIV key and Ed25519 anchor authorize acquisition from an untrusted
store. Signatures bind encrypted bytes; AEAD authenticates before parsing.
Neither implements the owner channel, host-resistant rollback, erasure, HE
verification or attestation. ID digests are public metadata, not hiding
commitments. Logical HE/cache data equivalence is an honest-owner/Q76.5 premise.

Local search uses an isolated stateless popcount library, every distance and
ordinal ties. Existing cache APIs keep their historical numeric-ID contract.
"""

from __future__ import annotations

import ctypes as ct
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import secrets
import struct
import threading

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

MAX_ROWS = 32768
MAX_DIMENSION = 512
MAX_PATCH_ROWS = 32
MAX_PACKET_BYTES = 1 << 22
MAX_DESCRIPTOR_BYTES = 512
UINT64_MAX = (1 << 64) - 1
CONTEXT_MAGIC = b"cuhepy/cache-context/v1\0"
PACKET_MAGIC = b"cuhepy/cache-packet/v1\0"
DESCRIPTOR_MAGIC = b"cuhepy/cache-delivery/v1\0"
AAD_MAGIC = b"cuhepy/cache-AAD/v1\0"
IDS_MAGIC = b"cuhepy/cache-ordered-IDs/v1\0"
PACKET_OVERHEAD = len(PACKET_MAGIC) + 12 + 16
SNAPSHOT = 1
UPDATE = 2


def _fixed(value, size, name):
    if type(value) is not bytes or len(value) != size:
        raise ValueError(f"Invalid {name}")


def _word(value, dimension):
    if type(value) is not int or not 0 <= value < 1 << dimension:
        raise ValueError("Invalid binary word")


def _id_digest(raw, count):
    return hashlib.sha256(IDS_MAGIC + struct.pack("<I", count) + raw).digest()


@dataclass(frozen=True)
class Context:
    namespace: bytes
    key_id: bytes
    snapshot_id: bytes
    epoch: int
    count: int
    dimension: int
    ordered_ids_digest: bytes

    def __post_init__(self):
        self._validate()

    def _validate(self):
        for name in ("namespace", "key_id", "snapshot_id", "ordered_ids_digest"):
            _fixed(getattr(self, name), 32, name)
        if (
            type(self.epoch) is not int
            or not 1 <= self.epoch <= UINT64_MAX
            or type(self.count) is not int
            or not 1 <= self.count <= MAX_ROWS
            or type(self.dimension) is not int
            or not 1 <= self.dimension <= MAX_DIMENSION
        ):
            raise ValueError("Invalid owner-pinned cache geometry/epoch")

    def encode(self):
        self._validate()
        return (
            CONTEXT_MAGIC
            + self.namespace
            + self.key_id
            + self.snapshot_id
            + struct.pack("<QIH", self.epoch, self.count, self.dimension)
            + self.ordered_ids_digest
        )

    @property
    def row_width(self):
        self._validate()
        return (self.dimension + 7) // 8

    @property
    def raw_body_bytes(self):
        return self.count * (8 + self.row_width)


@dataclass(frozen=True)
class Delivery:
    context: Context
    packet: bytes
    descriptor: bytes


@dataclass(frozen=True)
class PatchDelivery:
    previous_context: Context
    context: Context
    packet: bytes
    descriptor: bytes


@dataclass(frozen=True)
class Result:
    context: Context
    scores: tuple[int, ...]
    top3_positions: tuple[int, ...]
    top3: tuple[tuple[int, int], ...]


def _contexts(kind, contexts):
    expected = 1 if kind == SNAPSHOT else 2 if kind == UPDATE else 0
    if not expected or len(contexts) != expected or any(type(x) is not Context for x in contexts):
        raise ValueError("Invalid cache delivery kind/context")
    return bytes([kind]) + b"".join(x.encode() for x in contexts)


def _sign(packet, owner, kind, contexts):
    """Trusted owner helper; not a client acceptance or provisioning API."""
    if not isinstance(owner, Ed25519PrivateKey):
        raise ValueError("Owner Ed25519 key required")
    body = DESCRIPTOR_MAGIC + _contexts(kind, contexts) + hashlib.sha256(packet).digest()
    return body + owner.sign(body)


def _seal_body(body, key, kind, contexts):
    """Trusted owner helper. Public seal functions validate the plaintext first."""
    _fixed(key, 32, "AES-256-GCM-SIV key")
    nonce = secrets.token_bytes(12)
    encrypted = AESGCMSIV(key).encrypt(nonce, body, AAD_MAGIC + _contexts(kind, contexts))
    return PACKET_MAGIC + nonce + encrypted


def seal_snapshot(rows, ids, dimension, key, owner, *, namespace, key_id, snapshot_id, epoch):
    """Owner encodes one complete snapshot; opaque identity tokens are caller supplied."""
    if (
        type(rows) is not tuple
        or type(ids) is not tuple
        or not 1 <= len(rows) <= MAX_ROWS
        or len(rows) != len(ids)
        or type(dimension) is not int
        or not 1 <= dimension <= MAX_DIMENSION
    ):
        raise ValueError("Invalid complete cache rows/IDs")
    for row in rows:
        _word(row, dimension)
    if any(type(i) is not int or not 0 <= i <= UINT64_MAX for i in ids) or len(set(ids)) != len(
        ids
    ):
        raise ValueError("Invalid unique UInt64 ordered IDs")
    encoded_ids = b"".join(i.to_bytes(8, "little") for i in ids)
    context = Context(
        namespace,
        key_id,
        snapshot_id,
        epoch,
        len(rows),
        dimension,
        _id_digest(encoded_ids, len(rows)),
    )
    body = encoded_ids + b"".join(x.to_bytes(context.row_width, "little") for x in rows)
    packet = _seal_body(body, key, SNAPSHOT, (context,))
    return Delivery(context, packet, _sign(packet, owner, SNAPSHOT, (context,)))


def _next_patch_context(previous, current):
    if type(previous) is not Context or type(current) is not Context:
        raise ValueError("Invalid patch context")
    previous.encode()
    current.encode()
    if (
        previous.epoch == UINT64_MAX
        or current.epoch != previous.epoch + 1
        or current.snapshot_id == previous.snapshot_id
        or any(
            getattr(previous, name) != getattr(current, name)
            for name in ("namespace", "key_id", "count", "dimension", "ordered_ids_digest")
        )
    ):
        raise ValueError("Patch must preserve shape/IDs/key and advance exactly one epoch")


def _changes(changes, context):
    if type(changes) is not tuple or not 1 <= len(changes) <= min(MAX_PATCH_ROWS, context.count):
        raise ValueError("Invalid bounded cache patch")
    previous = -1
    for change in changes:
        if type(change) is not tuple or len(change) != 2:
            raise ValueError("Invalid row change")
        position, word = change
        if type(position) is not int or not previous < position < context.count:
            raise ValueError("Patch ordinals must be unique, sorted and in range")
        _word(word, context.dimension)
        previous = position


def seal_update(changes, key, owner, previous_context, *, snapshot_id):
    """Owner seals a replacement patch; unchanged ordered IDs preserve row ordinals."""
    if type(previous_context) is not Context:
        raise ValueError("Previous owner context required")
    previous_context.encode()
    current = Context(
        previous_context.namespace,
        previous_context.key_id,
        snapshot_id,
        previous_context.epoch + 1,
        previous_context.count,
        previous_context.dimension,
        previous_context.ordered_ids_digest,
    )
    _next_patch_context(previous_context, current)
    _changes(changes, current)
    body = struct.pack("<H", len(changes)) + b"".join(
        struct.pack("<I", position) + word.to_bytes(current.row_width, "little")
        for position, word in changes
    )
    contexts = (previous_context, current)
    packet = _seal_body(body, key, UPDATE, contexts)
    return PatchDelivery(previous_context, current, packet, _sign(packet, owner, UPDATE, contexts))


class _ProcessOwned:
    def _initialize_owner(self):
        self._pid = os.getpid()
        self._lock = threading.RLock()
        self._closed = False

    def _check_process(self):
        # A fork may inherit a lock held by a vanished thread. Check PID first.
        if os.getpid() != self._pid:
            raise RuntimeError("Cache object belongs to another process")

    def _check_open(self):
        if self._closed:
            raise RuntimeError("Cache object is closed")

    def __copy__(self):
        raise TypeError("Cache objects cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("Cache objects cannot be copied")

    def __reduce_ex__(self, protocol):
        raise TypeError("Cache objects cannot be pickled")


class NativePopcount(_ProcessOwned):
    """Trusted explicit library path, stateless C ABI, owned immutable byte inputs."""

    def __init__(self, library_path):
        self._initialize_owner()
        self.library_path = Path(library_path).resolve(strict=True)
        self._lib = ct.CDLL(str(self.library_path))
        self._lib.cuhepy_cache_popcount_abi.argtypes = []
        self._lib.cuhepy_cache_popcount_abi.restype = ct.c_uint32
        if self._lib.cuhepy_cache_popcount_abi() != 1:
            raise ValueError("Wrong cache native ABI")
        self._call = self._lib.cuhepy_cache_popcount
        self._call.argtypes = [
            ct.POINTER(ct.c_ubyte),
            ct.c_size_t,
            ct.c_uint32,
            ct.c_uint32,
            ct.POINTER(ct.c_ubyte),
            ct.c_size_t,
            ct.POINTER(ct.c_uint16),
            ct.c_size_t,
            ct.POINTER(ct.c_uint32),
            ct.c_size_t,
        ]
        self._call.restype = ct.c_int

    def scan(self, rows, count, dimension, query):
        self._check_process()
        with self._lock:
            self._check_open()
            if (
                type(rows) is not bytes
                or type(query) is not bytes
                or type(count) is not int
                or not 1 <= count <= MAX_ROWS
                or type(dimension) is not int
                or not 1 <= dimension <= MAX_DIMENSION
            ):
                raise ValueError("Invalid native cache input")
            width = (dimension + 7) // 8
            if len(rows) != count * width or len(query) != width:
                raise ValueError("Wrong native cache lengths")
            # c_char_p retains the immutable bytes, including embedded NULs;
            # this synchronous call uses explicit lengths, never C strlen.
            row_ref, query_ref = ct.c_char_p(rows), ct.c_char_p(query)
            scores = (ct.c_uint16 * count)()
            positions = (ct.c_uint32 * min(3, count))()
            status = self._call(
                ct.cast(row_ref, ct.POINTER(ct.c_ubyte)),
                len(rows),
                count,
                dimension,
                ct.cast(query_ref, ct.POINTER(ct.c_ubyte)),
                len(query),
                scores,
                count,
                positions,
                len(positions),
            )
            if status:
                raise ValueError("Native cache grammar rejected")
            return tuple(scores), tuple(positions)

    def close(self):
        self._check_process()
        with self._lock:
            self._closed = True  # Logical close; no promise of DSO unload.


class CacheClient(_ProcessOwned):
    """One current trusted owner pin and one fully validated retained plaintext cache."""

    def __init__(self, native, key, owner_anchor, current_context):
        if type(native) is not NativePopcount or type(current_context) is not Context:
            raise ValueError("Native control and owner context required")
        _fixed(key, 32, "AES-256-GCM-SIV key")
        _fixed(owner_anchor, 32, "Ed25519 owner anchor")
        current_context.encode()
        self._initialize_owner()
        self._native = native
        self._key = key
        self._aead = AESGCMSIV(key)
        self._anchor_bytes = owner_anchor
        self._anchor = Ed25519PublicKey.from_public_bytes(owner_anchor)
        self._current = current_context
        self._cached = None
        self._rows = self._ids = b""

    @property
    def current_context(self):
        self._check_process()
        with self._lock:
            self._check_open()
            return self._current

    def pin_current(self, context):
        """Trusted owner channel only. Peer descriptors never call this operation."""
        self._check_process()
        with self._lock:
            self._check_open()
            if type(context) is not Context:
                raise ValueError("Owner context required")
            context.encode()
            old = self._current
            if (
                old.epoch == UINT64_MAX
                or context.epoch != old.epoch + 1
                or context.snapshot_id == old.snapshot_id
                or context.namespace != old.namespace
                or context.key_id != old.key_id
            ):
                raise ValueError("Current owner pin must advance exactly one epoch")
            # Old bytes may be retained, but query cannot use them after this pin.
            # Shape/ID changes require full acquisition, never a row patch.
            self._current = context

    def _open(self, packet, descriptor, kind, contexts, minimum, maximum):
        if (
            type(packet) is not bytes
            or not minimum + PACKET_OVERHEAD
            <= len(packet)
            <= min(maximum + PACKET_OVERHEAD, MAX_PACKET_BYTES)
            or packet[: len(PACKET_MAGIC)] != PACKET_MAGIC
        ):
            raise ValueError("Malformed cache packet")
        prefix = DESCRIPTOR_MAGIC + _contexts(kind, contexts)
        expected = len(prefix) + 32 + 64
        if (
            type(descriptor) is not bytes
            or len(descriptor) != expected
            or expected > MAX_DESCRIPTOR_BYTES
        ):
            raise ValueError("Malformed cache descriptor")
        try:
            self._anchor.verify(descriptor[-64:], descriptor[:-64])
        except InvalidSignature as error:
            raise ValueError("Untrusted cache descriptor") from error
        if (
            descriptor[: len(prefix)] != prefix
            or descriptor[len(prefix) : -64] != hashlib.sha256(packet).digest()
        ):
            raise ValueError("Foreign/stale cache context or ciphertext")
        start = len(PACKET_MAGIC)
        try:
            return self._aead.decrypt(
                packet[start : start + 12],
                packet[start + 12 :],
                AAD_MAGIC + _contexts(kind, contexts),
            )
        except InvalidTag as error:
            raise ValueError("Cache authentication failed") from error

    def acquire(self, packet, descriptor):
        """Late network downloads are checked against the current pin at publication."""
        self._check_process()
        with self._lock:
            self._check_open()
            context = self._current
            raw = self._open(
                packet,
                descriptor,
                SNAPSHOT,
                (context,),
                context.raw_body_bytes,
                context.raw_body_bytes,
            )
            if len(raw) != context.raw_body_bytes:
                raise ValueError("Wrong authenticated snapshot length")
            split = 8 * context.count
            ids, rows = raw[:split], raw[split:]
            if _id_digest(ids, context.count) != context.ordered_ids_digest:
                raise ValueError("Snapshot ordered-ID binding failed")
            seen = set()
            for (identifier,) in struct.iter_unpack("<Q", ids):
                if identifier in seen:
                    raise ValueError("Snapshot IDs are not unique")
                seen.add(identifier)
            if context.dimension % 8:
                mask = 0xFF ^ ((1 << (context.dimension % 8)) - 1)
                if any(
                    rows[i] & mask
                    for i in range(context.row_width - 1, len(rows), context.row_width)
                ):
                    raise ValueError("Snapshot has nonzero physical padding")
            # No state publication until signature, AEAD and entire grammar pass.
            self._ids, self._rows, self._cached = ids, rows, context

    def apply_update(self, packet, descriptor):
        self._check_process()
        with self._lock:
            self._check_open()
            if self._cached is None:
                raise ValueError("No acquired previous cache")
            old, current = self._cached, self._current
            _next_patch_context(old, current)
            width = current.row_width
            raw = self._open(
                packet,
                descriptor,
                UPDATE,
                (old, current),
                2 + 4 + width,
                2 + min(MAX_PATCH_ROWS, current.count) * (4 + width),
            )
            count = int.from_bytes(raw[:2], "little")
            if not 1 <= count <= min(MAX_PATCH_ROWS, current.count) or len(raw) != 2 + count * (
                4 + width
            ):
                raise ValueError("Invalid authenticated patch count/length")
            changes = tuple(
                (
                    int.from_bytes(raw[at : at + 4], "little"),
                    int.from_bytes(raw[at + 4 : at + 4 + width], "little"),
                )
                for at in range(2, len(raw), 4 + width)
            )
            _changes(changes, current)
            revised = bytearray(self._rows)
            for position, word in changes:
                revised[position * width : (position + 1) * width] = word.to_bytes(width, "little")
            self._rows, self._cached = bytes(revised), current

    def query(self, word):
        self._check_process()
        with self._lock:
            self._check_open()
            if self._cached != self._current:
                raise ValueError("Current cache has not been acquired or updated")
            _word(word, self._current.dimension)
            scores, positions = self._native.scan(
                self._rows,
                self._current.count,
                self._current.dimension,
                word.to_bytes(self._current.row_width, "little"),
            )
            top3 = tuple(
                (scores[i], int.from_bytes(self._ids[8 * i : 8 * i + 8], "little"))
                for i in positions
            )
            return Result(self._current, scores, positions, top3)

    def inventory(self):
        """Canonical body counts/models, not process RSS or measured stage peaks."""
        self._check_process()
        with self._lock:
            self._check_open()
            return {
                "active": self._cached == self._current,
                "retained_row_bytes": len(self._rows),
                "retained_ID_bytes": len(self._ids),
                "retained_canonical_body_bytes": len(self._rows) + len(self._ids),
                "symmetric_key_bytes": len(self._key),
                "owner_anchor_bytes": len(self._anchor_bytes),
                "current_context_encoding_bytes": len(self._current.encode()),
                "cached_context_encoding_bytes": 0
                if self._cached is None
                else len(self._cached.encode()),
                "query_native_output_bytes": 2 * self._current.count
                + 4 * min(3, self._current.count),
                "acquisition_plaintext_body_bytes": self._current.raw_body_bytes,
                "update_full_row_copy_bytes": len(self._rows),
                "qualification": "Canonical body inventory only; excludes Python objects/returned tuples, parsing sets, crypto/DSO/lock overhead and buffers owned by callers. Acquisition also holds decrypted body; update holds old rows, bytearray and new bytes. Not measured peak/RSS/timing.",
            }

    def close(self):
        self._check_process()
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._rows = self._ids = b""
            self._cached = self._current = None
            self._key = self._aead = self._anchor = self._anchor_bytes = None
            # Clearing references is not secure erasure; caller owns native DSO.
