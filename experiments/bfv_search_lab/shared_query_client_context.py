"""Q76.5 compact public client provisioning, with a separately trusted owner pin.

The honest owner attests logical equivalence of cache and HE views. This is not
a ciphertext/plaintext-equivalence proof or a private HE client. There is no
decrypt callback, library loader, attestation or response-release capability.
Signatures and currentness precede payload parsing; independently reconstructed
certificate digests precede metadata publication. A store cannot advance pins.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import struct
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import msgpack

from experiments.bfv_search_lab import shared_query_certificate as certificate

MAX_DESCRIPTOR_BYTES = 278528
ENVELOPE_TAG = b"cuhepy/q76-client-descriptor/v1"
PAYLOAD_TAG = b"cuhepy/q76-client-context/v1"
SIGN_DOMAIN = b"cuhepy/q76-client-signature/v1\0"
PIN_DOMAIN = b"cuhepy/q76-client-current-pin/v1\0"
CACHE_IDS_DOMAIN = b"cuhepy/cache-ordered-IDs/v1\0"
OWNER_EQUIVALENCE = b"honest-owner-logical-HE-cache-equivalence-v1"
SCORE_CONTRACT = b"all-exact-distances-ties-by-original-row-ordinal-v1"
MODE_TAGS = tuple(x.encode("ascii") for x in certificate.MODES)
UINT64_MAX = (1 << 64) - 1


def _fixed(value, name):
    if type(value) is not bytes or len(value) != 32:
        raise ValueError(f"Invalid immutable {name}")


def _uint(value, name, *, minimum=0, maximum=UINT64_MAX):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"Invalid {name}")


def _ids(ids, count):
    if (
        type(ids) is not tuple
        or len(ids) != count
        or any(type(x) is not int or not 0 <= x <= UINT64_MAX for x in ids)
        or len(set(ids)) != count
    ):
        raise ValueError("Complete unique ordered UInt64 IDs required")
    return b"".join(struct.pack("<Q", x) for x in ids)


def cache_ids_digest(raw, count):
    _uint(count, "cache record coverage", minimum=1, maximum=32768)
    if type(raw) is not bytes or len(raw) != 8 * count:
        raise ValueError("Incomplete cache ID bytes")
    return hashlib.sha256(CACHE_IDS_DOMAIN + struct.pack("<I", count) + raw).digest()


def _pack(value):
    return msgpack.packb(value, use_bin_type=True)


def _unpack(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_DESCRIPTOR_BYTES:
        raise ValueError("Wrong immutable bounded descriptor")
    try:
        value = msgpack.unpackb(
            raw,
            raw=False,
            max_array_len=13,
            max_map_len=0,
            max_bin_len=MAX_DESCRIPTOR_BYTES,
            max_str_len=0,
            max_ext_len=0,
        )
        if _pack(value) != raw:
            raise ValueError("Noncanonical MessagePack descriptor")
        return value
    except (ValueError, TypeError, OverflowError, RecursionError, msgpack.UnpackException) as error:
        raise ValueError("Malformed complete bounded descriptor") from error


@dataclass(frozen=True)
class CurrentPin:
    """Trusted provisioning input, never learned/promoted from a store packet."""

    namespace: bytes
    revision: bytes
    epoch: int
    payload_digest: bytes

    def __post_init__(self):
        self._validate()

    def _validate(self):
        for name in ("namespace", "revision", "payload_digest"):
            _fixed(getattr(self, name), name)
        _uint(self.epoch, "logical owner epoch", minimum=1)


@dataclass(frozen=True)
class CacheBinding:
    key_id: bytes
    snapshot_id: bytes
    epoch: int
    ordered_ids_digest: bytes

    def __post_init__(self):
        self._validate()

    def _validate(self):
        for name in ("key_id", "snapshot_id", "ordered_ids_digest"):
            _fixed(getattr(self, name), name)
        _uint(self.epoch, "cache epoch", minimum=1)

    def fields(self):
        self._validate()
        return [self.key_id, self.snapshot_id, self.epoch, self.ordered_ids_digest]


@dataclass(frozen=True)
class ModeBinding:
    mode: str
    epoch: int
    snapshot_id: bytes
    policy_digest: bytes
    code_digest: bytes
    certificate_digest: bytes

    def __post_init__(self):
        self._validate()

    def _validate(self):
        if type(self.mode) is not str or self.mode not in certificate.MODES:
            raise ValueError("Unimplemented client mode")
        _uint(self.epoch, "HE snapshot epoch")
        for name in ("snapshot_id", "policy_digest", "code_digest", "certificate_digest"):
            _fixed(getattr(self, name), name)

    def fields(self):
        self._validate()
        return [
            self.mode.encode("ascii"),
            self.epoch,
            self.snapshot_id,
            self.policy_digest,
            self.code_digest,
            self.certificate_digest,
        ]


@dataclass(frozen=True)
class ClientMetadata:
    pin: CurrentPin
    geometry: certificate.Geometry
    key_id: bytes
    ids: tuple[int, ...]
    packed_ids: bytes
    ordered_ids_digest: bytes
    cache: CacheBinding
    modes: tuple[ModeBinding, ModeBinding, ModeBinding]

    def mode(self, trusted_choice):
        # This returns public metadata only. It does not choose/load executable
        # code or enroll/decrypt/authorize any server response.
        if type(trusted_choice) is not str or trusted_choice not in certificate.MODES:
            raise ValueError("Trusted supported mode selection required")
        return self.modes[certificate.MODES.index(trusted_choice)]


@dataclass(frozen=True)
class Delivery:
    pin: CurrentPin
    packet: bytes


def _profile_fields(profile):
    if type(profile) is not certificate.Geometry:
        raise ValueError("Selected geometry required")
    profile._validate()
    return [
        profile.n,
        profile.dimension,
        profile.t,
        profile.eta,
        profile.q.to_bytes(15, "little"),
        profile.p,
        list(profile.primes),
    ]


def _profile(fields):
    if (
        type(fields) is not list
        or len(fields) != 7
        or type(fields[4]) is not bytes
        or len(fields[4]) != 15
        or type(fields[6]) is not list
        or len(fields[6]) != 2
    ):
        raise ValueError("Incomplete selected client geometry")
    return certificate.Geometry(
        *fields[:4], int.from_bytes(fields[4], "little"), fields[5], tuple(fields[6])
    )


def _bindings(modes):
    if (
        type(modes) is not tuple
        or len(modes) != 3
        or any(type(x) is not ModeBinding for x in modes)
        or tuple(x.mode for x in modes) != certificate.MODES
    ):
        raise ValueError("All three supported modes in canonical order are required")
    for mode in modes:
        mode._validate()


def _plan(profile, count, key_id, ids_digest, mode):
    return certificate.TrustedPlan(
        profile,
        count,
        key_id,
        ids_digest,
        mode.snapshot_id,
        mode.policy_digest,
        mode.code_digest,
        mode.mode,
    )


def seal_descriptor(
    ids, owner, *, namespace, revision, epoch, geometry, key_id, cache, modes, certificates
):
    """Trusted owner helper; deliver its pin through the separate trusted channel.

    This validates public declarations only. The owner must independently ensure
    valid private inputs and that all bound views represent the logical revision.
    HE mode epochs are separately bound and need not equal the logical/cache
    epoch. This preserves the existing authenticated HE enrollment contract.
    """
    for value, name in ((namespace, "namespace"), (revision, "revision"), (key_id, "HE key ID")):
        _fixed(value, name)
    _uint(epoch, "logical owner epoch", minimum=1)
    _profile_fields(geometry)
    if type(ids) is not tuple or not 1 <= len(ids) <= 2 * geometry.n:
        raise ValueError("Invalid complete ID coverage")
    raw = _ids(ids, len(ids))
    digest = hashlib.sha256(raw).digest()  # Existing HE transcript convention.
    if type(cache) is not CacheBinding:
        raise ValueError("Explicit cache binding required")
    cache._validate()
    if cache.epoch != epoch or cache.ordered_ids_digest != cache_ids_digest(raw, len(ids)):
        raise ValueError("Cache context does not bind the same current ordered IDs")
    _bindings(modes)
    if type(certificates) is not tuple or len(certificates) != 3:
        raise ValueError("All three checked public certificates are required")
    for mode, packet in zip(modes, certificates, strict=True):
        certificate.check_certificate(
            packet,
            _plan(geometry, len(ids), key_id, digest, mode),
            expected_digest=mode.certificate_digest,
        )
    if not isinstance(owner, Ed25519PrivateKey):
        raise ValueError("Owner Ed25519 key required")
    payload = _pack(
        [
            PAYLOAD_TAG,
            namespace,
            revision,
            epoch,
            _profile_fields(geometry),
            key_id,
            len(ids),
            raw,
            digest,
            cache.fields(),
            [x.fields() for x in modes],
            OWNER_EQUIVALENCE,
            SCORE_CONTRACT,
        ]
    )
    signature = owner.sign(SIGN_DOMAIN + payload)
    packet = _pack([ENVELOPE_TAG, payload, signature])
    if len(packet) > MAX_DESCRIPTOR_BYTES:
        raise ValueError("Descriptor exceeds the registered cap")
    return Delivery(
        CurrentPin(namespace, revision, epoch, hashlib.sha256(PIN_DOMAIN + payload).digest()),
        packet,
    )


def verify_descriptor(packet, owner_anchor, current):
    """Authenticate and compare the separately trusted exact pin before parsing.

    Complete certificates need not travel to the client: their exact expected
    reference digests are independently reconstructed from compact metadata.
    The received public certificate remains independently checked at enrollment.
    No certificate body or HE enrollment/evaluation key is retained here.
    """
    _fixed(owner_anchor, "owner anchor")
    if type(current) is not CurrentPin:
        raise ValueError("Separately trusted current owner pin required")
    current._validate()
    outer = _unpack(packet)
    if (
        type(outer) is not list
        or len(outer) != 3
        or outer[0] != ENVELOPE_TAG
        or type(outer[1]) is not bytes
        or type(outer[2]) is not bytes
        or len(outer[2]) != 64
    ):
        raise ValueError("Incomplete authenticated descriptor envelope")
    payload = outer[1]
    try:
        Ed25519PublicKey.from_public_bytes(owner_anchor).verify(outer[2], SIGN_DOMAIN + payload)
    except (InvalidSignature, ValueError) as error:
        raise ValueError("Foreign or altered owner descriptor") from error
    if hashlib.sha256(PIN_DOMAIN + payload).digest() != current.payload_digest:
        raise ValueError("Descriptor is not the separately pinned current owner context")
    fields = _unpack(payload)
    if (
        type(fields) is not list
        or len(fields) != 13
        or fields[0] != PAYLOAD_TAG
        or fields[11] != OWNER_EQUIVALENCE
        or fields[12] != SCORE_CONTRACT
    ):
        raise ValueError("Incomplete logical client context or changed output contract")
    for value, name in (
        (fields[1], "namespace"),
        (fields[2], "revision"),
        (fields[5], "HE key ID"),
        (fields[8], "HE ID digest"),
    ):
        _fixed(value, name)
    _uint(fields[3], "logical epoch", minimum=1)
    if (fields[1], fields[2], fields[3]) != (current.namespace, current.revision, current.epoch):
        raise ValueError("Foreign logical context")
    profile = _profile(fields[4])
    count = fields[6]
    _uint(count, "complete record count", minimum=1, maximum=2 * profile.n)
    raw = fields[7]
    if type(raw) is not bytes or len(raw) != 8 * count:
        raise ValueError("Incomplete packed ordered IDs")
    ids = tuple(value[0] for value in struct.iter_unpack("<Q", raw))
    _ids(ids, count)
    if hashlib.sha256(raw).digest() != fields[8]:
        raise ValueError("HE ID digest does not bind all ordered IDs")
    if type(fields[9]) is not list or len(fields[9]) != 4:
        raise ValueError("Incomplete cache binding")
    cache = CacheBinding(*fields[9])
    if cache.epoch != current.epoch or cache.ordered_ids_digest != cache_ids_digest(raw, count):
        raise ValueError("Cache/HE ordered ID or current epoch mismatch")
    if type(fields[10]) is not list or len(fields[10]) != 3:
        raise ValueError("Complete three-mode binding required")
    modes = []
    for tag, body in zip(MODE_TAGS, fields[10], strict=True):
        if type(body) is not list or len(body) != 6 or body[0] != tag:
            raise ValueError("Changed, reordered or incomplete mode binding")
        mode = ModeBinding(tag.decode("ascii"), *body[1:])
        modes.append(mode)
        plan = _plan(profile, count, fields[5], fields[8], mode)
        # Do not trust the signature or a supplied digest for static semantics.
        # Reconstruct the exact selected reference, then check its complete digest.
        expected = certificate.make_certificate(plan)
        certificate.check_certificate(expected, plan, expected_digest=mode.certificate_digest)
    return ClientMetadata(current, profile, fields[5], ids, raw, fields[8], cache, tuple(modes))


class DescriptorClient:
    """Process-owned public metadata adapter; owns no private crypto capability."""

    def __init__(self, owner_anchor, current):
        _fixed(owner_anchor, "owner anchor")
        if type(current) is not CurrentPin:
            raise ValueError("Trusted current owner pin required")
        current._validate()
        self._anchor, self._current = owner_anchor, current
        self._metadata = None
        self._pid, self._closed = os.getpid(), False
        self._lock = threading.RLock()

    def _process(self):
        # Check before the lock: a fork may inherit it from a vanished thread.
        if self._pid != os.getpid():
            raise RuntimeError("Inherited client metadata adapter")

    def _open(self):
        if self._closed:
            raise RuntimeError("Closed client metadata adapter")

    def acquire(self, packet):
        self._process()
        with self._lock:
            self._open()
            current = self._current
        result = verify_descriptor(packet, self._anchor, current)
        with self._lock:
            self._open()
            if self._current != current:
                raise ValueError("Owner current pin changed during descriptor acquisition")
            self._metadata = result  # Publish only the completely validated result.
            return result

    def advance_current(self, trusted_current):
        """Trusted owner-channel operation; never called by acquisition."""
        self._process()
        if type(trusted_current) is not CurrentPin:
            raise ValueError("Trusted current owner pin required")
        trusted_current._validate()
        with self._lock:
            self._open()
            old = self._current
            if (
                old.epoch == UINT64_MAX
                or trusted_current.namespace != old.namespace
                or trusted_current.epoch != old.epoch + 1
                or trusted_current.revision == old.revision
            ):
                raise ValueError(
                    "Owner pin must preserve namespace and advance one logical revision"
                )
            self._current, self._metadata = trusted_current, None

    def metadata(self):
        self._process()
        with self._lock:
            self._open()
            if self._metadata is None:
                raise ValueError("No validated current client metadata")
            return self._metadata

    def close(self):
        self._process()
        with self._lock:
            self._closed, self._metadata = True, None

    def __copy__(self):
        raise TypeError("Client metadata ownership cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Client metadata ownership cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Client metadata ownership cannot be serialized")

    def __enter__(self):
        self._process()
        with self._lock:
            self._open()
        return self

    def __exit__(self, *_args):
        self.close()
