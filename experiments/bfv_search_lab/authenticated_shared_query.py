"""Q76 owner-authenticated public native search, without private release.

Honest owner encoding/samplers and the local prototype code are trusted. Owner
signatures bind bytes; they do not prove binary plaintexts, noise supports or
RLWE security. The checker has no HE secret or signing secret. Replay/current
snapshot enforcement and actual attestation belong to the later controller.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from gmpy2 import is_prime, mpz
import msgpack

from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab import seeded_bgv as seeded
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.shared_query_bounds import Profile

ENROLL_TAG = b"cuhepy-q76-owner-enrollment-v1"
QUERY_TAG = b"cuhepy-q76-owner-request-v1"
REPLY_TAG = b"cuhepy-q76-full-reply-v1"
ORIGIN_TAG = b"honest-owner-seeded-binary-canonical30-v1"
SIGN_DOMAIN = b"cuhepy-q76-domain-separated-Ed25519-v1"
POLICY_TAG = b"cuhepy-q76-internal-canonical30-two-prime-v1"


def _pack(value):
    return msgpack.packb(value, use_bin_type=True)


def _unpack(packet, *, limit, array_cap):
    if type(packet) is not bytes or len(packet) > limit:
        raise ValueError("Wrong immutable bounded packet")
    try:
        fields = msgpack.unpackb(
            packet,
            raw=False,
            max_array_len=array_cap,
            max_map_len=0,
            max_bin_len=limit,
            max_str_len=0,
            max_ext_len=0,
        )
    except (ValueError, TypeError, OverflowError, msgpack.UnpackException) as error:
        raise ValueError("Malformed complete packet") from error
    if _pack(fields) != packet:
        raise ValueError("Noncanonical packet encoding")
    return fields


def _fixed(value, size, label):
    if type(value) is not bytes or len(value) != size:
        raise ValueError(f"Wrong {label}")
    return value


def _epoch(value):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError("Wrong snapshot epoch")
    return value


def _owner_bytes(key):
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _signature_message(tag, payload):
    # This is ordinary Ed25519 over a small domain-separated message containing
    # the exact-payload hash. Its binding additionally assumes SHA256 collision
    # resistance; it is not a claim to implement the Ed25519ph variant.
    return _pack([SIGN_DOMAIN, tag, hashlib.sha256(payload).digest()])


def _sign(tag, payload, owner):
    if not isinstance(owner, Ed25519PrivateKey):
        raise ValueError("Trusted owner signing key required")
    return _pack([tag, payload, owner.sign(_signature_message(tag, payload))])


def _verify(packet, anchor, tag, limit):
    fields = _unpack(packet, limit=limit, array_cap=3)
    if (
        type(fields) is not list
        or len(fields) != 3
        or fields[0] != tag
        or type(fields[1]) is not bytes
        or type(fields[2]) is not bytes
        or len(fields[2]) != 64
    ):
        raise ValueError("Wrong signed envelope")
    payload, signature = fields[1:]
    try:
        anchor.verify(signature, _signature_message(tag, payload))
    except InvalidSignature as error:
        raise ValueError("Owner authentication rejected") from error
    return payload


def _profile_fields(profile):
    return [
        profile.n,
        profile.dimension,
        profile.q.to_bytes(native.COMMON_WIDTH, "little"),
        profile.p,
        profile.t,
        profile.eta,
        ORIGIN_TAG,
    ]


def _profile(fields):
    if (
        type(fields) is not list
        or len(fields) != 7
        or fields[6] != ORIGIN_TAG
        or any(type(fields[i]) is not int for i in (0, 1, 3, 4, 5))
    ):
        raise ValueError("Wrong declared owner-origin profile")
    q = int.from_bytes(_fixed(fields[2], native.COMMON_WIDTH, "Q"), "little")
    return Profile(fields[0], fields[1], q, fields[3], fields[4], fields[5], "owner", "canonical30")


def _metadata(profile, primes, key_id, ids):
    if (
        type(primes) is not list
        or len(primes) != 2
        or type(ids) is not bytes
        or not ids
        or len(ids) % 8
        or len(ids) > 2 * profile.n * 8
    ):
        raise ValueError("Wrong complete prime/record coverage")
    values = tuple(int.from_bytes(ids[at : at + 8], "little") for at in range(0, len(ids), 8))
    metadata = native.PublicMetadata(
        profile, tuple(primes), _fixed(key_id, 32, "key ID").hex(), values
    )
    if any(
        (p - 1) % (2 * profile.n) or not is_prime(p, 50) for p in metadata.primes
    ) or not is_prime(profile.p, 50):
        raise ValueError("Wrong actual prime/terminal profile")
    return metadata


def _public_key(metadata):
    # Seed expansion needs only the authenticated namespace and public profile;
    # it does not use the asymmetric public-key A/B polynomials. Their origin
    # relationship is supplied by the honest owner, not inferred from this view.
    p = metadata.profile
    return bgv.PublicKey(p.n, p.t, mpz(p.q), p.eta, (), (), metadata.key_id)


def _expand_seeded(packet, metadata):
    p = metadata.profile
    width = p.n * native.COMMON_WIDTH
    fields = _unpack(packet, limit=width + 256, array_cap=4)
    if type(fields) is not list or len(fields) != 4 or any(type(x) is not bytes for x in fields):
        raise ValueError("Wrong original seeded packet")
    # The existing public parser checks tag, key, seed, coefficient range and
    # complete coverage before expanding the uniform term. No encryption runs.
    cipher = seeded.expand(packet, _public_key(metadata))
    return native.pack_common(tuple(tuple(map(int, row)) for row in cipher.components), p.n, p.q)


def sign_enrollment(metadata, key_body, index_packets, epoch, policy_digest, owner):
    """Trusted owner helper; binary encoding/sampler correctness is an assumption."""
    if type(metadata) is not native.PublicMetadata or type(index_packets) is not tuple:
        raise ValueError("Owner metadata and immutable seeded index required")
    p = metadata.profile
    if (
        type(key_body) is not bytes
        or len(key_body) != (p.levels + 1) * 8 * p.n * native.COMMON_WIDTH
        or len(index_packets) != metadata.groups * p.dimension
        or any(
            type(packet) is not bytes or len(packet) > p.n * native.COMMON_WIDTH + 256
            for packet in index_packets
        )
    ):
        raise ValueError("Wrong full owner input coverage")
    payload = _pack(
        [
            _profile_fields(p),
            list(metadata.primes),
            bytes.fromhex(metadata.key_id),
            b"".join(value.to_bytes(8, "little") for value in metadata.ids),
            _epoch(epoch),
            _fixed(policy_digest, 32, "policy digest"),
            key_body,
            list(index_packets),
        ]
    )
    if len(payload) + 128 > native.PACKET_CAP:
        raise ValueError("Enrollment packet cap exceeded")
    return _sign(ENROLL_TAG, payload, owner)


def sign_request(snapshot_id, epoch, policy_digest, nonce, seeded_query, owner):
    """A nonce is an owner-chosen request identity; the later journal enforces reuse."""
    if type(seeded_query) is not bytes or len(seeded_query) > 16384 * native.COMMON_WIDTH + 256:
        raise ValueError("Wrong bounded original query")
    payload = _pack(
        [
            _fixed(snapshot_id, 32, "snapshot ID"),
            _epoch(epoch),
            _fixed(policy_digest, 32, "policy digest"),
            _fixed(nonce, 32, "request nonce"),
            seeded_query,
        ]
    )
    return _sign(QUERY_TAG, payload, owner)


@dataclass(frozen=True)
class RequestBinding:
    snapshot_id: bytes
    epoch: int
    policy_digest: bytes
    request_digest: bytes
    nonce: bytes
    ids_digest: bytes

    def fields(self):
        return [
            self.snapshot_id,
            self.epoch,
            self.policy_digest,
            self.request_digest,
            self.nonce,
            self.ids_digest,
        ]


class OwnerFactory:
    """Trusted local entry point; the owner verification anchor is never peer-chosen."""

    def __init__(self, owner_public_key, library):
        if type(library) is not native.NativeLibrary:
            raise ValueError("Explicit trusted isolated native library required")
        self._anchor = Ed25519PublicKey.from_public_bytes(_fixed(owner_public_key, 32, "owner key"))
        self._owner_id = owner_public_key
        self._library = library
        # A reproducibility/policy binding, not attestation of execution. The
        # local filesystem/runtime is trusted in this prototype.
        self._policy_digest = hashlib.sha256(
            _pack(
                [
                    POLICY_TAG,
                    native.ABI,
                    hashlib.sha256(library.path.read_bytes()).digest(),
                    hashlib.sha256(Path(native.__file__).read_bytes()).digest(),
                    hashlib.sha256(Path(__file__).read_bytes()).digest(),
                ]
            )
        ).digest()

    @property
    def policy_digest(self):
        return self._policy_digest

    def enroll(self, packet):
        payload = _verify(packet, self._anchor, ENROLL_TAG, native.PACKET_CAP)
        fields = _unpack(payload, limit=native.PACKET_CAP, array_cap=1024)
        if type(fields) is not list or len(fields) != 8:
            raise ValueError("Wrong complete owner enrollment")
        metadata = _metadata(_profile(fields[0]), fields[1], fields[2], fields[3])
        epoch = _epoch(fields[4])
        if _fixed(fields[5], 32, "policy digest") != self.policy_digest:
            raise ValueError("Foreign code/policy enrollment")
        p, keys, index = metadata.profile, fields[6], fields[7]
        if (
            type(keys) is not bytes
            or len(keys) != (p.levels + 1) * 8 * p.n * native.COMMON_WIDTH
            or type(index) is not list
            or len(index) != metadata.groups * p.dimension
        ):
            raise ValueError("Wrong full enrolled key/index coverage")
        # Validate every key coordinate before seed preparation or native NTTs.
        for at in range(0, len(keys), native.COMMON_WIDTH):
            if int.from_bytes(keys[at : at + native.COMMON_WIDTH], "little") >= p.q:
                raise ValueError("Noncanonical enrolled key coordinate")
        stride = 2 * p.n * native.COMMON_WIDTH
        expanded = bytearray(len(index) * stride)
        for tile, seeded_packet in enumerate(index):
            expanded[tile * stride : (tile + 1) * stride] = _expand_seeded(seeded_packet, metadata)
        # No peer graph, bounds or plan object is accepted by the native core.
        context = self._library.enroll(metadata, keys, bytes(expanded))
        snapshot = hashlib.sha256(ENROLL_TAG + self._owner_id + payload).digest()
        return OwnerEnrollment(self, context, snapshot, epoch, packet)


class OwnerEnrollment:
    """An authenticated immutable snapshot, not a current-snapshot authority."""

    def __init__(self, factory, context, snapshot_id, epoch, public_wire):
        self._factory, self._context = factory, context
        self._snapshot_id, self._epoch, self._public_wire = snapshot_id, epoch, public_wire

    @property
    def snapshot_id(self):
        return self._snapshot_id

    @property
    def epoch(self):
        return self._epoch

    @property
    def metadata(self):
        return self._context.metadata

    @property
    def public_wire(self):
        return self._public_wire

    @property
    def stats(self):
        return self._context.stats

    def request(self, packet):
        self._context._require_process()
        self._context._require_open()
        p = self.metadata.profile
        payload = _verify(
            packet, self._factory._anchor, QUERY_TAG, p.n * native.COMMON_WIDTH + 1024
        )
        fields = _unpack(payload, limit=p.n * native.COMMON_WIDTH + 768, array_cap=5)
        if (
            type(fields) is not list
            or len(fields) != 5
            or _fixed(fields[0], 32, "snapshot ID") != self.snapshot_id
            or _epoch(fields[1]) != self.epoch
            or _fixed(fields[2], 32, "policy digest") != self._factory.policy_digest
        ):
            raise ValueError("Foreign signed request context")
        nonce = _fixed(fields[3], 32, "request nonce")
        raw = _expand_seeded(fields[4], self.metadata)
        digest = hashlib.sha256(QUERY_TAG + self._factory._owner_id + payload).digest()
        ids = b"".join(value.to_bytes(8, "little") for value in self.metadata.ids)
        binding = RequestBinding(
            self.snapshot_id,
            self.epoch,
            self._factory.policy_digest,
            digest,
            nonce,
            hashlib.sha256(ids).digest(),
        )
        return PublicRequest(self._context.query(raw), binding, packet)

    def close(self):
        self._context.close()

    def __enter__(self):
        self._context.__enter__()
        return self

    def __exit__(self, *_args):
        self.close()

    def __copy__(self):
        raise TypeError("Authenticated enrollment ownership cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Authenticated enrollment ownership cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Authenticated enrollment ownership cannot be serialized")


class PublicRequest:
    """Owned signed original query and full public reply predicate, with no callback."""

    def __init__(self, query, binding, original_wire):
        self._query, self._binding, self._original_wire = query, binding, original_wire

    @property
    def binding(self):
        return self._binding

    @property
    def original_wire(self):
        return self._original_wire

    def reply(self, body, compact_frame):
        """Public producer framing helper; its output must still be checked."""
        if (
            type(body) is not bytes
            or len(body) != self._query.metadata.body_size
            or type(compact_frame) is not bytes
            or len(compact_frame)
            > 2 * self._query.metadata.groups * self._query.metadata.terminal_row_size + 256
        ):
            raise ValueError("Wrong full reply body/frame coverage")
        return _pack([REPLY_TAG, *self.binding.fields(), body, compact_frame])

    def produce_packet(self):
        body = self._query.produce()
        return self.reply(body, self._query.expected_response(body))

    def accepts_packet(self, packet):
        # Reject ownership before parsing; this is public acceptance, never a
        # permission to run private work or a proof of current snapshot state.
        self._query._require_process()
        self._query._require_open()
        try:
            limit = (
                self._query.metadata.body_size
                + 2 * self._query.metadata.groups * self._query.metadata.terminal_row_size
                + 1024
            )
            fields = _unpack(packet, limit=limit, array_cap=9)
            return (
                type(fields) is list
                and len(fields) == 9
                and fields[0] == REPLY_TAG
                and type(fields[2]) is int
                and all(type(fields[i]) is bytes and len(fields[i]) == 32 for i in (1, 3, 4, 5, 6))
                and fields[1:7] == self.binding.fields()
                and self._query.verifies(fields[7], fields[8])
            )
        except (ValueError, TypeError, OverflowError):
            return False

    def close(self):
        self._query.close()

    def __enter__(self):
        self._query.__enter__()
        return self

    def __exit__(self, *_args):
        self.close()

    def __copy__(self):
        raise TypeError("Signed native request ownership cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Signed native request ownership cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Signed native request ownership cannot be serialized")
