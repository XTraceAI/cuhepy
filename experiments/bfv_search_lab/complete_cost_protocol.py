"""Q77 local result delivery after complete public admission.

This bridge measures a protected-process prototype, not attested execution or
a secure remote service. The signer has no HE secret. It signs only from the
existing durable journal's claimed callback. The client uses a separately
trusted local verifier anchor and owner descriptor; no message promotes either.
Private callbacks and their results stay in the owner process. Crash-resistant
client state, nonrollback host state and private side channels remain Q78.
"""

from __future__ import annotations

import hashlib
import os
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import gmpy2
import msgpack

from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import lifecycle_shared_query as life
from experiments.bfv_search_lab import shared_query_certificate as cert
from experiments.bfv_search_lab import shared_query_client_context as context

ENVELOPE_TAG = b"cuhepy/Q77/local-result-envelope/v1"
PAYLOAD_TAG = b"cuhepy/Q77/local-result/v1"
SIGN_DOMAIN = b"cuhepy/Q77/local-result-signature/v1\0"
MAX_ATTEMPTS = 256


class PrivateFinishFailed(RuntimeError):
    """Consumed local attempt; no callback exception or result is disclosed."""


def _pack(value):
    return msgpack.packb(value, use_bin_type=True)


def _unpack(packet, limit):
    if type(packet) is not bytes or not 1 <= len(packet) <= limit:
        raise ValueError("Invalid immutable bounded result packet")
    try:
        fields = msgpack.unpackb(
            packet,
            raw=False,
            max_array_len=9,
            max_map_len=0,
            max_bin_len=limit,
            max_str_len=64,
            max_ext_len=0,
        )
        if _pack(fields) != packet:
            raise ValueError("Noncanonical result encoding")
        return fields
    except (ValueError, TypeError, OverflowError, RecursionError, msgpack.UnpackException) as error:
        raise ValueError("Malformed result encoding") from error


def frame_limit(metadata):
    if type(metadata) is not context.ClientMetadata:
        raise ValueError("Verified owner client metadata required")
    p = metadata.geometry
    groups = (len(metadata.ids) + p.n - 1) // p.n
    return 2 * groups * ((p.n * p.p.bit_length() + 7) // 8) + 256


def validate_frame(frame, metadata):
    """Validate public complete compact syntax, not secret phase correctness.

    Runtime equality is the protected signer's admission obligation. This check
    includes every physical ciphertext coordinate and canonical bit padding;
    zero plaintext tails and Hamming semantics belong to the private finish.
    """
    p = metadata.geometry
    fields = _unpack(frame, frame_limit(metadata))
    expected = [
        "cuhepy-lab-bgv-compact-v1",
        p.n,
        p.t,
        p.p.to_bytes((p.p.bit_length() + 7) // 8, "little"),
        metadata.key_id,
        len(metadata.ids),
        p.dimension,
    ]
    groups = (len(metadata.ids) + p.n - 1) // p.n
    width = (p.n * p.p.bit_length() + 7) // 8
    if (
        type(fields) is not list
        or len(fields) != 2
        or _pack(fields[0]) != _pack(expected)
        or type(fields[1]) is not list
        or len(fields[1]) != groups
    ):
        raise ValueError("Foreign or incomplete compact frame")
    for pair in fields[1]:
        if type(pair) is not list or len(pair) != 2:
            raise ValueError("Incomplete compact component coverage")
        for row in pair:
            if type(row) is not bytes or len(row) != width:
                raise ValueError("Wrong full compact polynomial coverage")
            value = gmpy2.mpz.from_bytes(row, "little")
            if value.bit_length() > p.n * p.p.bit_length():
                raise ValueError("Noncanonical compact bit padding")
            coefficients = gmpy2.unpack(value, p.p.bit_length())
            if len(coefficients) > p.n or any(coefficient >= p.p for coefficient in coefficients):
                raise ValueError("Noncanonical compact coefficient")
    return frame


def original_binding(packet, owner_anchor, metadata, mode):
    """Bind a signed original without expanding ciphertexts or using an HE key."""
    selected = metadata.mode(mode)
    width = metadata.geometry.n * 15
    payload = auth._verify(
        packet, Ed25519PublicKey.from_public_bytes(owner_anchor), auth.QUERY_TAG, width + 1024
    )
    fields = auth._unpack(payload, limit=width + 768, array_cap=5)
    if (
        type(fields) is not list
        or len(fields) != 5
        or auth._fixed(fields[0], 32, "snapshot") != selected.snapshot_id
        or auth._epoch(fields[1]) != selected.epoch
        or auth._fixed(fields[2], 32, "policy") != selected.policy_digest
        or type(fields[4]) is not bytes
        or not 1 <= len(fields[4]) <= width + 256
    ):
        raise ValueError("Original request differs from owner mode context")
    return auth.RequestBinding(
        selected.snapshot_id,
        selected.epoch,
        selected.policy_digest,
        hashlib.sha256(auth.QUERY_TAG + owner_anchor + payload).digest(),
        auth._fixed(fields[3], 32, "nonce"),
        metadata.ordered_ids_digest,
    )


def _payload(metadata, mode, binding, frame):
    selected = metadata.mode(mode)
    if (
        type(binding) is not auth.RequestBinding
        or binding.snapshot_id != selected.snapshot_id
        or type(binding.epoch) is not int
        or binding.epoch != selected.epoch
        or binding.policy_digest != selected.policy_digest
        or binding.ids_digest != metadata.ordered_ids_digest
    ):
        raise ValueError("Foreign complete result binding")
    life._binding_bytes(binding)
    pin = metadata.pin
    return _pack(
        [
            PAYLOAD_TAG,
            pin.namespace,
            pin.revision,
            pin.epoch,
            pin.payload_digest,
            metadata.key_id,
            selected.fields(),
            binding.fields(),
            frame,
        ]
    )


def _signed_packet(owner, metadata, mode, binding, frame):
    """Trusted implementation detail; tests use only public signing fixtures."""
    validate_frame(frame, metadata)
    payload = _payload(metadata, mode, binding, frame)
    return _pack([ENVELOPE_TAG, payload, owner.sign(SIGN_DOMAIN + payload)])


class _Owned:
    def _initialize(self):
        self._pid, self._closed = os.getpid(), False
        self._lock = threading.RLock()

    def _process(self):
        if os.getpid() != self._pid:
            raise RuntimeError("Inherited local result context")

    def _open(self):
        if self._closed:
            raise RuntimeError("Closed local result context")

    def __copy__(self):
        raise TypeError("Local result ownership cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Local result ownership cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Local result context cannot be serialized")


class LocalResultSigner(_Owned):
    """One signing entry point, after the existing durable admission claim."""

    def __init__(self, journal, signer, descriptor):
        if type(journal) is not life.LocalJournal:
            raise ValueError("Explicit trusted local journal required")
        if not isinstance(signer, Ed25519PrivateKey):
            raise ValueError("Locally provisioned result signing key required")
        if type(descriptor) is not context.DescriptorClient:
            raise ValueError("Owner-pinned descriptor handle required")
        journal._require()
        descriptor._process()
        if journal._owner != descriptor._anchor:
            raise ValueError("Journal and descriptor must have the same trusted owner anchor")
        self._initialize()
        self._journal, self._signer, self._descriptor = journal, signer, descriptor

    @property
    def public_key(self):
        self._process()
        with self._lock:
            self._open()
            return self._signer.public_key().public_bytes_raw()

    def issue(self, authorization, mode):
        self._process()
        self._descriptor._process()
        # Descriptor advance and signing linearize under the same owner pin.
        with self._descriptor._lock, self._lock:
            self._open()
            metadata = self._descriptor.metadata()
            if type(authorization) is not life.LocalAuthorization:
                raise ValueError("Actual local journal authorization required")
            selected = metadata.mode(mode)
            if self._journal._policy != selected.policy_digest:
                raise ValueError("Signer journal differs from owner mode policy")
            _payload(metadata, mode, authorization.binding, authorization.frame)
            emitted = []

            def callback(frame):
                emitted.append(
                    _signed_packet(self._signer, metadata, mode, authorization.binding, frame)
                )

            life.LocalReleaseGuard(self._journal).deliver(authorization, callback)
            if len(emitted) != 1:
                raise RuntimeError("No unique claimed result was emitted")
            return emitted[0]

    def close(self):
        self._process()
        with self._lock:
            self._closed, self._signer = True, None


class ResultClient(_Owned):
    """Owner-local at-most-once private finish with fixed local verifier anchors.

    The attempt set is process-local, not a crash/nonrollback authority. Keep
    this handle in trusted owner custody for the entire registered block. A
    server never receives a private callback result or diagnostic from this API.
    """

    def __init__(self, descriptor, verifier_anchors):
        if type(descriptor) is not context.DescriptorClient:
            raise ValueError("Owner-pinned descriptor handle required")
        if (
            type(verifier_anchors) is not tuple
            or len(verifier_anchors) != 3
            or any(type(row) is not tuple or len(row) != 2 for row in verifier_anchors)
            or tuple(row[0] for row in verifier_anchors) != cert.MODES
        ):
            raise ValueError("All verifier anchors in trusted mode order required")
        for _, anchor in verifier_anchors:
            auth._fixed(anchor, 32, "local verifier anchor")
        self._initialize()
        self._descriptor, self._anchors = descriptor, dict(verifier_anchors)
        self._attempts = {}

    def begin(self, mode, original_packet):
        self._process()
        self._descriptor._process()
        with self._descriptor._lock, self._lock:
            self._open()
            metadata = self._descriptor.metadata()
            binding = original_binding(original_packet, self._descriptor._anchor, metadata, mode)
            if binding.nonce in self._attempts:
                raise life.ConsumedRequestError("Owner request identity already consumed")
            if len(self._attempts) >= MAX_ATTEMPTS:
                raise RuntimeError("Registered local owner attempt cap exhausted")
            attempt = _Attempt(self, metadata, mode, binding)
            self._attempts[binding.nonce] = attempt
            return attempt

    def close(self):
        self._process()
        with self._lock:
            self._closed = True


class _Attempt:
    def __init__(self, client, metadata, mode, binding):
        self._client, self._metadata, self._mode, self._binding = client, metadata, mode, binding
        self._state = "waiting"

    @property
    def binding(self):
        return self._binding

    def finish(self, packet, private_callback):
        client, descriptor = self._client, self._client._descriptor
        client._process()
        descriptor._process()
        if not callable(private_callback):
            raise ValueError("Owner-local private callback required")
        with descriptor._lock, client._lock:
            client._open()
            if self._state != "waiting":
                raise life.ConsumedRequestError("Owner finish already consumed")
            # First complete response attempt consumes this local identity,
            # including public rejection. No adaptive private callback retry.
            self._state = "rejected"
            current = descriptor.metadata()
            if current != self._metadata:
                raise life.StaleSnapshotError("Owner pin changed before private finish")
            limit = frame_limit(current) + 2048
            outer = _unpack(packet, limit)
            if (
                type(outer) is not list
                or len(outer) != 3
                or outer[0] != ENVELOPE_TAG
                or type(outer[1]) is not bytes
                or type(outer[2]) is not bytes
                or len(outer[2]) != 64
            ):
                raise ValueError("Malformed local result envelope")
            payload = outer[1]
            try:
                Ed25519PublicKey.from_public_bytes(client._anchors[self._mode]).verify(
                    outer[2], SIGN_DOMAIN + payload
                )
            except (ValueError, InvalidSignature) as error:
                raise ValueError("Foreign or modified local result") from error
            fields = _unpack(payload, limit)
            if type(fields) is not list or len(fields) != 9 or type(fields[8]) is not bytes:
                raise ValueError("Incomplete local result payload")
            frame = fields[8]
            # Byte equality rejects bool/int aliases, foreign contexts, mode
            # substitution, partial requests and noncanonical signed metadata.
            if payload != _payload(current, self._mode, self.binding, frame):
                raise ValueError("Result differs from exact current owner request")
            validate_frame(frame, current)
            self._state = "claimed"
            try:
                result = private_callback(frame)
            except Exception:
                self._state = "callback_failed"
                raise PrivateFinishFailed(
                    "Local private finish failed; attempt stays consumed"
                ) from None
            self._state = "delivered"
            return result

    def __copy__(self):
        raise TypeError("Local owner attempt cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Local owner attempt cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Local owner attempt cannot be serialized")
