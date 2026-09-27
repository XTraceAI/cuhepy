"""Experimental BGV authentication: measured evaluation BEFORE private decryption.

Reuses the BFV AWS Nitro certificate/PCR verifier, with separate BGV domains.
The enclave receives only public data. Its ephemeral receipt key authenticates
output computed inside that enclave, never caller-supplied ciphertexts/hashes.
There is no CUDA endorsement, mock-root option or unauthenticated fallback.

This is a protocol implementation for review, not a production assurance claim.
See docs/research/bgv-authentication.md for the threat model and private scope.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time
from typing import Any, Protocol

from Crypto.Signature import eddsa

from cuhepy.hamming.bfv_nitro import (
    MAX_NITRO_DOCUMENT_BYTES, NitroAttestationPolicy, NitroIdentity, verify_nitro_attestation,
)
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, transport_bgv as wire
from experiments.bfv_search_lab import compressed_query_bgv as query_codec
from experiments.bfv_search_lab import compressed_response_bgv as response_codec
from experiments.bfv_search_lab import owner_bgv as owner, results_bgv as results
from experiments.bfv_search_lab.native_bgv import NativeServer
from experiments.bfv_search_lab.private_bgv import PrivateDecoder
from experiments.bfv_search_lab.security_bgv import (
    BGVExecutionPolicy, BGVProtocolError, context, exact_bytes, pack_setup, unpack_setup,
)

_REGISTER, _HELLO, _QUERY, _RECEIPT = b"XGNI01", b"XGNH01", b"XGNQ01", b"XGNR01"
_OWNER_CONTEXT = b"CUHEPY-BGV-NITRO-OWNER-v1"
_POP_CONTEXT = b"CUHEPY-BGV-NITRO-ENROLL-v1"
_RECEIPT_CONTEXT = b"CUHEPY-BGV-NITRO-RECEIPT-v1"
HELLO_BYTES, QUERY_OVERHEAD, RECEIPT_BYTES, REGISTRATION_OVERHEAD = 134, 134, 198, 110
_SESSION_SECONDS, _MAX_ATTESTATIONS = 300, 1024


def _verifier(public: bytes, domain: bytes) -> Any:
    key = eddsa.import_public_key(exact_bytes(public, 32))
    if (key.pointQ * 8).is_point_at_infinity():
        raise BGVProtocolError("Invalid BGV signing identity")
    return eddsa.new(key, "rfc8032", context=domain)


def _session(context_digest: bytes, nonce: bytes, key: bytes) -> bytes:
    return hashlib.sha256(b"CUHEPY-BGV-NITRO-SESSION-v1\0" + context_digest + nonce + key).digest()


class _Attestor(Protocol):
    def random_seed(self) -> bytes: ...
    def attest(self, public_key: bytes, nonce: bytes, context: bytes) -> bytes: ...


class BGVAttestedServer:
    """Public CPU evaluator intended to execute INSIDE a measured Nitro image.

    Instantiation on an ordinary machine establishes no trust. An arbitrary
    attestor cannot generate evidence accepted under the verifier's AWS root.
    The first valid registrant may occupy an empty service; hosting access
    control and availability are separate from result authenticity.
    """

    def __init__(self, registration: bytes, attestor: _Attestor, *,
                 policy: BGVExecutionPolicy | None = None) -> None:
        self.policy = policy or BGVExecutionPolicy()
        if (type(registration) is not bytes
            or not REGISTRATION_OVERHEAD < len(registration)
            <= self.policy.max_setup_bytes + REGISTRATION_OVERHEAD
            or registration[:6] != _REGISTER):
            raise BGVProtocolError("Invalid BGV registration")
        public, epoch = registration[6:38], int.from_bytes(registration[38:46], "big")
        setup = registration[46:-64]
        self._context = context(setup, public, epoch, self.policy)
        self._owner = _verifier(public, _OWNER_CONTEXT)
        # Hash opaque bounded bytes and verify authorization BEFORE setup parsing.
        self._owner.verify(_REGISTER + self._context, registration[-64:])
        pk, keys, index, count = unpack_setup(setup, self.policy)
        self._server = NativeServer(pk, keys, residue=True, device="cpu")
        self._index = self._server.prepare_index(index, count)
        self._bounds = self.policy.response_bounds(pk, count)
        self._attestor = attestor
        key = eddsa.import_private_key(exact_bytes(attestor.random_seed(), 32))
        self._public = key.public_key().export_key(format="raw")
        self._spki = key.public_key().export_key(format="DER")
        self._signer = eddsa.new(key, "rfc8032", context=_RECEIPT_CONTEXT)
        self._enrollment = eddsa.new(key, "rfc8032", context=_POP_CONTEXT)
        self._active: bytes | None = None
        self._deadline = 0.0
        self._seen_hellos: set[bytes] = set()
        self._seen_queries: set[bytes] = set()
        self._pid = os.getpid()
        self._lock = threading.Lock()

    def _process(self) -> None:
        if os.getpid() != self._pid:
            raise BGVProtocolError("Start a fresh attested BGV server after fork")

    def attest(self, hello: bytes) -> tuple[bytes, bytes]:
        self._process()
        with self._lock:
            exact_bytes(hello, HELLO_BYTES)
            if hello[:6] != _HELLO or hello[6:38] != self._context:
                raise BGVProtocolError("BGV enrollment context mismatch")
            self._owner.verify(hello[:-64], hello[-64:])
            nonce = hello[38:70]
            if nonce in self._seen_hellos or len(self._seen_hellos) >= _MAX_ATTESTATIONS:
                raise BGVProtocolError("BGV enrollment replay or exhausted budget")
            self._seen_hellos.add(nonce)
            self._active = None
            document = self._attestor.attest(self._spki, nonce, self._context)
            if type(document) is not bytes or not 0 < len(document) <= MAX_NITRO_DOCUMENT_BYTES:
                raise BGVProtocolError("Invalid Nitro evidence length")
            proof = self._enrollment.sign(hello[:-64] + hashlib.sha256(document).digest())
            self._active = _session(self._context, nonce, self._public)
            self._deadline = time.monotonic() + _SESSION_SECONDS
            return document, proof

    def search(self, request: bytes) -> tuple[bytes, bytes]:
        self._process()
        with self._lock:
            if (self._active is None or time.monotonic() >= self._deadline
                or type(request) is not bytes
                or not QUERY_OVERHEAD < len(request) <= self.policy.max_query_bytes + QUERY_OVERHEAD
                or request[:6] != _QUERY or request[6:38] != self._active):
                raise BGVProtocolError("BGV attested query rejected")
            inner = request[38:-64]  # 32-byte owner nonce followed by seeded ciphertext.
            digest = hashlib.sha256(inner).digest()
            self._owner.verify(_QUERY + self._context + self._active + digest, request[-64:])
            if digest in self._seen_queries or len(self._seen_queries) >= self.policy.max_queries:
                raise BGVProtocolError("BGV query replay or exhausted budget")
            self._seen_queries.add(digest)  # One attempt, including evaluation failure.
            pk = self._server.pk
            query = (query_codec.expand(inner[32:], pk, dropped_bits=self.policy.query_drop_bits,
                                         backend="native") if self.policy.query_drop_bits
                     else owner.expand(inner[32:], pk))
            response = self._server.search_compact(query, self._index,
                                                   bits=self.policy.terminal_bits)
            # Exactly one CPU evaluation. The only signed response is its output.
            packet = compact.pack(response, self._index.count, self.policy.dimension, pk)
            if self.policy.response_drop_bits:
                packet = response_codec.compress(packet, pk, count=self._index.count,
                    dimension=self.policy.dimension, bits=self.policy.terminal_bits,
                    bounds=self._bounds, dropped_bits=self.policy.response_drop_bits, backend="native")
            if len(packet) > self.policy.max_response_bytes or time.monotonic() >= self._deadline:
                raise BGVProtocolError("BGV response exceeded its byte budget or session lease")
            message = (_RECEIPT + self._context + self._active + digest
                       + hashlib.sha256(packet).digest())
            return packet, message + self._signer.sign(message)

    def __reduce_ex__(self, protocol: Any) -> Any:
        raise TypeError("Attested BGV servers cannot be copied or serialized")


class BGVAttestedClient:
    """Owner client with mandatory Nitro provenance and a fixed-work decoder.

    Raw OwnerClient remains a separate fixture API. A failed receipt never
    falls back to it. The native decoder covers terminal secret arithmetic;
    this client's key import, encryption and plaintext handling are variable-time.
    """

    def __init__(self, pk: bgv.PublicKey, sk: bgv.SecretKey, keys: trace.EvaluationKeys,
                 index: list[bgv.Ciphertext], count: int,
                 attestation_policy: NitroAttestationPolicy, *, index_epoch: int = 0,
                 policy: BGVExecutionPolicy | None = None) -> None:
        if not isinstance(attestation_policy, NitroAttestationPolicy):
            raise TypeError("An explicit Nitro PCR policy is required")
        self.policy = policy or BGVExecutionPolicy()
        self.attestation_policy = attestation_policy
        self.pk, self.count = pk, count
        self._bounds = self.policy.response_bounds(pk, count)
        self._setup = pack_setup(pk, keys, index, count, self.policy)
        key = eddsa.import_private_key(secrets.token_bytes(32))
        self._public = key.public_key().export_key(format="raw")
        self._owner: Any = eddsa.new(key, "rfc8032", context=_OWNER_CONTEXT)
        self._context = context(self._setup, self._public, index_epoch, self.policy)
        self._epoch = index_epoch
        self._decoder = PrivateDecoder(pk, sk, bits=self.policy.terminal_bits)
        self._encryptor = owner.OwnerClient(pk, sk, native=True, rns=True)
        self._identity: NitroIdentity | None = None
        self._active: bytes | None = None
        self._receipt_verifier: Any = None
        self._deadline = 0.0
        self._hello: bytes | None = None
        self._hello_started = 0.0
        self._pending: set[bytes] = set()
        self._used_queries = 0
        self._closed = False
        self._pid = os.getpid()
        self._gate = threading.RLock()

    def _check(self) -> None:
        if os.getpid() != self._pid or self._closed:
            raise BGVProtocolError("BGV client is closed or belongs to another process")

    def registration_packet(self) -> bytes:
        self._check()
        with self._gate:
            self._check()
            return (_REGISTER + self._public + self._epoch.to_bytes(8, "big") + self._setup
                    + self._owner.sign(_REGISTER + self._context))

    def begin_attestation(self) -> bytes:
        self._check()
        with self._gate:
            self._check()
            self._active = self._identity = self._receipt_verifier = None
            self._pending.clear()
            self._hello_started = time.monotonic()
            self._hello = _HELLO + self._context + secrets.token_bytes(32)
            return self._hello + self._owner.sign(self._hello)

    def accept_attestation(self, document: bytes, proof: bytes) -> None:
        self._check()
        with self._gate:
            self._check()
            try:
                if self._hello is None or time.monotonic() - self._hello_started > (
                    self.attestation_policy.handshake_timeout_seconds
                ):
                    raise BGVProtocolError("No current BGV Nitro challenge")
                identity = verify_nitro_attestation(document, self.attestation_policy,
                    nonce=self._hello[38:70], context=self._context)
                _verifier(identity.public_key, _POP_CONTEXT).verify(
                    self._hello + hashlib.sha256(document).digest(), exact_bytes(proof, 64))
                remaining = min(self.attestation_policy.max_session_seconds,
                                identity.certificate_expires_at - time.time())
                if remaining <= 0 or time.monotonic() - self._hello_started > (
                    self.attestation_policy.handshake_timeout_seconds
                ):
                    raise BGVProtocolError("BGV enrollment expired")
                self._receipt_verifier = _verifier(identity.public_key, _RECEIPT_CONTEXT)
                self._active = _session(self._context, self._hello[38:70], identity.public_key)
                self._identity = identity
                self._deadline = time.monotonic() + remaining
                self._hello = None
            except (ValueError, TypeError, OverflowError):
                raise BGVProtocolError("BGV enrollment rejected before decryption") from None

    def _require_session(self) -> bytes:
        self._check()
        if (self._identity is None or self._active is None
            or time.monotonic() >= self._deadline
            or time.time() >= self._identity.certificate_expires_at):
            raise BGVProtocolError("Fresh BGV Nitro attestation is required")
        return self._active

    def begin_query(self, query: list[int]) -> bytes:
        self._check()
        with self._gate:
            session = self._require_session()
            if (len(self._pending) >= self.policy.max_pending
                or self._used_queries >= self.policy.max_queries):
                raise BGVProtocolError("BGV query budget exhausted")
            if len(query) != self.policy.dimension or any(type(x) is not int or x not in (0, 1) for x in query):
                raise ValueError("Expected a binary BGV query of the pinned dimension")
            self._used_queries += 1
            message, _ = bgv.coefficient_inputs(query, [], self.pk.n)
            packet = self._encryptor.encrypt(message)
            if self.policy.query_drop_bits:
                packet = query_codec.compress(packet, self.pk,
                    dropped_bits=self.policy.query_drop_bits, backend="native")
            if len(packet) > self.policy.max_query_bytes:
                raise BGVProtocolError("BGV query exceeds its byte budget")
            inner = secrets.token_bytes(32) + packet
            digest = hashlib.sha256(inner).digest()
            self._require_session()  # Encryption must not carry us beyond the lease.
            signature = self._owner.sign(_QUERY + self._context + session + digest)
            self._pending.add(digest)
            return _QUERY + session + inner + signature

    def finish_query(self, response: bytes, receipt: bytes, *, k: int = 3,
                     all_distances: bool = True) -> results.SearchResult:
        self._check()
        with self._gate:
            try:
                session = self._require_session()
                if type(response) is not bytes or not 0 < len(response) <= self.policy.max_response_bytes:
                    raise BGVProtocolError("Invalid BGV response length")
                exact_bytes(receipt, RECEIPT_BYTES)
                digest = receipt[70:102]
                if (receipt[:6] != _RECEIPT or receipt[6:38] != self._context
                    or receipt[38:70] != session or digest not in self._pending
                    or receipt[102:134] != hashlib.sha256(response).digest()):
                    raise BGVProtocolError("BGV receipt binding mismatch")
                self._receipt_verifier.verify(receipt[:134], receipt[134:])
                self._require_session()
            except (ValueError, TypeError, OverflowError):
                raise BGVProtocolError("BGV response rejected before decryption") from None
            # Consume once BEFORE parsing, decompression, or private operations.
            # Authentication failures above leave the legitimate ticket available.
            self._pending.remove(digest)
            results.validate_layout(self.pk.n, self.pk.t, self.count, self.policy.dimension, k, all_distances)
            bounds = self._bounds
            if self.policy.response_drop_bits:
                response, bounds = response_codec.expand(response, self.pk, count=self.count,
                    dimension=self.policy.dimension, bits=self.policy.terminal_bits,
                    bounds=bounds, dropped_bits=self.policy.response_drop_bits, backend="native")
            pairs = wire._unpack_fields(response, self.pk, count=self.count,
                dimension=self.policy.dimension, modulus=self._decoder.modulus, bounds=bounds)
            plaintexts = self._decoder.decode_packed(pairs)
            # Deliberately use arithmetic decoding, not a plaintext-indexed lookup
            # table. Python result handling/top-k remains outside the CT scope.
            return results.finish(plaintexts, self.count, self.policy.dimension, self.pk,
                                  k=k, all_distances=all_distances, method="heap")

    def cancel_pending_queries(self) -> None:
        self._check()
        with self._gate:
            self._check()
            self._pending.clear()

    def close(self) -> None:
        if os.getpid() != self._pid:
            raise BGVProtocolError("BGV client belongs to another process")
        with self._gate:
            self._closed = True
            self._pending.clear()
            self._hello = self._active = self._identity = self._receipt_verifier = None
            self._decoder.close()
            self._encryptor.close()
            self._owner = None  # Drop references; Python signing keys are not securely erased.

    def __reduce_ex__(self, protocol: Any) -> Any:
        raise TypeError("Attested BGV clients cannot be copied or serialized")
