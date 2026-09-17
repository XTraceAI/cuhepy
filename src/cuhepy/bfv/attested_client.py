"""One attested public BFV evaluation, with mandatory approval before decryption.

The owner retains BFV and request-signing secrets. The Nitro evaluator generates
its own ephemeral receipt key and computes each result itself. Its host knows
only public BFV data and the legacy transport MAC key. Raw and recomputing BFV
APIs remain separate; this protocol never falls back to them after rejection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from collections.abc import Sequence
from dataclasses import asdict
from typing import Protocol

from Crypto.Signature import eddsa

from cuhepy.bfv.assurance import bfv_review_policy, hamming_noise_bound
from cuhepy.bfv.client import BFVClient
from cuhepy.bfv.guarded_client import _CIRCUIT
from cuhepy.bfv.nitro import (
    MAX_NITRO_DOCUMENT_BYTES,
    NitroAttestationPolicy,
    NitroIdentity,
    verify_nitro_attestation,
)
from cuhepy.bfv.security import (
    BFVExecutionPolicy,
    BFVProtocolError,
    _bytes,
    _key,
    _pack,
    _record,
    _unpack,
    protect_bfv_state,
    unprotect_bfv_state,
)
from cuhepy.bfv.verified_client import BFVVerifiedClient, BFVVerifiedServer
from cuhepy.bfv.evaluator import BFVServerBackend
from cuhepy.bfv.private import BFVPrivateBackend


_REGISTER = b"XBNI01"
_HELLO = b"XBNH01"
_QUERY = b"XBNQ01"
_RECEIPT = b"XBNR01"
_OWNER_CONTEXT = b"XTRACE-BFV-NITRO-OWNER-v1"
_POP_CONTEXT = b"XTRACE-BFV-NITRO-ENROLL-v1"
_RECEIPT_CONTEXT = b"XTRACE-BFV-NITRO-RECEIPT-v1"
_STATE_CONTEXT = b"XTRACE-BFV-NITRO-PRIVATE-STATE-v1"
# Shared with the bounded transport; changing a format requires a new version.
NITRO_HELLO_BYTES = 6 + 32 + 32 + 64
NITRO_QUERY_OVERHEAD = 6 + 32 + 64
NITRO_RECEIPT_BYTES = 6 + 4 * 32 + 64
_SESSION_SECONDS = 300
_MAX_ATTESTATIONS = 1024


def _verifier(public_key: bytes, context: bytes) -> eddsa.EdDSASigScheme:
    """Import an Ed25519 identity, rejecting small-order keys before use."""
    key = eddsa.import_public_key(_bytes(public_key, 32))
    if (key.pointQ * 8).is_point_at_infinity():
        raise BFVProtocolError("Invalid BFV signing identity")
    return eddsa.new(key, "rfc8032", context=context)


def _epoch(index_epoch: int) -> bytes:
    """Encode an owner-maintained index version without bool/integer coercion."""
    if type(index_epoch) is not int or not 0 <= index_epoch < 1 << 64:
        raise ValueError("BFV index epoch must be an unsigned 64-bit integer")
    return index_epoch.to_bytes(8, "big")


def _policy_digest(policy: BFVExecutionPolicy) -> bytes:
    """Commit to local arithmetic AND admission limits, independent of map order."""
    return hashlib.sha256(
        json.dumps(asdict(policy), sort_keys=True, separators=(",", ":")).encode()
    ).digest()


def _context(
    setup_digest: bytes, owner: bytes, index_epoch: int, policy: BFVExecutionPolicy
) -> bytes:
    """Bind the circuit, actual setup, epoch, owner and execution policy together."""
    return hashlib.sha256(
        b"XTRACE-BFV-NITRO-CONTEXT-v1\0"
        + _CIRCUIT
        + _policy_digest(policy)
        + _bytes(setup_digest, 32)
        + _bytes(owner, 32)
        + _epoch(index_epoch)
    ).digest()


def _session_id(context: bytes, nonce: bytes, public_key: bytes) -> bytes:
    """Separate renewals and enclave restarts, even for an unchanged BFV index."""
    return hashlib.sha256(b"XTRACE-BFV-NITRO-SESSION-v1\0" + context + nonce + public_key).digest()


class _Attestor(Protocol):
    """Protected-runtime evidence source; the remote client still verifies AWS PKI."""

    def random_seed(self) -> bytes: ...
    def attest(self, public_key: bytes, nonce: bytes, context: bytes) -> bytes: ...


class BFVAttestedServer:
    """Public-only evaluator intended to execute INSIDE the measured Nitro image.

    A local instance is not a TEE. The real service passes NitroNSM as attestor;
    a synthetic provider cannot produce evidence accepted under the AWS root.
    Every signing path has a fixed purpose: enrollment or an internally computed
    search result. No arbitrary signing, host-result or external-cache API exists.
    One owner, one index and one active attestation session are supported.
    """

    def __init__(
        self,
        setup: bytes,
        authentication_key: bytes,
        owner_public_key: bytes,
        index_epoch: int,
        attestor: _Attestor,
        *,
        policy: BFVExecutionPolicy | None = None,
        backend: BFVServerBackend = "residue",
    ) -> None:
        self.policy = policy or bfv_review_policy()
        if type(setup) is not bytes or len(setup) > self.policy.max_setup_bytes:
            raise BFVProtocolError("BFV setup exceeds the local size policy")
        self._owner = _verifier(owner_public_key, _OWNER_CONTEXT)
        self._context = _context(
            hashlib.sha256(setup).digest(), owner_public_key, index_epoch, self.policy
        )
        self._server = BFVVerifiedServer(
            setup, authentication_key, policy=self.policy, backend=backend
        )
        if not hamming_noise_bound(self.policy, self._server._count).sufficient:
            raise BFVProtocolError("BFV circuit exceeds the conservative correctness bound")
        self._attestor = attestor
        signing_key = eddsa.import_private_key(_key(attestor.random_seed()))
        self._public_key = signing_key.public_key().export_key(format="raw")
        self._public_spki = signing_key.public_key().export_key(format="DER")
        self._signer = eddsa.new(signing_key, "rfc8032", context=_RECEIPT_CONTEXT)
        self._enrollment_signer = eddsa.new(signing_key, "rfc8032", context=_POP_CONTEXT)
        self._session: bytes | None = None
        self._deadline = 0.0
        self._seen_nonces: set[bytes] = set()
        self._lock = threading.Lock()

    @classmethod
    def from_registration(
        cls,
        packet: bytes,
        attestor: _Attestor,
        *,
        policy: BFVExecutionPolicy | None = None,
        backend: BFVServerBackend = "residue",
    ) -> BFVAttestedServer:
        """Verify the enrolling owner's request before importing BFV key JSON.

        Enrollment is self-authorized: the first registrant can claim this empty
        service. The client accepts only attestation bound to ITS owner key and
        setup. Hosting/account access control is a separate deployment concern.
        A hostile parent can claim or stop the service, causing denial of service.
        """
        policy = policy or bfv_review_policy()
        setup, auth, owner, epoch, signature = _record(
            _unpack(packet, limit=policy.max_setup_bytes + 1024), 5
        )
        if type(setup) is not bytes or len(setup) > policy.max_setup_bytes:
            raise BFVProtocolError("BFV registration exceeds its size limit")
        context = _context(hashlib.sha256(setup).digest(), owner, epoch, policy)
        _verifier(owner, _OWNER_CONTEXT).verify(
            _REGISTER + context + hashlib.sha256(_key(auth)).digest(), _bytes(signature, 64)
        )
        return cls(setup, auth, owner, epoch, attestor, policy=policy, backend=backend)

    def attest(self, hello: bytes) -> tuple[bytes, bytes]:
        """Authenticate an owner challenge, obtain NSM evidence and prove key custody.

        Renewal replaces the one active session. Old requests cannot enter it.
        Nonces are consumed before requesting evidence; failed enrollment needs
        a fresh owner challenge, and replay state stays bounded.
        """
        with self._lock:
            _bytes(hello, NITRO_HELLO_BYTES)
            if hello[:6] != _HELLO or hello[6:38] != self._context:
                raise BFVProtocolError("BFV enrollment context mismatch")
            self._owner.verify(hello[:-64], hello[-64:])
            nonce = hello[38:70]
            if nonce in self._seen_nonces or len(self._seen_nonces) >= _MAX_ATTESTATIONS:
                raise BFVProtocolError("BFV attestation replayed or budget exhausted")
            self._seen_nonces.add(nonce)
            document = self._attestor.attest(self._public_spki, nonce, self._context)
            if type(document) is not bytes or not 0 < len(document) <= MAX_NITRO_DOCUMENT_BYTES:
                raise BFVProtocolError("Nitro evidence exceeds its size limit")
            proof = self._enrollment_signer.sign(hello[:-64] + hashlib.sha256(document).digest())
            self._session = _session_id(self._context, nonce, self._public_key)
            self._deadline = time.monotonic() + _SESSION_SECONDS
            return document, proof

    def search(self, request: bytes) -> tuple[bytes, bytes]:
        """Verify owner/session authorization, evaluate once, and sign exact output.

        The serialized gate excludes renewal while a search is running. An
        expired computation produces no receipt. Only public BFV input reaches
        the arithmetic implementation; the signer never imports a BFV secret.
        """
        with self._lock:
            if (
                self._session is None
                or time.monotonic() >= self._deadline
                or type(request) is not bytes
                or not NITRO_QUERY_OVERHEAD
                < len(request)
                <= self.policy.max_query_bytes + NITRO_QUERY_OVERHEAD
                or request[:6] != _QUERY
                or request[6:38] != self._session
            ):
                raise BFVProtocolError("BFV attested request rejected")
            query = request[38:-64]
            digest = hashlib.sha256(query).digest()
            self._owner.verify(_QUERY + self._context + self._session + digest, request[-64:])
            response = self._server.search(query)  # Exactly one complete BFV evaluation.
            if time.monotonic() >= self._deadline:
                raise BFVProtocolError("BFV attested session expired during evaluation")
            message = (
                _RECEIPT
                + self._context
                + self._session
                + digest
                + hashlib.sha256(response).digest()
            )
            return response, message + self._signer.sign(message)


class BFVAttestedClient:
    """Nitro-required BFV session with an owner request key and local secret key.

    Supply exact PCR pins from a trusted build and an owner-maintained index
    epoch. The public API cannot accept a synthetic root or a verifier callback.
    Restores require fresh attestation; active sessions and pending requests are
    never persisted. Trusted local Python code can access internals, as with the
    other BFV clients; this is not an isolation boundary within one process.
    """

    def __init__(
        self,
        client: BFVClient,
        authentication_key: bytes,
        attestation_policy: NitroAttestationPolicy,
        *,
        index_epoch: int = 0,
        policy: BFVExecutionPolicy | None = None,
        private_backend: BFVPrivateBackend = "native",
    ) -> None:
        self._session = BFVVerifiedClient(
            client,
            authentication_key,
            policy=policy or bfv_review_policy(),
            private_backend=private_backend,
        )
        self._configure(attestation_policy, index_epoch, secrets.token_bytes(32))

    def _configure(
        self, policy: NitroAttestationPolicy, index_epoch: int, owner_seed: bytes
    ) -> None:
        """Initialize owner credentials and an unattested state, also after restore."""
        _epoch(index_epoch)
        if not isinstance(policy, NitroAttestationPolicy):
            raise TypeError("Use an owner-configured NitroAttestationPolicy")
        self.attestation_policy = policy
        self.index_epoch = index_epoch
        self._owner_seed = _key(owner_seed)
        if hmac.compare_digest(owner_seed, self._session._authentication_key):
            raise ValueError("The owner signing and server transport keys must differ")
        key = eddsa.import_private_key(owner_seed)
        self._owner_public = key.public_key().export_key(format="raw")
        self._owner = eddsa.new(key, "rfc8032", context=_OWNER_CONTEXT)
        self._gate = threading.RLock()
        self._identity: NitroIdentity | None = None
        self._enrolled_session: bytes | None = None
        self._receipt_verifier: eddsa.EdDSASigScheme | None = None
        self._deadline = 0.0
        self._hello: bytes | None = None
        self._hello_started = 0.0

    @property
    def policy(self) -> BFVExecutionPolicy:
        return self._session.policy

    @property
    def setup_digest(self) -> bytes:
        if self._session._setup_digest is None:
            raise BFVProtocolError("Prepare a BFV index first")
        return self._session._setup_digest

    @property
    def vector_ids(self) -> tuple[str, ...]:
        return self._session.vector_ids

    @property
    def verification_state_bytes(self) -> int:
        return self._session.verification_state_bytes

    def _context(self) -> bytes:
        return _context(self.setup_digest, self._owner_public, self.index_epoch, self.policy)

    def prepare_index(
        self, vectors: list[list[int]], *, vector_ids: Sequence[str] | None = None
    ) -> bytes:
        """Prepare the existing encrypted setup and private Hamming summary once."""
        with self._gate:
            if not hamming_noise_bound(self.policy, len(vectors)).sufficient:
                raise BFVProtocolError("BFV circuit exceeds the conservative correctness bound")
            return self._session.prepare_index(vectors, vector_ids=vector_ids)

    def registration_packet(self, setup: bytes) -> bytes:
        """Authorize public setup import without retaining a second index copy.

        This contains the legacy transport MAC key, which is intentionally not
        an owner credential. No BFV secret, owner seed or private summary leaves.
        The caller supplies the exact bytes returned by prepare_index.
        """
        with self._gate:
            if (
                type(setup) is not bytes
                or len(setup) > self.policy.max_setup_bytes
                or hashlib.sha256(setup).digest() != self.setup_digest
            ):
                raise BFVProtocolError("Registration is not the owner-prepared setup")
            auth = self._session._authentication_key
            signature = self._owner.sign(
                _REGISTER + self._context() + hashlib.sha256(auth).digest()
            )
            return _pack([setup, auth, self._owner_public, self.index_epoch, signature])

    def begin_attestation(self) -> bytes:
        """Start or renew enrollment, discarding old sessions and pending queries."""
        with self._gate:
            context = self._context()
            self._identity = self._receipt_verifier = self._enrolled_session = None
            self._session.cancel_pending_queries()
            self._hello_started = time.monotonic()
            self._hello = _HELLO + context + secrets.token_bytes(32)
            return self._hello + self._owner.sign(self._hello)

    def accept_attestation(self, document: bytes, proof_of_possession: bytes) -> None:
        """Verify fresh AWS evidence and key possession against the pending challenge.

        Rejected evidence leaves the challenge pending until its original local
        deadline. A valid enrollment consumes it once. No private BFV operation
        occurs in this method, and no trust decision comes from the host.
        """
        with self._gate:
            try:
                if self._hello is None or time.monotonic() - self._hello_started > (
                    self.attestation_policy.handshake_timeout_seconds
                ):
                    raise BFVProtocolError("No current Nitro challenge")
                identity = verify_nitro_attestation(
                    document,
                    self.attestation_policy,
                    nonce=self._hello[38:70],
                    context=self._context(),
                )
                _verifier(identity.public_key, _POP_CONTEXT).verify(
                    self._hello + hashlib.sha256(document).digest(), _bytes(proof_of_possession, 64)
                )
                remaining = min(
                    self.attestation_policy.max_session_seconds,
                    identity.certificate_expires_at - time.time(),
                )
                if remaining <= 0 or time.monotonic() - self._hello_started > (
                    self.attestation_policy.handshake_timeout_seconds
                ):
                    raise BFVProtocolError("Nitro enrollment expired")
                self._identity = identity
                self._receipt_verifier = _verifier(identity.public_key, _RECEIPT_CONTEXT)
                self._enrolled_session = _session_id(
                    self._context(), self._hello[38:70], identity.public_key
                )
                self._deadline = time.monotonic() + remaining
                self._hello = None
            except (ValueError, TypeError, OverflowError):
                raise BFVProtocolError("Nitro enrollment rejected before decryption") from None

    def _require_session(self) -> bytes:
        """Enforce both monotonic lease expiry and certificate wall-clock expiry."""
        if (
            self._identity is None
            or self._enrolled_session is None
            or time.monotonic() >= self._deadline
            or time.time() >= self._identity.certificate_expires_at
        ):
            raise BFVProtocolError("Fresh Nitro attestation is required")
        return self._enrolled_session

    def begin_query(self, query: list[int]) -> bytes:
        """Encrypt an owner query and sign its digest under the attested session."""
        with self._gate:
            session = self._require_session()
            inner = self._session.begin_query(query)
            self._require_session()
            signature = self._owner.sign(
                _QUERY + self._context() + session + hashlib.sha256(inner).digest()
            )
            return _QUERY + session + inner + signature

    def finish_query(self, response: bytes, receipt: bytes) -> list[int]:
        """Check provenance before BFV parsing/decryption and consume a ticket once."""
        with self._gate:
            try:
                session = self._require_session()
                if type(response) is not bytes or len(response) > self.policy.max_response_bytes:
                    raise BFVProtocolError("BFV response exceeds its size limit")
                _bytes(receipt, NITRO_RECEIPT_BYTES)
                if (
                    receipt[:6] != _RECEIPT
                    or receipt[6:38] != self._context()
                    or receipt[38:70] != session
                    or receipt[102:134] != hashlib.sha256(response).digest()
                ):
                    raise BFVProtocolError("BFV receipt binding mismatch")
                with self._session._lock:
                    if not any(
                        p.request_digest == receipt[70:102] for p in self._session._pending.values()
                    ):
                        raise BFVProtocolError("BFV receipt is not for a pending owner query")
                if self._receipt_verifier is None:
                    raise BFVProtocolError("Missing attested receipt key")
                self._receipt_verifier.verify(receipt[:134], receipt[134:])
                self._require_session()
            except (ValueError, TypeError, OverflowError):
                raise BFVProtocolError("BFV response rejected before decryption") from None
            # The outer lock excludes renewal during private work; the inner
            # session consumes the ticket before its own private decoding.
            return self._session.finish_query(response)

    def cancel_pending_queries(self) -> None:
        """Discard pending queries without renewing attestation or query budgets."""
        with self._gate:
            self._session.cancel_pending_queries()

    def _storage_binding(self) -> bytes:
        return hashlib.sha256(
            _STATE_CONTEXT
            + self.setup_digest
            + _epoch(self.index_epoch)
            + _policy_digest(self.policy)
            + self.attestation_policy.digest()
        ).digest()

    def protect_state(self, wrapping_key: bytes) -> bytes:
        """Encrypt owner credentials and BFV state; omit enrollment and pending work.

        The epoch and trust policy are authenticated. The application must retain
        its expected epoch durably; encrypted files alone do not prevent rollback.
        """
        with self._gate:
            if hmac.compare_digest(_key(wrapping_key), self._owner_seed):
                raise ValueError("The wrapping and owner signing keys must differ")
            return protect_bfv_state(
                _pack([self._owner_seed, self._session.protect_state(wrapping_key)]),
                wrapping_key,
                self._storage_binding(),
            )

    @classmethod
    def restore(
        cls,
        setup: bytes,
        protected: bytes,
        authentication_key: bytes,
        wrapping_key: bytes,
        attestation_policy: NitroAttestationPolicy,
        *,
        index_epoch: int,
        policy: BFVExecutionPolicy | None = None,
        private_backend: BFVPrivateBackend = "native",
    ) -> BFVAttestedClient:
        """Restore with the owner-maintained epoch/policy, requiring new attestation."""
        policy = policy or bfv_review_policy()
        if type(setup) is not bytes or len(setup) > policy.max_setup_bytes:
            raise BFVProtocolError("BFV setup exceeds its size limit")
        binding = hashlib.sha256(
            _STATE_CONTEXT
            + hashlib.sha256(setup).digest()
            + _epoch(index_epoch)
            + _policy_digest(policy)
            + attestation_policy.digest()
        ).digest()
        seed, inner = _record(
            _unpack(unprotect_bfv_state(protected, wrapping_key, binding), limit=1024 * 1024), 2
        )
        _key(seed)
        if hmac.compare_digest(_key(wrapping_key), seed):
            raise BFVProtocolError("Invalid BFV wrapping key separation")
        session = BFVVerifiedClient.restore(
            setup,
            inner,
            authentication_key,
            wrapping_key,
            policy=policy,
            private_backend=private_backend,
        )
        if not hamming_noise_bound(policy, len(session.vector_ids)).sufficient:
            raise BFVProtocolError("BFV circuit exceeds the conservative correctness bound")
        result = cls.__new__(cls)
        result._session = session
        result._configure(attestation_policy, index_epoch, seed)
        return result
