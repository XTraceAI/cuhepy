"""Approve the exact public BFV computation before allowing private decryption.

The verifier is controlled by the data owner, separately from the untrusted
evaluator. Its Ed25519 key is NOT the evaluator's transport authentication key.
Recomputation costs another full evaluation; a receipt is not a SNARK or an
attestation of an untrusted machine. No network service is supplied here.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence

from Crypto.Signature import eddsa

from xtrace_sdk.x_vec.crypto.bfv_client import BFVClient
from xtrace_sdk.x_vec.crypto.bfv_assurance import bfv_review_policy, hamming_noise_bound
from xtrace_sdk.x_vec.crypto.bfv_security import (
    BFVExecutionPolicy,
    BFVProtocolError,
    _bytes,
    _key,
    protect_bfv_state,
    unprotect_bfv_state,
)
from xtrace_sdk.x_vec.crypto.bfv_verified_client import BFVVerifiedClient, BFVVerifiedServer
from xtrace_sdk.x_vec.crypto.encryption.bfv_evaluator import BFVServerBackend
from xtrace_sdk.x_vec.crypto.encryption.bfv_private import BFVPrivateBackend


_CONTEXT = b"XTRACE-BFV-PUBLIC-RECOMPUTATION-v1"
_MAGIC = b"XBFVR1"
# A versioned circuit identifier, independent of the chosen arithmetic backend.
# Bump this for any semantic or canonical-wire change, including compaction.
_CIRCUIT = hashlib.sha256(
    b"XTrace BFV packed binary Hamming v1; two-row layout; exact tensor rounding; "
    b"binary gadget keys; canonical v1 ciphertexts; terminal prime compaction"
).digest()
_MESSAGE_BYTES = len(_MAGIC) + 4 * 32
_RECEIPT_BYTES = _MESSAGE_BYTES + 64
_STATE_CONTEXT = b"XTRACE-BFV-GUARDED-PRIVATE-STATE-v1"


def bfv_verifier_public_key(signing_seed: bytes) -> bytes:
    """Derive the Ed25519 pin on the owner; provision it through a trusted path."""
    return eddsa.import_private_key(_key(signing_seed)).public_key().export_key(format="raw")


def _receipt_verifier(pin: bytes) -> eddsa.EdDSASigScheme:
    key = eddsa.import_public_key(pin)
    # PyCryptodome accepts the encoded identity point. It is not a usable
    # signing identity: cofactored Ed25519 verification would accept trivial
    # signatures under a small-order key. Reject this configuration explicitly.
    if (key.pointQ * 8).is_point_at_infinity():
        raise ValueError("BFV verifier pin must not be a small-order point")
    return eddsa.new(key, "rfc8032", context=_CONTEXT)


class BFVPublicVerifier:
    """Owner-controlled public-only recomputation and narrowly scoped signing.

    Supply the expected setup digest directly from the owner. Never provision
    this signer to the untrusted evaluator. The only signing operation first
    recomputes the prescribed result; it never signs an arbitrary caller hash.
    All acceptance decisions here depend on PUBLIC ciphertexts and setup only.
    """

    def __init__(
        self,
        setup: bytes,
        authentication_key: bytes,
        signing_seed: bytes,
        *,
        expected_setup_digest: bytes,
        policy: BFVExecutionPolicy | None = None,
        backend: BFVServerBackend = "residue",
    ) -> None:
        self.policy = policy or bfv_review_policy()
        if type(setup) is not bytes or len(setup) > self.policy.max_setup_bytes:
            raise BFVProtocolError("BFV setup exceeds the local size policy")
        self._setup_digest = hashlib.sha256(setup).digest()
        if not hmac.compare_digest(self._setup_digest, _bytes(expected_setup_digest, 32)):
            raise BFVProtocolError("BFV verifier setup is not the owner-pinned setup")
        if hmac.compare_digest(_key(signing_seed), _key(authentication_key)):
            raise ValueError("The verifier signing seed must differ from the evaluator key")
        self._signer = eddsa.new(
            eddsa.import_private_key(signing_seed), "rfc8032", context=_CONTEXT
        )
        self._server = BFVVerifiedServer(
            setup, authentication_key, policy=self.policy, backend=backend
        )

    def approve(self, query: bytes, response: bytes) -> bytes:
        """Recompute, compare exact bytes, and sign only that approved transcript.

        A well-formed authenticated query consumes the verifier's replay ticket
        even if the proposed result is wrong. Its existing server policy bounds
        parsing, concurrent work and total requests. No BFV secret is available.
        """
        if type(response) is not bytes or len(response) > self.policy.max_response_bytes:
            raise BFVProtocolError("BFV proposed response exceeds its size limit")
        expected = self._server.search(query)
        if not hmac.compare_digest(response, expected):
            raise BFVProtocolError("BFV proposed result differs from public recomputation")
        message = (
            _MAGIC
            + _CIRCUIT
            + self._setup_digest
            + hashlib.sha256(query).digest()
            + hashlib.sha256(response).digest()
        )
        return message + self._signer.sign(message)


class BFVGuardedClient:
    """Require a pinned verifier's computation receipt BEFORE private decryption.

    This composes the prior result-checked session rather than inheriting its
    unguarded finish method. There is no missing-receipt fallback. Only the
    owner configures the verification key; received packets cannot select it.
    Python object internals are not a boundary against malicious local code.
    """

    def __init__(
        self,
        client: BFVClient,
        authentication_key: bytes,
        verifier_public_key: bytes,
        *,
        policy: BFVExecutionPolicy | None = None,
        private_backend: BFVPrivateBackend = "native",
    ) -> None:
        self._pin = _bytes(verifier_public_key, 32)
        self._verifier = _receipt_verifier(self._pin)
        self._session = BFVVerifiedClient(
            client,
            authentication_key,
            policy=policy or bfv_review_policy(),
            private_backend=private_backend,
        )

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

    def prepare_index(
        self, vectors: list[list[int]], *, vector_ids: Sequence[str] | None = None
    ) -> bytes:
        if not hamming_noise_bound(self.policy, len(vectors)).sufficient:
            raise BFVProtocolError("BFV policy fails the conservative Hamming correctness bound")
        return self._session.prepare_index(vectors, vector_ids=vector_ids)

    def begin_query(self, query: list[int]) -> bytes:
        return self._session.begin_query(query)

    def finish_query(self, response: bytes, receipt: bytes) -> list[int]:
        """Check bounded receipt/signature/bindings before parsing BFV ciphertexts.

        A bad receipt never reaches private decryption or plaintext checking.
        Replays of a valid receipt still face the inner one-use query ticket.
        Successful decryption, honest-circuit failures and local side channels
        still require correctness/implementation analysis; this is not a claim
        of general CCA2 security for a malleable homomorphic encryption scheme.
        """
        try:
            if type(response) is not bytes or len(response) > self.policy.max_response_bytes:
                raise BFVProtocolError("BFV response rejected")
            _bytes(receipt, _RECEIPT_BYTES)
            offset = len(_MAGIC)
            if (
                receipt[:offset] != _MAGIC
                or receipt[offset : offset + 32] != _CIRCUIT
                or receipt[offset + 32 : offset + 64] != self.setup_digest
                or not hmac.compare_digest(
                    receipt[offset + 96 : _MESSAGE_BYTES], hashlib.sha256(response).digest()
                )
            ):
                raise BFVProtocolError("BFV response rejected")
            # Bind the receipt to a pending, OWNER-generated request. The peer
            # knows the transport MAC key and could otherwise request signatures
            # for its own ciphertexts from the verifier.
            request_digest = receipt[offset + 64 : offset + 96]
            with self._session._lock:
                if not any(
                    p.request_digest == request_digest for p in self._session._pending.values()
                ):
                    raise BFVProtocolError("BFV response rejected")
            self._verifier.verify(receipt[:_MESSAGE_BYTES], receipt[_MESSAGE_BYTES:])
        except (ValueError, TypeError, OverflowError):
            raise BFVProtocolError("BFV response rejected before decryption") from None
        return self._session.finish_query(response)

    def cancel_pending_queries(self) -> None:
        self._session.cancel_pending_queries()

    def _storage_binding(self) -> bytes:
        return hashlib.sha256(_STATE_CONTEXT + self.setup_digest + self._pin).digest()

    def protect_state(self, wrapping_key: bytes) -> bytes:
        """Bind the saved session to this receipt gate and pinned verification key.

        The outer AEAD prevents restoring this export through the old unguarded
        session API or changing the verifier pin without authenticating storage.
        It does not provide durable anti-rollback protection.
        """
        return protect_bfv_state(
            self._session.protect_state(wrapping_key), wrapping_key, self._storage_binding()
        )

    @classmethod
    def restore(
        cls,
        setup: bytes,
        protected: bytes,
        authentication_key: bytes,
        wrapping_key: bytes,
        verifier_public_key: bytes,
        *,
        policy: BFVExecutionPolicy | None = None,
        private_backend: BFVPrivateBackend = "native",
    ) -> BFVGuardedClient:
        policy = policy or bfv_review_policy()
        if type(setup) is not bytes or len(setup) > policy.max_setup_bytes:
            raise BFVProtocolError("BFV setup exceeds the local size policy")
        pin = _bytes(verifier_public_key, 32)
        verifier = _receipt_verifier(pin)
        binding = hashlib.sha256(_STATE_CONTEXT + hashlib.sha256(setup).digest() + pin).digest()
        inner = unprotect_bfv_state(protected, wrapping_key, binding)
        session = BFVVerifiedClient.restore(
            setup,
            inner,
            authentication_key,
            wrapping_key,
            policy=policy,
            private_backend=private_backend,
        )
        if not hamming_noise_bound(policy, len(session.vector_ids)).sufficient:
            raise BFVProtocolError("BFV policy fails the conservative Hamming correctness bound")
        # Avoid importing a second native private context just to restore metadata.
        result = cls.__new__(cls)
        result._pin = pin
        result._verifier = verifier
        result._session = session
        return result
