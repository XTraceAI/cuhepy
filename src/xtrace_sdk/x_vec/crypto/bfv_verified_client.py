"""Authenticated, result-checked BFV sessions for a trusted data-owner client.

A private Freivalds-style summary checks the binary Hamming result in O(M+D)
client work, without adding server arithmetic. This protocol is experimental:
post-decryption checking is NOT chosen-ciphertext security. Keep outcomes and
timing private, and obtain independent review before deployment.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from collections.abc import Sequence
from dataclasses import dataclass

from xtrace_sdk.x_vec.crypto.bfv_client import BFVClient
from xtrace_sdk.x_vec.crypto.bfv_security import (
    BFVExecutionPolicy,
    BFVProtocolError,
    _authenticate,
    _authenticated_body,
    _bytes,
    _decode_ciphertexts,
    _encode_ciphertexts,
    _key,
    _pack,
    _record,
    _unpack,
    protect_bfv_state,
    unprotect_bfv_state,
)
from xtrace_sdk.x_vec.crypto.encryption.bfv import _coefficient_modulus, _load_key_json
from xtrace_sdk.x_vec.crypto.encryption.bfv_evaluator import BFVServerBackend
from xtrace_sdk.x_vec.crypto.encryption.bfv_private import BFVPrivateBackend, BFVPrivateDecoder


_FIELD = (1 << 255) - 19
_SETUP, _QUERY, _RESPONSE = 1, 2, 3


class _HammingSummary:
    """Private linear fingerprint; neither seed nor columns may reach the server.

    For weights r_i, store R=sum(r_i) and S_j=sum(r_i*x_ij). Then
    sum(r_i*d_i)=sum(S_j)+R*|q|-2*sum(q_j*S_j) modulo the verification field.
    HMAC expands an independent secret seed into pseudorandom field weights.
    Rejection sampling avoids modulo bias. This field is separate from BFV's t.
    """

    def __init__(self, vectors: Sequence[Sequence[int]], dimension: int, session: bytes) -> None:
        self.seed = secrets.token_bytes(32)
        self.session = session
        self.count = len(vectors)
        self.columns = [0] * dimension
        self.total = 0
        for i, row in enumerate(vectors):
            weight = self.weight(i)
            self.total += weight
            for j, bit in enumerate(row):
                if bit:
                    self.columns[j] += weight
        self.total %= _FIELD
        self.columns = [value % _FIELD for value in self.columns]

    def weight(self, index: int) -> int:
        prefix = b"XTRACE-BFV-HAMMING-CHECK-v1\0" + self.session + index.to_bytes(8, "little")
        for retry in range(16):
            digest = hmac.digest(self.seed, prefix + bytes([retry]), "sha256")
            candidate = int.from_bytes(digest, "little") & ((1 << 255) - 1)
            if candidate < _FIELD:
                return candidate
        raise RuntimeError("BFV verification weight generation failed")

    def expected(self, query: Sequence[int]) -> int:
        # BFVClient also accepts numpy/GMP Integral scalars. Convert before
        # mixing them with 255-bit values so fixed-width scalar coercion cannot
        # overflow or silently truncate the private fingerprint arithmetic.
        bits = [int(bit) for bit in query]
        return (
            sum(self.columns)
            + self.total * sum(bits)
            - 2 * sum(c * bit for c, bit in zip(self.columns, bits, strict=True))
        ) % _FIELD

    def matches(self, distances: Sequence[int], expected: int) -> bool:
        if len(distances) != self.count:
            return False
        actual = sum(self.weight(i) * value for i, value in enumerate(distances)) % _FIELD
        return hmac.compare_digest(actual.to_bytes(32, "little"), expected.to_bytes(32, "little"))

    def export(self) -> list[bytes]:
        return [
            self.seed,
            self.total.to_bytes(32, "little"),
            *(c.to_bytes(32, "little") for c in self.columns),
        ]

    @classmethod
    def restore(
        cls, data: list[bytes], dimension: int, count: int, session: bytes
    ) -> _HammingSummary:
        _record(data, dimension + 2)
        seed = _bytes(data[0], 32)
        values = [int.from_bytes(_bytes(value, 32), "little") for value in data[1:]]
        if any(value >= _FIELD for value in values):
            raise BFVProtocolError("Invalid BFV verification summary")
        result = cls.__new__(cls)
        result.seed, result.session, result.count = seed, session, count
        result.total, result.columns = values[0], values[1:]
        return result


@dataclass(frozen=True)
class _PendingQuery:
    request_digest: bytes
    expected: int


def _ids(values: Sequence[str] | None, count: int) -> tuple[str, ...]:
    result = tuple(str(i) for i in range(count)) if values is None else tuple(values)
    if len(result) != count or any(
        type(v) is not str or not 1 <= len(v.encode()) <= 256 for v in result
    ):
        raise BFVProtocolError("Expected one bounded identifier per vector")
    if len(set(result)) != count:
        raise BFVProtocolError("BFV vector identifiers must be unique")
    return result


def _setup_fields(
    setup: bytes, authentication_key: bytes, policy: BFVExecutionPolicy
) -> tuple[bytes, str, str, int, tuple[str, ...], bytes]:
    body = _authenticated_body(setup, authentication_key, _SETUP, policy.max_setup_bytes)
    session, config, public, count, ids, index = _record(
        _unpack(body, limit=policy.max_setup_bytes, array_limit=policy.max_vectors), 6
    )
    session = _bytes(session, 16)
    if type(config) is not bytes or len(config) > 4096:
        raise BFVProtocolError("Invalid BFV configuration")
    if type(public) is not bytes or len(public) > policy.max_public_key_bytes:
        raise BFVProtocolError("BFV public key exceeds its import limit")
    if type(count) is not int or not 1 <= count <= policy.max_vectors:
        raise BFVProtocolError("BFV vector count exceeds the local policy")
    if type(index) is not bytes or len(index) > policy.max_index_bytes:
        raise BFVProtocolError("BFV index exceeds its import limit")
    if type(ids) is not list:
        raise BFVProtocolError("Invalid BFV vector identifiers")
    config_text, public_text = config.decode(), public.decode()
    if _load_key_json(config_text, 4096) != policy.config():
        raise BFVProtocolError("BFV setup does not match the locally pinned policy")
    return session, config_text, public_text, count, _ids(ids, count), index


class BFVVerifiedClient:
    """One immutable index/session with bounded, one-use query tickets.

    Retains a private O(D) summary rather than the original binary index.
    The authentication key is shared with this evaluator over a trusted channel;
    it must differ from the wrapping key and BFV private verification material.
    This object has no network, telemetry, noise-budget or server callback API.
    Return values and exceptions must stay inside the trusted client.
    """

    def __init__(
        self,
        client: BFVClient,
        authentication_key: bytes,
        *,
        policy: BFVExecutionPolicy | None = None,
        private_backend: BFVPrivateBackend = "python",
    ) -> None:
        if private_backend not in ("python", "native"):
            raise ValueError("Invalid BFV private backend")
        self.policy = policy or BFVExecutionPolicy()
        self.policy.check_client(client)
        keys = client._keys()
        # Snapshot key dictionaries, sharing immutable polynomial tuples. Loading
        # different keys into the original BFVClient cannot retarget this session.
        self._client = BFVClient(**self.policy.config(), skip_key_gen=True)
        self._client.public_key = {**keys["pk"], "galois_keys": dict(keys["pk"]["galois_keys"])}
        self._client.keys = {
            "pk": self._client.public_key,
            "sk": {"s": keys["sk"]["s"], "key_id": keys["sk"]["key_id"]},
        }
        self._private_decoder = (
            BFVPrivateDecoder(self._client) if private_backend == "native" else None
        )
        self._authentication_key = _key(authentication_key)
        self._session = secrets.token_bytes(16)
        self._setup_digest: bytes | None = None
        self._summary: _HammingSummary | None = None
        self._ids: tuple[str, ...] = ()
        self._pending: dict[bytes, _PendingQuery] = {}
        self._started = 0
        self._lock = threading.Lock()

    @property
    def vector_ids(self) -> tuple[str, ...]:
        return self._ids

    @property
    def verification_state_bytes(self) -> int:
        """Encoded summary payload only; excludes identifiers and Python objects."""
        return 0 if self._summary is None else (self.policy.embed_len + 2) * 32

    def prepare_index(
        self, vectors: list[list[int]], *, vector_ids: Sequence[str] | None = None
    ) -> bytes:
        """Encrypt and authenticate setup once; build the private result summary."""
        with self._lock:
            if self._setup_digest is not None:
                raise BFVProtocolError("Create a new verified client for a new index/session")
            if not 1 <= len(vectors) <= self.policy.max_vectors:
                raise BFVProtocolError("BFV vector count exceeds the local policy")
            ids = _ids(vector_ids, len(vectors))
            for vector in vectors:
                self._client._validate_vector(vector)
            pk = self._client._pk()
            tiles = (
                len(vectors) + self._client.vectors_per_ciphertext - 1
            ) // self._client.vectors_per_ciphertext
            minimum_bytes = (
                tiles * 2 * (self.policy.params.poly_modulus_degree * pk["q"].bit_length() // 8)
            )
            if minimum_bytes > self.policy.max_index_bytes:
                raise BFVProtocolError("BFV index exceeds the local size policy")
            summary = _HammingSummary(vectors, self.policy.embed_len, self._session)
            index = _encode_ciphertexts(self._client.encrypt_vec_packed(vectors), pk)
            public = self._client.stringify_pk().encode()
            if (
                len(index) > self.policy.max_index_bytes
                or len(public) > self.policy.max_public_key_bytes
            ):
                raise BFVProtocolError("BFV setup exceeds the local size policy")
            body = _pack(
                [
                    self._session,
                    self._client.stringify_config().encode(),
                    public,
                    len(vectors),
                    ids,
                    index,
                ]
            )
            setup = _authenticate(
                body, self._authentication_key, _SETUP, self.policy.max_setup_bytes
            )
            self._setup_digest = hashlib.sha256(setup).digest()
            self._summary, self._ids = summary, ids
            return setup

    def begin_query(self, query: list[int]) -> bytes:
        """Encrypt a query and bind its one-use ticket to this exact setup."""
        with self._lock:
            if self._setup_digest is None or self._summary is None:
                raise BFVProtocolError("Prepare a BFV index first")
            if (
                self._started >= self.policy.max_queries
                or len(self._pending) >= self.policy.max_pending_queries
            ):
                raise BFVProtocolError("BFV query budget exhausted")
            self._client._validate_vector(query)
            ticket = secrets.token_bytes(32)
            if ticket in self._pending:
                raise BFVProtocolError("BFV query ticket collision")
            ciphertext = _encode_ciphertexts(
                [self._client.encrypt_vec_one(query)], self._client._pk()
            )
            body = _pack([self._setup_digest, ticket, ciphertext])
            packet = _authenticate(
                body, self._authentication_key, _QUERY, self.policy.max_query_bytes
            )
            self._pending[ticket] = _PendingQuery(
                hashlib.sha256(packet).digest(), self._summary.expected(query)
            )
            self._started += 1
            return packet

    def finish_query(self, response: bytes) -> list[int]:
        """Authenticate, consume the ticket, then decrypt and check all distances.

        Never returns partial or unchecked plaintext. A post-decryption rejection
        is still secret-dependent: generic text is not an oracle/side-channel fix.
        """
        try:
            body = _authenticated_body(
                response, self._authentication_key, _RESPONSE, self.policy.max_response_bytes
            )
            setup, ticket, request, encoded = _record(
                _unpack(body, limit=self.policy.max_response_bytes), 4
            )
            _bytes(setup, 32)
            _bytes(ticket, 32)
            _bytes(request, 32)
            with self._lock:
                pending = self._pending.get(ticket)
                if (
                    setup != self._setup_digest
                    or pending is None
                    or request != pending.request_digest
                ):
                    raise BFVProtocolError("BFV response rejected")
                # A validly authenticated attempt consumes the ticket even if
                # its ciphertext or result later fails. Concurrent duplicates
                # can never trigger two private decryptions for the same ticket.
                del self._pending[ticket]
            if self._summary is None:
                raise BFVProtocolError("BFV response rejected")
            count = (
                len(self._ids) + self.policy.params.poly_modulus_degree - 1
            ) // self.policy.params.poly_modulus_degree
            ciphertexts = _decode_ciphertexts(
                encoded, self._client._pk(), count, self.policy.max_response_bytes
            )
            target = min(
                _coefficient_modulus(self.policy.response_modulus_bits), self._client._pk()["q"]
            )
            if any(ct[3] != target for ct in ciphertexts):
                raise BFVProtocolError("BFV response rejected")
            distances = (
                self._client.decode_hamming_client_packed(ciphertexts, len(self._ids))
                if self._private_decoder is None
                else self._private_decoder.decode_packed(ciphertexts, len(self._ids))
            )
            if not self._summary.matches(distances, pending.expected):
                raise BFVProtocolError("BFV response rejected")
            return distances
        except (ValueError, TypeError, OverflowError):
            raise BFVProtocolError("BFV response rejected") from None

    def cancel_pending_queries(self) -> None:
        """Locally discard tickets; does not reset the total query budget."""
        with self._lock:
            self._pending.clear()

    def protect_state(self, wrapping_key: bytes) -> bytes:
        """Encrypt keys and summary. Pending requests are deliberately not persisted.

        Protect against rollback in the application's storage. Restoring an old
        copy does not make in-memory budgets/replay state durable across restarts.
        """
        if hmac.compare_digest(_key(wrapping_key), self._authentication_key):
            raise ValueError(
                "The private wrapping key must differ from the server authentication key"
            )
        with self._lock:
            if self._setup_digest is None or self._summary is None:
                raise BFVProtocolError("Prepare a BFV index first")
            body = _pack(
                [self._client.stringify_sk().encode(), self._summary.export(), self._started]
            )
            return protect_bfv_state(body, wrapping_key, self._setup_digest)

    @classmethod
    def restore(
        cls,
        setup: bytes,
        protected: bytes,
        authentication_key: bytes,
        wrapping_key: bytes,
        *,
        policy: BFVExecutionPolicy | None = None,
        private_backend: BFVPrivateBackend = "python",
    ) -> BFVVerifiedClient:
        """Restore only with the exact authenticated setup and a private wrapping key."""
        policy = policy or BFVExecutionPolicy()
        if hmac.compare_digest(_key(wrapping_key), _key(authentication_key)):
            raise ValueError("The wrapping and server authentication keys must differ")
        # Check setup length/authentication and private-state binding before
        # parsing the public JSON or restoring the secret.
        _authenticated_body(setup, authentication_key, _SETUP, policy.max_setup_bytes)
        digest = hashlib.sha256(setup).digest()
        plaintext = unprotect_bfv_state(protected, wrapping_key, digest)
        session, config, public, count, ids, _ = _setup_fields(setup, authentication_key, policy)
        secret, summary, started = _record(
            _unpack(plaintext, limit=1024 * 1024, array_limit=policy.embed_len + 2), 3
        )
        if (
            type(secret) is not bytes
            or type(started) is not int
            or not 0 <= started <= policy.max_queries
        ):
            raise BFVProtocolError("Invalid BFV private state")
        client = BFVClient(**_load_key_json(config, 4096), skip_key_gen=True)
        client.load_stringified_keys(
            public, secret.decode(), max_public_key_chars=policy.max_public_key_bytes
        )
        result = cls(client, authentication_key, policy=policy, private_backend=private_backend)
        result._session, result._setup_digest, result._ids, result._started = (
            session,
            digest,
            ids,
            started,
        )
        result._summary = _HammingSummary.restore(summary, policy.embed_len, count, session)
        return result


class BFVVerifiedServer:
    """One authenticated public-only index with admission and replay limits.

    Pin policy/authentication_key in trusted service configuration. The setup
    hash covers every evaluation key, parameter, ordered ID and encrypted tile.
    Replay/admission state is in-memory; use durable service state or a fresh
    client-authorized setup after restart. A malicious server can ignore these
    checks, which is why the client separately verifies decrypted results.
    """

    def __init__(
        self,
        setup: bytes,
        authentication_key: bytes,
        *,
        policy: BFVExecutionPolicy | None = None,
        backend: BFVServerBackend = "residue",
    ) -> None:
        self.policy = policy or BFVExecutionPolicy()
        self._authentication_key = _key(authentication_key)
        _, config, public, count, ids, encoded = _setup_fields(
            setup, authentication_key, self.policy
        )
        self._client = BFVClient(
            **_load_key_json(config, 4096), skip_key_gen=True, server_backend=backend
        )
        self._client.load_stringified_keys(
            public, max_public_key_chars=self.policy.max_public_key_bytes
        )
        self._setup_digest = hashlib.sha256(setup).digest()
        self._count, self.vector_ids = count, ids
        tiles = (
            count + self._client.vectors_per_ciphertext - 1
        ) // self._client.vectors_per_ciphertext
        self._index = _decode_ciphertexts(
            encoded, self._client._pk(), tiles, self.policy.max_index_bytes
        )
        self._seen: set[bytes] = set()
        self._lock = threading.Lock()
        self._admission = threading.BoundedSemaphore(self.policy.max_concurrent_searches)

    def search(self, query: bytes) -> bytes:
        """Evaluate an authenticated one-use request with the existing BFV kernels."""
        if not self._admission.acquire(blocking=False):
            raise BFVProtocolError("BFV evaluator is at its concurrency limit")
        try:
            body = _authenticated_body(
                query, self._authentication_key, _QUERY, self.policy.max_query_bytes
            )
            setup, ticket, encoded = _record(_unpack(body, limit=self.policy.max_query_bytes), 3)
            _bytes(setup, 32)
            _bytes(ticket, 32)
            if setup != self._setup_digest:
                raise BFVProtocolError("BFV request belongs to another setup")
            with self._lock:
                if ticket in self._seen or len(self._seen) >= self.policy.max_queries:
                    raise BFVProtocolError("BFV request replayed or query budget exhausted")
                self._seen.add(ticket)
            ciphertext = _decode_ciphertexts(
                encoded, self._client._pk(), 1, self.policy.max_query_bytes
            )[0]
            response = self._client.encode_hamming_server_packed(
                ciphertext, self._index, self._count
            )
            body = _pack(
                [
                    self._setup_digest,
                    ticket,
                    hashlib.sha256(query).digest(),
                    _encode_ciphertexts(response, self._client._pk()),
                ]
            )
            return _authenticate(
                body, self._authentication_key, _RESPONSE, self.policy.max_response_bytes
            )
        finally:
            self._admission.release()
