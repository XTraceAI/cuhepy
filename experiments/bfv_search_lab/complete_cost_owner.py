"""Q77 owner custody and complete private finish after local receipt verification.

The owner supplies an honest key pair and a separately provisioned descriptor
and verifier anchors. Matching IDs/fingerprints cannot prove a secret/public
key relation. The native packed decoder is created lazily inside the consumed
receipt callback, never by parsing an unauthenticated response. This local
adapter is not attestation, crash-safe authority or complete side-channel
assurance. Python key import/copies and result handling remain outside the
existing native decoder's fixed-work arithmetic scope.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import heapq
import os
import threading

import gmpy2

from experiments.bfv_search_lab import complete_cost_protocol as receipt
from experiments.bfv_search_lab import private_bgv as private
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_certificate as cert
from experiments.bfv_search_lab import shared_query_client_context as context


def public_fingerprint(pk, geometry):
    """Reconstruct the existing key_gen fingerprint for the frozen Q120 law.

    This uses public coefficients only. It binds local key metadata to the
    descriptor, not mathematical secret-key validity or security parameters.
    """
    if type(geometry) is not cert.Geometry or type(pk) is not bgv.PublicKey:
        raise ValueError("Trusted frozen owner public key and geometry required")
    geometry._validate()
    if (
        any(type(x) is not int for x in (pk.n, pk.t, pk.eta))
        or type(pk.q) is not gmpy2.mpz
        or (pk.n, pk.t, int(pk.q), pk.eta) != (geometry.n, geometry.t, geometry.q, geometry.eta)
        or type(pk.key_id) is not str
        or len(pk.key_id) != 64
    ):
        raise ValueError("Owner public key differs from frozen geometry")
    digest = hashlib.sha256(f"cuhepy-shallow-bgv-v1:{pk.n}:{pk.t}:{pk.q}:{pk.eta}".encode())
    bits, width = geometry.q.bit_length(), (geometry.n * geometry.q.bit_length() + 7) // 8
    for polynomial in (pk.a, pk.b):
        if (
            type(polynomial) is not tuple
            or len(polynomial) != geometry.n
            or any(type(x) not in (int, gmpy2.mpz) or not 0 <= x < pk.q for x in polynomial)
        ):
            raise ValueError("Complete canonical owner public polynomial required")
        digest.update(gmpy2.pack(list(polynomial), bits).to_bytes(width, "little"))
    if pk.key_id != digest.hexdigest():
        raise ValueError("Owner public fingerprint differs from its key ID")
    return digest.digest()


class _Owned:
    def _initialize(self):
        self._pid, self._closed = os.getpid(), False
        self._lock = threading.RLock()

    def _process(self):
        # Check before touching a lock held by a vanished thread after fork.
        if os.getpid() != self._pid:
            raise RuntimeError("Inherited owner context")

    def _open(self):
        if self._closed:
            raise RuntimeError("Closed owner context")

    def __copy__(self):
        raise TypeError("Owner contexts cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Owner contexts cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Owner contexts cannot be serialized")


class OwnerKeyCustody(_Owned):
    """Owner-process lifetime for one fixed key and its lazy private decoder.

    There is no key-generation/export or public decrypt method. The caller
    still owns its supplied SecretKey; closing this holder cannot erase those
    Python copies. The existing native handle wipes its locked buffers on
    close. Worker isolation and actual private correctness are separate gates.
    """

    def __init__(self, pk, sk, geometry):
        key_id = public_fingerprint(pk, geometry)
        if (
            type(sk) is not bgv.SecretKey
            or type(sk.key_id) is not str
            or sk.key_id != pk.key_id
            or type(sk.s) is not tuple
            or len(sk.s) != geometry.n
            or any(type(x) not in (int, gmpy2.mpz) or x not in (0, 1, pk.q - 1) for x in sk.s)
        ):
            raise ValueError("Matching local ternary secret metadata required")
        self._initialize()
        self._geometry, self._key_id = geometry, key_id
        self._pk = bgv.PublicKey(
            pk.n,
            pk.t,
            gmpy2.mpz(pk.q),
            pk.eta,
            tuple(map(gmpy2.mpz, pk.a)),
            tuple(map(gmpy2.mpz, pk.b)),
            pk.key_id,
        )
        self._secret = bgv.SecretKey(tuple(map(gmpy2.mpz, sk.s)), sk.key_id)
        self._decoder = None

    def __repr__(self):
        return "OwnerKeyCustody(<private owner context>)"

    def _bind_locked(self, metadata):
        self._open()
        if (
            type(metadata) is not context.ClientMetadata
            or metadata.geometry != self._geometry
            or metadata.key_id != self._key_id
        ):
            raise ValueError("Owner key differs from complete current client geometry/key")

    def _bind(self, metadata):
        self._process()
        with self._lock:
            self._bind_locked(metadata)

    def _finish_admitted(self, frame, metadata):
        """Internal consumed-callback target; never a raw response API.

        ResultClient has already authenticated the complete frame, current
        descriptor and original request and checked every public coefficient.
        Preserve packed bytes here instead of rebuilding GMP ciphertext rows.
        """
        self._process()
        with self._lock:
            self._bind_locked(metadata)
            try:
                fields = receipt._unpack(frame, receipt.frame_limit(metadata))
                pairs = tuple(tuple(pair) for pair in fields[1])
                if self._decoder is None:
                    self._decoder = private.PrivateDecoder(
                        self._pk, self._secret, bits=self._geometry.p.bit_length()
                    )
                    if int(self._decoder.modulus) != self._geometry.p:
                        raise ValueError("Private decoder differs from owner terminal modulus")
                polynomials = self._decoder.decode_packed(pairs)
                return complete_scores(polynomials, metadata)
            except BaseException:
                # No new request may retry private work on a failed context.
                # Callback diagnostics still remain inside owner custody.
                try:
                    self._close_locked()
                except Exception:
                    # The handle is already disabled. Native cleanup failure
                    # must not reopen private work or expose another error.
                    pass
                raise

    def _close_locked(self):
        self._closed = True
        decoder, self._decoder = self._decoder, None
        self._secret = None
        if decoder is not None:
            decoder.close()

    def close(self):
        self._process()
        with self._lock:
            if self._closed:
                return
            self._close_locked()

    def __enter__(self):
        self._process()
        with self._lock:
            self._open()
        return self

    def __exit__(self, *_args):
        self.close()


@dataclass(frozen=True)
class Match:
    ordinal: int
    identifier: int
    distance: int


@dataclass(frozen=True)
class SearchResult:
    """Owner-local plaintext output, with every distance and bound ordinal hits."""

    distances: tuple[int, ...]
    nearest: tuple[Match, ...]


def complete_scores(polynomials, metadata):
    """Validate decoded plaintexts, not ciphertext validity or authorization.

    This pure score operation can be unit-tested without private arithmetic.
    A caller with plaintext already has the data; it grants no decrypt right.
    """
    if type(metadata) is not context.ClientMetadata:
        raise ValueError("Verified complete client metadata required")
    p, count = metadata.geometry, len(metadata.ids)
    groups = (count + p.n - 1) // p.n
    if type(polynomials) is not list or len(polynomials) != groups:
        raise ValueError("Incomplete decoded group coverage")
    distances = []
    for group, polynomial in enumerate(polynomials):
        if type(polynomial) is not list or len(polynomial) != p.n:
            raise ValueError("Incomplete decoded physical polynomial")
        for lane, value in enumerate(polynomial):
            if type(value) is not int or not 0 <= value < p.t:
                raise ValueError("Noncanonical decoded plaintext residue")
            ordinal = group * p.n + lane
            if ordinal >= count:
                if value != 0:
                    raise ValueError("Nonzero unused plaintext tail")
                continue
            dot = value if value <= p.t // 2 else value - p.t
            if not -p.dimension <= dot <= p.dimension or (p.dimension - dot) % 2:
                raise ValueError("Invalid complete signed Hamming score")
            distances.append((p.dimension - dot) // 2)
    # O(count * log(3)); IDs are labels and never replace ordinal tie-breaking.
    selected = heapq.nsmallest(3, enumerate(distances), key=lambda item: (item[1], item[0]))
    return SearchResult(
        tuple(distances),
        tuple(Match(ordinal, metadata.ids[ordinal], distance) for ordinal, distance in selected),
    )


class OwnerClient(_Owned):
    """Owner-only receipt-to-private-output adapter with no caller callback API.

    The descriptor and all three local verifier anchors are separately trusted
    inputs. Per-client close leaves shared owner key custody alive for other
    blocks; its owner explicitly closes it after the registered lifetime.
    """

    def __init__(self, descriptor, verifier_anchors, keys):
        if type(descriptor) is not context.DescriptorClient or type(keys) is not OwnerKeyCustody:
            raise ValueError("Trusted owner descriptor and key-custody handle required")
        descriptor._process()
        with descriptor._lock:
            keys._bind(descriptor.metadata())
            receiver = receipt.ResultClient(descriptor, verifier_anchors)
        self._initialize()
        self._descriptor, self._receiver, self._keys = descriptor, receiver, keys

    def begin(self, mode, original_packet):
        self._process()
        self._descriptor._process()
        with self._descriptor._lock, self._lock:
            self._open()
            metadata = self._descriptor.metadata()
            self._keys._bind(metadata)
            attempt = self._receiver.begin(mode, original_packet)
            return OwnerAttempt(self, attempt, metadata)

    def close(self):
        self._process()
        with self._lock:
            if not self._closed:
                self._closed = True
                self._receiver.close()

    def __enter__(self):
        self._process()
        with self._lock:
            self._open()
        return self

    def __exit__(self, *_args):
        self.close()


class OwnerAttempt:
    """One owner-bound finish; no peer-selected decoder or private callback."""

    def __init__(self, client, attempt, metadata):
        if (
            type(client) is not OwnerClient
            or type(attempt) is not receipt._Attempt
            or attempt._client is not client._receiver
            or metadata != attempt._metadata
            or client._receiver._attempts.get(attempt.binding.nonce) is not attempt
        ):
            raise ValueError("Actual reserved owner attempt and captured metadata required")
        self._client, self._attempt, self._metadata = client, attempt, metadata

    @property
    def binding(self):
        return self._attempt.binding

    def finish(self, packet):
        client, descriptor = self._client, self._client._descriptor
        client._process()
        descriptor._process()
        with descriptor._lock, client._lock:
            client._open()
            return self._attempt.finish(
                packet, lambda frame: client._keys._finish_admitted(frame, self._metadata)
            )

    def __copy__(self):
        raise TypeError("Owner attempts cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Owner attempts cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Owner attempts cannot be serialized")
