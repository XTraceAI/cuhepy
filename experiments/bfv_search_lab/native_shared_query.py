"""Q76 bounded public adapter for the homemade shared-query BGV core.

The caller supplies trusted owner-origin metadata and public buffers. This is
not enrollment authentication, attestation or a private-release controller.
The library is explicitly selected by a trusted caller; no response can choose
an executable or a graph. Secret keys and encryption/decryption are absent.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from math import prod
import os
from pathlib import Path
import threading

import msgpack

from experiments.bfv_search_lab.shared_query_bounds import Profile

COMMON_WIDTH = 15
ABI = 1202
PACKET_CAP = 1 << 31
DIAGNOSTIC_WORD_CAP = 1 << 16


def _bytes(value, length, label):
    if type(value) is not bytes or len(value) != length or length > PACKET_CAP:
        raise ValueError(f"Wrong immutable {label} coverage")
    return value


def _pointer(data):
    # c_char_p retains the immutable bytes object during the synchronous call.
    # Explicit lengths, rather than C string termination, bound every access.
    return ctypes.cast(ctypes.c_char_p(data), ctypes.c_void_p)


def pack_common(polynomials, n, q):
    """Canonical whole-Q input format, never independently decomposed limbs."""
    if (
        type(n) is not int
        or not 8 <= n <= 16384
        or n & (n - 1)
        or type(q) is not int
        or q.bit_length() != 120
        or type(polynomials) is not tuple
        or len(polynomials) * n * COMMON_WIDTH > PACKET_CAP
    ):
        raise ValueError("Wrong bounded polynomial collection")
    body = bytearray()
    for row in polynomials:
        if type(row) is not tuple or len(row) != n:
            raise ValueError("Wrong complete polynomial")
        for value in row:
            if type(value) is not int or not 0 <= value < q:
                raise ValueError("Noncanonical whole-Q coefficient")
            body.extend(value.to_bytes(COMMON_WIDTH, "little"))
    return bytes(body)


@dataclass(frozen=True)
class PublicMetadata:
    profile: Profile
    primes: tuple[int, int]
    key_id: str
    ids: tuple[int, ...]

    def __post_init__(self):
        p = self.profile
        if (
            type(p) is not Profile
            or p.n > 16384
            or p.q.bit_length() != 120
            or p.index_mode != "owner"
            or p.policy != "canonical30"
            or not 1 << 15 <= p.p < 1 << 60
            or type(self.primes) is not tuple
            or len(self.primes) != 2
            or any(type(x) is not int or not 1 << 59 <= x < 1 << 60 for x in self.primes)
            or self.primes[0] == self.primes[1]
            or prod(self.primes) != p.q
            or type(self.key_id) is not str
            or len(self.key_id) != 64
            or any(x not in "0123456789abcdef" for x in self.key_id)
            or type(self.ids) is not tuple
            or not 1 <= len(self.ids) <= 2 * p.n
            or any(type(x) is not int or not 0 <= x < 1 << 64 for x in self.ids)
            or len(set(self.ids)) != len(self.ids)
        ):
            raise ValueError("Wrong bounded public owner-canonical enrollment")
        p.require_safe()  # Public deterministic box, never sampled private noise.

    @property
    def groups(self):
        return (len(self.ids) + self.profile.n - 1) // self.profile.n

    @property
    def sources(self):
        return self.profile.padded - 1 + self.groups

    @property
    def body_size(self):
        return (self.sources + 2 * self.groups) * self.profile.n * COMMON_WIDTH

    @property
    def terminal_row_size(self):
        return (self.profile.n * self.profile.p.bit_length() + 7) // 8


@dataclass(frozen=True)
class NativeStats:
    body_bytes: int
    source_polynomials: int
    residual_polynomials: int
    graph_nodes: int
    public_rows: int
    setup_forward_prime_NTTs: int
    cached_public_row_bytes: int
    map_and_shift_bytes: int


class NativeLibrary:
    """Load one explicitly chosen isolated build, without compilation fallback."""

    def __init__(self, path):
        self.path = Path(path).resolve(strict=True)
        self._lib = ctypes.CDLL(str(self.path))
        signatures = {
            "abi": (ctypes.c_uint, []),
            "create": (
                ctypes.c_void_p,
                [ctypes.c_size_t] * 3
                + [ctypes.c_uint64] * 5
                + [ctypes.c_void_p, ctypes.c_size_t] * 2,
            ),
            "destroy": (None, [ctypes.c_void_p]),
            "query": (ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]),
            "query_destroy": (None, [ctypes.c_void_p]),
            "check": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]),
            "residuals": (
                ctypes.c_int,
                [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                ],
            ),
            "produce": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]),
            "terminal": (
                ctypes.c_int,
                [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                ],
            ),
            "stats": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]),
        }
        for name, (result, args) in signatures.items():
            function = getattr(self._lib, "cuhepy_shared_" + name)
            function.restype, function.argtypes = result, args
        if self._lib.cuhepy_shared_abi() != ABI:
            raise ValueError("Wrong isolated shared-query ABI")

    def enroll(self, metadata, key_body, index_body):
        return NativePublicContext(self, metadata, key_body, index_body)

    def from_reference(self, context, primes):
        """Copy an already trusted reference context; authenticating it is Q76.2."""
        metadata = PublicMetadata(context.profile, primes, context.key_id, context.ids)
        keys = (context.relin, *(key for _, key in context.rotations))
        expected_schedule = tuple(
            1 + metadata.profile.n // (1 << level) for level in range(metadata.profile.levels)
        )
        if tuple(exponent for exponent, _ in context.rotations) != expected_schedule:
            raise ValueError("Wrong full rotation-key schedule")
        key_rows = tuple(row for key in keys for column in key for row in column)
        index_rows = tuple(row for pair in context.index for row in pair)
        return self.enroll(
            metadata,
            pack_common(key_rows, metadata.profile.n, metadata.profile.q),
            pack_common(index_rows, metadata.profile.n, metadata.profile.q),
        )


class _OwnedHandle:
    def _initialize(self, library, handle):
        self._library, self._handle = library, handle
        self._pid = os.getpid()
        self._lock = threading.RLock()

    def _require_open(self):
        if self._pid != os.getpid() or not self._handle:
            raise RuntimeError("Closed or inherited native public handle")

    def _require_process(self):
        # Reject before acquiring a possibly inherited locked mutex after fork.
        if self._pid != os.getpid():
            raise RuntimeError("Inherited native public handle")

    def close(self):
        if self._pid != os.getpid():
            self._handle = None
            return
        with self._lock:
            # A forked copy cannot be used or call back into inherited native
            # state. The original process remains its sole lifecycle owner.
            if self._handle and self._pid == os.getpid():
                self._destroy(self._handle)
            self._handle = None

    def __enter__(self):
        self._require_process()
        with self._lock:
            self._require_open()
        return self

    def __exit__(self, *_args):
        self.close()

    def __del__(self):
        if hasattr(self, "_lock"):
            self.close()

    def __copy__(self):
        raise TypeError("Native ownership cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Native ownership cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Native ownership cannot be serialized")


class NativePublicContext(_OwnedHandle):
    """Owned immutable native preparation. Closing it leaves existing queries owned."""

    def __init__(self, library, metadata, key_body, index_body):
        if type(library) is not NativeLibrary or type(metadata) is not PublicMetadata:
            raise ValueError("Explicit library and immutable metadata required")
        p = metadata.profile
        _bytes(key_body, (p.levels + 1) * 4 * 2 * p.n * COMMON_WIDTH, "evaluation key")
        _bytes(index_body, 2 * p.dimension * metadata.groups * p.n * COMMON_WIDTH, "index")
        handle = library._lib.cuhepy_shared_create(
            p.n,
            p.dimension,
            len(metadata.ids),
            *metadata.primes,
            p.t,
            p.eta,
            p.p,
            _pointer(key_body),
            len(key_body),
            _pointer(index_body),
            len(index_body),
        )
        if not handle:
            raise ValueError("Native public enrollment rejected")
        self._initialize(library, handle)
        self._metadata = metadata
        self._destroy = library._lib.cuhepy_shared_destroy
        self._stats = self._read_stats()
        if (
            self._stats.body_bytes,
            self._stats.source_polynomials,
            self._stats.residual_polynomials,
        ) != (metadata.body_size, metadata.sources, metadata.sources + 2 * metadata.groups):
            self.close()
            raise ValueError("Native graph coverage mismatch")

    @property
    def metadata(self):
        return self._metadata

    @property
    def stats(self):
        return self._stats

    def _read_stats(self):
        output = (ctypes.c_uint64 * 8)()
        if self._library._lib.cuhepy_shared_stats(self._handle, output, 8):
            raise ValueError("Native public stats unavailable")
        return NativeStats(*output)

    def query(self, query_body):
        self._require_process()
        p = self.metadata.profile
        _bytes(query_body, 2 * p.n * COMMON_WIDTH, "original query")
        with self._lock:
            self._require_open()
            handle = self._library._lib.cuhepy_shared_query(
                self._handle, _pointer(query_body), len(query_body)
            )
            if not handle:
                raise ValueError("Native original query rejected")
        return NativeQuery(self._library, handle, self.metadata, self.stats)


class NativeQuery(_OwnedHandle):
    """Public arithmetic/query ownership only; none of these methods releases secrets."""

    def __init__(self, library, handle, metadata, stats):
        self._initialize(library, handle)
        self._destroy = library._lib.cuhepy_shared_query_destroy
        self._metadata, self._stats = metadata, stats

    @property
    def metadata(self):
        return self._metadata

    def produce(self):
        self._require_process()
        with self._lock:
            self._require_open()
            output = ctypes.create_string_buffer(self.metadata.body_size)
            if self._library._lib.cuhepy_shared_produce(self._handle, output, len(output)):
                raise ValueError("Native public producer failed")
            return output.raw

    def check(self, body):
        self._require_process()
        with self._lock:
            self._require_open()
            if type(body) is not bytes or len(body) != self.metadata.body_size:
                return False
            result = self._library._lib.cuhepy_shared_check(self._handle, _pointer(body), len(body))
            # The native core rejects malformed canonical grammar before any
            # transform. Neither -1 nor an arithmetic mismatch authorizes work.
            return result == 1

    def residuals(self, body):
        """Small public diagnostics in each actual prime, in root order."""
        self._require_process()
        _bytes(body, self.metadata.body_size, "full relation body")
        n = self.metadata.profile.n
        words = 2 * self._stats.residual_polynomials * n
        if words > DIAGNOSTIC_WORD_CAP:
            raise ValueError("Small residual diagnostic cap exceeded")
        with self._lock:
            self._require_open()
            output = (ctypes.c_uint64 * words)()
            if self._library._lib.cuhepy_shared_residuals(
                self._handle, _pointer(body), len(body), output, words
            ):
                raise ValueError("Native residual diagnostics rejected")
            return tuple(
                tuple(
                    tuple(output[(2 * root + limb) * n + i] for i in range(n)) for limb in range(2)
                )
                for root in range(self._stats.residual_polynomials)
            )

    def expected_response(self, body):
        """Reconstruct the complete public terminal frame; not an acceptance check."""
        self._require_process()
        _bytes(body, self.metadata.body_size, "full relation body")
        with self._lock:
            self._require_open()
            m, p = self.metadata, self.metadata.profile
            width = m.terminal_row_size
            output = ctypes.create_string_buffer(2 * m.groups * width)
            if self._library._lib.cuhepy_shared_terminal(
                self._handle, _pointer(body), len(body), output, len(output)
            ):
                raise ValueError("Native terminal rejected")
            raw = output.raw
            header = [
                "cuhepy-lab-bgv-compact-v1",
                p.n,
                p.t,
                p.p.to_bytes((p.p.bit_length() + 7) // 8, "little"),
                bytes.fromhex(m.key_id),
                len(m.ids),
                p.dimension,
            ]
            rows = [
                [raw[(2 * g + c) * width : (2 * g + c + 1) * width] for c in range(2)]
                for g in range(m.groups)
            ]
            return msgpack.packb([header, rows], use_bin_type=True)

    def verifies(self, body, response):
        """Complete public arithmetic/frame equality; authentication is still external."""
        self._require_process()
        with self._lock:
            self._require_open()
            limit = 2 * self.metadata.groups * self.metadata.terminal_row_size + 256
            return (
                type(response) is bytes
                and len(response) <= limit
                and self.check(body)
                and response == self.expected_response(body)
            )
