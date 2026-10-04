"""Q76 exact aggregate control with a genuine protected BGV prefix/suffix.

The three tensor aggregates are admitted by complete equality in both actual
prime NTTs, using the same optimized three-product arithmetic as replay. This
known exact control pays its protected products and does not claim statistical
sampling savings. It has no HE secret, private hook or hidden challenge. Local
origin/authentication/rollback assumptions remain those of the prototype.
"""

from __future__ import annotations

import ctypes
import hashlib
from pathlib import Path

from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import native_shared_query as native

AGGREGATE_ABI = 1
REPLY_TAG = b"cuhepy-q76-exact-aggregate-reply-v1"
POLICY_TAG = b"cuhepy-q76-exact-aggregate-prefix-suffix-v1"


def body_size(metadata):
    return 3 * metadata.groups * metadata.profile.n * native.COMMON_WIDTH


def _frame(metadata, raw):
    p, width = metadata.profile, metadata.terminal_row_size
    return auth._pack(
        [
            [
                "cuhepy-lab-bgv-compact-v1",
                p.n,
                p.t,
                p.p.to_bytes((p.p.bit_length() + 7) // 8, "little"),
                bytes.fromhex(metadata.key_id),
                len(metadata.ids),
                p.dimension,
            ],
            [
                [raw[(2 * g + c) * width : (2 * g + c + 1) * width] for c in range(2)]
                for g in range(metadata.groups)
            ],
        ]
    )


class _Arithmetic:
    def __init__(self, library):
        if type(library) is not native.NativeLibrary:
            raise ValueError("Explicit trusted native aggregate library required")
        try:
            abi = library._lib.cuhepy_shared_aggregate_abi
            produce = library._lib.cuhepy_shared_aggregate_produce
            finish = library._lib.cuhepy_shared_aggregate_finish
        except AttributeError as error:
            raise ValueError("Explicit aggregate symbols required; no fallback") from error
        abi.restype, abi.argtypes = ctypes.c_uint, []
        for fn in (produce, finish):
            fn.restype, fn.argtypes = (
                ctypes.c_int,
                [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                ],
            )
        if abi() != AGGREGATE_ABI:
            raise ValueError("Wrong isolated exact aggregate ABI")
        self._library, self._produce, self._finish = library, produce, finish

    def _require(self, query):
        if type(query) is not native.NativeQuery or query._library is not self._library:
            raise ValueError("Owned query from the explicit aggregate library required")
        query._require_process()

    def produce(self, query):
        self._require(query)
        with query._lock:
            query._require_open()
            m = query.metadata
            body = ctypes.create_string_buffer(body_size(m))
            output = ctypes.create_string_buffer(2 * m.groups * m.terminal_row_size)
            if self._produce(query._handle, body, len(body), output, len(output)):
                raise ValueError("Native aggregate producer failed")
            return body.raw, _frame(m, output.raw)

    def checked_frame(self, query, body):
        self._require(query)
        with query._lock:
            query._require_open()
            m = query.metadata
            if type(body) is not bytes or len(body) != body_size(m):
                return None
            output = ctypes.create_string_buffer(2 * m.groups * m.terminal_row_size)
            result = self._finish(
                query._handle, native._pointer(body), len(body), output, len(output)
            )
            return _frame(m, output.raw) if result == 1 else None


class AggregateFactory(auth.OwnerFactory):
    """Trusted exact-mode selection; owner-signed input grammar stays the same."""

    def __init__(self, owner_public_key, library):
        super().__init__(owner_public_key, library)
        self._arithmetic = _Arithmetic(library)
        source = Path(__file__).parent / "_shared_query/shared_query_aggregate.cpp"
        self._policy_digest = hashlib.sha256(
            auth._pack(
                [
                    POLICY_TAG,
                    AGGREGATE_ABI,
                    self._policy_digest,
                    hashlib.sha256(source.read_bytes()).digest(),
                    hashlib.sha256(Path(__file__).read_bytes()).digest(),
                ]
            )
        ).digest()

    def _make_request(self, query, binding, original_wire):
        return AggregateRequest(query, binding, original_wire, self._arithmetic)


class AggregateRequest(auth.PublicRequest):
    """Exact public aggregate/frame predicate; the journal provides release authority."""

    def __init__(self, query, binding, original_wire, arithmetic):
        super().__init__(query, binding, original_wire)
        self._arithmetic = arithmetic

    def reply(self, body, compact_frame):
        if (
            type(body) is not bytes
            or len(body) != body_size(self._query.metadata)
            or type(compact_frame) is not bytes
            or len(compact_frame)
            > 2 * self._query.metadata.groups * self._query.metadata.terminal_row_size + 256
        ):
            raise ValueError("Wrong full aggregate/frame coverage")
        return auth._pack([REPLY_TAG, *self.binding.fields(), body, compact_frame])

    def produce_packet(self):
        return self.reply(*self._arithmetic.produce(self._query))

    def checked_frame(self, packet):
        self._query._require_process()
        self._query._require_open()
        try:
            frame_cap = (
                2 * self._query.metadata.groups * self._query.metadata.terminal_row_size + 256
            )
            limit = body_size(self._query.metadata) + frame_cap + 768
            fields = auth._unpack(packet, limit=limit, array_cap=9)
            valid = (
                type(fields) is list
                and len(fields) == 9
                and fields[0] == REPLY_TAG
                and type(fields[2]) is int
                and all(type(fields[i]) is bytes and len(fields[i]) == 32 for i in (1, 3, 4, 5, 6))
                and fields[1:7] == self.binding.fields()
                and type(fields[7]) is bytes
                and len(fields[7]) == body_size(self._query.metadata)
                and type(fields[8]) is bytes
                and len(fields[8]) <= frame_cap
            )
            return (
                fields[8]
                if valid and self._arithmetic.checked_frame(self._query, fields[7]) == fields[8]
                else None
            )
        except (ValueError, TypeError, OverflowError):
            return None
