"""Q76 matched prepared replay of the authenticated public BGV computation.

This known-method control shares the genuine native arithmetic with the trace
producer, but allocates/returns no source witness. It recomputes every compact
ciphertext coefficient before public admission. It has no HE secret. The local
lifecycle and trusted filesystem/runtime assumptions are unchanged; a code
digest is a reproducibility binding, never evidence of attested execution.
"""

from __future__ import annotations

import ctypes
import hashlib
from pathlib import Path

from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import lifecycle_shared_query as life
from experiments.bfv_search_lab import native_shared_query as native

REPLAY_ABI = 1
REPLY_TAG = b"cuhepy-q76-prepared-replay-reply-v1"
POLICY_TAG = b"cuhepy-q76-matched-prepared-replay-v1"


class _Arithmetic:
    def __init__(self, library):
        if type(library) is not native.NativeLibrary:
            raise ValueError("Explicit trusted native replay library required")
        try:
            abi = library._lib.cuhepy_shared_replay_abi
            run = library._lib.cuhepy_shared_replay
        except AttributeError as error:
            raise ValueError("Explicit replay symbols required; no fallback") from error
        abi.restype, abi.argtypes = ctypes.c_uint, []
        run.restype, run.argtypes = (
            ctypes.c_int,
            [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t],
        )
        if abi() != REPLAY_ABI:
            raise ValueError("Wrong isolated prepared replay ABI")
        self._library, self._run = library, run

    def frame(self, query):
        if type(query) is not native.NativeQuery or query._library is not self._library:
            raise ValueError("Owned query from the explicit replay library required")
        query._require_process()  # Before any inherited mutex can be acquired.
        with query._lock:
            query._require_open()
            m, p = query.metadata, query.metadata.profile
            width = m.terminal_row_size
            output = ctypes.create_string_buffer(2 * m.groups * width)
            if self._run(query._handle, output, len(output)):
                raise ValueError("Native prepared replay failed")
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
            return auth._pack([header, rows])


class ReplayFactory(auth.OwnerFactory):
    """Trusted mode selection. Enrollment/request grammar remains owner signed."""

    def __init__(self, owner_public_key, library):
        super().__init__(owner_public_key, library)
        self._arithmetic = _Arithmetic(library)
        source = Path(__file__).parent / "_shared_query/shared_query_replay.cpp"
        self._policy_digest = hashlib.sha256(
            auth._pack(
                [
                    POLICY_TAG,
                    REPLAY_ABI,
                    self._policy_digest,
                    hashlib.sha256(source.read_bytes()).digest(),
                    hashlib.sha256(Path(__file__).read_bytes()).digest(),
                ]
            )
        ).digest()

    def _make_request(self, query, binding, original_wire):
        return ReplayRequest(query, binding, original_wire, self._arithmetic)


class ReplayRequest(auth.PublicRequest):
    """Full-frame replay predicate; freshness/release still belongs to the journal."""

    def __init__(self, query, binding, original_wire, arithmetic):
        super().__init__(query, binding, original_wire)
        self._arithmetic = arithmetic

    def reply(self, compact_frame):
        if (
            type(compact_frame) is not bytes
            or len(compact_frame)
            > 2 * self._query.metadata.groups * self._query.metadata.terminal_row_size + 256
        ):
            raise ValueError("Wrong bounded immutable replay frame")
        return auth._pack([REPLY_TAG, *self.binding.fields(), compact_frame])

    def produce_packet(self):
        return self.reply(self._arithmetic.frame(self._query))

    def checked_frame(self, packet):
        self._query._require_process()
        self._query._require_open()
        try:
            limit = 2 * self._query.metadata.groups * self._query.metadata.terminal_row_size + 1024
            fields = auth._unpack(packet, limit=limit, array_cap=8)
            valid = (
                type(fields) is list
                and len(fields) == 8
                and fields[0] == REPLY_TAG
                and type(fields[2]) is int
                and all(type(fields[i]) is bytes and len(fields[i]) == 32 for i in (1, 3, 4, 5, 6))
                and fields[1:7] == self.binding.fields()
                and type(fields[7]) is bytes
                and len(fields[7]) <= limit - 768
            )
            # No remembered producer answer bypasses verification: each valid
            # public admission recomputes the complete frame from original inputs.
            return fields[7] if valid and fields[7] == self._arithmetic.frame(self._query) else None
        except (ValueError, TypeError, OverflowError):
            return None


class PreparedReplayAuthorizer:
    """Trusted full execution control, with one evaluation and no server witness.

    Only the signed original request is received. This distinct trusted service
    entry point computes its own entire frame, then uses the same durable
    authorization/claim lifecycle. It never treats a proposed frame as checked.
    """

    def __init__(self, journal):
        if type(journal) is not life.LocalJournal:
            raise ValueError("Explicit trusted local journal required")
        self.journal = journal

    def execute(self, enrollment, original_packet):
        if (
            type(enrollment) is not auth.OwnerEnrollment
            or type(enrollment._factory) is not ReplayFactory
        ):
            raise ValueError("Explicit trusted replay enrollment required")
        reservation = self.journal.reserve(enrollment, original_packet)
        request = None
        try:
            request = enrollment.request(original_packet)
            if request.binding != reservation.binding:
                raise life.LifecycleError("Replay request differs from consumed original")
            frame = request._arithmetic.frame(request._query)
            packet = request.reply(frame)
            authorization = self.journal._authorize(
                reservation, hashlib.sha256(packet).digest(), frame
            )
            return packet, authorization
        except BaseException:
            self.journal._reject(reservation, "prepared_replay_failed")
            raise
        finally:
            if request is not None:
                request.close()
