"""Q77 bounded actual loopback transport and per-message measurements.

Userspace pacing is a declared local experimental link condition. It supplies
no confidentiality, authentication, attestation or estimate of AWS networking.
Only public messages belong on this channel. The worker/coordinator must keep
private keys and callback diagnostics out of payloads and telemetry.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import os
import select
import socket
import struct
import threading
import time

MAX_FRAME = 1 << 31
CHUNK = 1 << 16
HEADER = struct.Struct("!Q")


class TransportError(RuntimeError):
    """Public bounded transport failure; contains no message payload."""


@dataclass(frozen=True)
class Link:
    bytes_per_second: int
    one_way_delay_ns: int

    def __post_init__(self):
        if (
            type(self.bytes_per_second) is not int
            or not 1 <= self.bytes_per_second <= 1 << 40
            or type(self.one_way_delay_ns) is not int
            or not 0 <= self.one_way_delay_ns <= 60_000_000_000
        ):
            raise ValueError("Explicit bounded local link conditions required")


@dataclass(frozen=True)
class Transfer:
    direction: str
    kind: str
    started_ns: int
    finished_ns: int
    thread_cpu_ns: int
    wire_bytes: int
    payload_bytes: int
    payload_sha256: str | None
    completed: bool
    process: int
    thread: int

    def as_dict(self):
        return asdict(self)


def connected_pair():
    """Actual IPv4 TCP loopback pair, useful for bounded protocol tests."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    left = right = None
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        left = socket.create_connection(listener.getsockname(), timeout=5)
        right, _ = listener.accept()
        return left, right
    except BaseException:
        if left is not None:
            left.close()
        if right is not None:
            right.close()
        raise
    finally:
        listener.close()


class BoundedStream:
    """Owned full-duplex stream; individual send/receive messages serialize.

    Absolute deadlines bound both IO and pacing. Header coverage is checked
    before body allocation. Trace records contain lengths/hashes, never data.
    A failed message closes the stream: a partial frame cannot be retried as
    a new message on the same byte stream.
    """

    def __init__(self, sock, *, cap, link, timeout_ns, observer=None):
        if (
            type(sock) is not socket.socket
            or sock.family != socket.AF_INET
            or sock.type & socket.SOCK_STREAM != socket.SOCK_STREAM
            or sock.getpeername()[0] != "127.0.0.1"
            or type(cap) is not int
            or not 1 <= cap <= MAX_FRAME
            or type(link) is not Link
            or type(timeout_ns) is not int
            or not 1 <= timeout_ns <= 3_600_000_000_000
            or observer is not None
            and not callable(observer)
        ):
            raise ValueError("Connected loopback socket and explicit bounds required")
        self._sock, self.cap, self.link, self.timeout_ns = sock, cap, link, timeout_ns
        self._observer = observer
        self._pid, self._closed = os.getpid(), False
        self._send_lock, self._receive_lock = threading.RLock(), threading.RLock()
        self._history_lock = threading.Lock()
        self._history = []
        sock.setblocking(False)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def _process(self):
        if self._pid != os.getpid():
            raise RuntimeError("Inherited local stream")

    def _open(self):
        if self._closed:
            raise TransportError("Closed local stream")

    @staticmethod
    def _kind(kind):
        if type(kind) is not str or not 1 <= len(kind) <= 64 or not kind.isascii():
            raise ValueError("Bounded trusted telemetry kind required")

    def _wait(self, deadline, *, write):
        self._open()
        remaining = deadline - time.perf_counter_ns()
        if remaining <= 0:
            raise TransportError("Local transport deadline exhausted")
        reads, writes = ([], [self._sock]) if write else ([self._sock], [])
        try:
            readable, writable, _ = select.select(reads, writes, [], min(remaining / 1e9, 0.25))
        except (OSError, ValueError) as error:
            raise TransportError("Local transport unavailable") from error
        return bool(readable or writable)

    def _pause_until(self, target, deadline):
        while True:
            self._open()
            now = time.perf_counter_ns()
            if now >= deadline:
                raise TransportError("Local pacing deadline exhausted")
            if now >= target:
                return
            time.sleep(min(target - now, deadline - now, 250_000_000) / 1e9)

    def _record(self, direction, kind, start, cpu_start, wire, size, digest, completed):
        record = Transfer(
            direction,
            kind,
            start,
            time.perf_counter_ns(),
            time.thread_time_ns() - cpu_start,
            wire,
            size,
            digest,
            completed,
            os.getpid(),
            threading.get_ident(),
        )
        with self._history_lock:
            self._history.append(record)
        if self._observer is not None:
            self._observer(record)

    def send(self, data, *, kind):
        self._process()
        self._kind(kind)
        if type(data) is not bytes or not 1 <= len(data) <= self.cap:
            raise ValueError("Invalid immutable bounded public message")
        with self._send_lock:
            self._open()
            start, cpu_start = time.perf_counter_ns(), time.thread_time_ns()
            deadline, wire, completed = start + self.timeout_ns, 0, False
            try:
                for segment in (memoryview(HEADER.pack(len(data))), memoryview(data)):
                    at = 0
                    while at < len(segment):
                        if not self._wait(deadline, write=True):
                            continue
                        piece = segment[at : at + CHUNK]
                        # Pace before delivery, so receiver completion cannot
                        # precede the declared length/rate/delay envelope.
                        target = (
                            start
                            + self.link.one_way_delay_ns
                            + ((wire + len(piece)) * 1_000_000_000 + self.link.bytes_per_second - 1)
                            // self.link.bytes_per_second
                        )
                        self._pause_until(target, deadline)
                        try:
                            written = self._sock.send(piece)
                        except BlockingIOError:
                            continue
                        if written == 0:
                            raise TransportError("Local peer stopped reading")
                        at, wire = at + written, wire + written
                completed = True
            except (OSError, TransportError, MemoryError) as error:
                self.close()
                raise TransportError("Public message send failed") from error
            finally:
                self._record(
                    "send",
                    kind,
                    start,
                    cpu_start,
                    wire,
                    len(data),
                    hashlib.sha256(data).hexdigest(),
                    completed,
                )

    def receive(self, *, kind):
        self._process()
        self._kind(kind)
        with self._receive_lock:
            self._open()
            start, cpu_start = time.perf_counter_ns(), time.thread_time_ns()
            deadline, wire, size, completed, digest = start + self.timeout_ns, 0, 0, False, None

            def read_exact(target):
                nonlocal wire
                at = 0
                view = memoryview(target)
                while at < len(view):
                    if not self._wait(deadline, write=False):
                        continue
                    try:
                        received = self._sock.recv_into(view[at : at + CHUNK])
                    except BlockingIOError:
                        continue
                    if received == 0:
                        raise TransportError("Public message ended before full coverage")
                    at, wire = at + received, wire + received

            try:
                header = bytearray(HEADER.size)
                read_exact(header)
                size = HEADER.unpack(header)[0]
                if not 1 <= size <= self.cap:
                    raise TransportError("Public message length exceeds trusted bound")
                body = bytearray(size)
                read_exact(body)
                result = bytes(body)
                digest, completed = hashlib.sha256(result).hexdigest(), True
                return result
            except (OSError, TransportError, MemoryError) as error:
                self.close()
                raise TransportError("Public message receive failed") from error
            finally:
                self._record("receive", kind, start, cpu_start, wire, size, digest, completed)

    def history(self):
        self._process()
        with self._history_lock:
            return tuple(self._history)

    def close(self):
        self._process()
        self._closed = True
        try:
            self._sock.close()
        except OSError:
            pass

    def __copy__(self):
        raise TypeError("Local stream ownership cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Local stream ownership cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Local stream cannot be serialized")
