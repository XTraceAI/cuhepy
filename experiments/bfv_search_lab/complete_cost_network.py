"""Q77 aggregate public link pacing across competing streams.

Keep one budget per full-duplex direction at each shared relay endpoint.
Reservations cover real header/body chunks, not a sum of stage models. This
declared userspace condition is not a fair-queue simulator or AWS measurement.
The relay topology and its owned copies/work still belong in the execution
freeze. Only public ciphertext/cache packets belong on these streams.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
import threading
import time

from experiments.bfv_search_lab import complete_cost_transport as transport


@dataclass(frozen=True)
class Reservation:
    ordinal: int
    started_ns: int
    finished_ns: int
    wire_bytes: int


class DirectionBudget:
    """One process-owned aggregate serialization lane, shared by threads.

    Admission of a chunk is atomic. Expired/unaffordable reservations cannot
    change the lane. A failed actual transfer retains its paid credit; it is
    not refunded or retried as a new frame. Direction budgets are independent.
    """

    def __init__(self, link):
        if type(link) is not transport.Link:
            raise ValueError("Explicit public link required")
        self.link, self._pid = link, os.getpid()
        self._lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._next_ns, self._history = 0, []

    def _process(self):
        if os.getpid() != self._pid:
            raise RuntimeError("Inherited shared link budget")

    def reserve(self, size, *, earliest_ns, deadline_ns):
        self._process()
        if (
            type(size) is not int
            or not 1 <= size <= transport.CHUNK
            or type(earliest_ns) is not int
            or type(deadline_ns) is not int
            or not 0 <= earliest_ns < deadline_ns
        ):
            raise ValueError("Bounded chunk and absolute readiness/deadline required")
        with self._lock:
            start = max(earliest_ns, self._next_ns)
            duration = (
                size * 1_000_000_000 + self.link.bytes_per_second - 1
            ) // self.link.bytes_per_second
            finish = start + duration
            if finish >= deadline_ns:
                raise transport.TransportError("Shared link deadline exhausted")
            record = Reservation(len(self._history), start, finish, size)
            self._history.append(record)
            self._next_ns = finish
            return record

    def history(self):
        self._process()
        with self._lock:
            return tuple(self._history)

    @contextmanager
    def sending(self, deadline_ns):
        """Serialize actual chunk delivery too, so delayed threads cannot burst.

        Backpressure and scheduler delay occupy the lane. Waiting for its lock
        shares the message's absolute deadline; no waiter can block forever.
        """
        self._process()
        if type(deadline_ns) is not int:
            raise ValueError("Absolute link deadline required")
        remaining = deadline_ns - time.perf_counter_ns()
        if remaining <= 0 or not self._send_lock.acquire(timeout=remaining / 1e9):
            raise transport.TransportError("Shared delivery deadline exhausted")
        try:
            if time.perf_counter_ns() >= deadline_ns:
                raise transport.TransportError("Shared delivery deadline exhausted")
            yield
        finally:
            self._send_lock.release()

    def __copy__(self):
        raise TypeError("Shared link budgets cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Shared link budgets cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Shared link budgets cannot be serialized")


class BudgetedStream(transport.BoundedStream):
    """Existing bounded receive grammar, with a shared send serialization lane.

    The initial one-way delay establishes earliest delivery readiness; actual
    header/body credits serialize after that readiness. Partial socket writes
    retain the original chunk credit. Independent connections do not receive
    independent bandwidth. A topology must shape each physical direction once.
    """

    def __init__(self, sock, *, budget, cap, timeout_ns, observer=None):
        if type(budget) is not DirectionBudget:
            raise ValueError("Shared process-owned directional budget required")
        budget._process()
        super().__init__(sock, cap=cap, link=budget.link, timeout_ns=timeout_ns, observer=observer)
        self._budget = budget

    def send(self, data, *, kind):
        self._process()
        self._budget._process()
        self._kind(kind)
        if type(data) is not bytes or not 1 <= len(data) <= self.cap:
            raise ValueError("Invalid immutable bounded public message")
        with self._send_lock:
            self._open()
            start, cpu_start = time.perf_counter_ns(), time.thread_time_ns()
            deadline, wire, completed = start + self.timeout_ns, 0, False
            ready = start + self.link.one_way_delay_ns
            try:
                for segment in (memoryview(transport.HEADER.pack(len(data))), memoryview(data)):
                    at = 0
                    while at < len(segment):
                        with self._budget.sending(deadline):
                            if not self._wait(deadline, write=True):
                                continue
                            end = min(len(segment), at + transport.CHUNK)
                            credit = self._budget.reserve(
                                end - at,
                                earliest_ns=max(time.perf_counter_ns(), ready),
                                deadline_ns=deadline,
                            )
                            self._pause_until(credit.finished_ns, deadline)
                            while at < end:
                                if not self._wait(deadline, write=True):
                                    continue
                                try:
                                    written = self._sock.send(segment[at:end])
                                except BlockingIOError:
                                    continue
                                if written == 0:
                                    raise transport.TransportError("Local peer stopped reading")
                                at, wire = at + written, wire + written
                completed = True
            except (OSError, transport.TransportError, MemoryError) as error:
                self.close()
                raise transport.TransportError("Shared public message send failed") from error
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
