"""Bounded actual shared-link controls; no HE arithmetic or timing cohort."""

import copy
import os
import pickle
import threading
import time

import pytest

from experiments.bfv_search_lab import complete_cost_network as shared
from experiments.bfv_search_lab import complete_cost_transport as transport


def test_aggregate_credit_serializes_header_and_body_without_failed_reservation_mutation():
    budget = shared.DirectionBudget(transport.Link(1000, 0))
    first = budget.reserve(8, earliest_ns=0, deadline_ns=1_000_000_000)
    second = budget.reserve(100, earliest_ns=1, deadline_ns=1_000_000_000)
    assert (first.started_ns, first.finished_ns, second.started_ns, second.finished_ns) == (
        0,
        8_000_000,
        8_000_000,
        108_000_000,
    )
    before = budget.history()
    with pytest.raises(transport.TransportError):
        budget.reserve(1, earliest_ns=1, deadline_ns=108_000_001)
    assert budget.history() == before


def test_full_duplex_directions_have_independent_capacity():
    up, down = (shared.DirectionBudget(transport.Link(1000, 0)) for _ in range(2))
    assert up.reserve(10, earliest_ns=10, deadline_ns=100_000_000) == down.reserve(
        10, earliest_ns=10, deadline_ns=100_000_000
    )
    assert up.history() == down.history()


@pytest.mark.parametrize("size", (0, True, -1, transport.CHUNK + 1))
def test_invalid_chunk_has_no_credit(size):
    budget = shared.DirectionBudget(transport.Link(1000, 0))
    with pytest.raises(ValueError):
        budget.reserve(size, earliest_ns=0, deadline_ns=1_000_000_000)
    assert budget.history() == ()


@pytest.mark.parametrize("operation", ("reserve", "history", "sending"))
def test_inherited_budget_rejects_before_held_locks(operation):
    budget = shared.DirectionBudget(transport.Link(1000, 0))
    budget._pid = os.getpid() + 1
    budget._lock.acquire()
    budget._send_lock.acquire()
    try:
        with pytest.raises(RuntimeError):
            if operation == "reserve":
                budget.reserve(1, earliest_ns=0, deadline_ns=100)
            elif operation == "history":
                budget.history()
            else:
                with budget.sending(time.perf_counter_ns() + 1_000_000):
                    pass
    finally:
        budget._lock.release()
        budget._send_lock.release()


def test_budget_has_no_copy_or_serialization_authority():
    budget = shared.DirectionBudget(transport.Link(1000, 0))
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(budget)


def test_two_real_connections_share_chunks_and_complete_coverage():
    budget = shared.DirectionBudget(transport.Link(1_000_000, 0))
    pairs = [transport.connected_pair() for _ in range(2)]
    senders = [
        shared.BudgetedStream(left, budget=budget, cap=1 << 18, timeout_ns=2_000_000_000)
        for left, _ in pairs
    ]
    receivers = [
        transport.BoundedStream(right, cap=1 << 18, link=budget.link, timeout_ns=2_000_000_000)
        for _, right in pairs
    ]
    payloads = [b"public-cache" * 6000, b"public-response" * 30]
    results, errors = {}, []
    barrier = threading.Barrier(2)

    def send(i):
        try:
            barrier.wait()
            senders[i].send(payloads[i], kind="competing-public-message")
        except BaseException as error:
            errors.append(error)

    threads = [threading.Thread(target=send, args=(i,)) for i in range(2)]
    try:
        for thread in threads:
            thread.start()
        for i, receiver in enumerate(receivers):
            results[i] = receiver.receive(kind="complete-public-receive")
        for thread in threads:
            thread.join(timeout=3)
            assert not thread.is_alive()
        assert errors == [] and results == dict(enumerate(payloads))
        history = budget.history()
        assert sum(r.wire_bytes for r in history) == sum(
            len(x) + transport.HEADER.size for x in payloads
        )
        assert all(
            a.finished_ns <= b.started_ns for a, b in zip(history, history[1:], strict=False)
        )
        assert all(sender.history()[0].completed for sender in senders)
        assert max(sender.history()[0].finished_ns for sender in senders) >= history[-1].finished_ns
    finally:
        for stream in senders + receivers:
            stream.close()


def test_partial_socket_writes_keep_original_credit():
    left, right = transport.connected_pair()
    budget = shared.DirectionBudget(transport.Link(1_000_000, 0))
    sender = shared.BudgetedStream(left, budget=budget, cap=4096, timeout_ns=1_000_000_000)
    receiver = transport.BoundedStream(right, cap=4096, link=budget.link, timeout_ns=1_000_000_000)

    class Partial:
        def __init__(self, sock):
            self.sock, self.calls = sock, 0

        def __getattr__(self, name):
            return getattr(self.sock, name)

        def send(self, data):
            self.calls += 1
            return self.sock.send(data[:3])

    partial = Partial(sender._sock)
    sender._sock = partial
    try:
        sender.send(b"public" * 30, kind="partial-public-writes")
        assert receiver.receive(kind="whole") == b"public" * 30
        assert partial.calls > 2 and len(budget.history()) == 2
        assert sum(r.wire_bytes for r in budget.history()) == 188
    finally:
        sender.close()
        receiver.close()


def test_shared_lock_wait_is_bounded_and_failed_message_closes():
    left, right = transport.connected_pair()
    budget = shared.DirectionBudget(transport.Link(1_000_000, 0))
    sender = shared.BudgetedStream(left, budget=budget, cap=4096, timeout_ns=10_000_000)
    budget._send_lock.acquire()
    try:
        with pytest.raises(transport.TransportError):
            sender.send(b"public", kind="expired-public-send")
        assert budget.history() == () and sender._closed
        assert not sender.history()[0].completed and sender.history()[0].wire_bytes == 0
    finally:
        budget._send_lock.release()
        sender.close()
        right.close()


def test_public_send_validation_does_not_mutate_link():
    left, right = transport.connected_pair()
    budget = shared.DirectionBudget(transport.Link(1_000_000, 0))
    sender = shared.BudgetedStream(left, budget=budget, cap=4, timeout_ns=1_000_000_000)
    try:
        for data in (b"", b"exceeds", bytearray(b"pub")):
            with pytest.raises(ValueError):
                sender.send(data, kind="invalid-public-input")
        assert budget.history() == () and sender.history() == ()
    finally:
        sender.close()
        right.close()
