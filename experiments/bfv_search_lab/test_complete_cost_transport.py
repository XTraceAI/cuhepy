"""Q77 bounded TCP grammar/ownership/pacing tests, not a performance panel."""

import copy
import os
import pickle
import select
import signal
import socket
import struct
import threading
import time

import pytest

from experiments.bfv_search_lab import complete_cost_transport as transport

FAST = transport.Link(1_000_000_000, 0)


def streams(*, cap=1 << 18, link=FAST, timeout_ns=2_000_000_000):
    left, right = transport.connected_pair()
    return tuple(
        transport.BoundedStream(sock, cap=cap, link=link, timeout_ns=timeout_ns)
        for sock in (left, right)
    )


def in_thread(callback):
    errors = []

    def wrapped():
        try:
            callback()
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=wrapped, daemon=True)
    thread.start()
    return thread, errors


def finish(thread, errors):
    thread.join(3)
    assert not thread.is_alive() and not errors


@pytest.mark.parametrize("size", [1, 8, 65535, 65536, 65537, 131073])
def test_complete_tcp_bytes_and_both_direction_accounting(size):
    left, right = streams()
    payload = bytes(i % 251 for i in range(size))
    thread, errors = in_thread(lambda: left.send(payload, kind="public-query"))
    assert right.receive(kind="public-query") == payload
    finish(thread, errors)
    sent, received = left.history()[0], right.history()[0]
    assert sent.completed and received.completed
    assert sent.wire_bytes == received.wire_bytes == size + 8
    assert sent.payload_bytes == received.payload_bytes == size
    assert sent.payload_sha256 == received.payload_sha256
    assert sent.finished_ns >= sent.started_ns and received.finished_ns >= received.started_ns
    assert sent.thread_cpu_ns >= 0 and received.thread_cpu_ns >= 0
    assert "data" not in sent.as_dict() and "payload" not in sent.as_dict()
    left.close()
    right.close()


def test_sequential_frames_do_not_merge_or_leave_trailing_body_bytes():
    left, right = streams()
    messages = (b"first\0message", b"second", bytes(70000))
    thread, errors = in_thread(
        lambda: [left.send(message, kind="sequence") for message in messages]
    )
    assert tuple(right.receive(kind="sequence") for _ in messages) == messages
    finish(thread, errors)
    assert len(left.history()) == len(right.history()) == 3
    left.close()
    right.close()


@pytest.mark.parametrize("declared", [0, 65, 1 << 31, (1 << 64) - 1])
def test_untrusted_header_length_is_rejected_before_body_allocation(declared):
    raw, peer = transport.connected_pair()
    stream = transport.BoundedStream(peer, cap=64, link=FAST, timeout_ns=1_000_000_000)
    raw.sendall(struct.pack("!Q", declared))
    with pytest.raises(transport.TransportError):
        stream.receive(kind="header-fault")
    record = stream.history()[0]
    assert record.wire_bytes == 8 and not record.completed and record.payload_sha256 is None
    assert record.payload_bytes == declared
    with pytest.raises(transport.TransportError):
        stream.receive(kind="after-failure")
    raw.close()


@pytest.mark.parametrize(
    "packet", [b"", b"\0", bytes(7), struct.pack("!Q", 32), struct.pack("!Q", 32) + b"short"]
)
def test_eof_and_partial_frames_cannot_be_retried(packet):
    raw, peer = transport.connected_pair()
    stream = transport.BoundedStream(peer, cap=64, link=FAST, timeout_ns=1_000_000_000)
    raw.sendall(packet)
    raw.close()
    with pytest.raises(transport.TransportError):
        stream.receive(kind="partial")
    assert not stream.history()[0].completed and stream.history()[0].wire_bytes == len(packet)
    with pytest.raises(transport.TransportError):
        stream.receive(kind="retry")


@pytest.mark.parametrize("bad", [b"", bytes(65), bytearray(b"x"), memoryview(b"x"), "public", None])
def test_invalid_local_message_is_rejected_without_writing_a_header(bad):
    left, right = streams(cap=64)
    with pytest.raises(ValueError):
        left.send(bad, kind="local-fault")
    assert not left.history()
    readable, _, _ = select.select([right._sock], [], [], 0.01)
    assert not readable
    left.close()
    right.close()


def test_receive_and_pacing_deadlines_are_terminal():
    left, right = streams(timeout_ns=10_000_000)
    with pytest.raises(transport.TransportError):
        right.receive(kind="timeout")
    assert not right.history()[0].completed
    left.close()
    slow_left, slow_right = streams(link=transport.Link(1, 0), timeout_ns=10_000_000)
    with pytest.raises(transport.TransportError):
        slow_left.send(b"public", kind="pacing-timeout")
    assert not slow_left.history()[0].completed and slow_left.history()[0].wire_bytes == 0
    slow_right.close()


def test_receiver_cannot_finish_before_declared_paced_delivery():
    # A bounded correctness assertion for userspace pacing, not a throughput
    # estimate. Checking receive completion catches final-chunk early delivery.
    link = transport.Link(65536, 5_000_000)
    left, right = streams(link=link)
    payload = b"x" * 2048
    thread, errors = in_thread(lambda: left.send(payload, kind="paced"))
    assert right.receive(kind="paced") == payload
    finish(thread, errors)
    sent, received = left.history()[0], right.history()[0]
    minimum = (
        link.one_way_delay_ns
        + ((len(payload) + 8) * 1_000_000_000 + link.bytes_per_second - 1) // link.bytes_per_second
    )
    assert received.finished_ns >= sent.started_ns + minimum
    left.close()
    right.close()


def test_multiple_senders_serialize_whole_frames():
    left, right = streams()
    messages = tuple(bytes([i]) * (70000 + i) for i in range(4))
    jobs = [in_thread(lambda data=data: left.send(data, kind="parallel-send")) for data in messages]
    received = tuple(right.receive(kind="parallel-send") for _ in messages)
    for thread, errors in jobs:
        finish(thread, errors)
    assert set(received) == set(messages)
    assert len(left.history()) == len(right.history()) == 4
    left.close()
    right.close()


def test_full_duplex_directions_can_progress_without_shared_message_locks():
    left, right = streams()
    jobs = [
        in_thread(lambda: left.send(b"left" * 20000, kind="left")),
        in_thread(lambda: right.send(b"right" * 20000, kind="right")),
    ]
    assert right.receive(kind="left") == b"left" * 20000
    assert left.receive(kind="right") == b"right" * 20000
    for thread, errors in jobs:
        finish(thread, errors)
    assert {entry.direction for entry in left.history()} == {"send", "receive"}
    left.close()
    right.close()


def test_close_unblocks_waiting_receiver_and_preserves_failure_record():
    left, right = streams()
    entered = threading.Event()

    def pending():
        entered.set()
        right.receive(kind="pending")

    thread, errors = in_thread(pending)
    assert entered.wait(1)
    # Let receive enter its select before closing; this does not measure a
    # service duration or tune any workload parameter.
    time.sleep(0.01)
    right.close()
    thread.join(2)
    assert not thread.is_alive() and len(errors) == 1
    assert isinstance(errors[0], transport.TransportError)
    assert len(right.history()) == 1 and not right.history()[0].completed
    left.close()


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_socket_ownership_cannot_be_copied(operation):
    left, right = streams()
    with pytest.raises(TypeError):
        operation(left)
    left.close()
    right.close()


def test_fork_rejection_precedes_inherited_send_lock():
    left, right = streams()
    left._send_lock.acquire()
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            left.send(b"public", kind="fork")
            os.write(write_fd, b"bad")
        except RuntimeError:
            os.write(write_fd, b"rejected")
        finally:
            os._exit(0)
    os.close(write_fd)
    try:
        ready, _, _ = select.select([read_fd], [], [], 3)
        if not ready:
            os.kill(child, signal.SIGKILL)
        assert ready and os.read(read_fd, 32) == b"rejected"
    finally:
        left._send_lock.release()
        os.close(read_fd)
        os.waitpid(child, 0)
    thread, errors = in_thread(lambda: left.send(b"parent", kind="parent"))
    assert right.receive(kind="parent") == b"parent"
    finish(thread, errors)
    left.close()
    right.close()


@pytest.mark.parametrize(
    "rate,delay",
    [(0, 0), (True, 0), (-1, 0), (1 << 41, 0), (1, -1), (1, True), (1, 60_000_000_001)],
)
def test_invalid_link_conditions_are_not_silently_normalized(rate, delay):
    with pytest.raises(ValueError):
        transport.Link(rate, delay)


@pytest.mark.parametrize("kind", ["", "x" * 65, "private-µ", b"label", None])
def test_telemetry_kind_is_trusted_bounded_metadata(kind):
    left, right = streams()
    with pytest.raises(ValueError):
        left.send(b"public", kind=kind)
    assert not left.history()
    left.close()
    right.close()


@pytest.mark.parametrize(
    "cap,timeout",
    [(0, 1), (True, 1), ((1 << 31) + 1, 1), (1, 0), (1, True), (1, 3_600_000_000_001)],
)
def test_explicit_transport_bounds_reject_bool_and_out_of_range(cap, timeout):
    left, right = transport.connected_pair()
    try:
        with pytest.raises(ValueError):
            transport.BoundedStream(left, cap=cap, link=FAST, timeout_ns=timeout)
    finally:
        left.close()
        right.close()


def test_only_explicit_connected_loopback_tcp_is_supported():
    unconnected = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises((ValueError, OSError)):
            transport.BoundedStream(unconnected, cap=64, link=FAST, timeout_ns=1_000_000)
    finally:
        unconnected.close()
    left, right = socket.socketpair()
    try:
        with pytest.raises(ValueError):
            transport.BoundedStream(left, cap=64, link=FAST, timeout_ns=1_000_000)
    finally:
        left.close()
        right.close()
