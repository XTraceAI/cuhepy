"""Bounded actual TCP frames and partial/truncated stream controls."""

import pytest

from experiments.bfv_search_lab import loopback_transfer as transfer


class Fragments:
    def __init__(self, chunks):
        self.chunks = iter(chunks)

    def recv(self, _count):
        return next(self.chunks, b"")


def test_partial_reads_and_truncation_and_work_limit():
    assert transfer.receive_exact(Fragments((b"ab", b"c", b"def")), 6) == b"abcdef"
    with pytest.raises(ValueError, match="Truncated"):
        transfer.receive_exact(Fragments((b"ab",)), 3)
    with pytest.raises(ValueError, match="bound"):
        transfer.receive_exact(Fragments(()), transfer.MAX_PACKET + 1)


def test_persistent_tcp_small_and_large_actual_payloads():
    packets = (b"one", bytes(range(256)) * 4096)
    with transfer.Probe(packets) as probe:
        upload = probe.upload(1)
        assert probe.uploaded[1] == packets[1] and upload["payload_bytes"] == len(packets[1])
        for ordinal in (0, 1, 0):
            actual, receipt = probe.transfer(ordinal)
            assert actual == packets[ordinal]
            assert receipt["payload_bytes"] == len(actual)
            assert receipt["client_request_frame_bytes"] == receipt["server_reply_frame_bytes"] == 8
        with pytest.raises(ValueError):
            probe.transfer(2)
