"""E75 wire identity, one-use accounting, and key-release ordering controls."""

from contextlib import closing
from dataclasses import replace
import struct

import pytest

from benchmarks.enrolled_service_lab import open_response
from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import enrolled_rpc as rpc
from experiments.bfv_search_lab import loopback_exchange as exchange
from experiments.bfv_search_lab import native_linear_check as checks
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import verification_lifetime as lifetime


def fixture():
    s = space.space(tree.layout(tree.context(32, ("0", "10", "11"), 257), (3, 2, 1), (37, 9, 1)), (0, 1, 2))
    groups = [[[(i + j) % 3 - 1 for j in range(f)] for i in range(c)]
              for c, f in zip(s.layout.counts, s.layout.features, strict=True)]
    pk, sk = masked.key_gen(s, q_bits=40, eta=1)
    return s, groups, pk, sk


def test_bundle_exact_framing_and_bounded_work():
    packets = (b"a", b"bb", bytes(range(256)))
    body = rpc.bundle(packets)
    assert rpc.unbundle(body, 3) == packets
    for bad in (body[:-1], body + b"x", struct.pack("<Q", 8193) + body[8:],
                struct.pack("<QQ", 3, 1 << 63) + body[16:]):
        with pytest.raises(ValueError):
            rpc.unbundle(bad, 3)
    for bad in ((), (b"",), [b"a"], (b"a",) * 8193):
        with pytest.raises(ValueError):
            rpc.bundle(bad)


def test_actual_received_index_answer_delta_and_full_coefficients_equal():
    s, groups, pk, sk = fixture()
    epoch = b"e" * 32
    with closing(owner.OwnerClient(pk, sk)) as client:
        capture = rpc.CaptureClient(client)
        index, _ = masked.enroll(s, groups, epoch, capture)
        server = rpc.LinearServer(s, pk, epoch, budget=2)
        assert server(b"I" + rpc.bundle(capture.take())) == b"\x01"
        assert server._index == index
        with pytest.raises(RuntimeError, match="enrolled"):
            server(b"I" + rpc.bundle((b"x",)))
        ticket, answer, _ = masked.prepare(s, groups, epoch, bytes(16), b"r" * 32, capture)
        body = b"A" + bytes(16) + rpc.bundle(capture.take())
        assert server(body) == b"\x01"
        with pytest.raises(RuntimeError, match="consumed"):
            server(body)
        request = ticket.consume(tuple(i % pk.t for i in range(s.dimension)), epoch)
        assert rpc.parse_request(request.token_id + request.body(), s, epoch) == request
        output = server(b"Q" + request.token_id + request.body())
        expected = masked.evaluate(index, answer, request, pk)
        assert rpc.owner_bounds(request, pk) == tuple(c.phase_bound for c in expected)
        assert output == codec.pack(tuple(x for c in expected for p in c.components for x in p), int(pk.q))
        with pytest.raises(RuntimeError, match="consumed"):
            server(b"Q" + request.token_id + request.body())


@pytest.mark.parametrize("malformed", [False, True])
def test_rejected_body_consumes_lifetime_before_any_private_decryption(monkeypatch, malformed):
    s, groups, pk, sk = fixture()
    epoch = b"e" * 32
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, epoch, client)
        ticket, answer, _ = masked.prepare(s, groups, epoch, bytes(16), b"r" * 32, client)
        request = ticket.consume((1,) * s.dimension, epoch)
        checker = checks.NativeVectorCheck(index, pk, rounds=4, budget=2)
        budget = lifetime.AttemptBudget(2)
        gate = budget.bind(checker)
        gate.prepare_answer(answer)
        valid = masked.evaluate(index, answer, request, pk)
        first = valid[0]
        changed = replace(first, components=(((first.components[0][0] + 1) % pk.q, *first.components[0][1:]),
                                             first.components[1]))
        bad = codec.pack(tuple(x for c in (changed, *valid[1:]) for p in c.components for x in p), int(pk.q))
        if malformed:
            bad = bad[:-1]

        def forbidden(*_args):
            pytest.fail("Rejected body reached secret decryption")

        monkeypatch.setattr(bgv, "decrypt", forbidden)
        with pytest.raises(ValueError):
            open_response(bad, request, pk, sk, gate)
        assert budget.used == 1
        with pytest.raises(RuntimeError):
            open_response(bad, request, pk, sk, gate)
        assert budget.used == 2


def test_noncanonical_delta_and_unenrolled_command_rejected():
    s, _groups, pk, _sk = fixture()
    epoch = b"e" * 32
    with pytest.raises(ValueError, match="shape"):
        rpc.parse_request(bytes(16), s, epoch)
    with pytest.raises(ValueError, match="Noncanonical"):
        rpc.parse_request(bytes(16) + b"\xff\xff" * s.dimension, s, epoch)
    with pytest.raises(RuntimeError, match="not enrolled"):
        rpc.LinearServer(s, pk, epoch)(b"Q" + bytes(16))


def test_actual_tcp_callback_uses_received_requests_and_stored_upload():
    server = rpc.CacheServer()
    stored = bytes(range(256)) * 4096
    with exchange.Exchange(server) as peer:
        ack, upload = peer.call(b"I" + stored)
        actual, download = peer.call(b"Q")
        assert ack == b"\x01" and actual == stored
        assert upload["application_bytes"] == 16 + 1 + len(stored) + 1
        assert download["application_bytes"] == 16 + 1 + len(stored)
    assert not peer.errors


def test_dynamic_tcp_response_and_packet_limit():
    seen = []

    def handler(body):
        seen.append(body)
        return body[::-1]

    with exchange.Exchange(handler) as peer:
        for body in (b"one", b"another"):
            received, _ = peer.call(body)
            assert received == body[::-1]
        with pytest.raises(ValueError):
            peer.call(b"")
    assert seen == [b"one", b"another"]
