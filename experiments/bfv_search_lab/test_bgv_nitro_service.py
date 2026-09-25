"""Admission and untrusted stream tests for the separate BGV measured service."""

import socket
import threading
import time

import gmpy2
import msgpack
import pytest

pytest.importorskip("cbor2")
pytest.importorskip("OpenSSL")

from cuhepy.hamming.bfv_security import _unpack
from experiments.bgv_nitro.service import EnclaveApplication
from experiments.bgv_nitro import transport as wire
from experiments.bfv_search_lab import security_bgv as security
from experiments.bfv_search_lab.test_attested_bgv import material, issuer, trusted, make_session


def call(app, kind, payload=b"", header=None):
    left, right = socket.socketpair()
    def serve():
        with right:
            app.handle(right, timeout=1)
    worker = threading.Thread(target=serve)
    worker.start()
    with left:
        left.settimeout(2)
        if header is None:
            wire.send_frame(left, kind, payload, app.policy.max_setup_bytes + 110)
        else:
            left.sendall(header)
        deadline = time.monotonic() + 2
        returned, length = wire.receive_header(left, deadline)
        assert length <= app.policy.max_response_bytes + 256
        result = wire.receive_exact(left, length, deadline)
    worker.join(2)
    assert not worker.is_alive()
    return returned, result


def test_framed_registration_attestation_and_query(material, trusted):
    client, _, _ = make_session(material, trusted, enrolled=False)
    app = EnclaveApplication(trusted, policy=client.policy)
    assert call(app, wire.REGISTER, client.registration_packet()) == (wire.REGISTER, b"registered")
    kind, evidence = call(app, wire.ATTEST, client.begin_attestation())
    assert kind == wire.ATTEST
    client.accept_attestation(*_unpack(evidence, limit=32768))
    kind, response = call(app, wire.SEARCH, client.begin_query([0, 1, 0]))
    assert kind == wire.SEARCH
    assert client.finish_query(*_unpack(response, limit=1 << 20)).distances == (0, 3, 1)
    # Replacement must be rejected without waiting for its advertised body.
    header = wire._HEADER.pack(wire._MAGIC, wire.REGISTER, app.policy.max_setup_bytes)
    assert call(app, wire.REGISTER, header=header)[0] == wire.ERROR
    client.close()


@pytest.mark.parametrize("magic,kind,length", [
    (b"BAD!", 1, 0), (b"XBN1", 1, 0), (b"XGN1", 99, 0),
    (b"XGN1", 1, 2**32 - 1), (b"XGN1", 3, 5000),
])
def test_headers_rejected_before_body(material, trusted, magic, kind, length):
    client, _, _ = make_session(material, trusted, enrolled=False)
    app = EnclaveApplication(trusted, policy=client.policy)
    assert call(app, kind, header=wire._HEADER.pack(magic, kind, length))[0] == wire.ERROR
    assert app.server is None
    client.close()


@pytest.mark.parametrize("change", ["tag", "fingerprint", "a", "count_bool", "count_limit",
                                   "key_shape", "coefficient", "index_shape", "trailing", "map"])
def test_setup_canonical_validation(material, trusted, change):
    client, _, _ = make_session(material, trusted)
    packet, policy = client._setup, client.policy
    value = msgpack.unpackb(packet)
    if change == "tag":
        value[0] = b"BFV"
    elif change == "fingerprint":
        value[1] = bytes(32)
    elif change == "a":
        value[2] = b""
    elif change == "count_bool":
        value[4] = True
    elif change == "count_limit":
        value[4] = policy.max_vectors + 1
    elif change == "key_shape":
        value[5][0].pop()
    elif change == "coefficient":
        value[6][0][0] = gmpy2.pack([policy.q] * policy.n, 120).to_bytes(15 * policy.n, "little")
    elif change == "index_shape":
        value[6].pop()
    elif change == "map":
        value = {}
    bad = msgpack.packb(value, use_bin_type=True) + (b"x" if change == "trailing" else b"")
    with pytest.raises(ValueError):
        security.unpack_setup(bad, policy)
    client.close()


@pytest.mark.parametrize("field,value", [
    ("n", True), ("n", 4), ("n", 65536), ("dimension", 0),
    ("terminal_bits", 61), ("query_drop_bits", 120), ("response_drop_bits", 25),
    ("max_pending", 0), ("max_queries", 65537), ("owner_index", 1),
    ("max_setup_bytes", 1 << 40), ("max_response_bytes", 1 << 40),
])
def test_policy_rejects_unbounded_or_ambiguous_values(field, value):
    with pytest.raises(ValueError):
        security.BGVExecutionPolicy(**{field: value})


def test_remote_rejects_declared_oversize_before_reading(monkeypatch):
    # Socket pairs exercise the actual remote API without opening a listener.
    left, right = socket.socketpair()
    def malicious():
        with right:
            deadline = time.monotonic() + 2
            _, size = wire.receive_header(right, deadline)
            wire.receive_exact(right, size, deadline)
            right.sendall(wire._HEADER.pack(wire._MAGIC, wire.ATTEST, 2**32 - 1))
    worker = threading.Thread(target=malicious)
    worker.start()
    monkeypatch.setattr(socket, "create_connection", lambda *a, **kw: left)
    with pytest.raises(security.BGVProtocolError):
        wire.NitroRemote(timeout=2).attest(bytes(134))
    worker.join(2)
    assert not worker.is_alive()
