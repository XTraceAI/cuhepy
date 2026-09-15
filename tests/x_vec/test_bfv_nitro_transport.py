"""Exercise the actual framed service with hostile headers and an untrusted relay.

Local socket pairs substitute only for networking/hardware, while owner/receipt
signatures and certificate validation execute normally against a test-only CA.
"""

import json
import socket
import threading
import time

import pytest

pytest.importorskip("cbor2")
pytest.importorskip("OpenSSL")

from experiments.bfv_nitro.service import EnclaveApplication
from experiments.bfv_nitro import transport as wire
from tests.x_vec.test_bfv_attested_client import make_session, private, issuer, trusted
from xtrace_sdk.x_vec.crypto.bfv_security import BFVProtocolError, _unpack


def call(app, kind, payload=b"", header=None):
    """Exchange a single frame with the measured service's real handler."""
    client, server = socket.socketpair()

    def serve():
        with server:
            app.handle(server, timeout=1.0)

    thread = threading.Thread(target=serve)
    thread.start()
    with client:
        client.settimeout(2)
        if header is not None:
            client.sendall(header)
        else:
            wire.send_frame(client, kind, payload, app.policy.max_setup_bytes + 1024)
        deadline = time.monotonic() + 2
        returned, length = wire.receive_header(client, deadline)
        assert length <= app.policy.max_response_bytes + 256
        body = wire.receive_exact(client, length, deadline)
    thread.join(2)
    assert not thread.is_alive()
    return returned, body


def test_complete_framed_roundtrip(private, trusted):
    client, _, setup, *_ = make_session(private, trusted, enroll=False)
    app = EnclaveApplication(trusted, policy=client.policy, backend="optimized")
    assert call(app, wire.REGISTER, client.registration_packet(setup)) == (
        wire.REGISTER,
        b"registered",
    )
    kind, body = call(app, wire.ATTEST, client.begin_attestation())
    assert kind == wire.ATTEST
    client.accept_attestation(*_unpack(body, limit=32768))
    kind, body = call(app, wire.SEARCH, client.begin_query([0, 1, 0]))
    assert kind == wire.SEARCH
    assert client.finish_query(*_unpack(body, limit=client.policy.max_response_bytes + 256)) == [
        0,
        3,
        1,
    ]
    # Reject replacement before reading the declared (large) setup body.
    header = wire._HEADER.pack(wire._MAGIC, wire.REGISTER, app.policy.max_setup_bytes)
    assert call(app, wire.REGISTER, header=header)[0] == wire.ERROR


@pytest.mark.parametrize(
    "magic,kind,length",
    [(b"BAD!", 1, 0), (b"XBN1", 99, 0), (b"XBN1", 1, 2**32 - 1), (b"XBN1", 3, 1_000_000)],
)
def test_invalid_headers_fail_before_body_allocation(private, trusted, magic, kind, length):
    client, *_ = make_session(private, trusted, enroll=False)
    app = EnclaveApplication(trusted, policy=client.policy)
    assert call(app, kind, header=wire._HEADER.pack(magic, kind, length))[0] == wire.ERROR
    assert app.server is None


def test_truncation_and_absolute_deadline():
    left, right = socket.socketpair()
    with left, right:
        right.sendall(b"x")
        right.shutdown(socket.SHUT_WR)
        with pytest.raises(BFVProtocolError):
            wire.receive_exact(left, 2, time.monotonic() + 1)
        with pytest.raises(TimeoutError):
            wire.receive_exact(left, 1, time.monotonic() - 1)


def test_remote_rejects_wrong_kind_or_oversize_response_before_reading():
    """An attacker cannot make a small RPC buffer a setup-sized response."""
    for kind, length in ((wire.REGISTER, 1), (wire.ATTEST, 2**32 - 1), (wire.ERROR, 65)):
        with socket.create_server(("127.0.0.1", 0)) as listener:

            def malicious(kind=kind, length=length):
                stream, _ = listener.accept()
                with stream:
                    deadline = time.monotonic() + 2
                    _, size = wire.receive_header(stream, deadline)
                    wire.receive_exact(stream, size, deadline)
                    stream.sendall(wire._HEADER.pack(wire._MAGIC, kind, length))

            worker = threading.Thread(target=malicious)
            worker.start()
            remote = wire.NitroRemote(port=listener.getsockname()[1], timeout=2)
            with pytest.raises(BFVProtocolError):
                remote.attest(bytes(134))
            worker.join(2)
            assert not worker.is_alive()


@pytest.mark.parametrize("algorithm", ["Sha384 { ... }", "Sha384"])
def test_owner_loads_official_cli_measurement_format(tmp_path, algorithm):
    """Accept the literal HashAlgorithm emitted by the locally built Nitro CLI."""
    from experiments.bfv_nitro.client import load_measurements
    from tests.x_vec.nitro_fixtures import PCRS

    path = tmp_path / "measurements.json"
    measurements = {
        "HashAlgorithm": algorithm,
        **{f"PCR{i}": digest.hex() for i, digest in PCRS.items()},
    }
    path.write_text(json.dumps({"Measurements": measurements}))
    assert load_measurements(path).pcrs == PCRS
    measurements["HashAlgorithm"] = "Sha384-unrecognized"
    path.write_text(json.dumps({"Measurements": measurements}))
    with pytest.raises(ValueError, match="SHA-384"):
        load_measurements(path)
