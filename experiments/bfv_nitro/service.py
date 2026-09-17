"""Measured, single-owner Nitro evaluator; run INSIDE the enclave image.

The entrypoint fixes the review BFV policy and residue backend. Parent messages
cannot select code, libraries, parameters, execution backends or output hashes.
There is no debug/mock-attestation mode, secret import, shell or signing endpoint.
Only one request is serviced at a time, bounding memory and concurrent parsing.
"""

from __future__ import annotations

import resource
import socket
import time

from cuhepy.bfv.assurance import bfv_review_policy
from cuhepy.bfv.attested_client import (
    BFVAttestedServer,
    NITRO_HELLO_BYTES,
    NITRO_QUERY_OVERHEAD,
)
from cuhepy.bfv.nitro import NitroNSM
from cuhepy.bfv.security import BFVProtocolError, _pack

from .transport import REGISTER, ATTEST, SEARCH, ERROR, receive_header, receive_exact, send_frame


class EnclaveApplication:
    """One immutable server, initialized once through its signed registration.

    Constructor arguments are trusted local code configuration for tests/builds.
    The deployed main function supplies only the real NSM and fixed defaults.
    """

    def __init__(self, nsm, *, policy=None, backend="residue"):
        self.nsm = nsm
        self.policy = policy or bfv_review_policy()
        self.backend = backend
        self.server = None

    def handle(self, stream: socket.socket, *, timeout=60.0):
        """Handle one bounded RPC, checking operation state before reading its body."""
        deadline = time.monotonic() + timeout
        try:
            kind, length = receive_header(stream, deadline)
            limits = {
                REGISTER: self.policy.max_setup_bytes + 1024,
                ATTEST: NITRO_HELLO_BYTES,
                SEARCH: self.policy.max_query_bytes + NITRO_QUERY_OVERHEAD,
            }
            if kind not in limits or length > limits[kind]:
                raise BFVProtocolError("Invalid Nitro request length")
            if (kind == REGISTER) != (self.server is None):
                raise BFVProtocolError("Invalid Nitro service state")
            payload = receive_exact(stream, length, deadline)
            if kind == REGISTER:
                self.server = BFVAttestedServer.from_registration(
                    payload, self.nsm, policy=self.policy, backend=self.backend
                )
                result = b"registered"
            elif kind == ATTEST:
                result = _pack(self.server.attest(payload))
            else:
                result = _pack(self.server.search(payload))
            stream.settimeout(timeout)
            send_frame(stream, kind, result, self.policy.max_response_bytes + 256)
        except (ValueError, TypeError, OverflowError, OSError):
            # No decryption occurs here. Do not reflect exception strings,
            # payloads, keys or arbitrary host-controlled content into logs.
            try:
                stream.settimeout(1.0)
                send_frame(stream, ERROR, b"request rejected", 64)
            except OSError:
                pass


def main():
    """Start the fixed vsock service with real NSM; fail if hardware is absent."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    nsm = NitroNSM()
    try:
        app = EnclaveApplication(nsm)
        with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as listener:
            listener.bind((socket.VMADDR_CID_ANY, 5000))
            listener.listen(4)
            while True:
                stream, _ = listener.accept()
                with stream:
                    app.handle(stream)
    finally:
        nsm.close()


if __name__ == "__main__":
    main()
