"""Bounded request/response framing for an untrusted TCP/vsock transport.

This module supplies no trust: the SDK verifies attestation and receipts. Frame
lengths and operation kinds are checked before buffering, with a deadline for
the entire read. Each RPC uses a new connection; no custom secure channel or
key-exchange scheme is introduced.
"""

from __future__ import annotations

import socket
import struct
import time

from experiments.bfv_search_lab.security_bgv import BGVExecutionPolicy, BGVProtocolError, exact_bytes
from experiments.bfv_search_lab.attested_bgv import HELLO_BYTES, QUERY_OVERHEAD, RECEIPT_BYTES, REGISTRATION_OVERHEAD
from cuhepy.hamming.bfv_nitro import MAX_NITRO_DOCUMENT_BYTES
# Reuse the existing bounded tuple codec and deadline-aware byte reader only.
from cuhepy.hamming.bfv_security import _record, _unpack
from experiments.bfv_nitro.transport import receive_exact


REGISTER, ATTEST, SEARCH, ERROR = 1, 2, 3, 0
_HEADER = struct.Struct("!4sBI")
_MAGIC = b"XGN1"


def receive_header(stream: socket.socket, deadline: float) -> tuple[int, int]:
    """Parse the fixed header without allocating space for its claimed body."""
    magic, kind, length = _HEADER.unpack(receive_exact(stream, _HEADER.size, deadline))
    if magic != _MAGIC or kind not in (REGISTER, ATTEST, SEARCH, ERROR):
        raise BGVProtocolError("Invalid Nitro frame header")
    return kind, length


def send_frame(stream: socket.socket, kind: int, payload: bytes, limit: int) -> None:
    """Send a bounded frame; the caller configures the socket write timeout."""
    if type(payload) is not bytes or len(payload) > limit or len(payload) >= 1 << 32:
        raise BGVProtocolError("Nitro frame exceeds its size limit")
    stream.sendall(_HEADER.pack(_MAGIC, kind, len(payload)))
    stream.sendall(payload)


class NitroRemote:
    """Owner-side RPC helper for a relay, with no decryption or acceptance feedback.

    Connect through an authenticated tunnel/TLS deployment for transport privacy
    and access control. The Nitro-required client independently authenticates
    evidence and responses even if the relay is malicious.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9000,
        *,
        policy: BGVExecutionPolicy | None = None,
        timeout: float = 60.0,
    ) -> None:
        if not 0 < timeout <= 300:
            raise ValueError("Use a transport timeout in (0, 300] seconds")
        self.host, self.port, self.timeout = host, port, timeout
        self.policy = policy or BGVExecutionPolicy()

    def _call(self, kind: int, payload: bytes, request_limit: int, response_limit: int) -> bytes:
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as stream:
            send_frame(stream, kind, payload, request_limit)
            deadline = time.monotonic() + self.timeout
            returned, length = receive_header(stream, deadline)
            if returned not in (kind, ERROR) or length > (
                64 if returned == ERROR else response_limit
            ):
                raise BGVProtocolError("Unexpected Nitro response frame")
            result = receive_exact(stream, length, deadline)
            if returned == ERROR:
                raise BGVProtocolError("Nitro service rejected the request")
            return result

    def register(self, packet: bytes) -> None:
        """Upload a signed public setup; acknowledgement does not establish trust."""
        if self._call(REGISTER, packet, self.policy.max_setup_bytes + REGISTRATION_OVERHEAD, 32) != b"registered":
            raise BGVProtocolError("Invalid Nitro registration acknowledgement")

    def attest(self, hello: bytes) -> tuple[bytes, bytes]:
        """Return bounded evidence and possession proof for the SDK to validate."""
        result = self._call(ATTEST, hello, HELLO_BYTES, MAX_NITRO_DOCUMENT_BYTES + 128)
        document, proof = _record(_unpack(result, limit=MAX_NITRO_DOCUMENT_BYTES + 128), 2)
        if type(document) is not bytes or len(document) > MAX_NITRO_DOCUMENT_BYTES:
            raise BGVProtocolError("Invalid Nitro evidence")
        return document, exact_bytes(proof, 64)

    def search(self, query: bytes) -> tuple[bytes, bytes]:
        """Return encrypted bytes and receipt; never perform private work here."""
        result = self._call(
            SEARCH,
            query,
            self.policy.max_query_bytes + QUERY_OVERHEAD,
            self.policy.max_response_bytes + 256,
        )
        response, receipt = _record(_unpack(result, limit=self.policy.max_response_bytes + 256), 2)
        if type(response) is not bytes or len(response) > self.policy.max_response_bytes:
            raise BGVProtocolError("Invalid Nitro response")
        return response, exact_bytes(receipt, RECEIPT_BYTES)
