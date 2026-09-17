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

from cuhepy.bfv.assurance import bfv_review_policy
from cuhepy.bfv.attested_client import (
    NITRO_HELLO_BYTES,
    NITRO_QUERY_OVERHEAD,
    NITRO_RECEIPT_BYTES,
)
from cuhepy.bfv.nitro import MAX_NITRO_DOCUMENT_BYTES
from cuhepy.bfv.security import (
    BFVExecutionPolicy,
    BFVProtocolError,
    _bytes,
    _pack,
    _record,
    _unpack,
)


REGISTER, ATTEST, SEARCH, ERROR = 1, 2, 3, 0
_HEADER = struct.Struct("!4sBI")
_MAGIC = b"XBN1"


def receive_exact(stream: socket.socket, length: int, deadline: float) -> bytes:
    """Read a caller-bounded length; a stalled peer cannot renew the deadline."""
    result = bytearray()
    while len(result) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Nitro frame deadline exceeded")
        stream.settimeout(remaining)
        chunk = stream.recv(min(65536, length - len(result)))
        if not chunk:
            raise BFVProtocolError("Truncated Nitro frame")
        result.extend(chunk)
    return bytes(result)


def receive_header(stream: socket.socket, deadline: float) -> tuple[int, int]:
    """Parse the fixed header without allocating space for its claimed body."""
    magic, kind, length = _HEADER.unpack(receive_exact(stream, _HEADER.size, deadline))
    if magic != _MAGIC or kind not in (REGISTER, ATTEST, SEARCH, ERROR):
        raise BFVProtocolError("Invalid Nitro frame header")
    return kind, length


def send_frame(stream: socket.socket, kind: int, payload: bytes, limit: int) -> None:
    """Send a bounded frame; the caller configures the socket write timeout."""
    if type(payload) is not bytes or len(payload) > limit or len(payload) >= 1 << 32:
        raise BFVProtocolError("Nitro frame exceeds its size limit")
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
        policy: BFVExecutionPolicy | None = None,
        timeout: float = 60.0,
    ) -> None:
        if not 0 < timeout <= 300:
            raise ValueError("Use a transport timeout in (0, 300] seconds")
        self.host, self.port, self.timeout = host, port, timeout
        self.policy = policy or bfv_review_policy()

    def _call(self, kind: int, payload: bytes, request_limit: int, response_limit: int) -> bytes:
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as stream:
            send_frame(stream, kind, payload, request_limit)
            deadline = time.monotonic() + self.timeout
            returned, length = receive_header(stream, deadline)
            if returned not in (kind, ERROR) or length > (
                64 if returned == ERROR else response_limit
            ):
                raise BFVProtocolError("Unexpected Nitro response frame")
            result = receive_exact(stream, length, deadline)
            if returned == ERROR:
                raise BFVProtocolError("Nitro service rejected the request")
            return result

    def register(self, packet: bytes) -> None:
        """Upload a signed public setup; acknowledgement does not establish trust."""
        if self._call(REGISTER, packet, self.policy.max_setup_bytes + 1024, 32) != b"registered":
            raise BFVProtocolError("Invalid Nitro registration acknowledgement")

    def attest(self, hello: bytes) -> tuple[bytes, bytes]:
        """Return bounded evidence and possession proof for the SDK to validate."""
        result = self._call(ATTEST, hello, NITRO_HELLO_BYTES, MAX_NITRO_DOCUMENT_BYTES + 128)
        document, proof = _record(_unpack(result, limit=MAX_NITRO_DOCUMENT_BYTES + 128), 2)
        if type(document) is not bytes or len(document) > MAX_NITRO_DOCUMENT_BYTES:
            raise BFVProtocolError("Invalid Nitro evidence")
        return document, _bytes(proof, 64)

    def search(self, query: bytes) -> tuple[bytes, bytes]:
        """Return encrypted bytes and receipt; never perform private work here."""
        result = self._call(
            SEARCH,
            query,
            self.policy.max_query_bytes + NITRO_QUERY_OVERHEAD,
            self.policy.max_response_bytes + 256,
        )
        response, receipt = _record(_unpack(result, limit=self.policy.max_response_bytes + 256), 2)
        if type(response) is not bytes or len(response) > self.policy.max_response_bytes:
            raise BFVProtocolError("Invalid Nitro response")
        return response, _bytes(receipt, NITRO_RECEIPT_BYTES)
