"""E75 actual request/response TCP harness, not an authenticated protocol.

Both directions have an eight-byte length followed by bounded actual bytes.
A callback processes only the received bytes. Same-process threads share the
CPU/GIL. Receipts exclude TCP/IP headers, retransmission, WAN and TLS. This
module handles no private provisioning, authorization or durable state.
"""

from __future__ import annotations

import socket
import struct
import threading
import time

from experiments.bfv_search_lab.loopback_transfer import MAX_PACKET, receive_exact


def packet(value):
    if type(value) is not bytes or not 1 <= len(value) <= MAX_PACKET:
        raise ValueError("Bounded nonempty measurement packet required")
    return struct.pack("<Q", len(value)) + value


class Exchange:
    def __init__(self, handler):
        if not callable(handler):
            raise ValueError("Measurement callback required")
        self.handler, self.errors = handler, []
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.settimeout(60)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._client, self._peer = None, None

    def _serve(self):
        try:
            self._peer, _ = self._listener.accept()
            self._peer.settimeout(60)
            self._peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            while True:
                first = self._peer.recv(8)
                if not first:
                    break
                length, = struct.unpack("<Q", first + receive_exact(self._peer, 8 - len(first)))
                request = receive_exact(self._peer, length)
                if not request:
                    raise ValueError("Empty measurement request")
                self._peer.sendall(packet(self.handler(request)))
        except Exception as error:  # Fail the run rather than return a success-looking body.
            self.errors.append(type(error).__name__)
        finally:
            if self._peer is not None:
                self._peer.close()

    def __enter__(self):
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        start = time.perf_counter()
        self._client = socket.create_connection(self._listener.getsockname(), timeout=60)
        self._client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.connection_establish_s = time.perf_counter() - start
        return self

    def call(self, body):
        framed = packet(body)
        start = time.perf_counter()
        self._client.sendall(framed)
        length, = struct.unpack("<Q", receive_exact(self._client, 8))
        received = receive_exact(self._client, length)
        if not received:
            raise ValueError("Empty measurement response")
        return received, {"rpc_wall_s": time.perf_counter() - start,
                          "request_body_bytes": len(body), "response_body_bytes": len(received),
                          "request_frame_bytes": 8, "response_frame_bytes": 8,
                          "application_bytes": 16 + len(body) + len(received)}

    def __exit__(self, exc_type, _exc, _traceback):
        if self._client is not None:
            self._client.close()
        self._listener.close()
        self._thread.join(timeout=5)
        if exc_type is None and (self._thread.is_alive() or self.errors):
            raise RuntimeError("Request measurement did not finish cleanly")
