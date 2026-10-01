"""E67 TCP measurement harness, explicitly not a deployed protocol/channel.

One loopback peer receives bounded catalog packets. Client requests cost eight
application bytes; replies cost an eight-byte frame plus the actual payload.
IP/TCP headers, retransmission, WAN/TLS and application security are not modeled.
"""

from __future__ import annotations

import socket
import struct
import threading
import time

MAX_PACKET = 64 << 20


def receive_exact(sock, count):
    if type(count) is not int or not 0 <= count <= MAX_PACKET:
        raise ValueError("Transfer exceeds measurement bound")
    chunks, remaining = [], count
    while remaining:
        chunk = sock.recv(min(remaining, 65536))
        if not chunk:
            raise ValueError("Truncated measurement frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class Probe:
    def __init__(self, packets):
        if type(packets) is not tuple or not packets or any(type(p) is not bytes or not 1 <= len(p) <= MAX_PACKET for p in packets):
            raise ValueError("Bounded measurement packet catalog required")
        self.packets, self.errors, self.uploaded = packets, [], {}
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.settimeout(5)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._client = None
        self._peer = None

    def _serve(self):
        try:
            self._peer, _ = self._listener.accept()
            self._peer.settimeout(5)
            self._peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            while True:
                first = self._peer.recv(8)
                if not first:
                    break
                frame = first + receive_exact(self._peer, 8-len(first))
                ordinal, = struct.unpack("<Q", frame)
                uploading = bool(ordinal >> 63)
                ordinal &= (1 << 63) - 1
                if ordinal >= len(self.packets):
                    raise ValueError("Unknown measurement packet")
                packet = self.packets[ordinal]
                if uploading:
                    length, = struct.unpack("<Q", receive_exact(self._peer, 8))
                    if length != len(packet):
                        raise ValueError("Upload differs from pinned length")
                    uploaded = receive_exact(self._peer, length)
                    if uploaded != packet:
                        raise ValueError("Upload payload mismatch")
                    self.uploaded[ordinal] = uploaded
                    self._peer.sendall(struct.pack("<Q", length))
                else:
                    self._peer.sendall(struct.pack("<Q", len(packet)) + packet)
        except (OSError, ValueError) as error:
            self.errors.append(type(error).__name__)
        finally:
            if self._peer is not None:
                self._peer.close()

    def __enter__(self):
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        start = time.perf_counter()
        self._client = socket.create_connection(self._listener.getsockname(), timeout=5)
        self._client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.connection_establish_s = time.perf_counter() - start
        return self

    def transfer(self, ordinal):
        if type(ordinal) is not int or not 0 <= ordinal < len(self.packets):
            raise ValueError("Unknown pinned measurement packet")
        start = time.perf_counter()
        self._client.sendall(struct.pack("<Q", ordinal))
        length, = struct.unpack("<Q", receive_exact(self._client, 8))
        if length != len(self.packets[ordinal]):
            raise ValueError("Measurement length differs from pinned packet")
        received = receive_exact(self._client, length)
        seconds = time.perf_counter() - start
        if received != self.packets[ordinal]:
            raise ValueError("Measurement payload mismatch")
        return received, {"transfer_wall_s": seconds, "client_request_frame_bytes": 8,
                          "server_reply_frame_bytes": 8, "payload_bytes": length}

    def upload(self, ordinal):
        if type(ordinal) is not int or not 0 <= ordinal < len(self.packets):
            raise ValueError("Unknown pinned measurement packet")
        packet = self.packets[ordinal]
        start = time.perf_counter()
        self._client.sendall(struct.pack("<QQ", ordinal | (1 << 63), len(packet)) + packet)
        length, = struct.unpack("<Q", receive_exact(self._client, 8))
        if length != len(packet):
            raise ValueError("Upload acknowledgement mismatch")
        return {"transfer_wall_s": time.perf_counter()-start, "client_request_frame_bytes": 16,
                "server_reply_frame_bytes": 8, "payload_bytes": len(packet)}

    def __exit__(self, *args):
        self._client.close()
        self._thread.join(timeout=6)
        self._listener.close()
        if self._thread.is_alive() or self.errors:
            raise RuntimeError("Loopback measurement did not finish cleanly")
