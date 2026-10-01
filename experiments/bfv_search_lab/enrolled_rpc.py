"""E75 public-only callback for enrolled masked BGV TCP controls.

The context is already pinned. Actual seeded index/answer packets and deltas
are parsed from the received body, not fetched from an owner's Python object.
No secret key, private maps, mask seeds or checking fingerprints enter this
callback. Context bootstrap, channel security and durability are out of scope.
"""

from __future__ import annotations

import struct
import time

from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab.loopback_transfer import MAX_PACKET

MAX_COUNT = 8192


def bundle(packets):
    if (type(packets) is not tuple or not 1 <= len(packets) <= MAX_COUNT
            or any(type(p) is not bytes or not 1 <= len(p) <= MAX_PACKET for p in packets)
            or 8 + sum(8 + len(p) for p in packets) > MAX_PACKET - 17):
        raise ValueError("Bounded canonical packet bundle required")
    return struct.pack("<Q", len(packets)) + b"".join(struct.pack("<Q", len(p)) + p for p in packets)


def unbundle(body, expected):
    if (type(body) is not bytes or not 8 <= len(body) <= MAX_PACKET - 17
            or type(expected) is not int or not 1 <= expected <= MAX_COUNT):
        raise ValueError("Invalid bounded packet bundle")
    count, = struct.unpack("<Q", body[:8])
    if count != expected:
        raise ValueError("Packet count differs from pinned geometry")
    packets, at = [], 8
    for _ in range(count):
        if at + 8 > len(body):
            raise ValueError("Truncated packet length")
        length, = struct.unpack("<Q", body[at:at + 8])
        at += 8
        if not 1 <= length <= len(body) - at:
            raise ValueError("Truncated or empty bundled packet")
        packets.append(body[at:at + length])
        at += length
    if at != len(body):
        raise ValueError("Trailing bundled bytes")
    return tuple(packets)


class CaptureClient:
    """Owner-local packet recorder; never passed to the callback."""

    def __init__(self, client):
        self.client, self.pk, self.packets = client, client.pk, []

    def encrypt(self, plaintext):
        result = self.client.encrypt(plaintext)
        self.packets.append(result)
        return result

    def take(self):
        result = tuple(self.packets)
        self.packets.clear()
        return result


def parse_request(body, s, epoch):
    width = (s.layout.context.prime.bit_length() + 7) // 8
    if type(body) is not bytes or len(body) != 16 + width * s.dimension:
        raise ValueError("Masked request differs from pinned shape")
    request = masked.Request(s, epoch, body[:16], tuple(int.from_bytes(body[i:i + width], "little")
                                                     for i in range(16, len(body), width)))
    masked.validate_request(request)
    return request


def owner_bounds(request, pk):
    """Bound only from trusted fresh index/answer law and the pinned request."""
    masked.validate_request(request)
    masked._context(request.space, pk)
    norm = sum(sum(map(abs, row)) for row in space.corrections(request.space, request.delta))
    limit = (pk.t // 2 + pk.t * pk.eta) * (1 + norm)
    if 2 * limit >= pk.q:
        raise ValueError("Trusted full response bound exceeds Q")
    return (limit,) * request.space.layout.cost.response_ciphertexts


class LinearServer:
    def __init__(self, s, pk, epoch, *, budget=1024):
        masked._context(s, pk)
        masked.binding(epoch, bytes(16))
        if type(budget) is not int or not 1 <= budget <= 65536:
            raise ValueError("Bounded enrolled request budget required")
        self.space, self.pk, self.epoch, self.budget = s, pk, epoch, budget
        self._index, self._native = None, None
        self._answers, self._issued = {}, set()
        self.enrollment, self.last = {}, {}

    def __call__(self, body):
        if type(body) is not bytes or not body:
            raise ValueError("Empty enrolled command")
        command, data = body[:1], body[1:]
        pk, s = self.pk, self.space
        replies = s.layout.cost.response_ciphertexts
        start = time.perf_counter()
        if command == b"I":
            if self._native is not None:
                raise RuntimeError("Already enrolled")
            packets = unbundle(data, s.columns * replies)
            ciphers = tuple(owner.expand(p, pk) for p in packets)
            self._index = masked.Index(s, self.epoch, tuple(ciphers[i:i + replies]
                                                          for i in range(0, len(ciphers), replies)))
            expanded = time.perf_counter()
            self._native = native.NativeIndex(self._index, pk)
            self.enrollment = {"server_packet_parse_expand_s": expanded - start,
                               "server_native_prepare_s": time.perf_counter() - expanded}
            return b"\x01"
        if self._native is None:
            raise RuntimeError("Index not enrolled")
        if command == b"A":
            if len(data) < 16:
                raise ValueError("Truncated answer identifier")
            token_id = data[:16]
            masked.binding(self.epoch, token_id)
            if token_id in self._issued or len(self._issued) >= self.budget:
                raise RuntimeError("Answer identifier/budget consumed")
            packets = unbundle(data[16:], replies)
            answer = masked.Answer(s, self.epoch, token_id, tuple(owner.expand(p, pk) for p in packets))
            self._issued.add(token_id)
            self._answers[token_id] = answer
            self.last = {"server_answer_parse_expand_s": time.perf_counter() - start}
            return b"\x01"
        if command == b"Q":
            request = parse_request(data, s, self.epoch)
            answer = self._answers.pop(request.token_id, None)
            if answer is None:
                raise RuntimeError("Missing or consumed enrolled answer")
            parsed = time.perf_counter()
            output = self._native.evaluate(answer, request)
            evaluated = time.perf_counter()
            reply = codec.pack(tuple(x for c in output for p in c.components for x in p), int(pk.q))
            self.last = {"server_request_parse_s": parsed - start,
                         "server_native_evaluate_s": evaluated - parsed,
                         "server_response_pack_s": time.perf_counter() - evaluated}
            return reply
        raise ValueError("Unknown enrolled command")


class CacheServer:
    def __init__(self):
        self._packet = None

    def __call__(self, body):
        if type(body) is not bytes or not body:
            raise ValueError("Empty cache command")
        if body[:1] == b"I" and len(body) > 1 and self._packet is None:
            self._packet = body[1:]
            return b"\x01"
        if body == b"Q" and self._packet is not None:
            return self._packet
        raise ValueError("Unknown or duplicate cache command")
