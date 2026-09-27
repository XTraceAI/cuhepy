"""Bounded framing and parsing for a trusted LOOPBACK benchmark fixture only.

No authentication protocol is implemented here. A benchmark must compare the
received response to its locally known expected ciphertext before decryption.
No decryption-dependent acknowledgement is sent. Do not expose this as an API.
"""

from __future__ import annotations

import math
import hmac
import socket
import struct
import time

import gmpy2
from gmpy2 import mpz
import msgpack

from experiments.bfv_search_lab import compact_bgv as compact, shallow_bgv as bgv

MAX_FRAME = 16 << 20


def require_expected_fixture(packet: bytes, expected: bytes) -> None:
    """An unconditional local test gate, including under Python -O; not a proof."""
    if type(packet) is not bytes or type(expected) is not bytes or not hmac.compare_digest(packet, expected):
        raise ValueError("Response differs from the locally pinned fixture")


def read_exact(connection: socket.socket, length: int) -> bytes:
    if type(length) is not int or not 0 <= length <= MAX_FRAME:
        raise ValueError("Invalid fixture read length")
    result = bytearray()
    while len(result) < length:
        part = connection.recv(length - len(result))
        if not part:
            raise EOFError("Truncated fixture frame")
        result.extend(part)
    return bytes(result)


def receive(connection: socket.socket) -> bytes:
    length = struct.unpack("!I", read_exact(connection, 4))[0]
    if not 1 <= length <= MAX_FRAME:
        raise ValueError("Oversized or empty fixture frame")
    return read_exact(connection, length)


def send(connection: socket.socket, packet: bytes, *, mbps: float = 0, delay_ms: float = 0) -> None:
    """Application pacing, not a simulation of TCP congestion/loss or a WAN."""
    if (type(packet) is not bytes or not 1 <= len(packet) <= MAX_FRAME
        or not math.isfinite(mbps) or not math.isfinite(delay_ms) or mbps < 0 or delay_ms < 0):
        raise ValueError("Invalid fixture frame or link settings")
    framed = struct.pack("!I", len(packet)) + packet
    start = time.perf_counter()
    for end in range(0, len(framed), 16 << 10):
        part = framed[end:end + (16 << 10)]
        deadline = start + delay_ms / 1000 + (8 * (end + len(part)) / (mbps * 1e6) if mbps else 0)
        wait = deadline - time.perf_counter()
        if wait > 0:
            time.sleep(wait)
        connection.sendall(part)


def _context(pk: bgv.PublicKey, count: int, dimension: int, modulus: mpz) -> tuple[int, int, list]:
    if (type(count) is not int or not 1 <= count <= 64 * pk.n
        or type(dimension) is not int or not 1 <= dimension <= pk.n // 2 or pk.t <= 2 * dimension
        or not pk.t < modulus < pk.q or (modulus - pk.q) % pk.t):
        raise ValueError("Invalid fixture response context")
    groups, bits = (count + pk.n - 1) // pk.n, modulus.bit_length()
    width = (pk.n * bits + 7) // 8
    header = ["cuhepy-lab-bgv-compact-v1", pk.n, pk.t, modulus.to_bytes((bits + 7) // 8, "little"),
              bytes.fromhex(pk.key_id), count, dimension]
    return groups, width, header


def pack_native_fixture(pairs: tuple[tuple[bytes, bytes], ...], pk: bgv.PublicKey,
                        *, count: int, dimension: int, modulus: mpz) -> bytes:
    """Frame canonical coefficients already validated/packed by the native server."""
    groups, width, header = _context(pk, count, dimension, modulus)
    if (len(pairs) != groups or any(len(pair) != 2 or any(type(c) is not bytes or len(c) != width
                                                       for c in pair) for pair in pairs)):
        raise ValueError("Invalid native fixture component lengths")
    return msgpack.packb([header, pairs], use_bin_type=True)


def _unpack_fields(packet: bytes, pk: bgv.PublicKey, *, count: int, dimension: int,
                   modulus: mpz, bounds: list[int]) -> tuple[tuple[bytes, bytes], ...]:
    """Bound the envelope; the consumer MUST validate all coefficients before private work."""
    groups, width, expected = _context(pk, count, dimension, modulus)
    if (len(bounds) != groups or any(type(b) is not int or not 0 <= 2 * b < modulus for b in bounds)
        or type(packet) is not bytes or len(packet) > min(MAX_FRAME, 2 * groups * width + 4096)):
        raise ValueError("Invalid fixture response bounds/length")
    try:
        value = msgpack.unpackb(packet, raw=False, max_array_len=64, max_map_len=0,
                                max_bin_len=max(width, 32), max_str_len=64, max_ext_len=0)
        if type(value) is not list or len(value) != 2:
            raise ValueError("Invalid fixture envelope")
        header, body = value
        if (header != expected or type(header) is not list
            or any(type(a) is not type(b) for a, b in zip(header, expected, strict=True))
            or type(body) is not list or len(body) != groups):
            raise ValueError("Incorrect fixture response context/shape")
        output = []
        for pair in body:
            if type(pair) is not list or len(pair) != 2:
                raise ValueError("Invalid fixture component pair")
            for data in pair:
                if type(data) is not bytes or len(data) != width:
                    raise ValueError("Invalid fixture polynomial size")
            output.append((pair[0], pair[1]))
        return tuple(output)
    except (TypeError, OverflowError, msgpack.UnpackException) as error:
        raise ValueError("Invalid fixture response encoding") from error


def unpack_fixture(packet: bytes, pk: bgv.PublicKey, *, count: int, dimension: int,
                   modulus: mpz, bounds: list[int]) -> list[compact.CompactCiphertext]:
    """Parse against caller-pinned context and local bounds; never trust wire bounds."""
    pairs = _unpack_fields(packet, pk, count=count, dimension=dimension, modulus=modulus, bounds=bounds)
    output = []
    for pair, bound in zip(pairs, bounds, strict=True):
        components = []
        for data in pair:
            coefficients = gmpy2.unpack(mpz.from_bytes(data, "little"), modulus.bit_length())
            if len(coefficients) > pk.n or any(c >= modulus for c in coefficients):
                raise ValueError("Noncanonical fixture coefficient")
            coefficients.extend([mpz(0)] * (pk.n - len(coefficients)))
            components.append(tuple(coefficients))
        output.append(compact.CompactCiphertext((components[0], components[1]), pk.key_id, modulus, bound))
    return output
