"""Optional c0-only rounding of an already terminal-reduced BGV fixture response.

The same public congruent-coefficient map as the query codec adds a bounded
multiple of t to the phase. c1, N, P and the key stay fixed. This separate
envelope pins precision, context and layout; all bounds come from the caller.
It authenticates nothing. Received bytes must pass the existing fixture gate
BEFORE any private work, including after expansion to compact-v1 bytes.
"""

from __future__ import annotations

import gmpy2
from gmpy2 import mpz
import msgpack

from experiments.bfv_search_lab import compact_bgv as compact, shallow_bgv as bgv
from experiments.bfv_search_lab import compressed_query_bgv as query, transport_bgv as wire

_TAG = "cuhepy-lab-bgv-rounded-response-v1"


def _header(pk: bgv.PublicKey, count: int, dimension: int, p: mpz, drop: int) -> list:
    return [
        _TAG,
        pk.n,
        pk.t,
        p.to_bytes((p.bit_length() + 7) // 8, "little"),
        bytes.fromhex(pk.key_id),
        count,
        dimension,
        drop,
    ]


def _settings(
    pk: bgv.PublicKey, count: int, dimension: int, bits: int, bounds: list[int], drop: int
) -> tuple[mpz, query.CoefficientEncoding, list[int]]:
    if type(pk.n) is not int or not 8 <= pk.n <= 32768 or pk.n & (pk.n - 1):
        raise ValueError("Invalid rounded response degree")
    p = compact.terminal_modulus(pk.q, pk.t, bits)
    groups, _, _ = wire._context(pk, count, dimension, p)
    e = query.coefficient_encoding(p, pk.t, drop)
    if len(bounds) != groups or any(type(b) is not int or b < 0 for b in bounds):
        raise ValueError("Invalid rounded response bounds")
    adjusted = [b + e.added_bound for b in bounds]
    if any(2 * b >= p for b in adjusted):
        raise ValueError("Rounded response correctness bound exceeds P/2")
    return p, e, adjusted


def _canonical(data: bytes, n: int, p: mpz) -> list[mpz]:
    if type(data) is not bytes or len(data) != n * p.bit_length() // 8:
        raise ValueError("Invalid rounded response coefficient payload")
    coefficients = gmpy2.unpack(mpz.from_bytes(data, "little"), p.bit_length())
    if len(coefficients) > n or any(c >= p for c in coefficients):
        raise ValueError("Noncanonical rounded response coefficient")
    coefficients.extend([mpz(0)] * (n - len(coefficients)))
    return coefficients


def _binary_cost(length: int) -> int:
    return length + (2 if length < 256 else 3 if length < 65536 else 5)


def packet_size(
    pk: bgv.PublicKey, count: int, dimension: int, bits: int, dropped_bits: int | None
) -> int:
    """Exact emitted envelope size from public dimensions, with no dummy big payload."""
    p = compact.terminal_modulus(pk.q, pk.t, bits)
    groups, width1, header = wire._context(pk, count, dimension, p)
    if dropped_bits is None:
        width0 = width1
    else:
        width0 = pk.n * query.coefficient_encoding(p, pk.t, dropped_bits).coefficient_bits // 8
        header = _header(pk, count, dimension, p, dropped_bits)
    empty_size = len(msgpack.packb([header, [[b"", b""]] * groups], use_bin_type=True))
    return empty_size + groups * (_binary_cost(width0) + _binary_cost(width1) - 4)


def compress(
    packet: bytes,
    pk: bgv.PublicKey,
    *,
    count: int,
    dimension: int,
    bits: int,
    bounds: list[int],
    dropped_bits: int,
    backend: str = "python",
) -> bytes:
    p, e, _ = _settings(pk, count, dimension, bits, bounds, dropped_bits)
    native = query._implementation(backend)
    pairs = wire._unpack_fields(
        packet, pk, count=count, dimension=dimension, modulus=p, bounds=bounds
    )
    body = []
    width0 = pk.n * e.coefficient_bits // 8
    for c0, c1 in pairs:
        _canonical(c1, pk.n, p)
        if native is None:
            mask = (mpz(1) << dropped_bits) - 1
            words = [
                (c >> dropped_bits) * pk.t + (c & mask) % pk.t for c in _canonical(c0, pk.n, p)
            ]
            rounded = gmpy2.pack(words, e.coefficient_bits).to_bytes(width0, "little")
        else:
            rounded = native.compress_query_coefficients(
                c0, pk.n, format(p, "x"), pk.t, dropped_bits
            )
        body.append([rounded, c1])
    return msgpack.packb([_header(pk, count, dimension, p, dropped_bits), body], use_bin_type=True)


def expand(
    packet: bytes,
    pk: bgv.PublicKey,
    *,
    count: int,
    dimension: int,
    bits: int,
    bounds: list[int],
    dropped_bits: int,
    backend: str = "python",
) -> tuple[bytes, list[int]]:
    """Return canonical compact-v1 bytes and locally adjusted bounds, with no private work."""
    p, e, adjusted = _settings(pk, count, dimension, bits, bounds, dropped_bits)
    native = query._implementation(backend)
    width0, width1 = pk.n * e.coefficient_bits // 8, pk.n * p.bit_length() // 8
    if type(packet) is not bytes or len(packet) > min(
        wire.MAX_FRAME, packet_size(pk, count, dimension, bits, dropped_bits) + 256
    ):
        raise ValueError("Invalid rounded response length")
    try:
        value = msgpack.unpackb(
            packet,
            raw=False,
            max_array_len=64,
            max_map_len=0,
            max_bin_len=max(width0, width1, 32),
            max_str_len=64,
            max_ext_len=0,
        )
        expected = _header(pk, count, dimension, p, dropped_bits)
        if type(value) is not list or len(value) != 2:
            raise ValueError("Invalid rounded response envelope")
        header, pairs = value
        if (
            type(header) is not list
            or header != expected
            or any(type(a) is not type(b) for a, b in zip(header, expected, strict=True))
            or type(pairs) is not list
            or len(pairs) != len(bounds)
        ):
            raise ValueError("Incorrect rounded response context/shape")
        body = []
        for pair in pairs:
            if type(pair) is not list or len(pair) != 2:
                raise ValueError("Invalid rounded response pair")
            c0, c1 = pair
            if type(c0) is not bytes or len(c0) != width0:
                raise ValueError("Invalid rounded response c0 length")
            _canonical(c1, pk.n, p)
            if native is None:
                words = gmpy2.unpack(mpz.from_bytes(c0, "little"), e.coefficient_bits)
                words.extend([mpz(0)] * (pk.n - len(words)))
                coefficients = []
                for word in words:
                    high, residue = divmod(word, pk.t)
                    base = high << dropped_bits
                    if word > e.max_word or residue >= min(mpz(1) << dropped_bits, p - base):
                        raise ValueError("Noncanonical rounded response c0 word")
                    coefficients.append((base + residue + e.center) % p)
                original = gmpy2.pack(coefficients, p.bit_length()).to_bytes(width1, "little")
            else:
                original = native.expand_query_coefficients(
                    c0, pk.n, format(p, "x"), pk.t, dropped_bits
                )
            body.append((original, c1))
        return wire.pack_native_fixture(
            tuple(body), pk, count=count, dimension=dimension, modulus=p
        ), adjusted
    except (TypeError, OverflowError, msgpack.UnpackException) as error:
        raise ValueError("Invalid rounded response encoding") from error
