"""Bounded whole-Q GMP producer for Q76 source-scale correctness.

This public research reference independently evaluates expansion and the
feature-major contraction. It uses our GMP Kronecker convolution, never the
C++ NTT, native producer/checker, small graph interpreter or private HE work.
Canonical packed frontiers avoid retaining millions of Python coefficient
objects; the immutable index is read one ciphertext at a time. This is a
correctness control, not an authenticated service or security approval.
"""

from __future__ import annotations

from dataclasses import dataclass

import gmpy2
from gmpy2 import mpz
import msgpack

from cuhepy.bfv.scheme import _ring_product
from experiments.bfv_search_lab import native_shared_query as native

BITS = 120
WIDTH = 15
RADIX_BITS = 30
INPUT_CAP = 1 << 31


def _row(data, offset, n):
    values = gmpy2.unpack(mpz.from_bytes(data[offset : offset + n * WIDTH], "little"), BITS)
    values.extend([mpz(0)] * (n - len(values)))
    return tuple(values)


def _row_bytes(row):
    return gmpy2.pack(list(row), BITS).to_bytes(len(row) * WIDTH, "little")


def _validate_buffer(data, rows, n, q):
    if type(data) is not bytes or len(data) != rows * n * WIDTH or len(data) > INPUT_CAP:
        raise ValueError("Wrong complete immutable GMP buffer")
    for offset in range(0, len(data), n * WIDTH):
        if any(value >= q for value in _row(data, offset, n)):
            raise ValueError("Noncanonical whole-Q GMP coefficient")


def _add(left, right, q, sign=1):
    return tuple((a + sign * b) % q for a, b in zip(left, right, strict=True))


def _permute(row, q, *, exponent=1, shift=0):
    """Independent signed permutation in Z[X]/(X**N+1)."""
    n, result = len(row), [mpz(0)] * len(row)
    for i, value in enumerate(row):
        at = (i * exponent + shift) % (2 * n)
        result[at % n] = (value if at < n else -value) % q
    return tuple(result)


def _switch(source, key, q):
    n, mask = len(source), (1 << RADIX_BITS) - 1
    total = [(mpz(0),) * n, (mpz(0),) * n]
    for digit, column in enumerate(key):
        values = tuple((value >> (digit * RADIX_BITS)) & mask for value in source)
        for component in range(2):
            total[component] = _add(
                total[component], _ring_product(values, column[component], q), q
            )
    return tuple(total)


@dataclass(frozen=True)
class PublicTranscript:
    body: bytes
    response: bytes


@dataclass(frozen=True)
class GMPPublicContext:
    """Validated bounded immutable public inputs, with no native handle.

    Owner origin/authentication are the caller's separate obligations. The
    reference itself is not an admission or release authority. Buffer syntax
    and every input coordinate are checked before any ring multiplication.
    """

    metadata: native.PublicMetadata
    key_body: bytes
    index_body: bytes

    def __post_init__(self):
        metadata, key_body, index_body = self.metadata, self.key_body, self.index_body
        if type(metadata) is not native.PublicMetadata:
            raise ValueError("Bounded owner-canonical public metadata required")
        metadata.__post_init__()
        p = metadata.profile
        if any(
            (prime - 1) % (2 * p.n) or not gmpy2.is_prime(prime, 50) for prime in metadata.primes
        ) or not gmpy2.is_prime(p.p, 50):
            raise ValueError("Wrong actual GMP/terminal prime profile")
        if (
            type(key_body) is not bytes
            or type(index_body) is not bytes
            or len(key_body) + len(index_body) > INPUT_CAP
            or metadata.body_size > INPUT_CAP
        ):
            raise ValueError("GMP public input/output cap exceeded")
        _validate_buffer(key_body, (p.levels + 1) * 2 * p.ell, p.n, p.q)
        _validate_buffer(index_body, metadata.groups * p.dimension * 2, p.n, p.q)

    def _key(self, slot):
        p = self.metadata.profile
        stride, start = p.n * WIDTH, slot * 2 * p.ell * p.n * WIDTH
        return tuple(
            tuple(_row(self.key_body, start + (2 * digit + c) * stride, p.n) for c in range(2))
            for digit in range(p.ell)
        )

    def produce(self, query_body):
        """Complete canonical source/output body and independent compact frame.

        Whole-Q GMP convolution deliberately remains a separate arithmetic
        backend. Four direct products supply both cross terms independently
        of the native paired-Karatsuba implementation.
        """
        p = self.metadata.profile
        _validate_buffer(query_body, 2, p.n, p.q)
        q, stride = mpz(p.q), p.n * WIDTH
        frontier, sources = [query_body], bytearray()
        for level in range(p.levels):
            key = self._key(level + 1)  # Slot zero is the delayed relin key.
            even, odd = [], []
            for encoded in frontier:
                pair = tuple(_row(encoded, c * stride, p.n) for c in range(2))
                rotated = tuple(_permute(row, q, exponent=1 + p.n // (1 << level)) for row in pair)
                sources.extend(_row_bytes(rotated[1]))
                switched = _switch(rotated[1], key, q)
                rotated = (_add(rotated[0], switched[0], q), switched[1])
                plus = tuple(_add(a, b, q) for a, b in zip(pair, rotated, strict=True))
                minus = tuple(
                    _permute(_add(a, b, q, -1), q, shift=-(1 << level))
                    for a, b in zip(pair, rotated, strict=True)
                )
                even.append(b"".join(_row_bytes(row) for row in plus))
                odd.append(b"".join(_row_bytes(row) for row in minus))
            frontier = even + odd
        relin, outputs = self._key(0), []
        for group in range(self.metadata.groups):
            total = [(mpz(0),) * p.n for _ in range(3)]
            for feature in range(p.dimension):
                left = tuple(_row(frontier[feature], c * stride, p.n) for c in range(2))
                start = (group * p.dimension + feature) * 2 * stride
                right = tuple(_row(self.index_body, start + c * stride, p.n) for c in range(2))
                pieces = (
                    _ring_product(left[0], right[0], q),
                    _add(
                        _ring_product(left[0], right[1], q), _ring_product(left[1], right[0], q), q
                    ),
                    _ring_product(left[1], right[1], q),
                )
                total = [_add(a, b, q) for a, b in zip(total, pieces, strict=True)]
            sources.extend(_row_bytes(total[2]))
            switched = _switch(total[2], relin, q)
            outputs.append(tuple(_add(a, b, q) for a, b in zip(total[:2], switched, strict=True)))
        sources.extend(b"".join(_row_bytes(row) for pair in outputs for row in pair))
        body = bytes(sources)
        if len(body) != self.metadata.body_size:
            raise ValueError("Incomplete independently produced GMP transcript")
        return PublicTranscript(body, terminal_frame(self.metadata, tuple(outputs)))


def terminal_frame(metadata, outputs):
    """Exact congruent rounding and complete packed framing, with no C++ call."""
    if type(metadata) is not native.PublicMetadata:
        raise ValueError("Bounded complete terminal metadata required")
    metadata.__post_init__()
    p = metadata.profile
    if (
        type(outputs) is not tuple
        or len(outputs) != metadata.groups
        or any(type(pair) is not tuple or len(pair) != 2 for pair in outputs)
        or any(
            type(row) is not tuple
            or len(row) != p.n
            or any(type(x) not in (int, mpz) or not 0 <= x < p.q for x in row)
            for pair in outputs
            for row in pair
        )
    ):
        raise ValueError("Wrong complete whole-Q terminal output")
    compact_rows = []
    for pair in outputs:
        encoded = []
        for row in pair:
            values = []
            for value in row:
                residue = value % p.t
                rounded = (
                    (2 * (p.p * value - p.q * residue) + p.q * p.t) // (2 * p.q * p.t)
                ) * p.t + residue
                values.append(mpz(rounded % p.p))
            encoded.append(
                gmpy2.pack(values, p.p.bit_length()).to_bytes(metadata.terminal_row_size, "little")
            )
        compact_rows.append(encoded)
    header = [
        "cuhepy-lab-bgv-compact-v1",
        p.n,
        p.t,
        p.p.to_bytes((p.p.bit_length() + 7) // 8, "little"),
        bytes.fromhex(metadata.key_id),
        len(metadata.ids),
        p.dimension,
    ]
    return msgpack.packb([header, compact_rows], use_bin_type=True)
