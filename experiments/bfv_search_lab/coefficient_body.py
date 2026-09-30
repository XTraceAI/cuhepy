"""E37 exact Q coefficient bodies, with independent GMP and word bit codecs.

This is lossless packing, not rounding or a new authenticated transport.
The receiver pins Q, count and bit width before parsing; high padding and
noncanonical residues are rejected. Existing ciphertext metadata/gates remain
necessary. No plaintext, HE secret or integrity challenge enters this codec.
"""

from __future__ import annotations

import struct

import gmpy2
from gmpy2 import mpz

from experiments.bfv_search_lab import native_linear_check as check
from experiments.bfv_search_lab import polynomial_fingerprint as polynomial


def reference_pack(values: tuple[int | mpz, ...], q: int) -> bytes:
    polynomial.field(q, 1)
    if not 1 <= len(values) <= 1 << 20 or any(not 0 <= x < q for x in values):
        raise ValueError("Invalid canonical coefficient vector")
    bits = q.bit_length()
    return gmpy2.pack(list(values), bits).to_bytes((len(values) * bits + 7) // 8, "little")


def reference_unpack(body: bytes, length: int, q: int) -> tuple[mpz, ...]:
    polynomial.field(q, 1)
    bits = q.bit_length()
    if (type(body) is not bytes or type(length) is not int or not 1 <= length <= 1 << 20
            or len(body) != (length * bits + 7) // 8):
        raise ValueError("Invalid pinned coefficient body/count")
    value = mpz.from_bytes(body, "little")
    if value.bit_length() > length * bits:
        raise ValueError("Nonzero coefficient-body padding")
    words = gmpy2.unpack(value, bits)
    words.extend([mpz(0)] * (length - len(words)))
    if any(x >= q for x in words):
        raise ValueError("Noncanonical coefficient residue")
    return tuple(words)


def pack(values: tuple[int | mpz, ...], q: int) -> bytes:
    polynomial.field(q, 1)
    if not 1 <= len(values) <= 1 << 20 or any(not 0 <= x < q for x in values):
        raise ValueError("Invalid canonical coefficient vector")
    body = struct.pack(f"<{len(values)}Q", *values)
    return check.backend().pack_bits(body, q.bit_length(), q)


def unpack(body: bytes, length: int, q: int) -> tuple[mpz, ...]:
    polynomial.field(q, 1)
    if (type(body) is not bytes or type(length) is not int or not 1 <= length <= 1 << 20
            or len(body) != (length * q.bit_length() + 7) // 8):
        raise ValueError("Invalid pinned coefficient body/count")
    words = check.backend().unpack_bits(body, q.bit_length(), length, q)
    return tuple(mpz(x) for x in struct.unpack(f"<{length}Q", words))
