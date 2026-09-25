"""Experimental seeded-query compression by plaintext-congruent coefficient rounding.

For R=2**d, write a canonical c0 coefficient as c=R*h+r. Transmit
w=t*h+(r mod t), using a fixed public width. Reconstruct
c'=R*h+(r mod t)+t*floor(K/2), where K=floor((R-1)/t), then reduce mod Q.
Thus c'-c=t*(floor(K/2)-floor(r/t)) before reduction. Its absolute value is
at most E=t*ceil(K/2), independent of the plaintext, secret and observed noise.

Only c0 changes. The public-seeded c1, secret, ring and Q stay the same. The
new phase bound is B+E, and a no-wrap phase still decodes to the exact message
modulo t. The existing evaluator MUST propagate this larger bound through the
whole circuit and terminal reduction; valid query decryption alone is not enough.

This is deterministic public post-processing of a fresh seeded ciphertext, not
a new randomness distribution or a claim of a novel compression primitive.
It supplies no authentication, parameter assurance or private side-channel fix.
Bounds describe honest local encryption; arbitrary wire input cannot prove them.
See docs/research/bgv-query-compression.md for the derivation and experiment.
"""

from __future__ import annotations

from dataclasses import dataclass

import gmpy2
from gmpy2 import mpz
import msgpack

from experiments.bfv_search_lab import owner_bgv as owner, seeded_bgv as seeded
from experiments.bfv_search_lab import shallow_bgv as bgv

_TAG = b"cuhepy-lab-bgv-query-rounded-v1"


@dataclass(frozen=True)
class Encoding:
    dropped_bits: int
    coefficient_bits: int
    body_bytes: int
    max_word: int
    center: int
    added_bound: int
    query_bound: int


def parameters(pk: bgv.PublicKey, dropped_bits: int) -> Encoding:
    """Public, fixed encoding dimensions; never select precision from secret noise."""
    if (
        type(pk.n) is not int
        or not 8 <= pk.n <= 32768
        or pk.n & (pk.n - 1)
        or type(pk.t) is not int
        or not 3 <= pk.t < (1 << 30)
        or pk.t % 2 != 1
        or type(pk.eta) is not int
        or not 1 <= pk.eta <= 64
        or not 32 <= pk.q.bit_length() <= 240
        or pk.q % 2 != 1
        or pk.q <= pk.t
        or len(pk.key_id) != 64
        or any(c not in "0123456789abcdef" for c in pk.key_id)
        or type(dropped_bits) is not int
        or not 1 <= dropped_bits < pk.q.bit_length()
    ):
        raise ValueError("Invalid compressed BGV query context/precision")
    radix = 1 << dropped_bits
    intervals = (radix - 1) // pk.t
    center = pk.t * (intervals // 2)
    added = pk.t * ((intervals + 1) // 2)
    bound = pk.t // 2 + pk.t * pk.eta + added
    if 2 * bound >= pk.q:
        raise ValueError("Compressed query correctness bound exceeds Q/2")
    high, tail = divmod(int(pk.q) - 1, radix)
    maximum = high * pk.t + min(pk.t - 1, tail)
    bits = maximum.bit_length()
    return Encoding(dropped_bits, bits, (pk.n * bits + 7) // 8, maximum, center, added, bound)


def compress(packet: bytes, pk: bgv.PublicKey, *, dropped_bits: int) -> bytes:
    """Compress an existing fresh owner packet; requires no secret or fresh coins."""
    encoding = parameters(pk, dropped_bits)
    c0, seed = seeded._parse(packet, pk)
    mask = (mpz(1) << dropped_bits) - 1
    words = [(c >> dropped_bits) * pk.t + (c & mask) % pk.t for c in c0]
    body = gmpy2.pack(words, encoding.coefficient_bits).to_bytes(encoding.body_bytes, "little")
    return msgpack.packb(
        [_TAG, bytes.fromhex(pk.key_id), seed, dropped_bits, body], use_bin_type=True
    )


def expand(packet: bytes, pk: bgv.PublicKey, *, dropped_bits: int) -> bgv.Ciphertext:
    """Expand only the caller-pinned format/context; no private arithmetic occurs."""
    encoding = parameters(pk, dropped_bits)
    if type(packet) is not bytes or len(packet) > encoding.body_bytes + 256:
        raise ValueError("Invalid compressed BGV query length")
    try:
        fields = msgpack.unpackb(
            packet,
            raw=False,
            max_array_len=5,
            max_map_len=0,
            max_bin_len=max(encoding.body_bytes, 64),
            max_str_len=0,
            max_ext_len=0,
        )
    except (ValueError, TypeError, OverflowError, msgpack.UnpackException) as error:
        raise ValueError("Invalid compressed BGV query encoding") from error
    if type(fields) is not list or len(fields) != 5:
        raise ValueError("Invalid compressed BGV query fields")
    tag, key_id, seed, actual_drop, body = fields
    if (
        type(tag) is not bytes
        or tag != _TAG
        or type(key_id) is not bytes
        or key_id != bytes.fromhex(pk.key_id)
        or type(seed) is not bytes
        or len(seed) != 32
        or type(actual_drop) is not int
        or actual_drop != dropped_bits
        or type(body) is not bytes
        or len(body) != encoding.body_bytes
    ):
        raise ValueError("Incorrect compressed BGV query context/shape")
    integer = mpz.from_bytes(body, "little")
    if integer.bit_length() > pk.n * encoding.coefficient_bits:
        raise ValueError("Noncanonical compressed BGV query padding")
    words = gmpy2.unpack(integer, encoding.coefficient_bits)
    words.extend([mpz(0)] * (pk.n - len(words)))
    c0 = []
    radix = mpz(1) << dropped_bits
    for word in words:
        if word > encoding.max_word:
            raise ValueError("Noncanonical compressed BGV coefficient")
        high, residue = divmod(word, pk.t)
        base = high << dropped_bits
        # Last-bin and R<t holes must not create alternate encodings. There must
        # exist a canonical original coefficient with this high part/residue.
        if residue >= min(radix, pk.q - base):
            raise ValueError("Compressed coefficient has no canonical preimage")
        c0.append((base + residue + encoding.center) % pk.q)
    return bgv.Ciphertext(
        (tuple(c0), owner._uniform_bulk(seed, pk)), pk.key_id, encoding.query_bound
    )
