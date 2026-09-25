"""Fresh owner-encrypted BGV queries with a public seed for the uniform term.

Only c0 and a fresh 256-bit seed cross the query boundary; the server expands
c1 = a from a domain-separated SHAKE256 stream. Secret error sampling uses the
independent OS-backed sampler. There is no zero-token reuse or preprocessing
pool here. Variable-time owner encryption; experimental unauthenticated framing.
"""

from __future__ import annotations

import secrets

from Crypto.Hash import SHAKE256
import gmpy2
from gmpy2 import mpz
import msgpack

from cuhepy.bfv.scheme import _ring_product, _small_poly
from cuhepy.types import BFVPolynomial
from experiments.bfv_search_lab import shallow_bgv as bgv

_TAG = b"cuhepy-lab-bgv-seeded-query-v1"


def _uniform(seed: bytes, pk: bgv.PublicKey) -> BFVPolynomial:
    if type(seed) is not bytes or len(seed) != 32:
        raise ValueError("Invalid BGV public seed")
    stream = SHAKE256.new(data=_TAG + bytes.fromhex(pk.key_id) + seed)
    bits = pk.q.bit_length()
    width, mask = (bits + 7) // 8, (1 << bits) - 1
    result: list[mpz] = []
    while len(result) < pk.n:
        block = stream.read((pk.n - len(result)) * width)
        for at in range(0, len(block), width):
            value = int.from_bytes(block[at:at + width], "little") & mask
            if value < pk.q:
                result.append(mpz(value))
    return tuple(result)


def encrypt(plaintext: list[int], pk: bgv.PublicKey, sk: bgv.SecretKey) -> bytes:
    if sk.key_id != pk.key_id or len(sk.s) != pk.n:
        raise ValueError("Wrong seeded BGV owner key")
    if len(plaintext) != pk.n or any(type(x) is not int for x in plaintext):
        raise ValueError("Expected N integer query coefficients")
    seed = secrets.token_bytes(32)
    a = _uniform(seed, pk)
    product, error = _ring_product(a, sk.s, pk.q), _small_poly(pk.n, pk.eta, pk.q)
    message = [((x + pk.t // 2) % pk.t) - pk.t // 2 for x in plaintext]
    c0 = [(m + pk.t * e - v) % pk.q for m, e, v in zip(message, error, product, strict=True)]
    bits = pk.q.bit_length()
    packed = gmpy2.pack(c0, bits).to_bytes((pk.n * bits + 7) // 8, "little")
    return msgpack.packb([_TAG, bytes.fromhex(pk.key_id), seed, packed], use_bin_type=True)


def _parse_fields(packet: bytes, pk: bgv.PublicKey) -> tuple[bytes, bytes]:
    """Bound the shared envelope; each arithmetic path validates its coefficients."""
    bits = pk.q.bit_length()
    width = (pk.n * bits + 7) // 8
    if type(packet) is not bytes or len(packet) > width + 256:
        raise ValueError("Invalid seeded BGV packet size")
    try:
        fields = msgpack.unpackb(packet, raw=False, max_array_len=4, max_map_len=0,
                                max_bin_len=max(width, 64), max_str_len=0, max_ext_len=0)
    except (ValueError, msgpack.UnpackException) as error:
        raise ValueError("Invalid seeded BGV packet") from error
    if not isinstance(fields, list) or len(fields) != 4 or any(type(f) is not bytes for f in fields):
        raise ValueError("Invalid seeded BGV fields")
    tag, key_id, seed, packed = fields
    if tag != _TAG or key_id != bytes.fromhex(pk.key_id) or len(seed) != 32 or len(packed) != width:
        raise ValueError("Invalid seeded BGV context or shape")
    return packed, seed


def _parse(packet: bytes, pk: bgv.PublicKey) -> tuple[tuple[mpz, ...], bytes]:
    """Shared bounded parser; arithmetic variants preserve exactly this framing."""
    packed, seed = _parse_fields(packet, pk)
    bits = pk.q.bit_length()
    integer = mpz.from_bytes(packed, "little")
    if integer.bit_length() > pk.n * bits:
        raise ValueError("Noncanonical seeded BGV padding")
    c0 = gmpy2.unpack(integer, bits)
    if any(c >= pk.q for c in c0):
        raise ValueError("Noncanonical seeded BGV coefficient")
    c0.extend([mpz(0)] * (pk.n - len(c0)))
    return tuple(c0), seed


def expand(packet: bytes, pk: bgv.PublicKey) -> bgv.Ciphertext:
    c0, seed = _parse(packet, pk)
    bound = pk.t // 2 + pk.t * pk.eta
    return bgv.Ciphertext((c0, _uniform(seed, pk)), pk.key_id, bound)
