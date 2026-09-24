"""Research query preparation: seeded RLWE and one-use client preprocessing.

Raw local experiments only. The native polynomial helper is variable-time and
is not a reviewed private-key implementation. Zero encryptions in the pool must
remain private to the client: revealing a token and its consumed query reveals
the encoded message. Python memory is not securely erased here.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
import os
import secrets
import threading
from typing import Never, SupportsIndex

from Crypto.Hash import SHAKE256
import gmpy2
from gmpy2 import mpz
import msgpack

from cuhepy.bfv.rns import BFVRNSArithmetic
from cuhepy.bfv.scheme import BFV, _ring_product, _small_poly, _ternary_poly
from cuhepy.hamming.bfv import BFVClient
from cuhepy.types import BFVCiphertext, BFVPolynomial, BFVPublicKey, EncryptedVector

_TAG = b"cuhepy-lab-query-v1"


def _uniform(seed: bytes, pk: BFVPublicKey) -> BFVPolynomial:
    """Unbiased rejection sampling; the public stream never samples secret noise."""
    if len(seed) != 32:
        raise ValueError("Invalid public seed")
    stream = SHAKE256.new(data=_TAG + bytes.fromhex(pk["key_id"]) + seed)
    bits = pk["q"].bit_length()
    width, mask = (bits + 7) // 8, (1 << bits) - 1
    result: list[mpz] = []
    n = pk["params"].poly_modulus_degree
    while len(result) < n:
        # Read the same stream in batches: a Python/C call per coefficient was
        # more expensive than expanding this public component in the first run.
        block = stream.read((n - len(result)) * width)
        for at in range(0, len(block), width):
            value = int.from_bytes(block[at : at + width], "little") & mask
            if value < pk["q"]:
                result.append(mpz(value))
    return tuple(result)


def _pack(poly: BFVPolynomial, pk: BFVPublicKey) -> bytes:
    bits = pk["q"].bit_length()
    return int(gmpy2.pack(list(poly), bits)).to_bytes((len(poly) * bits + 7) // 8, "little")


def expand_query(packet: bytes, pk: BFVPublicKey) -> EncryptedVector:
    """Bound the experimental packet and reconstruct a standard full query."""
    n, q = pk["params"].poly_modulus_degree, pk["q"]
    width = (n * q.bit_length() + 7) // 8
    if not isinstance(packet, bytes) or len(packet) > 2 * width + 256:
        raise ValueError("Invalid query packet size")
    try:
        fields = msgpack.unpackb(packet, raw=False)
    except (ValueError, msgpack.UnpackException) as exc:
        raise ValueError("Invalid query packet") from exc
    if (
        not isinstance(fields, list)
        or len(fields) != 5
        or any(not isinstance(v, bytes) for v in fields)
    ):
        raise ValueError("Invalid query packet fields")
    tag, key_id, seed, c0, c1 = fields
    if tag != _TAG or key_id != bytes.fromhex(pk["key_id"]) or len(c0) != width:
        raise ValueError("Incompatible query context")
    if (seed and (len(seed) != 32 or c1)) or (not seed and len(c1) != width):
        raise ValueError("Invalid seeded query components")
    for component in (c0, c1):
        if not component:
            continue
        packed = mpz.from_bytes(component, "little")
        if packed.bit_length() > n * q.bit_length():
            raise ValueError("Noncanonical query padding")
        if any(value >= q for value in gmpy2.unpack(packed, q.bit_length())):
            raise ValueError("Noncanonical query coefficient")
    if seed:
        c1 = _pack(_uniform(seed, pk), pk)
    return [
        0x58424656,
        1,
        n,
        int(q),
        int(pk["key_id"], 16),
        2,
        int.from_bytes(c0, "little"),
        int.from_bytes(c1, "little"),
    ]


@dataclass(frozen=True)
class _ZeroToken:
    ciphertext: BFVCiphertext
    public_seed: bytes = b""


class QueryFactory:
    """Owner-side experimental encryptor; public and symmetric modes are separate."""

    def __init__(
        self,
        owner: BFVClient,
        *,
        seeded: bool = False,
        native: bool = False,
        native_encode: bool = False,
    ) -> None:
        self.owner = owner
        self.pk = owner._pk()
        self.seeded = seeded
        self.arithmetic = BFVRNSArithmetic(self.pk, fast=True) if native else None
        self.encoder = NativeBatchEncoder(owner) if native_encode else None
        self._pid = os.getpid()
        if seeded:
            owner._keys()  # Fail during setup if the caller has no secret key.

    def _check_context(self) -> None:
        if os.getpid() != self._pid:
            raise RuntimeError("Query context cannot be used after fork")
        if self.owner._pk() is not self.pk:
            raise ValueError("Owner key changed; construct a new query factory")

    def _product(self, a: BFVPolynomial, b: BFVPolynomial) -> BFVPolynomial:
        return (
            self.arithmetic.product(a, b) if self.arithmetic else _ring_product(a, b, self.pk["q"])
        )

    def _zero(self) -> _ZeroToken:
        self._check_context()
        pk, params, q = self.pk, self.pk["params"], self.pk["q"]
        n = params.poly_modulus_degree
        if self.seeded:
            seed = secrets.token_bytes(32)
            a = _uniform(seed, pk)
            secret = tuple(mpz(c % q) for c in self.owner._keys()["sk"]["s"])
            error = _small_poly(n, params.error_eta, q)
            product = self._product(a, secret)
            b = tuple((e - v) % q for e, v in zip(error, product, strict=True))
            return _ZeroToken(BFVCiphertext((b, a), q, pk["key_id"]), seed)
        u = _ternary_poly(n, q)
        e0, e1 = _small_poly(n, params.error_eta, q), _small_poly(n, params.error_eta, q)
        bu, au = self._product(pk["b"], u), self._product(pk["a"], u)
        c0 = tuple((v + e) % q for v, e in zip(bu, e0, strict=True))
        c1 = tuple((v + e) % q for v, e in zip(au, e1, strict=True))
        return _ZeroToken(BFVCiphertext((c0, c1), q, pk["key_id"]))

    def _finish(self, query: Sequence[int], token: _ZeroToken) -> bytes:
        self._check_context()
        slots = self.owner._query_slots(query)
        plaintext = (
            self.encoder.encode(slots)
            if self.encoder
            else BFV.batch_encode(slots, self.owner.params)
        )
        q = self.pk["q"]
        delta = q // self.owner.params.plain_modulus
        c0 = tuple(
            (v + delta * m) % q
            for v, m in zip(token.ciphertext.components[0], plaintext, strict=True)
        )
        c1 = b"" if token.public_seed else _pack(token.ciphertext.components[1], self.pk)
        return msgpack.packb(
            [_TAG, bytes.fromhex(self.pk["key_id"]), token.public_seed, _pack(c0, self.pk), c1],
            use_bin_type=True,
        )

    def encrypt(self, query: Sequence[int]) -> bytes:
        return self._finish(query, self._zero())


class NativeBatchEncoder:
    """Experimental cached native transform; no private side-channel assurance."""

    def __init__(self, owner: BFVClient) -> None:
        from cuhepy.bfv._cpu_ext import _bfv_rns

        if not hasattr(_bfv_rns, "create_batch_encoder"):
            raise RuntimeError("Rebuild the research CPU extension for native encoding")
        self._native = _bfv_rns
        self.n, self.t = owner.params.poly_modulus_degree, owner.params.plain_modulus
        self._plan = _bfv_rns.create_batch_encoder(self.n, self.t)

    def encode(self, slots: Sequence[int]) -> BFVPolynomial:
        if len(slots) > self.n or any(type(v) is not int or not 0 <= v < self.t for v in slots):
            raise ValueError("Invalid batch slots")
        packed = int(gmpy2.pack([mpz(v) for v in slots], 64)).to_bytes(8 * self.n, "little")
        result = self._native.batch_encode(self._plan, packed)
        values = list(gmpy2.unpack(mpz.from_bytes(result, "little"), 64))
        values.extend([mpz(0)] * (self.n - len(values)))
        return tuple(values)


class OneUseQueryPool:
    """Bounded in-memory preprocessing, rejecting fork/copy/pickle and reuse.

    A consumed token is removed before encoding, including on failure. This is
    a research pool, not crash-persistent storage or a secure-memory container.
    """

    def __init__(self, factory: QueryFactory, capacity: int = 32) -> None:
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError("Invalid query pool capacity")
        self.factory = factory
        self.capacity = capacity
        self._tokens: deque[_ZeroToken] = deque()
        self._pending = 0
        self._lock = threading.Lock()

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise TypeError("One-use query pools cannot be copied or serialized")

    def refill(self, count: int = 1) -> None:
        self.factory._check_context()  # Check before touching a possibly inherited lock.
        if type(count) is not int or count < 1:
            raise ValueError("Invalid refill count")
        with self._lock:
            if len(self._tokens) + self._pending + count > self.capacity:
                raise ValueError("Query pool capacity exceeded")
            self._pending += count
        try:
            tokens = [self.factory._zero() for _ in range(count)]
            with self._lock:
                self._tokens.extend(tokens)
        finally:
            with self._lock:
                self._pending -= count

    def encrypt(self, query: Sequence[int]) -> bytes:
        self.factory._check_context()
        with self._lock:
            if not self._tokens:
                raise RuntimeError("Query pool exhausted; refill outside the online path")
            token = self._tokens.popleft()
        return self.factory._finish(query, token)
