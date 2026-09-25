"""Owner-side BGV experiments: bulk sampling and exact ternary multiplication.

The scheme, centered-binomial distribution, public seed stream and packet format
are unchanged. Secret errors use fresh independent OS randomness on EVERY call;
no one-use pool or offline randomness is omitted from timings.

Private Python/GMP arithmetic remains variable-time. A closed owner drops its
references, but Python/GMP do not promise secure erasure. This local fixture
client supplies neither response authentication nor a production private backend.
It is separate from the public-only C++/CUDA server.
"""

from __future__ import annotations

import os
import secrets
import threading
from typing import Any, SupportsIndex

from Crypto.Hash import SHAKE256
import gmpy2
from gmpy2 import mpz
import msgpack

from cuhepy.bfv.scheme import _ring_product
from cuhepy.types import BFVPolynomial
from experiments.bfv_search_lab import shallow_bgv as bgv, seeded_bgv as seeded
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import results_bgv as results
from experiments.bfv_search_lab.native_owner_bgv import NativeTernaryProduct


def _uniform_bulk(seed: bytes, pk: bgv.PublicKey) -> BFVPolynomial:
    """Decode the identical SHAKE stream in bulk, retaining rejection sampling."""
    if type(seed) is not bytes or len(seed) != 32:
        raise ValueError("Invalid BGV public seed")
    stream = SHAKE256.new(data=seeded._TAG + bytes.fromhex(pk.key_id) + seed)
    bits = pk.q.bit_length()
    width, mask = (bits + 7) // 8, (mpz(1) << bits) - 1
    result: list[mpz] = []
    while len(result) < pk.n:
        remaining = pk.n - len(result)
        block = stream.read(remaining * width)
        values = gmpy2.unpack(mpz.from_bytes(block, "little"), width * 8)
        values.extend([mpz(0)] * (remaining - len(values)))
        if bits % 8:
            values = [value & mask for value in values]
        result.extend(value for value in values if value < pk.q)
    return tuple(result)


def expand(packet: bytes, pk: bgv.PublicKey) -> bgv.Ciphertext:
    c0, seed = seeded._parse(packet, pk)
    return bgv.Ciphertext((c0, _uniform_bulk(seed, pk)), pk.key_id, pk.t // 2 + pk.t * pk.eta)


def _errors_from_bytes(data: bytes, n: int, eta: int) -> list[int]:
    """Two disjoint eta-bit fields per coefficient; unused high bits are ignored."""
    if type(n) is not int or not 1 <= n <= 32768 or type(eta) is not int or not 1 <= eta <= 64:
        raise ValueError("Invalid centered-binomial dimensions")
    width = (2 * eta + 7) // 8
    if type(data) is not bytes or len(data) != n * width:
        raise ValueError("Incorrect centered-binomial entropy length")
    mask = (1 << eta) - 1
    words = [int.from_bytes(data[i:i + width], "little") for i in range(0, len(data), width)]
    return [(v & mask).bit_count() - ((v >> eta) & mask).bit_count() for v in words]


def _small_errors(n: int, eta: int) -> list[int]:
    return _errors_from_bytes(secrets.token_bytes(n * ((2 * eta + 7) // 8)), n, eta)


class TernaryProduct:
    """Exact Kronecker product with a small shifted secret, not q-1 coefficients.

    For J=1+X+...+X^(N-1), a*s = a*(s+J) - a*J. The first product has
    nonnegative integer coefficients <=2*N*(q-1); the second is 2*prefix(a)-sum(a)
    in the negacyclic ring. A public worst-case digit width prevents all carries
    between coefficients. No cyclic/subring/sparse-secret assumption is made.
    """

    def __init__(self, secret: BFVPolynomial, modulus: mpz) -> None:
        self.n = len(secret)
        if not 1 <= self.n <= 32768 or self.n & (self.n - 1) or not 3 <= modulus < (mpz(1) << 241):
            raise ValueError("Invalid ternary multiplication context")
        if any(c not in (0, 1, modulus - 1) for c in secret):
            raise ValueError("Expected a canonical ternary secret")
        self._shifted = tuple(mpz(0) if c == modulus - 1 else c + 1 for c in secret)
        self._packed: dict[int, mpz] = {}

    def prepare(self, modulus: mpz) -> tuple[int, mpz]:
        if not self._shifted:
            raise RuntimeError("Private multiplication cache is closed")
        if not 3 <= modulus < (mpz(1) << 240):
            raise ValueError("Invalid ternary multiplication modulus")
        width = (2 * self.n * (modulus - 1)).bit_length()
        if width not in self._packed:
            self._packed[width] = gmpy2.pack(list(self._shifted), width)
        return width, self._packed[width]

    def multiply(self, poly: BFVPolynomial, modulus: mpz) -> BFVPolynomial:
        if len(poly) != self.n or any(not 0 <= c < modulus for c in poly):
            raise ValueError("Noncanonical ternary product input")
        width, secret = self.prepare(modulus)
        values = gmpy2.unpack(gmpy2.pack(list(poly), width) * secret, width)
        values.extend([mpz(0)] * (2 * self.n - len(values)))
        total, prefix = sum(poly, mpz(0)), mpz(0)
        output = []
        for i, coefficient in enumerate(poly):
            prefix += coefficient
            output.append((values[i] - values[i + self.n] - 2 * prefix + total) % modulus)
        return tuple(output)

    def clear(self) -> None:
        # Drop references only. GMP's allocator and Python copies are not wiped.
        self._packed.clear()
        self._shifted = ()

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise TypeError("Private multiplication caches cannot be serialized")


class OwnerClient:
    """Explicit local owner with an amortized secret cache and fresh encryption."""

    def __init__(self, pk: bgv.PublicKey, sk: bgv.SecretKey, *, ternary: bool = True,
                 native: bool = False, rns: bool = False) -> None:
        if (type(ternary) is not bool or type(native) is not bool or (native and not ternary)
            or type(rns) is not bool or (rns and not native)
            or sk.key_id != pk.key_id or len(sk.s) != pk.n):
            raise ValueError("Wrong BGV owner context or multiplication mode")
        if (type(pk.n) is not int or not 8 <= pk.n <= 32768 or pk.n & (pk.n - 1)
            or not 32 <= pk.q.bit_length() <= 240 or pk.q % 2 != 1
            or type(pk.t) is not int or not 3 <= pk.t < (1 << 30) or pk.t % 2 != 1
            or type(pk.eta) is not int or not 1 <= pk.eta <= 64
            or len(pk.key_id) != 64 or any(c not in "0123456789abcdef" for c in pk.key_id)):
            raise ValueError("Invalid BGV owner parameters")
        self.pk = pk
        self._sk: bgv.SecretKey | None = sk
        self._product = NativeTernaryProduct(sk.s, pk.q, rns=rns) if native else TernaryProduct(sk.s, pk.q)
        self._ternary = ternary
        self._pid = os.getpid()
        self._lock = threading.RLock()
        if ternary:
            self._product.prepare(pk.q)

    def _check(self) -> bgv.SecretKey:
        # Check before acquiring an inherited lock, which could be held at fork.
        if os.getpid() != self._pid:
            raise RuntimeError("Create a new owner after fork")
        if self._sk is None:
            raise RuntimeError("BGV owner is closed")
        return self._sk

    def prepare_terminal(self, bits: int = 32) -> None:
        self._check()
        with self._lock:
            self._check()
            self._product.prepare(compact.terminal_modulus(self.pk.q, self.pk.t, bits))

    def encrypt(self, plaintext: list[int]) -> bytes:
        self._check()
        with self._lock:
            sk = self._check()
            pk = self.pk
            if len(plaintext) != pk.n or any(type(x) is not int for x in plaintext):
                raise ValueError("Expected N integer query coefficients")
            seed = secrets.token_bytes(32)
            a = _uniform_bulk(seed, pk)
            if isinstance(self._product, NativeTernaryProduct):
                entropy = secrets.token_bytes(pk.n * ((2 * pk.eta + 7) // 8))
                packed = self._product.encrypt(a, plaintext, entropy, pk.q, pk.t, pk.eta)
                return msgpack.packb([seeded._TAG, bytes.fromhex(pk.key_id), seed, packed], use_bin_type=True)
            error = _small_errors(pk.n, pk.eta)
            product = self._product.multiply(a, pk.q) if self._ternary else _ring_product(a, sk.s, pk.q)
            message = [((x + pk.t // 2) % pk.t) - pk.t // 2 for x in plaintext]
            c0 = [(m + pk.t * e - v) % pk.q for m, e, v in zip(message, error, product, strict=True)]
            bits = pk.q.bit_length()
            packed = gmpy2.pack(c0, bits).to_bytes((pk.n * bits + 7) // 8, "little")
            return msgpack.packb([seeded._TAG, bytes.fromhex(pk.key_id), seed, packed], use_bin_type=True)

    def decrypt_compact(self, cipher: compact.CompactCiphertext) -> list[int]:
        self._check()
        with self._lock:
            sk = self._check()
            compact._validate(cipher, self.pk)
            if not self._ternary:
                return compact.decrypt(cipher, self.pk, sk)
            if isinstance(self._product, NativeTernaryProduct):
                return self._product.decrypt(cipher.components, cipher.modulus, self.pk.t)
            p = cipher.modulus
            product = self._product.multiply(cipher.components[1], p)
            phase = [(a + b) % p for a, b in zip(cipher.components[0], product, strict=True)]
            return [int((c if c <= p // 2 else c - p) % self.pk.t) for c in phase]

    def close(self) -> None:
        if os.getpid() != self._pid:
            raise RuntimeError("Owner belongs to another process")
        with self._lock:
            self._sk = None
            self._product.clear()

    def finish(self, ciphertexts: list[compact.CompactCiphertext], count: int, dimension: int,
               *, k: int = 3, all_distances: bool = True, method: str = "native") -> results.SearchResult:
        """Local fixture decryption and stable top-k; no remote authenticity gate.

        ``all_distances=False`` avoids exporting the full plaintext result to
        Python. It does not reduce encrypted response traffic or server work.
        """
        self._check()
        with self._lock:
            self._check()
            results.validate_layout(self.pk.n, self.pk.t, count, dimension, k, all_distances)
            if method not in ("native", "sort", "heap", "lookup"):
                raise ValueError("Unknown owner result method")
            if method == "native" and not isinstance(self._product, NativeTernaryProduct):
                raise ValueError("Native finish requires a native owner")
            if len(ciphertexts) != (count + self.pk.n - 1) // self.pk.n:
                raise ValueError("Incorrect owner response count")
            for cipher in ciphertexts:
                compact._validate(cipher, self.pk)
                if cipher.modulus != ciphertexts[0].modulus:
                    raise ValueError("Mixed owner response moduli")
            if not ciphertexts:
                return results.SearchResult((), () if all_distances else None)
            if method == "native" and isinstance(self._product, NativeTernaryProduct):
                return self._product.finish([c.components for c in ciphertexts], ciphertexts[0].modulus,
                                            self.pk.t, count, dimension, k, all_distances)
            plaintexts = [self.decrypt_compact(c) for c in ciphertexts]
            return results.finish(plaintexts, count, dimension, self.pk, k=k,
                                  all_distances=all_distances, method=method)

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise TypeError("Private owner caches cannot be serialized")

    def __copy__(self) -> Any:
        raise TypeError("Private owner caches cannot be copied")

    def __deepcopy__(self, memo: Any) -> Any:
        raise TypeError("Private owner caches cannot be copied")
