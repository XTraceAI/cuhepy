"""Private variable-time GMP owner wrapper; never imported by the public server.

The extension is optional and separate from _native. No SEAL or CUDA dependency.
It implements the same shifted-ternary identity as owner_bgv.TernaryProduct.
"""

from __future__ import annotations

import importlib
import struct
from typing import Any, SupportsIndex

import gmpy2
from gmpy2 import mpz

from cuhepy.types import BFVPolynomial


class NativeTernaryProduct:
    def __init__(self, secret: BFVPolynomial, modulus: mpz) -> None:
        if not 8 <= len(secret) <= 32768 or len(secret) & (len(secret) - 1):
            raise ValueError("Invalid native owner degree")
        if any(c not in (0, 1, modulus - 1) for c in secret):
            raise ValueError("Expected a canonical ternary secret")
        self.n = len(secret)
        self._native = importlib.import_module("experiments.bfv_search_lab._owner._bgv_owner")
        shifted = bytes(0 if c == modulus - 1 else int(c) + 1 for c in secret)
        self._handle = self._native.create(self.n, shifted)

    def prepare(self, modulus: mpz) -> None:
        self._native.prepare(self._handle, format(modulus, "x"))

    def _pack(self, poly: BFVPolynomial, modulus: mpz) -> bytes:
        if len(poly) != self.n or any(not 0 <= c < modulus for c in poly):
            raise ValueError("Noncanonical native owner input")
        bits = modulus.bit_length()
        return gmpy2.pack(list(poly), bits).to_bytes((self.n * bits + 7) // 8, "little")

    def multiply(self, poly: BFVPolynomial, modulus: mpz) -> BFVPolynomial:
        data = self._native.multiply(self._handle, self._pack(poly, modulus), format(modulus, "x"))
        values = gmpy2.unpack(mpz.from_bytes(data, "little"), modulus.bit_length())
        values.extend([mpz(0)] * (self.n - len(values)))
        return tuple(values)

    def encrypt(self, a: BFVPolynomial, plaintext: list[int], entropy: bytes,
                modulus: mpz, t: int, eta: int) -> bytes:
        if len(plaintext) != self.n or any(type(c) is not int for c in plaintext):
            raise ValueError("Expected N integer plaintext coefficients")
        message = struct.pack(f"<{self.n}I", *(c % t for c in plaintext))
        return self._native.encrypt(self._handle, self._pack(a, modulus), message, entropy,
                                    format(modulus, "x"), t, eta)

    def decrypt(self, components: tuple[BFVPolynomial, BFVPolynomial], modulus: mpz, t: int) -> list[int]:
        data = self._native.decrypt(self._handle, self._pack(components[0], modulus),
                                    self._pack(components[1], modulus), format(modulus, "x"), t)
        return list(struct.unpack(f"<{self.n}I", data))

    def clear(self) -> None:
        self._native.close(self._handle)

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise TypeError("Private native owner caches cannot be serialized")
