"""Cached GMP evaluation of native BFV ciphertexts using public keys only.

The BFV scheme in ``bfv.py`` remains the reference implementation. This module
accelerates its key-switch dot products without changing parameters, rounding,
noise, or wire formats. It shares the scheme's experimental, variable-time status.
"""

from dataclasses import dataclass
from typing import Literal

import gmpy2
from gmpy2 import mpz

from xtrace_sdk.x_vec.crypto.encryption.bfv import BFV, _automorphism
from xtrace_sdk.x_vec.utils.xtrace_types import (
    BFVCiphertext,
    BFVPolynomial,
    BFVPublicKey,
    BFVSwitchKey,
)

BFVServerBackend = Literal["optimized", "reference"]


@dataclass(frozen=True)
class _PackedSwitchKey:
    """Public gadget key prepared for an exact, fused Kronecker dot product."""

    pairs: tuple[tuple[mpz, mpz], ...]
    width: int
    span: int
    low_mask: mpz
    bias_coefficient: mpz
    bias: mpz

    @staticmethod
    def compile(key: BFVSwitchKey, n: int, q: mpz, bits: int) -> "_PackedSwitchKey":
        # Each coefficient in the sum of ordinary convolutions is strictly
        # below len(key)*N*2^bits*q. One additional guard bit allows a signed
        # negacyclic fold inside GMP, without borrows between coefficient lanes.
        width = q.bit_length() + bits + (n * len(key)).bit_length() + 1
        span = n * width
        bias_coefficient = mpz(1) << (width - 1)
        return _PackedSwitchKey(
            tuple((gmpy2.pack(list(b), width), gmpy2.pack(list(a), width)) for b, a in key),
            width,
            span,
            (mpz(1) << span) - 1,
            bias_coefficient,
            gmpy2.pack([bias_coefficient] * n, width),
        )

    def apply(self, poly: BFVPolynomial, q: mpz, bits: int) -> tuple[BFVPolynomial, BFVPolynomial]:
        mask = (mpz(1) << bits) - 1
        accum0, accum1 = mpz(0), mpz(0)
        for i, (b, a) in enumerate(self.pairs):
            digits = gmpy2.pack([(c >> (i * bits)) & mask for c in poly], self.width)
            accum0 += digits * b
            accum1 += digits * a

        def finish(value: mpz) -> BFVPolynomial:
            # Fold X^N = -1 before unpacking. Every low/high coefficient is
            # < bias_coefficient, so low - high + bias lies strictly in (0,2^w).
            # Thus the packed subtraction has no cross-lane borrow, and unpack
            # returns exactly N coefficients, even for the zero polynomial.
            folded = (value & self.low_mask) - (value >> self.span) + self.bias
            return tuple((c - self.bias_coefficient) % q for c in gmpy2.unpack(folded, self.width))

        return finish(accum0), finish(accum1)


class BFVEvaluator:
    """Reusable native BFV server arithmetic, bound to one public key.

    ``optimized`` lazily caches packed evaluation keys and fuses gadget products;
    ``reference`` delegates to the original BFV routines. Both return identical
    ciphertexts. Reuse one evaluator across queries to amortize preparation.

    :param pk: Valid public key from key generation or public-key deserialization.
    :param backend: ``optimized`` (default) or ``reference``.

    The key dictionaries are snapshotted; immutable polynomial tuples are shared.
    Construct a new evaluator when changing keys. The cache is bounded by the
    number of evaluation keys in this snapshot and never stores query results.
    """

    def __init__(self, pk: BFVPublicKey, backend: BFVServerBackend = "optimized") -> None:
        if backend not in ("optimized", "reference"):
            raise ValueError("server_backend must be 'optimized' or 'reference'")
        self.backend = backend
        self._pk: BFVPublicKey = {**pk, "galois_keys": dict(pk["galois_keys"])}
        # Exponent zero identifies relinearization; Galois exponents are odd.
        self._switch_keys: dict[int, _PackedSwitchKey] = {}

    def _validate(self, ciphertext: BFVCiphertext) -> None:
        pk = self._pk
        n, q = pk["params"].poly_modulus_degree, ciphertext.modulus
        if ciphertext.key_id != pk["key_id"]:
            raise ValueError("Ciphertext belongs to a different BFV key")
        if not pk["params"].plain_modulus < q <= pk["q"]:
            raise ValueError("Invalid ciphertext modulus")
        if len(ciphertext.components) not in (2, 3):
            raise ValueError("BFV ciphertext must have two or three components")
        for poly in ciphertext.components:
            if len(poly) != n:
                raise ValueError("Invalid ciphertext polynomial")
            # Avoid Integral's Python ABC checks and int(mpz) conversions for
            # every native coefficient. Retain support for other Integral types
            # through the reference validator; never silently accept floats.
            if any(type(c) is not mpz and type(c) is not int for c in poly):
                BFV.validate_ciphertext(ciphertext, pk)
                return
            if min(poly) < 0 or max(poly) >= q:
                raise ValueError("Invalid ciphertext polynomial")

    def _pair(self, lhs: BFVCiphertext, rhs: BFVCiphertext) -> None:
        self._validate(lhs)
        if rhs is not lhs:
            self._validate(rhs)
        if lhs.modulus != rhs.modulus or len(lhs.components) != len(rhs.components):
            raise ValueError("Ciphertexts must have the same modulus and component count")

    def _switch(self, poly: BFVPolynomial, exponent: int) -> tuple[BFVPolynomial, BFVPolynomial]:
        pk, params = self._pk, self._pk["params"]
        if exponent not in self._switch_keys:
            key = pk["relin_key"] if exponent == 0 else pk["galois_keys"][exponent]
            self._switch_keys[exponent] = _PackedSwitchKey.compile(
                key, params.poly_modulus_degree, pk["q"], params.decomposition_bits
            )
        return self._switch_keys[exponent].apply(poly, pk["q"], params.decomposition_bits)

    def add(self, lhs: BFVCiphertext, rhs: BFVCiphertext) -> BFVCiphertext:
        """Add two ciphertexts with the same modulus and component count."""
        if self.backend == "reference":
            return BFV.add(lhs, rhs, self._pk)
        self._pair(lhs, rhs)
        return BFVCiphertext(
            tuple(
                tuple((a + b) % lhs.modulus for a, b in zip(p1, p2, strict=True))
                for p1, p2 in zip(lhs.components, rhs.components, strict=True)
            ),
            lhs.modulus,
            lhs.key_id,
        )

    def subtract(self, lhs: BFVCiphertext, rhs: BFVCiphertext) -> BFVCiphertext:
        """Subtract ciphertexts before squaring for binary XOR."""
        if self.backend == "reference":
            return BFV.subtract(lhs, rhs, self._pk)
        self._pair(lhs, rhs)
        return BFVCiphertext(
            tuple(
                tuple((a - b) % lhs.modulus for a, b in zip(p1, p2, strict=True))
                for p1, p2 in zip(lhs.components, rhs.components, strict=True)
            ),
            lhs.modulus,
            lhs.key_id,
        )

    def multiply_plain(self, ciphertext: BFVCiphertext, plaintext: BFVPolynomial) -> BFVCiphertext:
        """Apply an unscaled plaintext polynomial, e.g. a distance slot mask."""
        return BFV.multiply_plain(ciphertext, plaintext, self._pk)

    def relinearize(self, ciphertext: BFVCiphertext) -> BFVCiphertext:
        """Replace the quadratic component using the cached public gadget key."""
        if self.backend == "reference":
            return BFV.relinearize(ciphertext, self._pk)
        self._validate(ciphertext)
        if len(ciphertext.components) == 2:
            return ciphertext
        pk = self._pk
        if ciphertext.modulus != pk["q"]:
            raise ValueError("Relinearization requires the original ciphertext modulus")
        if not pk["relin_key"]:
            raise ValueError("Public key has no relinearization key")
        c0, c1, c2 = ciphertext.components
        k0, k1 = self._switch(c2, 0)
        return BFVCiphertext(
            (
                tuple((a + b) % pk["q"] for a, b in zip(c0, k0, strict=True)),
                tuple((a + b) % pk["q"] for a, b in zip(c1, k1, strict=True)),
            ),
            pk["q"],
            pk["key_id"],
        )

    def multiply(self, lhs: BFVCiphertext, rhs: BFVCiphertext) -> BFVCiphertext:
        """Keep the reference exact tensor product and scale; accelerate relinearization."""
        return self.relinearize(BFV.multiply(lhs, rhs, self._pk, relinearize=False))

    def xor(self, lhs: BFVCiphertext, rhs: BFVCiphertext) -> BFVCiphertext:
        """Slotwise binary XOR, (a-b)^2; encrypted inputs cannot be checked for bits."""
        difference = self.subtract(lhs, rhs)
        return self.multiply(difference, difference)

    def rotate_rows(self, ciphertext: BFVCiphertext, steps: int) -> BFVCiphertext:
        """Rotate both slot rows left (right for negative steps) using public keys."""
        if self.backend == "reference":
            return BFV.rotate_rows(ciphertext, steps, self._pk)
        self._validate(ciphertext)
        pk = self._pk
        if ciphertext.modulus != pk["q"] or len(ciphertext.components) != 2:
            raise ValueError("Rotation requires two components at the original modulus")
        n, q = pk["params"].poly_modulus_degree, pk["q"]
        exponent = pow(3, steps % (n // 2), 2 * n)
        if exponent == 1:
            return ciphertext
        if exponent not in pk["galois_keys"]:
            raise ValueError(f"Public key has no rotation key for steps={steps}")
        c0, c1 = (_automorphism(c, exponent, q) for c in ciphertext.components)
        k0, k1 = self._switch(c1, exponent)
        return BFVCiphertext(
            (tuple((a + b) % q for a, b in zip(c0, k0, strict=True)), k1), q, pk["key_id"]
        )
