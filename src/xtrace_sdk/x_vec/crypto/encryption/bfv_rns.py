"""Optional native RNS/NTT arithmetic with the existing BFV polynomial types.

The default uses auxiliary primes as temporary arithmetic workspaces. The
residue option uses a subset as the actual ciphertext modulus and keeps complete
search intermediates in that basis. Both match Python/GMP for the same keys.
"""

from typing import Any

import gmpy2
from gmpy2 import mpz

from xtrace_sdk.x_vec.utils.xtrace_types import BFVPolynomial, BFVPublicKey, BFVSwitchKey


class BFVRNSArithmetic:
    """Bind optional C++ kernels to one validated BFV public-key context."""

    def __init__(
        self,
        pk: BFVPublicKey,
        *,
        fast: bool = False,
        residue: bool = False,
        kernel_level: int | None = None,
    ) -> None:
        try:
            from xtrace_sdk.x_vec.crypto.bfv_cpu_ext import _bfv_rns
        except ImportError as error:
            raise ImportError(
                "BFV RNS CPU extension is unavailable. Build it with "
                "make -C src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext PYTHON=/path/to/python; "
                "or select server_backend='optimized' for the Python/GMP evaluator."
            ) from error
        if _bfv_rns.ABI_VERSION != 4:
            raise ImportError("BFV RNS CPU extension has an incompatible ABI; rebuild it")
        self._native = _bfv_rns
        self._pk = pk
        params = pk["params"]
        if residue and not params.rns_modulus:
            raise ValueError(
                "The residue backend requires fresh keys generated with rns_modulus=True"
            )
        self.n = params.poly_modulus_degree
        self.width = (pk["q"].bit_length() + 7) // 8
        if kernel_level is None:
            kernel_level = 2 if residue else 0
        if (
            type(kernel_level) is not int
            or kernel_level not in (0, 1, 2)
            or (kernel_level and not residue)
        ):
            raise ValueError("kernel_level must be 0..2; nonzero levels require residue arithmetic")
        self._ring = _bfv_rns.create_ring(
            self.n, format(pk["q"], "x"), params.decomposition_bits, fast, residue, kernel_level
        )
        self._keys: dict[int, object] = {}

    def _pack(self, poly: BFVPolynomial) -> bytes:
        return gmpy2.pack(list(poly), 8 * self.width).to_bytes(self.n * self.width, "little")

    def _unpack(self, data: bytes) -> BFVPolynomial:
        values = gmpy2.unpack(mpz.from_bytes(data, "little"), 8 * self.width)
        values.extend([mpz(0)] * (self.n - len(values)))
        return tuple(values)

    def switch(
        self, poly: BFVPolynomial, exponent: int, key: BFVSwitchKey
    ) -> tuple[BFVPolynomial, BFVPolynomial]:
        """Prepare each public gadget key once, then reuse its NTT representation."""
        b, a = self._native.apply_key(self._prepare_key(exponent, key), self._pack(poly))
        return self._unpack(b), self._unpack(a)

    def _prepare_key(self, exponent: int, key: BFVSwitchKey) -> object:
        if exponent not in self._keys:
            self._keys[exponent] = self._native.compile_key(
                self._ring, tuple((self._pack(b), self._pack(a)) for b, a in key)
            )
        return self._keys[exponent]

    def rotate(
        self, components: tuple[BFVPolynomial, ...], exponent: int, key: BFVSwitchKey
    ) -> tuple[BFVPolynomial, ...]:
        """Keep the automorphism and key-switch intermediates in the native module."""
        output = self._native.rotate_rows(
            self._prepare_key(exponent, key), tuple(self._pack(c) for c in components), exponent
        )
        return tuple(self._unpack(c) for c in output)

    def hamming_tile(
        self,
        query: tuple[BFVPolynomial, ...],
        tile: tuple[BFVPolynomial, ...],
        exponents: list[int],
        mask: BFVPolynomial,
    ) -> tuple[BFVPolynomial, ...]:
        """Run the existing tile circuit without materializing Python intermediates."""
        relin = self._prepare_key(0, self._pk["relin_key"])
        rotations = tuple(
            (g, relin if g == 1 else self._prepare_key(g, self._pk["galois_keys"][g]))
            for g in exponents
        )
        output = self._native.hamming_tile(
            relin,
            tuple(self._pack(c) for c in query),
            tuple(self._pack(c) for c in tile),
            rotations,
            self._pack(mask),
            self._pk["params"].plain_modulus,
        )
        return tuple(self._unpack(c) for c in output)

    def product(self, lhs: BFVPolynomial, rhs: BFVPolynomial) -> BFVPolynomial:
        """Exact negacyclic product, reduced modulo the original ciphertext modulus."""
        return self._unpack(self._native.ring_product(self._ring, self._pack(lhs), self._pack(rhs)))

    def multiply(
        self, lhs: tuple[BFVPolynomial, ...], rhs: tuple[BFVPolynomial, ...], t: int
    ) -> tuple[BFVPolynomial, ...]:
        """Tensor products over the integers, then exact BFV scale-and-round."""
        output = self._native.multiply(
            self._ring,
            tuple(self._pack(poly) for poly in lhs),
            None if lhs is rhs else tuple(self._pack(poly) for poly in rhs),
            t,
        )
        return tuple(self._unpack(poly) for poly in output)

    def cache_info(self) -> dict[str, Any]:
        info = dict(self._native.ring_info(self._ring))
        info["switch_keys"] = len(self._keys)
        info["key_payload_bytes"] = sum(self._native.key_bytes(key) for key in self._keys.values())
        return info
