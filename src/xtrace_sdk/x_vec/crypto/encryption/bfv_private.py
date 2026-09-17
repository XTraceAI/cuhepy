"""Fixed-width native terminal decryption behind the existing BFV wire format.

Only the native decryption/slot transform has the fixed-work design. Key
generation/import, encryption, Python plaintext handling and verification are
outside that claim. Imported native key/scratch buffers are locked and wiped;
existing Python key objects and returned plaintexts are not erased by this API.
Never expose this raw private primitive to an untrusted caller.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Literal

import gmpy2

from xtrace_sdk.x_vec.crypto.encryption.bfv import (
    BFV,
    _coefficient_modulus,
    _rns_coefficient_primes,
)

if TYPE_CHECKING:
    from xtrace_sdk.x_vec.crypto.bfv_client import BFVClient

BFVPrivateBackend = Literal["python", "native"]


class BFVPrivateDecoder:
    """A private native context; unavailable/unsupported configurations fail closed."""

    def __init__(self, client: BFVClient) -> None:
        try:
            from xtrace_sdk.x_vec.crypto.bfv_cpu_ext import _bfv_private
        except ImportError as exc:
            raise RuntimeError(
                "Build the BFV private CPU extension before selecting native private decoding"
            ) from exc
        if _bfv_private.ABI_VERSION != 1:
            raise RuntimeError("Rebuild the BFV private CPU extension (ABI 1 required)")
        self._native = _bfv_private
        self._pk = client._pk()
        self._n = client.params.poly_modulus_degree
        self._q = min(int(_coefficient_modulus(client.response_modulus_bits)), int(self._pk["q"]))
        self._t = client.params.plain_modulus
        self._capacity, self._lanes = client.vectors_per_ciphertext, client.lanes_per_row
        self._embed_len = client.embed_len
        keys = client._keys()
        secret = keys["sk"]["s"]
        if (
            keys["sk"]["key_id"] != self._pk["key_id"]
            or len(secret) != self._n
            or any(c not in (-1, 0, 1) for c in secret)
        ):
            raise ValueError("Invalid native private key")
        p0, p1 = _rns_coefficient_primes(self._n, 120)
        self._context = self._native.create_decoder(
            self._n, self._q, self._t, p0, p1, bytes(int(c) & 255 for c in secret)
        )

    def decode_slots(self, wire: Sequence[int | bytes]) -> list[int]:
        # Framing, canonical coefficients and packing conversions are PUBLIC.
        # This public parser is called only after the receipt in guarded sessions.
        ct = BFV.ciphertext_from_ints(wire, self._pk)
        if len(ct.components) != 2 or ct.modulus != self._q:
            raise ValueError(
                "Native private decoding requires the exact two-component terminal response"
            )
        components = [
            int(gmpy2.pack(list(poly), 64)).to_bytes(8 * self._n, "little")
            for poly in ct.components
        ]
        encoded = self._native.decode_slots(self._context, *components)
        return [int.from_bytes(encoded[4 * i : 4 * i + 4], "little") for i in range(self._n)]

    def decode_packed(
        self, ciphertexts: Sequence[Sequence[int | bytes]], vector_count: int
    ) -> list[int]:
        if (
            type(vector_count) is not int
            or vector_count < 1
            or len(ciphertexts) != (vector_count + self._n - 1) // self._n
        ):
            raise ValueError("Invalid private packed response count")
        result = []
        for group, wire in enumerate(ciphertexts):
            slots = self.decode_slots(wire)
            for position in range(min(self._n, vector_count - group * self._n)):
                tile, lane = divmod(position, self._capacity)
                row, column = divmod(lane, self._lanes)
                result.append(slots[row * (self._n // 2) + tile * self._lanes + column])
        if any(not 0 <= d <= self._embed_len for d in result):
            raise ValueError("BFV distance out of range")
        return result

    def close(self) -> None:
        """Wipe native key buffers; wait for an active decode and reject future ones."""
        self._native.close_decoder(self._context)
