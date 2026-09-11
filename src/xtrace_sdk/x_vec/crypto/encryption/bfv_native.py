"""Complete C++ public-key evaluation behind the existing BFV wire interface.

Only the framing and packed byte buffers cross Python. Polynomial objects,
rotations, the merge tree and response compaction stay inside the native server.
Key generation, encryption and decryption use the existing BFV implementation.
"""

from collections.abc import Sequence
from numbers import Integral
from typing import Any

from xtrace_sdk.x_vec.crypto.encryption.bfv import _coefficient_modulus
from xtrace_sdk.x_vec.crypto.encryption.bfv_rns import BFVRNSArithmetic
from xtrace_sdk.x_vec.utils.xtrace_types import EncryptedVector


class BFVNativeServer:
    """Immutable native plan with public evaluation keys and a prepared slot mask."""

    def __init__(
        self, arithmetic: BFVRNSArithmetic, padded_embed_len: int, response_modulus_bits: int
    ) -> None:
        self.arithmetic = arithmetic
        self.padded_embed_len = padded_embed_len
        self.response_modulus_bits = response_modulus_bits
        pk = arithmetic._pk
        if (
            type(padded_embed_len) is not int
            or not 1 <= padded_embed_len <= arithmetic.n // 2
            or padded_embed_len & (padded_embed_len - 1)
        ):
            raise ValueError("Invalid native server padded dimension")
        if (
            type(response_modulus_bits) is not int
            or not pk["params"].plain_modulus.bit_length() + 8
            <= response_modulus_bits
            <= pk["q"].bit_length()
        ):
            raise ValueError("Invalid target modulus bit length")
        self._target = min(_coefficient_modulus(response_modulus_bits), pk["q"])
        self._key_id = int(pk["key_id"], 16)
        self._packed_bytes = (arithmetic.n * pk["q"].bit_length() + 7) // 8
        self._capacity = arithmetic.n // padded_embed_len
        exponents = {
            pow(3, sign * (self._capacity // 2) * (1 << i) % (arithmetic.n // 2), 2 * arithmetic.n)
            for sign in (1, -1)
            for i in range(padded_embed_len.bit_length() - 1)
        } - {1}
        if not exponents.issubset(pk["galois_keys"]):
            raise ValueError("Public key lacks native server rotation keys")
        self._server = arithmetic._native.create_server(
            arithmetic._prepare_key(0, pk["relin_key"]),
            tuple((g, arithmetic._prepare_key(g, pk["galois_keys"][g])) for g in sorted(exponents)),
            padded_embed_len,
            pk["params"].plain_modulus,
            format(self._target, "x"),
        )

    def _wire(self, values: Sequence[int | bytes]) -> tuple[bytes, bytes]:
        if len(values) != 8:
            raise ValueError("Native server requires two-component BFV ciphertext framing")
        if any(not isinstance(v, (Integral, bytes)) for v in values):
            raise ValueError("Ciphertext entries must be nonnegative integers or bytes")
        data = [int.from_bytes(v, "little") if isinstance(v, bytes) else int(v) for v in values]
        if any(v < 0 for v in data):
            raise ValueError("Ciphertext entries must be nonnegative")
        expected = [
            0x58424656,
            1,
            self.arithmetic.n,
            int(self.arithmetic._pk["q"]),
            self._key_id,
            2,
        ]
        if data[:6] != expected:
            raise ValueError("Incompatible BFV ciphertext header, modulus or key")
        if any(v.bit_length() > self._packed_bytes * 8 for v in data[6:]):
            raise ValueError("Packed polynomial exceeds N coefficients")
        # Coefficient bounds are checked in C++ while importing the bit-packed
        # buffers. Do not construct or validate N Python integers per component.
        return data[6].to_bytes(self._packed_bytes, "little"), data[7].to_bytes(
            self._packed_bytes, "little"
        )

    def search(
        self,
        query: Sequence[int | bytes],
        index: Sequence[Sequence[int | bytes]],
        vector_count: int,
        *,
        compact: bool = True,
        profile: dict[str, Any] | None = None,
    ) -> list[EncryptedVector]:
        """Search with unchanged wire bytes; optionally collect native phase timings.

        Profiling is opt-in and should be excluded from performance samples.
        """
        if (
            type(vector_count) is not int
            or vector_count < 0
            or len(index) != (vector_count + self._capacity - 1) // self._capacity
        ):
            raise ValueError("vector_count does not match the packed ciphertext count")
        args = (
            self._server,
            self._wire(query),
            tuple(self._wire(v) for v in index),
            vector_count,
            compact,
        )
        native = self.arithmetic._native
        if profile is None:
            packed = native.packed_search(*args)
        else:
            packed, timings = native.profile_packed_search(*args)
            profile.update(timings)
        q = self._target if compact else self.arithmetic._pk["q"]
        header = [0x58424656, 1, self.arithmetic.n, int(q), self._key_id, 2]
        return [
            header + [int.from_bytes(b, "little"), int.from_bytes(a, "little")] for b, a in packed
        ]

    def cache_bytes(self) -> int:
        """Payload of prepared plaintext tables and mask, excluding evaluation keys."""
        return self.arithmetic._native.server_bytes(self._server)
