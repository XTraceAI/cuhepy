"""Native CPU BFV client for individual and packed encrypted Hamming distances.

This implements the local HammingClientBase interface. The BFV wire format and
packed index need corresponding server support before use with XTrace's HTTP API.
"""

import json
from collections.abc import Sequence
from dataclasses import asdict
from numbers import Integral
from typing import Any

from xtrace_sdk.x_vec.crypto.device import DeviceMode
from xtrace_sdk.x_vec.crypto.encryption.bfv import BFV
from xtrace_sdk.x_vec.crypto.hamming_client_base import HammingClientBase
from xtrace_sdk.x_vec.utils.xtrace_types import (
    BFVCiphertext,
    BFVKeyPair,
    BFVParameters,
    BFVPolynomial,
    BFVPublicKey,
    EncryptedVector,
)


class BFVClient(HammingClientBase):
    """Self-implemented BFV Hamming client, using GMP on the CPU.

    ``encrypt_vec_batch`` keeps the existing one-ciphertext-per-vector contract.
    The explicit ``*_packed`` methods amortize each ciphertext over several
    database vectors and pack up to N distances into each response ciphertext.
    All homomorphic evaluation uses public keys only; top-k stays on the client.

    :param embed_len: Binary embedding dimension, at most N/2 and less than t.
    :param poly_modulus_degree: Ring degree N, a power of two.
    :param coeff_modulus_bits: Bit length of the initial ciphertext modulus q.
    :param response_modulus_bits: Smaller modulus used after the Hamming circuit.
    :param skip_key_gen: Construct an empty client for loading saved keys.
    :param device: ``cpu`` or ``auto``; a CUDA implementation is not yet available.
    """

    def __init__(
        self,
        embed_len: int = 512,
        poly_modulus_degree: int = 8192,
        plain_modulus: int = 65537,
        coeff_modulus_bits: int = 180,
        decomposition_bits: int = 30,
        error_eta: int = 21,
        response_modulus_bits: int = 50,
        skip_key_gen: bool = False,
        device: DeviceMode = "auto",
    ) -> None:
        if device not in ("cpu", "auto", "gpu"):
            raise ValueError("device must be 'auto', 'cpu', or 'gpu'")
        if device == "gpu":
            raise NotImplementedError("Native BFV currently supports only the CPU backend")
        self.device = "cpu"
        self.params = BFVParameters(
            poly_modulus_degree, plain_modulus, coeff_modulus_bits, decomposition_bits, error_eta
        )
        self.embed_len = embed_len
        self.response_modulus_bits = response_modulus_bits
        self._configure_layout()
        self.keys: BFVKeyPair | None = None
        self.public_key: BFVPublicKey | None = None
        if not skip_key_gen:
            self.keys = BFV.key_gen(**asdict(self.params), rotation_steps=self._rotation_steps())
            self.public_key = self.keys["pk"]

    def _configure_layout(self) -> None:
        BFV.validate_parameters(self.params)
        n, t = self.params.poly_modulus_degree, self.params.plain_modulus
        if (
            type(self.embed_len) is not int
            or not 1 <= self.embed_len <= n // 2
            or self.embed_len >= t
        ):
            raise ValueError("embed_len must be positive, <= N/2, and < plain_modulus")
        if (
            type(self.response_modulus_bits) is not int
            or not t.bit_length() + 8
            <= self.response_modulus_bits
            <= self.params.coeff_modulus_bits
        ):
            raise ValueError(
                "response_modulus_bits must be between plain_modulus bits + 8 and coeff_modulus_bits"
            )
        self.padded_embed_len = 1 << (self.embed_len - 1).bit_length()
        self.lanes_per_row = n // (2 * self.padded_embed_len)
        self.vectors_per_ciphertext = 2 * self.lanes_per_row
        self.distances_per_ciphertext = n
        self._mask_cache: dict[int, BFVPolynomial] = {}

    def _rotation_steps(self) -> list[int]:
        return [
            sign * self.lanes_per_row * (1 << i)
            for i in range(self.padded_embed_len.bit_length() - 1)
            for sign in (1, -1)
        ]

    def _pk(self) -> BFVPublicKey:
        if self.public_key is None:
            raise RuntimeError("Keys not initialized")
        return self.public_key

    def _keys(self) -> BFVKeyPair:
        if self.keys is None:
            raise RuntimeError("Secret key not initialized; public-only clients cannot decrypt")
        return self.keys

    @staticmethod
    def has_gpu() -> bool:
        return False

    def stringify_pk(self) -> str:
        """Public encryption/evaluation keys; safe to separate from the secret key."""
        return BFV.serialize_public_key(self._pk())

    def stringify_sk(self) -> str:
        return BFV.serialize_secret_key(self._keys()["sk"])

    def stringify_config(self) -> str:
        return json.dumps(
            {
                "embed_len": self.embed_len,
                **asdict(self.params),
                "response_modulus_bits": self.response_modulus_bits,
                "device": "cpu",
            }
        )

    def load_config(self, config: dict[str, Any]) -> None:
        """Load layout/arithmetic settings before loading keys, as in the Paillier clients."""
        candidate = BFVClient(
            **{k: v for k, v in config.items() if k != "device"}, skip_key_gen=True
        )
        if self.public_key is not None and candidate.stringify_config() != self.stringify_config():
            raise ValueError(
                "Load a changed configuration into an empty client before loading its keys"
            )
        self.params = candidate.params
        self.embed_len = candidate.embed_len
        self.response_modulus_bits = candidate.response_modulus_bits
        self._configure_layout()

    def load_stringified_keys(self, pk: str, sk: str | None = None) -> None:
        """Load private client keys, or just public keys for server-side evaluation.

        :param pk: ``stringify_pk()`` JSON, including the evaluation keys.
        :param sk: ``stringify_sk()`` JSON. Omit on the server.
        """
        public_key = BFV.deserialize_public_key(pk)
        if public_key["params"] != self.params:
            raise ValueError("Loaded BFV key parameters do not match the client configuration")
        n = self.params.poly_modulus_degree
        required = {pow(3, step % (n // 2), 2 * n) for step in self._rotation_steps()} - {1}
        if not public_key["relin_key"] or not required.issubset(public_key["galois_keys"]):
            raise ValueError("Public key lacks evaluation keys required by this Hamming layout")
        keys: BFVKeyPair | None = None
        if sk is not None:
            keys = {"pk": public_key, "sk": BFV.deserialize_secret_key(sk, public_key)}
        self.public_key = public_key
        self.keys = keys

    def _validate_vector(self, embd: Sequence[int]) -> None:
        if len(embd) != self.embed_len:
            raise ValueError(
                f"Embedding length {len(embd)} does not match expected {self.embed_len}"
            )
        if any(not isinstance(bit, Integral) or bit not in (0, 1) for bit in embd):
            raise ValueError("Embedding vector must contain binary integers")

    def _query_slots(self, embd: Sequence[int]) -> list[int]:
        self._validate_vector(embd)
        # Dimension-major layout: each dimension occupies B consecutive lanes.
        # Repeat the query across every lane, identically in the two rows.
        row = [int(bit) for bit in embd for _ in range(self.lanes_per_row)]
        row.extend([0] * ((self.padded_embed_len - self.embed_len) * self.lanes_per_row))
        return row + row

    def encrypt_vec_one(self, embd: list[int]) -> EncryptedVector:
        """Encrypt one vector, replicated across all lanes so it also serves as a query."""
        pk = self._pk()
        return BFV.ciphertext_to_ints(
            BFV.encrypt(BFV.batch_encode(self._query_slots(embd), self.params), pk), pk
        )

    def encrypt_vec_batch(self, embds: list[list[int]]) -> list[EncryptedVector]:
        """Encrypt vectors independently, preserving HammingClientBase semantics."""
        return [self.encrypt_vec_one(embd) for embd in embds]

    def encrypt_vec_packed(self, embds: list[list[int]]) -> list[EncryptedVector]:
        """Build a packed encrypted index with up to N/padded_dimension vectors per ciphertext."""
        pk = self._pk()
        for embd in embds:
            self._validate_vector(embd)
        result = []
        n, b, capacity = (
            self.params.poly_modulus_degree,
            self.lanes_per_row,
            self.vectors_per_ciphertext,
        )
        for start in range(0, len(embds), capacity):
            slots = [0] * n
            for lane, embd in enumerate(embds[start : start + capacity]):
                row, column = divmod(lane, b)
                for dimension, bit in enumerate(embd):
                    slots[row * (n // 2) + dimension * b + column] = int(bit)
            result.append(
                BFV.ciphertext_to_ints(BFV.encrypt(BFV.batch_encode(slots, self.params), pk), pk)
            )
        return result

    def _distance_tile(
        self, query: BFVCiphertext, tile: BFVCiphertext, count: int
    ) -> BFVCiphertext:
        pk = self._pk()
        distance = BFV.xor(query, tile, pk)
        for i in range(self.padded_embed_len.bit_length() - 1):
            step = self.lanes_per_row * (1 << i)
            distance = BFV.add(distance, BFV.rotate_rows(distance, step, pk), pk)
        # The rotate/add tree repeats sums in each dimension block. Retain only
        # the first block in each row and clear unused lanes in a partial tile.
        if count not in self._mask_cache:
            if len(self._mask_cache) >= 8:
                del self._mask_cache[next(iter(self._mask_cache))]
            mask = [0] * self.params.poly_modulus_degree
            for lane in range(count):
                row, col = divmod(lane, self.lanes_per_row)
                mask[row * (len(mask) // 2) + col] = 1
            self._mask_cache[count] = BFV.batch_encode(mask, self.params)
        return BFV.multiply_plain(distance, self._mask_cache[count], pk)

    def encode_hamming_server(
        self,
        ct1: Sequence[int | bytes],
        ct2: Sequence[int | bytes],
        *,
        compact: bool = True,
    ) -> EncryptedVector:
        """Compute an encrypted distance using only public evaluation keys."""
        pk = self._pk()
        result = self._distance_tile(
            BFV.ciphertext_from_ints(ct1, pk), BFV.ciphertext_from_ints(ct2, pk), 1
        )
        if compact:
            result = BFV.modulus_switch(result, self.response_modulus_bits, pk)
        return BFV.ciphertext_to_ints(result, pk)

    def encode_hamming_server_packed(
        self,
        query: Sequence[int | bytes],
        index: Sequence[Sequence[int | bytes]],
        vector_count: int,
        *,
        compact: bool = True,
    ) -> list[EncryptedVector]:
        """Evaluate a packed index and return ceil(vector_count/N) ciphertexts.

        A binary carry tree packs distance tiles using right rotations by powers
        of two. Only a logarithmic number of intermediate tiles is kept per
        response. The caller retains candidate IDs in the original index order.
        """
        pk = self._pk()
        capacity = self.vectors_per_ciphertext
        self._validate_count(vector_count, len(index), capacity)
        query_ct = BFV.ciphertext_from_ints(query, pk)
        result = []
        tiles_per_response = self.padded_embed_len
        for start in range(0, len(index), tiles_per_response):
            stack: list[tuple[BFVCiphertext, int]] = []
            for offset, wire in enumerate(index[start : start + tiles_per_response]):
                count = min(capacity, vector_count - (start + offset) * capacity)
                tile = self._distance_tile(query_ct, BFV.ciphertext_from_ints(wire, pk), count)
                size = 1
                while stack and stack[-1][1] == size:
                    left, _ = stack.pop()
                    tile = BFV.add(left, BFV.rotate_rows(tile, -self.lanes_per_row * size, pk), pk)
                    size *= 2
                stack.append((tile, size))
            # Partial groups have a decreasing list of powers of two. Combining
            # from the right uses the same already-generated rotation keys.
            combined, _ = stack.pop()
            while stack:
                left, size = stack.pop()
                combined = BFV.add(
                    left, BFV.rotate_rows(combined, -self.lanes_per_row * size, pk), pk
                )
            if compact:
                combined = BFV.modulus_switch(combined, self.response_modulus_bits, pk)
            result.append(BFV.ciphertext_to_ints(combined, pk))
        return result

    @staticmethod
    def _validate_count(count: int, ciphertexts: int, capacity: int) -> None:
        if type(count) is not int or count < 0 or ciphertexts != (count + capacity - 1) // capacity:
            raise ValueError("vector_count does not match the packed ciphertext count")

    def _decode_slots(self, cipher: Sequence[int | bytes]) -> list[int]:
        return BFV.batch_decode(
            BFV.decrypt(BFV.ciphertext_from_ints(cipher, self._pk()), self._keys()), self.params
        )

    def _check_distances(self, distances: list[int]) -> list[int]:
        if any(not 0 <= value <= self.embed_len for value in distances):
            raise ValueError(
                "Decoded distance is out of range; check input, parameters and noise budget"
            )
        return distances

    def decode_hamming_client_one(self, cipher: Sequence[int | bytes]) -> int:
        """Decrypt the first distance slot of an individual response."""
        return self._check_distances([self._decode_slots(cipher)[0]])[0]

    def decode_hamming_client_batch(self, ciphers: Sequence[Sequence[int | bytes]]) -> list[int]:
        return [self.decode_hamming_client_one(cipher) for cipher in ciphers]

    def decode_hamming_client_packed(
        self,
        ciphers: Sequence[Sequence[int | bytes]],
        vector_count: int,
    ) -> list[int]:
        """Decrypt packed distances in input order; padded slots are omitted."""
        n, b = self.params.poly_modulus_degree, self.lanes_per_row
        self._validate_count(vector_count, len(ciphers), n)
        result = []
        for group, cipher in enumerate(ciphers):
            slots = self._decode_slots(cipher)
            for position in range(min(n, vector_count - group * n)):
                tile, lane = divmod(position, self.vectors_per_ciphertext)
                row, column = divmod(lane, b)
                result.append(slots[row * (n // 2) + tile * b + column])
        return self._check_distances(result)
