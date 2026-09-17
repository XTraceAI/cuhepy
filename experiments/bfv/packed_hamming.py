"""Offline BFV research prototype; independent of the production SDK/API.

Both inputs are encrypted. The server receives only serialized evaluation keys,
an encrypted index, and an encrypted query. It returns packed exact distances;
top-k selection still happens on the client. See README.md for the protocol,
layout, costs, and limits. This is not an authenticated production transport.
"""

from __future__ import annotations

import hashlib
import heapq
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from numbers import Integral
from pathlib import Path
from typing import Any

import msgpack

try:
    from tenseal import sealapi as seal
except ImportError as exc:
    raise ImportError("Install experiments/bfv/requirements.txt to run the BFV experiment") from exc


PROTOCOL = "xtrace-bfv-tiled-v1"
SLOTS = 8192
PLAIN_MODULUS = 65537


@dataclass(frozen=True)
class Layout:
    """Fixed SEAL TC128 parameters, with zero padding for arbitrary dimensions."""

    dimension: int = 512

    def __post_init__(self) -> None:
        if type(self.dimension) is not int or not 1 <= self.dimension <= SLOTS // 2:
            raise ValueError(f"dimension must be an integer in [1, {SLOTS // 2}]")

    @property
    def padded_dimension(self) -> int:
        return 1 << (self.dimension - 1).bit_length()

    @property
    def lanes(self) -> int:
        return SLOTS // 2 // self.padded_dimension

    @property
    def vectors_per_ciphertext(self) -> int:
        return 2 * self.lanes

    def result_slot(self, position: int) -> int:
        """Map a candidate's position within a response block to its BFV slot."""
        tile, lane = divmod(position, self.vectors_per_ciphertext)
        row, column = divmod(lane, self.lanes)
        return row * (SLOTS // 2) + tile * self.lanes + column


def _context() -> Any:
    params = seal.EncryptionParameters(seal.SCHEME_TYPE.BFV)
    params.set_poly_modulus_degree(SLOTS)
    params.set_plain_modulus(PLAIN_MODULUS)
    params.set_coeff_modulus(seal.CoeffModulus.BFVDefault(SLOTS, seal.SEC_LEVEL_TYPE.TC128))
    context = seal.SEALContext(params, True, seal.SEC_LEVEL_TYPE.TC128)
    if not context.parameters_set() or not context.first_context_data().qualifiers().using_batching:
        raise ValueError(context.parameters_error_message())
    return context


def _save(obj: Any) -> bytes:
    # TenSEAL 0.3.16's low-level SEAL binding only exposes file-based save/load.
    # Only ciphertexts and public/evaluation keys pass through here, never secrets.
    with tempfile.TemporaryDirectory(prefix="xtrace-bfv-") as directory:
        path = Path(directory) / "object.seal"
        obj.save(str(path))
        return path.read_bytes()


def _load(cls: Any, context: Any, payload: object) -> Any:
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("Expected nonempty serialized SEAL bytes")
    with tempfile.TemporaryDirectory(prefix="xtrace-bfv-") as directory:
        path = Path(directory) / "object.seal"
        path.write_bytes(payload)
        obj = cls()
        obj.load(context, str(path))
        return obj


def _pack(kind: str, layout: Layout, key_id: str, **fields: Any) -> bytes:
    return msgpack.packb(
        dict(protocol=PROTOCOL, kind=kind, dimension=layout.dimension, key_id=key_id, **fields),
        use_bin_type=True,
    )


def _unpack(payload: bytes, kind: str) -> dict[str, Any]:
    if not isinstance(payload, bytes):
        raise ValueError("Protocol messages must be bytes")
    try:
        packet = msgpack.unpackb(payload, raw=False)
    except (ValueError, TypeError, msgpack.ExtraData) as exc:
        raise ValueError("Invalid MessagePack packet") from exc
    if not isinstance(packet, dict) or packet.get("protocol") != PROTOCOL or packet.get("kind") != kind:
        raise ValueError(f"Expected a {PROTOCOL} {kind} packet")
    dimension = packet.get("dimension")
    if type(dimension) is not int:
        raise ValueError("Missing or invalid dimension")
    Layout(dimension)
    if not isinstance(packet.get("key_id"), str) or len(packet["key_id"]) != 64:
        raise ValueError("Invalid key identifier")
    return packet


def _check_identity(packet: dict[str, Any], layout: Layout, key_id: str) -> None:
    if packet["dimension"] != layout.dimension or packet["key_id"] != key_id:
        raise ValueError("Packet belongs to a different key or dimension")


def _ids(values: Any) -> list[int]:
    if not isinstance(values, (list, tuple)):
        raise ValueError("IDs must be a list or tuple")
    if any(type(value) is not int or not 0 <= value < 2**64 for value in values):
        raise ValueError("IDs must be unsigned 64-bit integers")
    if len(set(values)) != len(values):
        raise ValueError("IDs must be unique")
    return list(values)


def _ciphertexts(packet: dict[str, Any], expected: int) -> list[bytes]:
    values = packet.get("ciphertexts")
    if not isinstance(values, list) or len(values) != expected:
        raise ValueError(f"Expected {expected} ciphertexts")
    if any(not isinstance(value, bytes) or not value for value in values):
        raise ValueError("Ciphertexts must be nonempty bytes")
    return values


def _vector(values: Sequence[int], dimension: int) -> list[int]:
    if len(values) != dimension:
        raise ValueError(f"Expected a {dimension}-dimensional binary vector")
    if any(not isinstance(value, Integral) or value not in (0, 1) for value in values):
        raise ValueError("Vector entries must be binary integers")
    return [int(value) for value in values]


class BfvClient:
    """Owns the BFV secret key. Construct a separate server from server_bundle()."""

    def __init__(self, dimension: int = 512) -> None:
        self.layout = Layout(dimension)
        self.context = _context()
        generator = seal.KeyGenerator(self.context)
        self._secret_key = generator.secret_key()
        self._public_key = seal.PublicKey()
        self._relin_keys = seal.RelinKeys()
        generator.create_public_key(self._public_key)
        generator.create_relin_keys(self._relin_keys)
        steps = [self.layout.lanes << i for i in range(self.layout.padded_dimension.bit_length() - 1)]
        # Pass explicit Galois elements: the binding has ambiguous list[int]
        # overloads for rotation steps versus elements. SEAL's generator is 3.
        elements = sorted({pow(3, step % (SLOTS // 2), 2 * SLOTS) for step in steps + [-v for v in steps]})
        self._galois_keys = seal.GaloisKeys() if elements else None
        if elements:
            generator.create_galois_keys(elements, self._galois_keys)
        self._public_bytes = _save(self._public_key)
        self.key_id = hashlib.sha256(self._public_bytes).hexdigest()
        self._encoder = seal.BatchEncoder(self.context)
        self._encryptor = seal.Encryptor(self.context, self._public_key)
        self._decryptor = seal.Decryptor(self.context, self._secret_key)

    def server_bundle(self) -> bytes:
        """Export public and evaluation keys only. Cache this once per key/layout."""
        return _pack(
            "keys", self.layout, self.key_id, public_key=self._public_bytes,
            relin_keys=_save(self._relin_keys),
            galois_keys=_save(self._galois_keys) if self._galois_keys is not None else b"",
        )

    def _encrypt(self, slots: list[int]) -> bytes:
        plain, encrypted = seal.Plaintext(), seal.Ciphertext()
        self._encoder.encode(slots, plain)
        self._encryptor.encrypt(plain, encrypted)
        return _save(encrypted)

    def encrypt_query(self, vector: Sequence[int]) -> bytes:
        bits = _vector(vector, self.layout.dimension)
        padded = bits + [0] * (self.layout.padded_dimension - len(bits))
        slots = [bit for _row in range(2) for bit in padded for _lane in range(self.layout.lanes)]
        return _pack("query", self.layout, self.key_id, ciphertexts=[self._encrypt(slots)])

    def encrypt_index(self, vectors: Sequence[Sequence[int]], ids: Sequence[int] | None = None) -> bytes:
        record_ids = _ids(list(range(len(vectors))) if ids is None else list(ids))
        if len(record_ids) != len(vectors):
            raise ValueError("IDs and vectors must have the same length")
        ciphertexts = []
        width = self.layout.vectors_per_ciphertext
        for start in range(0, len(vectors), width):
            slots = [0] * SLOTS
            for lane, vector in enumerate(vectors[start:start + width]):
                bits = _vector(vector, self.layout.dimension)
                row, column = divmod(lane, self.layout.lanes)
                for dim, bit in enumerate(bits):
                    slots[row * (SLOTS // 2) + dim * self.layout.lanes + column] = bit
            ciphertexts.append(self._encrypt(slots))
        return _pack("index", self.layout, self.key_id, ids=record_ids, ciphertexts=ciphertexts)

    def decrypt_distances(self, response: bytes) -> list[tuple[int, int]]:
        packet = _unpack(response, "distances")
        _check_identity(packet, self.layout, self.key_id)
        ids = _ids(packet.get("ids"))
        ciphertexts = _ciphertexts(packet, (len(ids) + SLOTS - 1) // SLOTS)
        results = []
        for block, payload in enumerate(ciphertexts):
            encrypted = _load(seal.Ciphertext, self.context, payload)
            if self._decryptor.invariant_noise_budget(encrypted) <= 0:
                raise ValueError("BFV noise budget exhausted; distances cannot be trusted")
            plain = seal.Plaintext()
            self._decryptor.decrypt(encrypted, plain)
            slots = self._encoder.decode_uint64(plain)
            for position, record_id in enumerate(ids[block * SLOTS:(block + 1) * SLOTS]):
                distance = slots[self.layout.result_slot(position)]
                if not 0 <= distance <= self.layout.dimension:
                    raise ValueError("Decrypted distance is outside the valid Hamming range")
                results.append((record_id, distance))
        return results

    def top_k(self, response: bytes, k: int = 3) -> list[tuple[int, int]]:
        """Return (ID, distance), ordered by distance and then ID to break ties."""
        if type(k) is not int or k < 0:
            raise ValueError("k must be a nonnegative integer")
        return heapq.nsmallest(k, self.decrypt_distances(response), key=lambda item: (item[1], item[0]))

    def noise_budgets(self, response: bytes) -> list[int]:
        """Local experiment diagnostic. Never send decryption/noise feedback to a server."""
        packet = _unpack(response, "distances")
        _check_identity(packet, self.layout, self.key_id)
        ids = _ids(packet.get("ids"))
        return [
            self._decryptor.invariant_noise_budget(_load(seal.Ciphertext, self.context, payload))
            for payload in _ciphertexts(packet, (len(ids) + SLOTS - 1) // SLOTS)
        ]


class BfvServer:
    """Public evaluator reconstructed solely from bytes, with no decryptor or secret key."""

    def __init__(self, public_bundle: bytes) -> None:
        packet = _unpack(public_bundle, "keys")
        self.layout = Layout(packet["dimension"])
        self.key_id = packet["key_id"]
        public_bytes = packet.get("public_key")
        if not isinstance(public_bytes, bytes) or hashlib.sha256(public_bytes).hexdigest() != self.key_id:
            raise ValueError("Public key fingerprint mismatch")
        self.context = _context()
        _load(seal.PublicKey, self.context, public_bytes)
        self._relin_keys = _load(seal.RelinKeys, self.context, packet.get("relin_keys"))
        self._galois_keys = (
            _load(seal.GaloisKeys, self.context, packet.get("galois_keys"))
            if self.layout.padded_dimension > 1 else None
        )
        self._evaluator = seal.Evaluator(self.context)
        self._encoder = seal.BatchEncoder(self.context)

    def _input(self, payload: bytes) -> Any:
        encrypted = _load(seal.Ciphertext, self.context, payload)
        if encrypted.size() != 2 or encrypted.parms_id() != self.context.first_parms_id():
            raise ValueError("Expected a fresh, size-2 BFV input ciphertext")
        return encrypted

    def _rotate(self, encrypted: Any, step: int) -> Any:
        result = seal.Ciphertext()
        self._evaluator.rotate_rows(encrypted, step, self._galois_keys, result)
        return result

    def _tile_distances(self, encrypted: Any, query: Any, count: int) -> Any:
        ev = self._evaluator
        result = seal.Ciphertext()
        # For bits, (x - q)^2 = x XOR q. Exactly one ciphertext multiplication.
        ev.sub(encrypted, query, result)
        ev.square_inplace(result)
        ev.relinearize_inplace(result, self._relin_keys)
        step = self.layout.lanes
        while step < SLOTS // 2:
            ev.add_inplace(result, self._rotate(result, step))
            step *= 2
        # Keep one distance per valid candidate and erase all duplicated sums,
        # including dummy candidates in an incomplete final tile.
        mask = [0] * SLOTS
        for lane in range(count):
            row, column = divmod(lane, self.layout.lanes)
            mask[row * (SLOTS // 2) + column] = 1
        plain_mask = seal.Plaintext()
        self._encoder.encode(mask, plain_mask)
        ev.multiply_plain_inplace(result, plain_mask)
        return result

    def _merge(self, left: Any, right: Any, left_tiles: int) -> Any:
        self._evaluator.add_inplace(left, self._rotate(right, -left_tiles * self.layout.lanes))
        return left

    def search(self, encrypted_index: bytes, encrypted_query: bytes, *, compact: bool = True) -> bytes:
        """Compute every distance, packing up to 8192 into each returned ciphertext.

        compact=False retains the computation modulus for a serialization/noise
        comparison. Both variants have identical plaintext results.
        """
        index = _unpack(encrypted_index, "index")
        query_packet = _unpack(encrypted_query, "query")
        _check_identity(index, self.layout, self.key_id)
        _check_identity(query_packet, self.layout, self.key_id)
        ids = _ids(index.get("ids"))
        width = self.layout.vectors_per_ciphertext
        tiles = _ciphertexts(index, (len(ids) + width - 1) // width)
        query = self._input(_ciphertexts(query_packet, 1)[0])
        output = []
        for group_start in range(0, len(tiles), self.layout.padded_dimension):
            # Binary carry tree: logarithmic working ciphertext memory; each
            # merge uses one power-of-two rotation, including incomplete groups.
            pending: list[tuple[Any, int]] = []
            for tile_index in range(group_start, min(len(tiles), group_start + self.layout.padded_dimension)):
                count = min(width, len(ids) - tile_index * width)
                current = self._tile_distances(self._input(tiles[tile_index]), query, count)
                span = 1
                while pending and pending[-1][1] == span:
                    left, _ = pending.pop()
                    current = self._merge(left, current, span)
                    span *= 2
                pending.append((current, span))
            current, _ = pending.pop()
            while pending:
                left, span = pending.pop()
                current = self._merge(left, current, span)
            if compact:
                self._evaluator.mod_switch_to_inplace(current, self.context.last_parms_id())
            output.append(_save(current))
        return _pack("distances", self.layout, self.key_id, ids=ids, ciphertexts=output)
