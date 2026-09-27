"""Encrypted partial-sum experiment; raw local evaluation, without attestation.

The layout is a trusted caller choice, never inferred from decrypted contents.
It reveals coordinate-block distances to the owner. These methods are not wired
into the production-facing BFV client or its verification protocols.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from cuhepy.bfv.cuda import BFVCudaServer
from cuhepy.bfv.evaluator import BFVEvaluator
from cuhepy.bfv.native import BFVNativeServer
from cuhepy.bfv.private import BFVPrivateDecoder
from cuhepy.bfv.rns import BFVRNSArithmetic
from cuhepy.bfv.scheme import BFV
from cuhepy.hamming.bfv import BFVClient
from cuhepy.types import BFVCiphertext, EncryptedVector


@dataclass(frozen=True)
class PartialLayout:
    n: int
    dimension: int
    partials: int = 1

    def __post_init__(self) -> None:
        if (
            type(self.n) is not int
            or self.n < 2
            or self.n & (self.n - 1)
            or type(self.dimension) is not int
            or not 1 <= self.dimension <= self.n // 2
        ):
            raise ValueError("Invalid partial layout dimension/ring")
        if (
            type(self.partials) is not int
            or not 1 <= self.partials <= self.padded
            or self.partials & (self.partials - 1)
        ):
            raise ValueError("Invalid partial-sum count")

    @property
    def padded(self) -> int:
        return 1 << (self.dimension - 1).bit_length()

    @property
    def span(self) -> int:
        return self.padded // self.partials

    @property
    def lanes(self) -> int:
        return self.n // (2 * self.padded)

    @property
    def response_capacity(self) -> int:
        return self.n // self.partials

    def decode(
        self,
        owner: BFVClient,
        ciphers: Sequence[Sequence[int | bytes]],
        count: int,
        private: BFVPrivateDecoder | None = None,
    ) -> list[int]:
        if owner.params.poly_modulus_degree != self.n or owner.embed_len != self.dimension:
            raise ValueError("Owner and partial layout differ")
        owner._validate_count(count, len(ciphers), self.response_capacity)
        if private and self.partials == 1 and count:
            # Preserve the accepted client's exact decode path in C=1 benchmarks.
            return private.decode_packed(ciphers, count)
        lanes, capacity, half = self.lanes, self.response_capacity, self.n // 2
        bands = [
            (part * self.span * lanes, max(0, min(self.span, self.dimension - part * self.span)))
            for part in range(self.partials)
        ]
        result = []
        for group, cipher in enumerate(ciphers):
            slots = private.decode_slots(cipher) if private else owner._decode_slots(cipher)
            for position in range(min(capacity, count - group * capacity)):
                tile, lane = divmod(position, 2 * lanes)
                row, column = divmod(lane, lanes)
                at = row * half + tile * lanes + column
                distance = 0
                for offset, maximum in bands:
                    value = slots[at + offset]
                    if not 0 <= value <= maximum:
                        raise ValueError("Partial distance out of range")
                    distance += value
                result.append(distance)
        return result


class PartialNativeServer(BFVNativeServer):
    def __init__(
        self, arithmetic: BFVRNSArithmetic, layout: PartialLayout, response_bits: int
    ) -> None:
        if arithmetic.n != layout.n:
            raise ValueError("Arithmetic and layout rings differ")
        self.layout = layout
        super().__init__(arithmetic, layout.padded, response_bits)

    def _create_server(self, *args: Any) -> Any:
        if not hasattr(self._extension, "create_partial_server"):
            raise RuntimeError("Rebuild the research BFV CPU extension")
        return self._extension.create_partial_server(*args, self.layout.partials)


class PartialCudaServer(BFVCudaServer):
    def __init__(
        self,
        arithmetic: BFVRNSArithmetic,
        layout: PartialLayout,
        response_bits: int,
        *,
        kernel_level: int = 3,
        batch_tiles: int = 32,
    ) -> None:
        if arithmetic.n != layout.n:
            raise ValueError("Arithmetic and layout rings differ")
        self.layout = layout
        super().__init__(
            arithmetic,
            layout.padded,
            response_bits,
            kernel_level=kernel_level,
            batch_tiles=batch_tiles,
        )

    def _create_server(self, *args: Any) -> Any:
        if not hasattr(self._extension, "create_partial_server"):
            raise RuntimeError("Rebuild the research BFV CUDA extension")
        return self._extension.create_partial_server(
            *args, self._kernel_level, self._batch_tiles, self.layout.partials
        )


def reference_search(
    client: BFVClient,
    query: EncryptedVector,
    index: list[EncryptedVector],
    count: int,
    layout: PartialLayout,
    *,
    compact: bool = True,
) -> list[EncryptedVector]:
    """Independent Python BFV circuit, with the same binary merge order as C++."""
    if client.params.poly_modulus_degree != layout.n or client.embed_len != layout.dimension:
        raise ValueError("Client and partial layout differ")
    capacity = 2 * layout.lanes
    client._validate_count(count, len(index), capacity)
    pk = client._pk()
    evaluator = BFVEvaluator(pk, "reference")
    query_ct = BFV.ciphertext_from_ints(query, pk)
    steps = [layout.lanes * (1 << i) for i in range(layout.span.bit_length() - 1)]
    result = []
    for start in range(0, len(index), layout.span):
        stack: list[tuple[BFVCiphertext, int]] = []
        for offset, wire in enumerate(index[start : start + layout.span]):
            valid = min(capacity, count - (start + offset) * capacity)
            mask = [0] * layout.n
            for part in range(layout.partials):
                for lane in range(valid):
                    row, column = divmod(lane, layout.lanes)
                    mask[row * (layout.n // 2) + part * layout.span * layout.lanes + column] = 1
            tile = evaluator.hamming_tile(
                query_ct,
                BFV.ciphertext_from_ints(wire, pk),
                steps,
                BFV.batch_encode(mask, client.params),
            )
            size = 1
            while stack and stack[-1][1] == size:
                left, _ = stack.pop()
                tile = evaluator.add(left, evaluator.rotate_rows(tile, -layout.lanes * size))
                size *= 2
            stack.append((tile, size))
        combined, _ = stack.pop()
        while stack:
            left, size = stack.pop()
            combined = evaluator.add(left, evaluator.rotate_rows(combined, -layout.lanes * size))
        if compact:
            combined = BFV.modulus_switch(combined, client.response_modulus_bits, pk)
        result.append(BFV.ciphertext_to_ints(combined, pk))
    return result
