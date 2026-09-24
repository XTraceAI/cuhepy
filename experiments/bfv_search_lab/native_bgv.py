"""Public-only native evaluator for the isolated BGV coefficient experiments.

No secret key crosses this boundary. Prepared keys/index retain immutable NTT
representations; query and response coefficients cross Python exactly once.
The native arithmetic is variable-time. This is not an authenticated protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib
from typing import Any

import gmpy2
from gmpy2 import mpz

from cuhepy.types import BFVPolynomial
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import butterfly_bgv as butterfly


@dataclass(frozen=True)
class PreparedIndex:
    owner: object
    handle: Any
    phase_bounds: tuple[int, ...]
    count: int


class NativeServer:
    """Explicit opt-in lab backend; package BFV/Paillier behavior is unchanged."""

    def __init__(self, pk: bgv.PublicKey, keys: trace.EvaluationKeys, *, residue: bool = False,
                 device: str = "cpu") -> None:
        if device not in ("cpu", "cuda") or (device == "cuda" and not residue):
            raise ValueError("CUDA requires explicit persistent RNS mode")
        module = "_bgv_trace_cuda" if device == "cuda" else "_bgv_trace"
        _bgv_trace = importlib.import_module(f"experiments.bfv_search_lab._native.{module}")

        butterfly.validate_keys(pk, keys)
        self.pk, self.keys = pk, keys
        self._native = _bgv_trace
        self.width = (pk.q.bit_length() + 7) // 8
        self._identity = object()
        self._server = _bgv_trace.create_server(
            pk.n, format(pk.q, "x"), keys.digit_bits, keys.padded,
            tuple(tuple((self._pack(b), self._pack(a)) for b, a in key)
                  for key in (keys.relin, *(key for _, key in keys.rotations))),
            residue,
        )

    def _pack(self, poly: BFVPolynomial) -> bytes:
        return gmpy2.pack(list(poly), self.width * 8).to_bytes(self.pk.n * self.width, "little")

    def _unpack(self, poly: bytes) -> BFVPolynomial:
        values = gmpy2.unpack(mpz.from_bytes(poly, "little"), self.width * 8)
        values.extend([mpz(0)] * (self.pk.n - len(values)))
        return tuple(values)

    def prepare_index(self, index: list[bgv.Ciphertext], count: int) -> PreparedIndex:
        capacity = self.pk.n // self.keys.padded
        if type(count) is not int or count < 0 or len(index) != (count + capacity - 1) // capacity:
            raise ValueError("Invalid native trace index shape")
        for tile in index:
            bgv._validate(tile, self.pk)
            if len(tile.components) != 2:
                raise ValueError("Native trace inputs need two components")
        handle = self._native.prepare_index(
            self._server, tuple(tuple(self._pack(poly) for poly in ct.components) for ct in index)
        )
        return PreparedIndex(self._identity, handle, tuple(ct.phase_bound for ct in index), count)

    def search(self, query: bgv.Ciphertext, index: PreparedIndex,
               *, joint: bool = True) -> list[bgv.Ciphertext]:
        if index.owner is not self._identity or type(joint) is not bool:
            raise ValueError("Wrong native trace context or mode")
        bgv._validate(query, self.pk)
        if len(query.components) != 2:
            raise ValueError("Native trace inputs need two components")
        d, error = self.keys.padded, self.keys.switch_error_bound
        bounds = []
        for start in range(0, len(index.phase_bounds), d):
            relinearized = [self.pk.n * query.phase_bound * b + error
                            for b in index.phase_bounds[start:start + d]]
            if joint:
                bound, _ = butterfly.schedule(d, relinearized, error)
            else:
                bound = sum(d * b + (d - 1) * error for b in relinearized)
            if 2 * bound >= self.pk.q:
                raise ValueError("Native trace correctness bound exceeds Q/2")
            bounds.append(bound)
        output = self._native.search(self._server, tuple(self._pack(p) for p in query.components),
                                     index.handle, joint)
        return [bgv.Ciphertext(tuple(self._unpack(p) for p in pair), self.pk.key_id, bound)
                for pair, bound in zip(output, bounds, strict=True)]
