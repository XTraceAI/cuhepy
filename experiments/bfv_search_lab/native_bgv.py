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
from experiments.bfv_search_lab import compact_bgv as compact


@dataclass(frozen=True)
class PreparedIndex:
    owner: object
    handle: Any
    phase_bounds: tuple[int, ...]
    count: int


class NativeServer:
    """Explicit opt-in lab backend; package BFV/Paillier behavior is unchanged."""

    def __init__(self, pk: bgv.PublicKey, keys: trace.EvaluationKeys, *, residue: bool = False,
                 device: str = "cpu", cuda_level: int = 0) -> None:
        if device not in ("cpu", "cuda") or (device == "cuda" and not residue):
            raise ValueError("CUDA requires explicit persistent RNS mode")
        if type(cuda_level) is not int or not 0 <= cuda_level <= 4 or (device != "cuda" and cuda_level):
            raise ValueError("Invalid CUDA kernel level")
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
            residue, cuda_level,
        )

    def _pack(self, poly: BFVPolynomial) -> bytes:
        return gmpy2.pack(list(poly), self.width * 8).to_bytes(self.pk.n * self.width, "little")

    def _unpack(self, poly: bytes, width: int | None = None) -> BFVPolynomial:
        width = self.width if width is None else width
        if len(poly) != self.pk.n * width:
            raise ValueError("Incorrect native output polynomial length")
        values = gmpy2.unpack(mpz.from_bytes(poly, "little"), width * 8)
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

    def _bounds(self, query: bgv.Ciphertext, index: PreparedIndex, joint: bool) -> list[int]:
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
        return bounds

    def search(self, query: bgv.Ciphertext, index: PreparedIndex,
               *, joint: bool = True) -> list[bgv.Ciphertext]:
        bounds = self._bounds(query, index, joint)
        output = self._native.search(self._server, tuple(self._pack(p) for p in query.components),
                                     index.handle, joint)
        return [bgv.Ciphertext(tuple(self._unpack(p) for p in pair), self.pk.key_id, bound)
                for pair, bound in zip(output, bounds, strict=True)]

    def search_compact(self, query: bgv.Ciphertext, index: PreparedIndex, *, joint: bool = True,
                       bits: int = 32) -> list[compact.CompactCiphertext]:
        """Reduce in C++ before exporting; identical rounding and public bounds."""
        bounds = self._bounds(query, index, joint)
        p = compact.terminal_modulus(self.pk.q, self.pk.t, bits)
        reduced = [compact.reduced_bound(bound, self.pk, p) for bound in bounds]
        output = self._native.search_compact(
            self._server, tuple(self._pack(poly) for poly in query.components), index.handle,
            joint, self.pk.t, format(p, "x"),
        )
        width = (p.bit_length() + 7) // 8
        return [compact.CompactCiphertext((self._unpack(pair[0], width), self._unpack(pair[1], width)),
                                         self.pk.key_id, p, bound)
                for pair, bound in zip(output, reduced, strict=True)]

    def compact_result(self, cipher: bgv.Ciphertext, bits: int = 32) -> compact.CompactCiphertext:
        """Standalone public reduction, including both native boundary conversions."""
        bgv._validate(cipher, self.pk)
        if len(cipher.components) != 2:
            raise ValueError("Terminal BGV reduction requires two components")
        p = compact.terminal_modulus(self.pk.q, self.pk.t, bits)
        bound = compact.reduced_bound(cipher.phase_bound, self.pk, p)
        pair = self._native.compact_result(
            self._server, tuple(self._pack(poly) for poly in cipher.components), self.pk.t, format(p, "x"),
        )
        width = (p.bit_length() + 7) // 8
        return compact.CompactCiphertext((self._unpack(pair[0], width), self._unpack(pair[1], width)),
                                         self.pk.key_id, p, bound)
