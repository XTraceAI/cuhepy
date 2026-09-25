"""Public-only native evaluator for the isolated BGV coefficient experiments.

No secret key crosses this boundary. Prepared keys/index retain immutable NTT
representations; query and response coefficients cross Python exactly once.
The native arithmetic is variable-time. This is not an authenticated protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import os
from typing import Any, SupportsIndex

import gmpy2
from gmpy2 import mpz

from cuhepy.types import BFVPolynomial
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import transport_bgv as wire

NTT_VARIANTS = ("baseline", "indexed", "warp1024", "warp512", "warp2048")


@dataclass(frozen=True)
class PreparedIndex:
    owner: object
    handle: Any
    phase_bounds: tuple[int, ...]
    count: int


class NativeServer:
    """Explicit opt-in lab backend; package BFV/Paillier behavior is unchanged."""

    def __init__(self, pk: bgv.PublicKey, keys: trace.EvaluationKeys, *, residue: bool = False,
                 device: str = "cpu", cuda_level: int = 0, ntt_variant: str = "baseline") -> None:
        if device not in ("cpu", "cuda") or (device == "cuda" and not residue):
            raise ValueError("CUDA requires explicit persistent RNS mode")
        if type(cuda_level) is not int or not 0 <= cuda_level <= 4 or (device != "cuda" and cuda_level):
            raise ValueError("Invalid CUDA kernel level")
        if ntt_variant not in NTT_VARIANTS or (device != "cuda" and ntt_variant != "baseline"):
            raise ValueError("Invalid CUDA NTT variant")
        module = "_bgv_trace_cuda" if device == "cuda" else "_bgv_trace"
        _bgv_trace = importlib.import_module(f"experiments.bfv_search_lab._native.{module}")

        butterfly.validate_keys(pk, keys)
        self.pk, self.keys = pk, keys
        self._native = _bgv_trace
        self._device, self._cuda_level = device, cuda_level
        self.ntt_variant = ntt_variant
        self.width = (pk.q.bit_length() + 7) // 8
        self._identity = object()
        self._server = _bgv_trace.create_server(
            pk.n, format(pk.q, "x"), keys.digit_bits, keys.padded,
            tuple(tuple((self._pack(b), self._pack(a)) for b, a in key)
                  for key in (keys.relin, *(key for _, key in keys.rotations))),
            residue, cuda_level, NTT_VARIANTS.index(ntt_variant),
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

    def batch_workspace_bytes(self, index: PreparedIndex, requests: int) -> int:
        """Coefficient buffers only; index, keys, host memory and runtime excluded."""
        if index.owner is not self._identity or type(requests) is not int or not 0 <= requests <= 8:
            raise ValueError("Invalid batch workspace context/count")
        maximum = min(self.keys.padded, len(index.phase_bounds))
        return requests * (4 + 26 * maximum) * self.pk.n * 8 if maximum else 0

    def prepare_workspace(self, index: PreparedIndex) -> GPUWorkspace:
        """Allocate one explicit reusable lease; caller budgets concurrent leases."""
        if self._device != "cuda" or self._cuda_level != 4 or index.owner is not self._identity:
            raise ValueError("Persistent workspace requires this server's index and CUDA level 4")
        return GPUWorkspace(self, index)

    def _many_bounds(self, queries: list[bgv.Ciphertext], index: PreparedIndex,
                     batch_size: int, shared_index: bool) -> list[list[int]]:
        if (self._device != "cuda" or self._cuda_level != 4
            or type(batch_size) is not int or not 1 <= batch_size <= 8
            or type(shared_index) is not bool or len(queries) > 32):
            raise ValueError("Batched search requires CUDA level 4, batch size 1..8 and at most 32 queries")
        if self.batch_workspace_bytes(index, min(batch_size, len(queries))) > (4 << 30):
            raise ValueError("Batched coefficient workspace exceeds 4 GiB; reduce batch_size")
        return [self._bounds(query, index, True) for query in queries]

    def search_many(self, queries: list[bgv.Ciphertext], index: PreparedIndex,
                    *, batch_size: int = 4, shared_index: bool = True) -> list[list[bgv.Ciphertext]]:
        """Same-index, same-key distinct queries; joint circuit only, opt-in batching."""
        bounds = self._many_bounds(queries, index, batch_size, shared_index)
        output = self._native.search_many(
            self._server, tuple(tuple(self._pack(p) for p in q.components) for q in queries),
            index.handle, batch_size, shared_index,
        )
        return [[bgv.Ciphertext(tuple(self._unpack(p) for p in pair), self.pk.key_id, bound)
                 for pair, bound in zip(response, group_bounds, strict=True)]
                for response, group_bounds in zip(output, bounds, strict=True)]

    def search_many_compact(self, queries: list[bgv.Ciphertext], index: PreparedIndex,
                            *, batch_size: int = 4, shared_index: bool = True,
                            bits: int = 32) -> list[list[compact.CompactCiphertext]]:
        bounds = self._many_bounds(queries, index, batch_size, shared_index)
        p = compact.terminal_modulus(self.pk.q, self.pk.t, bits)
        reduced = [[compact.reduced_bound(b, self.pk, p) for b in group] for group in bounds]
        output = self._native.search_many_compact(
            self._server, tuple(tuple(self._pack(c) for c in q.components) for q in queries),
            index.handle, batch_size, shared_index, self.pk.t, format(p, "x"),
        )
        width = (p.bit_length() + 7) // 8
        return [[compact.CompactCiphertext((self._unpack(pair[0], width), self._unpack(pair[1], width)),
                                           self.pk.key_id, p, bound)
                 for pair, bound in zip(response, group_bounds, strict=True)]
                for response, group_bounds in zip(output, reduced, strict=True)]


class GPUWorkspace:
    """Single-request scratch and stream, serialized by a native lease lock.

    Separate instances can overlap on the GPU. Each call returns its own result;
    no batch barrier or request mixing. Close waits for native use to finish.
    """

    def __init__(self, server: NativeServer, index: PreparedIndex) -> None:
        if server._device != "cuda" or server._cuda_level != 4 or index.owner is not server._identity:
            raise ValueError("Persistent workspace requires this server's index and CUDA level 4")
        self.server, self.index = server, index
        self.coefficient_bytes = max(4 * server.pk.n * 8, server.batch_workspace_bytes(index, 1))
        self._terminal_allocated = False
        self._pid = os.getpid()
        self._handle = server._native.prepare_workspace(index.handle)

    def _check_process(self) -> None:
        if os.getpid() != self._pid:
            raise RuntimeError("Create a new GPU workspace after fork")

    def search_compact(self, query: bgv.Ciphertext, *, bits: int = 32,
                       gpu_terminal: bool = False) -> list[compact.CompactCiphertext]:
        self._check_process()
        if type(gpu_terminal) is not bool:
            raise ValueError("GPU terminal mode must be bool")
        server = self.server
        bounds = server._bounds(query, self.index, True)
        p = compact.terminal_modulus(server.pk.q, server.pk.t, bits)
        reduced = [compact.reduced_bound(bound, server.pk, p) for bound in bounds]
        function = (server._native.search_workspace_compact_gpu if gpu_terminal
                    else server._native.search_workspace_compact)
        output = function(
            self._handle, tuple(server._pack(poly) for poly in query.components), server.pk.t, format(p, "x"),
        )
        if gpu_terminal and not self._terminal_allocated and bounds:
            self.coefficient_bytes += 2 * server.pk.n * 8
            self._terminal_allocated = True
        width = (p.bit_length() + 7) // 8
        return [compact.CompactCiphertext((server._unpack(pair[0], width), server._unpack(pair[1], width)),
                                         server.pk.key_id, p, bound)
                for pair, bound in zip(output, reduced, strict=True)]

    def close(self) -> None:
        self._check_process()
        self.server._native.close_workspace(self._handle)

    def search_packet(self, query: bgv.Ciphertext, dimension: int, *, bits: int = 32,
                      gpu_terminal: bool = False) -> tuple[bytes, list[int]]:
        """Same compact-v1 bytes, without Python coefficient export/reimport.

        Bounds are computed locally and returned separately, never from a wire
        field. The envelope remains a trusted fixture without authentication.
        """
        self._check_process()
        if type(gpu_terminal) is not bool:
            raise ValueError("GPU terminal mode must be bool")
        server = self.server
        p = compact.terminal_modulus(server.pk.q, server.pk.t, bits)
        wire._context(server.pk, self.index.count, dimension, p)
        bounds = [compact.reduced_bound(b, server.pk, p)
                  for b in server._bounds(query, self.index, True)]
        function = (server._native.search_workspace_packed_gpu if gpu_terminal
                    else server._native.search_workspace_packed)
        pairs = function(self._handle, tuple(server._pack(poly) for poly in query.components),
                         server.pk.t, format(p, "x"))
        if gpu_terminal and not self._terminal_allocated:
            self.coefficient_bytes += 2 * server.pk.n * 8
            self._terminal_allocated = True
        packet = wire.pack_native_fixture(pairs, server.pk, count=self.index.count,
                                           dimension=dimension, modulus=p)
        return packet, bounds

    def __enter__(self) -> GPUWorkspace:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise TypeError("GPU workspaces cannot be copied or serialized")
