"""Optional public C++ evaluator for the E29 transposed CRT representation.

This is a short-subring NTT on full-ring ciphertext coefficient fibers, not
encryption with a smaller secret/ring. The independent GMP path remains the
reference. Private mask expansion, fingerprints and HE secrets stay outside
this server backend. No authentication or constant-time claim is added here.
"""

from __future__ import annotations

import importlib
import struct

import gmpy2
from gmpy2 import mpz

from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import shallow_bgv as bgv


def pack(values: tuple[bgv.Ciphertext, ...]) -> bytes:
    words = [int(x) for c in values for p in c.components for x in p]
    return struct.pack(f"<{len(words)}Q", *words)


class NativeIndex:
    def __init__(self, index: masked.Index, pk: bgv.PublicKey):
        _crt_subring = importlib.import_module("experiments.bfv_search_lab._subring._crt_subring")

        crt.validate(index.space)
        masked.binding(index.epoch, bytes(16))
        if (_crt_subring.ABI_VERSION != 1 or not gmpy2.is_prime(pk.q) or not 3 <= pk.q < 1 << 60
                or (pk.n, pk.t) != (index.space.layout.context.n, index.space.layout.context.prime)
                or len(index.columns) != index.space.columns or (pk.q - 1) % (2 * index.space.slots)):
            raise ValueError("Expected a prime word modulus with subring roots")
        self.space, self.epoch, self.pk = index.space, index.epoch, pk
        count = self.space.layout.cost.response_ciphertexts
        for column in index.columns:
            masked.validate_ciphertexts(column, count, pk)
        self._bounds = tuple(tuple(c.phase_bound for c in column) for column in index.columns)
        self._native = _crt_subring
        self._handles = []
        q = int(pk.q)
        # E30 mixes scalar columns and local CRT columns. Chain raw native
        # buffers so their partial sums require no intermediate Python integers.
        for slots in dict.fromkeys(self.space.column_degrees):
            positions = tuple(j for j, degree in enumerate(self.space.column_degrees) if degree == slots)
            psi = next((pow(a, (q - 1) // (2 * slots), q) for a in range(2, 1000)
                        if pow(pow(a, (q - 1) // (2 * slots), q), slots, q) == q - 1), None)
            if psi is None:
                raise ValueError("No subring root found in the bounded search")
            handle = _crt_subring.prepare(pk.n, slots, len(positions), count, q, psi,
                                         b"".join(pack(index.columns[j]) for j in positions))
            self._handles.append((positions, handle))

    def evaluate(self, answer: masked.Answer, request: masked.Request) -> tuple[bgv.Ciphertext, ...]:
        masked.validate_request(request)
        masked.binding(answer.epoch, answer.token_id)
        if (request.space != self.space or answer.space != self.space or request.epoch != self.epoch
                or answer.epoch != self.epoch or request.token_id != answer.token_id):
            raise ValueError("Prepared subring index/token/request mismatch")
        masked.validate_ciphertexts(answer.ciphertexts, self.space.layout.cost.response_ciphertexts, self.pk)
        short = crt.corrections(self.space, request.delta)
        norms = tuple(sum(map(abs, p)) for p in short)
        limits = tuple(c.phase_bound + sum(v * bounds[i] for v, bounds in zip(norms, self._bounds, strict=True))
                       for i, c in enumerate(answer.ciphertexts))
        if any(2 * b >= self.pk.q for b in limits):
            raise ValueError("Prepared linear phase bound exceeds Q")
        data = pack(answer.ciphertexts)
        for positions, handle in self._handles:
            weights = [v for j in positions for v in short[j]]
            data = self._native.evaluate(handle, struct.pack(f"<{len(weights)}q", *weights), data)
        words = tuple(mpz(v) for v in struct.unpack(f"<{len(data) // 8}Q", data))
        n = self.pk.n
        return tuple(bgv.Ciphertext((words[2 * i * n:(2 * i + 1) * n], words[(2 * i + 1) * n:(2 * i + 2) * n]),
                                   self.pk.key_id, limit) for i, limit in enumerate(limits))
