"""Guarded local interface for the isolated Q67 public evaluator prototype.

This evaluator has no secret key or authentication authority. Its public phase
bounds are honest owner metadata, not evidence granting decryption of a server
response. Use complete public replay for tiny tests; a complete native admission
controller for this changed semantic relation is not implemented yet.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
from pathlib import Path

from gmpy2 import mpz

from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import propagated_gadget_bgv as propagated
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


def load_backend(path: Path | str):
    path = Path(path).resolve(strict=True)
    if not path.name.startswith("_bgv_propagated."):
        raise ValueError("Explicit isolated propagation extension required")
    spec = importlib.util.spec_from_file_location("_bgv_propagated", path)
    if spec is None or spec.loader is None:
        raise ValueError("Cannot load propagation prototype")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def fixed(poly, n, q):
    if len(poly) != n or any(not 0 <= int(x) < q for x in poly):
        raise ValueError("Canonical Q120 polynomial required")
    return b"".join(int(x).to_bytes(15, "little") for x in poly)


@dataclass(frozen=True)
class PreparedIndex:
    owner: object
    handle: object
    bounds: tuple[int, ...]
    count: int


class NativePlan:
    """Public prepared plan; source propagation is exact under public guards."""

    def __init__(
        self, pk: bgv.PublicKey, keys: trace.EvaluationKeys, backend, *, propagate=True
    ):
        butterfly.validate_keys(pk, keys)
        if (
            pk.q.bit_length() != 120
            or pk.n > 16384
            or keys.digit_bits != 30
            or type(propagate) is not bool
        ):
            raise ValueError("Fixed Q120/30-bit prototype profile required")
        self.pk, self.keys, self.backend, self.propagate = pk, keys, backend, propagate
        public_keys = tuple(
            tuple(tuple(fixed(p, pk.n, int(pk.q)) for p in pair) for pair in key)
            for key in (keys.relin, *(k for _, k in keys.rotations))
        )
        self.handle = backend.create_server(
            pk.n, format(pk.q, "x"), keys.padded, public_keys, propagate
        )
        self._identity = object()

    def prepare(self, index: list[bgv.Ciphertext], count: int) -> PreparedIndex:
        capacity = self.pk.n // self.keys.padded
        if (
            type(count) is not int
            or count < 1
            or len(index) != (count + capacity - 1) // capacity
        ):
            raise ValueError("Wrong index coverage")
        for c in index:
            bgv._validate(c, self.pk)
            if len(c.components) != 2:
                raise ValueError("Two-component fresh index required")
        pairs = tuple(
            tuple(fixed(p, self.pk.n, int(self.pk.q)) for p in c.components)
            for c in index
        )
        return PreparedIndex(
            self._identity,
            self.backend.prepare_index(self.handle, pairs),
            tuple(int(c.phase_bound) for c in index),
            count,
        )

    def search(self, query: bgv.Ciphertext, index: PreparedIndex, *, terminal_bits=25):
        if type(index) is not PreparedIndex or index.owner is not self._identity:
            raise ValueError("Mixed prototype index context")
        bgv._validate(query, self.pk)
        if len(query.components) != 2:
            raise ValueError("Two-component query required")
        p = compact.terminal_modulus(self.pk.q, self.pk.t, terminal_bits)
        models = [
            propagated.model(
                self.pk.n,
                int(self.pk.q),
                self.pk.t,
                self.pk.eta,
                self.keys.padded,
                len(index.bounds[start : start + self.keys.padded]),
                30,
                int(query.phase_bound),
                max(index.bounds[start : start + self.keys.padded]),
                propagated_stages=int(self.propagate),
                terminal=int(p),
            )
            for start in range(0, len(index.bounds), self.keys.padded)
        ]
        if any(not m["Q_guard"] or not m["terminal_guard"] for m in models):
            raise ValueError("Public propagation/terminal guard failed")
        request = tuple(fixed(p, self.pk.n, int(self.pk.q)) for p in query.components)
        output = self.backend.search(self.handle, request, index.handle)
        if len(output) != len(models):
            raise RuntimeError("Wrong native response group count")
        return [
            bgv.Ciphertext(
                tuple(
                    tuple(
                        mpz(int.from_bytes(p[i : i + 15], "little"))
                        for i in range(0, len(p), 15)
                    )
                    for p in pair
                ),
                self.pk.key_id,
                m["full_phase_bound"],
            )
            for pair, m in zip(output, models, strict=True)
        ]
