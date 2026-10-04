"""Small public adapter for the isolated exact two-prime residual kernel.

Common-Q source grammar and owner profiles are validated in Python. This
diagnostic eagerly marshals the small complete input families; it is not a
large streaming parser, signer, attested controller or private release API.
No SEAL is used. Deterministic full-vector equality needs no challenge coins.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from pathlib import Path
import os
import weakref

from cuhepy.bfv.scheme import _rns_coefficient_primes
from experiments.bfv_search_lab import noise_cut_fusion as fusion
from experiments.bfv_search_lab import noise_cut_relation as relation


Word = ctypes.c_uint64
Size = ctypes.c_size_t
Pointer = ctypes.POINTER(Word)


def words(values):
    return (Word * len(values))(*values)


def load_backend(path):
    path = Path(path).resolve(strict=True)
    if path.name != "libnoise_cut_kernel.so":
        raise ValueError("Explicit isolated kernel library required")
    backend = ctypes.CDLL(str(path))
    backend.cuhepy_noise_cut_create.argtypes = [
        Size,
        Word,
        Word,
        Size,
        Pointer,
        Size,
        Pointer,
        Size,
        Pointer,
        Size,
    ]
    backend.cuhepy_noise_cut_create.restype = ctypes.c_void_p
    backend.cuhepy_noise_cut_destroy.argtypes = [ctypes.c_void_p]
    backend.cuhepy_noise_cut_destroy.restype = None
    backend.cuhepy_noise_cut_check.argtypes = [ctypes.c_void_p, Pointer, Size]
    backend.cuhepy_noise_cut_check.restype = ctypes.c_int
    backend.cuhepy_noise_cut_residuals.argtypes = [
        ctypes.c_void_p,
        Pointer,
        Size,
        Pointer,
    ]
    backend.cuhepy_noise_cut_residuals.restype = ctypes.c_int
    if hasattr(backend, "cuhepy_noise_cut_create_wire"):
        backend.cuhepy_noise_cut_create_wire.argtypes = [
            *backend.cuhepy_noise_cut_create.argtypes,
            Pointer,
            Size,
            Size,
            ctypes.c_char_p,
            Size,
        ]
        backend.cuhepy_noise_cut_create_wire.restype = ctypes.c_void_p
        backend.cuhepy_noise_cut_check_wire.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            Size,
        ]
        backend.cuhepy_noise_cut_check_wire.restype = ctypes.c_int
        backend.cuhepy_noise_cut_residuals_wire.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            Size,
            Pointer,
        ]
        backend.cuhepy_noise_cut_residuals_wire.restype = ctypes.c_int
    return backend


@dataclass(frozen=True)
class Kernel:
    statement: relation.Relation
    graph: fusion.Graph
    input_names: tuple[tuple, ...]
    primes: tuple[int, int]
    backend: object
    handle: int
    owner_pid: int

    @classmethod
    def prepare(cls, statement, graph, constants, backend):
        if (
            type(statement) is not relation.Relation
            or type(graph) is not fusion.Graph
            or (graph.n, graph.q) != (statement.n, statement.q)
            or graph.n > 128
            or len(graph.residuals)
            != len(statement.source_layout) + 2 * statement.groups
        ):
            raise ValueError("Complete enrolled small public relation required")
        primes = tuple(map(int, _rns_coefficient_primes(graph.n, graph.q.bit_length())))
        if len(primes) != 2 or primes[0] * primes[1] != graph.q:
            raise ValueError("Exact original Q must be the actual two native primes")
        graph = fusion.prune(graph)
        prepared = fusion.coefficients(graph, constants)
        names = tuple(
            dict.fromkeys(node.value for node in graph.nodes if node.kind == "input")
        )
        public_names = tuple(prepared)
        input_at = {name: i for i, name in enumerate(names)}
        public_at = {name: i for i, name in enumerate(public_names)}
        codes = {
            "zero": 0,
            "input": 1,
            "add": 2,
            "sub": 3,
            "scale": 4,
            "multiply": 5,
            "permute": 6,
        }
        descriptions = []
        for at, node in enumerate(graph.nodes):
            if node.kind not in codes or any(
                type(a) is not int or not 0 <= a < at for a in node.args
            ):
                raise ValueError("Wrong enrolled acyclic native program")
            a, b = (*node.args, 0, 0)[:2]
            value0 = value1 = 0
            if node.kind == "input":
                value0 = input_at[node.value]
            elif node.kind == "multiply":
                value0 = public_at[node.value]
            elif node.kind == "scale":
                value0, value1 = (int(node.value) % p for p in primes)
            elif node.kind == "permute":
                value0, value1 = node.value
            descriptions.extend((codes[node.kind], a, b, value0, value1))
        public_data = words(
            [x % p for name in public_names for p in primes for x in prepared[name]]
        )
        descriptors, roots = words(descriptions), words(graph.residuals)
        arguments = (
            graph.n,
            *primes,
            len(names),
            descriptors,
            len(graph.nodes),
            roots,
            len(graph.residuals),
            public_data,
            len(public_names),
        )
        if cls is WireKernel:
            if any(bits != 30 for _g, _level, _node, bits in statement.source_layout):
                raise ValueError(
                    "Native wire component enrolls canonical30 sources only"
                )
            bindings = []
            count = len(statement.source_layout)
            for name in names:
                kind, *args = name
                if kind == "query":
                    bindings.extend((0, args[0], 0))
                elif kind == "source-digit":
                    bindings.extend((1, args[0], args[1]))
                elif kind == "output":
                    bindings.extend((2, count + 2 * args[0] + args[1], 0))
                else:
                    raise ValueError("Unknown enrolled wire input")
            owner = dict(statement.trusted_inputs)
            query = b"".join(
                x.to_bytes(15, "little")
                for c in range(2)
                for x in relation.polynomial(owner["query", c], statement)
            )
            handle = backend.cuhepy_noise_cut_create_wire(
                *arguments,
                words(bindings),
                count,
                count + 2 * statement.groups,
                query,
                len(query),
            )
        else:
            handle = backend.cuhepy_noise_cut_create(*arguments)
        if not handle:
            raise ValueError("Native kernel rejected its enrolled program")
        result = cls(statement, graph, names, primes, backend, handle, os.getpid())
        weakref.finalize(result, backend.cuhepy_noise_cut_destroy, handle)
        return result

    def _inputs(self, sources, outputs):
        if os.getpid() != self.owner_pid:
            raise ValueError("Native public context belongs to another process")
        # Entire canonical grammar precedes native arithmetic. The inputs are
        # independently copied into private call buffers, never aliased wires.
        bound = fusion.bindings(self.statement, sources, outputs)
        return words(
            [
                x % p
                for name in self.input_names
                for p in self.primes
                for x in bound[name]
            ]
        )

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        memo[id(self)] = self
        return self

    def __reduce_ex__(self, _protocol):
        raise TypeError("Native process pointers cannot be serialized")

    def holds(self, sources, outputs):
        try:
            inputs = self._inputs(sources, outputs)
            result = self.backend.cuhepy_noise_cut_check(
                self.handle, inputs, len(self.input_names)
            )
            if result < 0:
                raise RuntimeError("Native input/kernel error")
            return result == 1
        except (ValueError, TypeError, KeyError, AttributeError):
            return False

    def residuals(self, sources, outputs):
        """Diagnostic complete coefficient vectors, separately in both primes."""
        inputs = self._inputs(sources, outputs)
        count, n = len(self.graph.residuals), self.graph.n
        output = (Word * (count * 2 * n))()
        if self.backend.cuhepy_noise_cut_residuals(
            self.handle, inputs, len(self.input_names), output
        ):
            raise RuntimeError("Native residual evaluation failed")
        return tuple(
            tuple(
                tuple(output[(2 * r + p) * n : (2 * r + p + 1) * n]) for p in range(2)
            )
            for r in range(count)
        )


@dataclass(frozen=True)
class WireKernel(Kernel):
    """Fixed-slot common-Q native primitive; no network/release controller."""

    def body(self, sources, outputs):
        # Identity/order/type checks stay explicit in this tuple adapter. The
        # raw native body has the immutable layout of the enrolled program.
        fusion.bindings(self.statement, sources, outputs)
        polynomials = (
            *[source.polynomial for source in sources],
            *[row for pair in outputs for row in pair],
        )
        return b"".join(x.to_bytes(15, "little") for row in polynomials for x in row)

    def holds_bytes(self, body):
        if type(body) is not bytes or os.getpid() != self.owner_pid:
            return False
        result = self.backend.cuhepy_noise_cut_check_wire(self.handle, body, len(body))
        return result == 1

    def holds(self, sources, outputs):
        try:
            return self.holds_bytes(self.body(sources, outputs))
        except (ValueError, TypeError, KeyError, AttributeError):
            return False

    def residuals_bytes(self, body):
        if type(body) is not bytes or os.getpid() != self.owner_pid:
            raise ValueError("Immutable common-Q body required")
        count, n = len(self.graph.residuals), self.graph.n
        output = (Word * (count * 2 * n))()
        if self.backend.cuhepy_noise_cut_residuals_wire(
            self.handle, body, len(body), output
        ):
            raise ValueError("Malformed whole native wire body")
        return tuple(
            tuple(
                tuple(output[(2 * r + p) * n : (2 * r + p + 1) * n]) for p in range(2)
            )
            for r in range(count)
        )

    def residuals(self, sources, outputs):
        return self.residuals_bytes(self.body(sources, outputs))
