"""E21: homemade encrypted generating-polynomial reference on constant slots.

This intentionally small, unbatched experiment implements the complete factor
circuit with repeated multiplication/relinearization and conservative bounds.
It does not import SEAL or provide a private prefix-selection protocol. Any
owner decryption in tests/benchmarks is of locally generated fixture output.
"""

from __future__ import annotations

from dataclasses import dataclass

from gmpy2 import mpz

from experiments.bfv_search_lab import answer_oracles as oracle
from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


@dataclass(frozen=True)
class AggregateResult:
    histogram: tuple[bgv.Ciphertext, ...]
    row_polynomials: tuple[tuple[bgv.Ciphertext, ...], ...]
    product_calls: int
    max_depth: int


@dataclass(frozen=True)
class _Value:
    cipher: bgv.Ciphertext
    depth: int


class _Circuit:
    def __init__(self, pk: bgv.PublicKey, keys: trace.EvaluationKeys):
        butterfly.validate_keys(pk, keys)
        if keys.padded != 1:
            raise ValueError("Aggregate reference uses only a relinearization key")
        self.pk, self.keys, self.products, self.depth = pk, keys, 0, 0

    def constant(self, value: int) -> _Value:
        centered = ((value + self.pk.t // 2) % self.pk.t) - self.pk.t // 2
        poly = (mpz(centered % self.pk.q),) + (mpz(0),) * (self.pk.n - 1)
        return _Value(trace._bounded((poly, (mpz(0),) * self.pk.n), abs(centered), self.pk), 0)

    def linear(self, a: _Value, b: _Value, factor: int = 1) -> _Value:
        components = tuple(tuple((x + factor * y) % self.pk.q for x, y in zip(p, q, strict=True))
                           for p, q in zip(a.cipher.components, b.cipher.components, strict=True))
        bound = a.cipher.phase_bound + abs(factor) * b.cipher.phase_bound
        return _Value(trace._bounded(components, bound, self.pk), max(a.depth, b.depth))

    def multiply(self, a: _Value, b: _Value) -> _Value:
        product = bgv.multiply(a.cipher, b.cipher, self.pk, karatsuba=True)
        c0, c1, c2 = product.components
        b0, b1 = trace._switch(c2, self.keys.relin, self.pk, self.keys.digit_bits)
        components = tuple(tuple((x + y) % self.pk.q for x, y in zip(p, q, strict=True))
                           for p, q in ((c0, b0), (c1, b1)))
        self.products += 1
        depth = 1 + max(a.depth, b.depth)
        self.depth = max(self.depth, depth)
        return _Value(trace._bounded(components, product.phase_bound + self.keys.switch_error_bound,
                                     self.pk), depth)

    def polynomial_product(self, a: list[_Value], b: list[_Value]) -> list[_Value]:
        out = [self.constant(0) for _ in range(len(a) + len(b) - 1)]
        for i, x in enumerate(a):
            for j, y in enumerate(b):
                out[i + j] = self.linear(out[i + j], self.multiply(x, y))
        return out


def encrypt_inputs(
    query: list[int], rows: list[list[int]], pk: bgv.PublicKey,
) -> tuple[list[bgv.Ciphertext], list[list[bgv.Ciphertext]]]:
    """Owner encodes each bit as a constant polynomial; no SIMD claimed."""
    oracle.validate_binary(query, rows)
    oracle.validate_field(pk.t, len(query), len(rows))
    def encode(value: int) -> bgv.Ciphertext:
        return bgv.encrypt([value] + [0] * (pk.n - 1), pk)
    return [encode(x) for x in query], [[encode(x) for x in row] for row in rows]


def search(
    query: list[bgv.Ciphertext], index: list[list[bgv.Ciphertext]],
    pk: bgv.PublicKey, keys: trace.EvaluationKeys,
) -> AggregateResult:
    if not query or any(len(row) != len(query) for row in index):
        raise ValueError("Invalid aggregate query/index dimensions")
    oracle.validate_field(pk.t, len(query), len(index))
    circuit = _Circuit(pk, keys)
    for cipher in (*query, *(ct for row in index for ct in row)):
        bgv._validate(cipher, pk)
        if len(cipher.components) != 2:
            raise ValueError("Aggregate inputs must have two components")
    one = circuit.constant(1)
    total = [circuit.constant(0) for _ in range(len(query) + 1)]
    cached = []
    for row in index:
        factors = []
        for x, q in zip(row, query, strict=True):
            a, b = _Value(x, 0), _Value(q, 0)
            mismatch = circuit.linear(circuit.linear(a, b), circuit.multiply(a, b), -2)
            factors.append([circuit.linear(one, mismatch, -1), mismatch])
        while len(factors) > 1:
            factors = [circuit.polynomial_product(factors[i], factors[i + 1])
                       if i + 1 < len(factors) else factors[i]
                       for i in range(0, len(factors), 2)]
        total = [circuit.linear(a, b) for a, b in zip(total, factors[0], strict=True)]
        cached.append(tuple(x.cipher for x in factors[0]))
    return AggregateResult(tuple(x.cipher for x in total), tuple(cached), circuit.products, circuit.depth)


def prefix_count(
    result: AggregateResult, distance: int, start: int, stop: int, pk: bgv.PublicKey,
) -> bgv.Ciphertext:
    """Public evaluator helper for the explicitly revealed-prefix toy protocol."""
    if (type(distance) is not int or not 0 <= distance < len(result.histogram)
            or type(start) is not int or type(stop) is not int
            or not 0 <= start <= stop <= len(result.row_polynomials)):
        raise ValueError("Invalid public prefix request")
    zero = (mpz(0),) * pk.n
    out = trace._bounded((zero, zero), 0, pk)
    for row in result.row_polynomials[start:stop]:
        bgv._validate(row[distance], pk)
        out = trace._add(out, row[distance], pk)
    return out
