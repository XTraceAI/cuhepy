"""Q71 complete generic affine polynomial relation for selected semantic cuts.

Canonical sources are unique common-Q integers. Their digits feed a virtual
ciphertext/digit graph; omitted derived cuts have no independent witness.
Whole residual polynomials are checked with independent schoolbook arithmetic.
This public diagnostic has no entropy, private key, native/proof backend or
release authority. Ordinary DAG normalization is a known generic control.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json

from experiments.bfv_search_lab import noise_cut_planner as planner
from experiments.bfv_search_lab import noise_cut_reference as reference
from experiments.bfv_search_lab import propagated_gadget_bgv as gadget
from experiments.bfv_search_lab import tensor_gadget_seed as seed


@dataclass(frozen=True)
class Node:
    kind: str
    args: tuple[int, ...]
    value: tuple | int | None = None


@dataclass(frozen=True)
class Source:
    group: int
    level: int
    node: int
    polynomial: tuple[int, ...]


@dataclass(frozen=True)
class Relation:
    n: int
    q: int
    groups: int
    source_layout: tuple[tuple[int, int, int, int], ...]
    nodes: tuple[Node, ...]
    residuals: tuple[int, ...]
    trusted_inputs: tuple[tuple[tuple, tuple[int, ...]], ...]
    statement_digest: str


class Builder:
    def __init__(self, n, q):
        self.n, self.q, self.nodes, self.cache = n, q, [], {}
        self.zero = self.intern(Node("zero", ()))

    def intern(self, node):
        if node not in self.cache:
            self.cache[node] = len(self.nodes)
            self.nodes.append(node)
        return self.cache[node]

    def input(self, name):
        return self.intern(Node("input", (), name))

    def add(self, a, b):
        if a == self.zero:
            return b
        if b == self.zero:
            return a
        return self.intern(Node("add", tuple(sorted((a, b)))))

    def sub(self, a, b):
        if a == b:
            return self.zero
        if b == self.zero:
            return a
        return self.intern(Node("sub", (a, b)))

    def scale(self, a, scalar):
        scalar %= self.q
        if not scalar or a == self.zero:
            return self.zero
        if scalar == 1:
            return a
        return self.intern(Node("scale", (a,), scalar))

    def multiply(self, a, public):
        poly = tuple(int(x) % self.q for x in public)
        if len(poly) != self.n:
            raise ValueError("Wrong public multiplier shape")
        if a == self.zero or not any(poly):
            return self.zero
        return self.intern(Node("multiply", (a,), poly))

    def permute(self, a, exponent=1, shift=0):
        exponent, shift = exponent % (2 * self.n), shift % (2 * self.n)
        if exponent % 2 != 1:
            raise ValueError("Odd automorphism required")
        if a == self.zero or (exponent, shift) == (1, 0):
            return a
        return self.intern(Node("permute", (a,), (exponent, shift)))

    def sum(self, terms):
        out = self.zero
        for term in terms:
            out = self.add(out, term)
        return out


def compile_relation(query, index, count, dimension, pk, canonical, rotations, plans):
    contexts = reference.profiles(
        query, index, count, dimension, pk, canonical, rotations
    )
    if type(plans) is not tuple or len(plans) != len(contexts):
        raise ValueError("Complete immutable plans required")
    for group, (p, plan) in enumerate(zip(contexts, plans, strict=True)):
        label = planner.replay(p, plan)
        if plan.count != min(p.d, len(index) - group * p.d) or not p.safe(label.peak):
            raise ValueError("Wrong coverage or unsafe public Q/P plan")
    n, q, d, bits = pk.n, int(pk.q), canonical.padded, rotations.digit_bits
    graph = Builder(n, q)
    fixed, layouts, residuals = [], [], []
    query_nodes = tuple(graph.input(("query", c)) for c in range(2))
    for c in range(2):
        fixed.append((("query", c), tuple(map(int, query.components[c]))))
    query_digits = None
    key_digits = {}

    def source(group, level, node, expression, width):
        slot = len(layouts)
        layouts.append((group, level, node, width))
        digits = tuple(
            graph.input(("source-digit", slot, j))
            for j in range((q.bit_length() + width - 1) // width)
        )
        recomposed = graph.sum(
            graph.scale(a, 1 << (j * width)) for j, a in enumerate(digits)
        )
        residuals.append(graph.sub(expression, recomposed))
        return digits

    def switch(digits, key):
        return tuple(
            graph.sum(
                graph.multiply(a, column[c])
                for a, column in zip(digits, key, strict=True)
            )
            for c in range(2)
        )

    def digits_of_query():
        nonlocal query_digits
        if query_digits is None:
            nodes = []
            for c, poly in enumerate(query.components):
                digits = gadget.canonical_digits(tuple(map(int, poly)), q, bits)
                rows = []
                for j, row in enumerate(digits):
                    name = ("query-digit", c, j)
                    fixed.append((name, row))
                    rows.append(graph.input(name))
                nodes.append(tuple(rows))
            query_digits = tuple(nodes)
        return query_digits

    for group, (p, plan) in enumerate(zip(contexts, plans, strict=True)):
        tiles = index[group * d : (group + 1) * d]

        def visit(value, offset, stride):
            if value.mode == "zero":
                return (graph.zero,) * 2, (graph.zero,) * p.ell
            if value.level == -1:
                tile = tiles[offset]
                c2 = graph.multiply(query_nodes[1], tile.components[1])
                digits = source(group, -1, offset, c2, 30)
                b, a = switch(digits, canonical.relin)
                c0 = graph.add(graph.multiply(query_nodes[0], tile.components[0]), b)
                c1 = graph.sum(
                    (
                        graph.multiply(query_nodes[0], tile.components[1]),
                        graph.multiply(query_nodes[1], tile.components[0]),
                        a,
                    )
                )
                pair = tuple(graph.permute(row, shift=1 - d) for row in (c0, c1))
                state = None
                if value.mode == "seed":
                    dq = digits_of_query()
                    di = tuple(
                        gadget.canonical_digits(tuple(map(int, row)), q, bits)
                        for row in tile.components
                    )
                    gamma = seed.power_digits(q, bits)
                    terms = [[] for _ in range(p.ell)]
                    for c in range(2):
                        for x in range(p.ell):
                            for y in range(p.ell):
                                product = graph.multiply(dq[c][x], di[1 - c][y])
                                for j in range(p.ell):
                                    terms[j].append(
                                        graph.scale(product, gamma[x][y][j])
                                    )
                    for digit, column in zip(digits, canonical.relin, strict=True):
                        for j, row in enumerate(
                            gadget.canonical_digits(tuple(map(int, column[1])), q, bits)
                        ):
                            terms[j].append(graph.multiply(digit, row))
                    state = tuple(
                        graph.permute(graph.sum(row), shift=1 - d) for row in terms
                    )
                return pair, state
            left, le = visit(value.left, offset, stride * 2)
            right, re = visit(value.right, offset + stride, stride * 2)
            shift = d >> (value.level + 1)
            exponent, key = rotations.rotations[value.level]
            moved = tuple(graph.permute(a, shift=shift) for a in right)
            plus = tuple(graph.add(a, b) for a, b in zip(left, moved, strict=True))
            minus = tuple(graph.sub(a, b) for a, b in zip(left, moved, strict=True))
            c0, z = (graph.permute(a, exponent) for a in minus)
            if value.mode == "derived":
                digits = tuple(
                    graph.permute(graph.sub(a, graph.permute(b, shift=shift)), exponent)
                    for a, b in zip(le, re, strict=True)
                )
            else:
                digits = source(group, value.level, offset, z, bits)
            b, a = switch(digits, key)
            pair = graph.sum((plus[0], c0, b)), graph.add(plus[1], a)
            state = None
            if value.retain:
                if value.level not in key_digits:
                    key_digits[value.level] = gadget.public_a_digits(key, q, bits)
                ad = key_digits[value.level]
                correction = tuple(
                    graph.sum(
                        graph.multiply(digit, ad[k][j])
                        for k, digit in enumerate(digits)
                    )
                    for j in range(p.ell)
                )
                if value.mode == "canonical" and not value.right.count:
                    base = tuple(
                        graph.permute(digit, pow(exponent, -1, 2 * n))
                        for digit in digits
                    )
                else:
                    base = tuple(
                        graph.add(x, graph.permute(y, shift=shift))
                        for x, y in zip(le, re, strict=True)
                    )
                state = tuple(
                    graph.add(x, y) for x, y in zip(base, correction, strict=True)
                )
            return pair, state

        output, _ = visit(plan, 0, 1)
        residuals.extend(
            graph.sub(row, graph.input(("output", group, c)))
            for c, row in enumerate(output)
        )
    identity = {
        "key_id": pk.key_id,
        "N": n,
        "Q": q,
        "t": pk.t,
        "count": count,
        "dimension": dimension,
        "contexts": [asdict(p) for p in contexts],
        "plans": [asdict(p) for p in plans],
        "nodes": [asdict(node) for node in graph.nodes],
        "trusted_inputs": fixed,
        "source_layout": layouts,
        "residuals": residuals,
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return Relation(
        n,
        q,
        len(contexts),
        tuple(layouts),
        tuple(graph.nodes),
        tuple(residuals),
        tuple(fixed),
        digest,
    )


def polynomial(row, relation):
    if (
        type(row) is not tuple
        or len(row) != relation.n
        or any(type(x) is not int or not 0 <= x < relation.q for x in row)
    ):
        raise ValueError("Immutable canonical common-Q polynomial required")
    return row


def residuals(relation, sources, outputs):
    """Independent complete evaluation; no HE product/switch/oracle is called."""
    if (
        type(relation) is not Relation
        or type(sources) is not tuple
        or len(sources) != len(relation.source_layout)
    ):
        raise ValueError("Wrong immutable complete source coverage")
    bindings = dict(relation.trusted_inputs)
    for slot, (value, (g, level, node, bits)) in enumerate(
        zip(sources, relation.source_layout, strict=True)
    ):
        if (
            type(value) is not Source
            or any(type(x) is not int for x in (value.group, value.level, value.node))
            or (value.group, value.level, value.node) != (g, level, node)
        ):
            raise ValueError("Wrong source order or identity")
        z = polynomial(value.polynomial, relation)
        for j in range((relation.q.bit_length() + bits - 1) // bits):
            bindings["source-digit", slot, j] = tuple(
                (x >> (j * bits)) & ((1 << bits) - 1) for x in z
            )
    if type(outputs) is not tuple or len(outputs) != relation.groups:
        raise ValueError("Wrong full output coverage")
    for g, pair in enumerate(outputs):
        if type(pair) is not tuple or len(pair) != 2:
            raise ValueError("Two immutable complete terminal components required")
        for c, row in enumerate(pair):
            bindings["output", g, c] = polynomial(row, relation)
    n, q, values = relation.n, relation.q, []
    for node in relation.nodes:
        if node.kind == "zero":
            value = (0,) * n
        elif node.kind == "input":
            value = bindings[node.value]
        elif node.kind in ("add", "sub"):
            a, b = (values[i] for i in node.args)
            sign = 1 if node.kind == "add" else -1
            value = tuple((x + sign * y) % q for x, y in zip(a, b, strict=True))
        elif node.kind == "scale":
            value = tuple(x * node.value % q for x in values[node.args[0]])
        elif node.kind == "multiply":
            # Different arithmetic from homemade HE/GMP ring products.
            out = [0] * n
            for i, x in enumerate(values[node.args[0]]):
                for j, y in enumerate(node.value):
                    out[(i + j) % n] += x * y * (-1 if i + j >= n else 1)
            value = tuple(x % q for x in out)
        elif node.kind == "permute":
            exponent, shift = node.value
            out = [0] * n
            for i, x in enumerate(values[node.args[0]]):
                power = i * exponent + shift
                out[power % n] += x * (-1 if (power // n) % 2 else 1)
            value = tuple(x % q for x in out)
        else:
            raise ValueError("Unknown frozen relation operation")
        values.append(value)
    return tuple(values[i] for i in relation.residuals)


def holds(relation, sources, outputs):
    try:
        return all(not any(row) for row in residuals(relation, sources, outputs))
    except (ValueError, TypeError, IndexError, KeyError, AttributeError):
        return False


def statistics(relation):
    kinds = Counter(node.kind for node in relation.nodes)
    multipliers = {node.value for node in relation.nodes if node.kind == "multiply"}
    return {
        "canonical_source_polynomials": len(relation.source_layout),
        "complete_terminal_Q_polynomials": 2 * relation.groups,
        "complete_residual_polynomials": len(relation.residuals),
        "generic_shared_DAG_nodes": len(relation.nodes),
        "operations_by_kind": dict(kinds),
        "unique_public_ring_multipliers": len(multipliers),
        "unique_multiplier_packed_Q_body_model_bytes": len(multipliers)
        * ((relation.n * relation.q.bit_length() + 7) // 8),
        "trusted_query_and_query_digit_polynomials": len(relation.trusted_inputs),
        "statement_digest": relation.statement_digest,
        "scope": "Known generic complete affine-DAG adaptation. Explicit representation/counts, not minimum state, native costs, timings or protected admission. Tensor query digits are locally bound, not new query wire payload.",
    }
