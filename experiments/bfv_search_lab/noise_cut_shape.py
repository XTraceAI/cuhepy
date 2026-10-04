"""Complete symbolic relation shape for fixed safe Q70 schedules.

Atoms have enrollment identities, never fabricated large ciphertext values.
The graph supports known Karatsuba tensors and charged canonical30 suffix
lowering. Toy graphs are checked against the prior exact public relation.
Large outputs are operation/state models, not encrypted executions.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.bfv_search_lab import noise_cut_fusion as fusion
from experiments.bfv_search_lab import noise_cut_lowering as lowering
from experiments.bfv_search_lab import noise_cut_planner as planner
from experiments.bfv_search_lab import tensor_gadget_factorization as factorization


@dataclass(frozen=True)
class Shape:
    graph: fusion.Graph
    source_layout: tuple[tuple[int, int, int, int], ...]
    widths: tuple[tuple[int, ...], ...]
    groups: int


def compile_shape(
    contexts, plans, *, lowered=False, local_boundaries=False, paired_kernels=False
):
    if (
        type(contexts) is not tuple
        or type(plans) is not tuple
        or not contexts
        or len(contexts) != len(plans)
    ):
        raise ValueError("Complete immutable enrolled contexts and plans required")
    first = contexts[0]
    if any(
        type(p) is not planner.Profile or (p.n, p.d, p.q) != (first.n, first.d, first.q)
        for p in contexts
    ):
        raise ValueError("One enrolled ring and layout required")
    widths = []
    for p, plan in zip(contexts, plans, strict=True):
        label = planner.replay(p, plan)
        if not p.safe(label.peak):
            raise ValueError("Unsafe original public plan")
        if lowered:
            label, ledger, _rows = lowering.lower(p, plan)
            if not p.safe(label.peak):
                raise ValueError("Unsafe lowered public plan")
            widths.append(tuple(ledger["rotation_radix_bits_by_level"]))
        else:
            widths.append((p.bits,) * (p.d.bit_length() - 1))
    n, q, d = first.n, first.q, first.d
    graph = fusion.Builder(n, q)
    layouts, residuals = [], []
    query = tuple(graph.input(("query", c)) for c in range(2))
    query_sum = graph.add(*query)
    # Preserve this shared Karatsuba input. Both generic controls get it.
    anchors = [query_sum]
    pairs = []
    if paired_kernels and not local_boundaries:
        raise ValueError("Paired kernels require local ciphertext boundaries")

    def public(kind, *args):
        return fusion.Public((kind, *args))

    def source(g, level, node, expression, bits):
        slot = len(layouts)
        layouts.append((g, level, node, bits))
        digits = tuple(
            graph.input(("source-digit", slot, j))
            for j in range((q.bit_length() + bits - 1) // bits)
        )
        total = graph.sum(graph.scale(a, 1 << (j * bits)) for j, a in enumerate(digits))
        residuals.append(graph.sub(expression, total))
        return digits

    def switch(digits, level, bits):
        kind = "relin" if level == -1 else "rotation"
        return tuple(
            graph.sum(
                graph.multiply(a, public(kind, level, bits, j, c))
                for j, a in enumerate(digits)
            )
            for c in range(2)
        )

    for g, (p, plan, row_widths) in enumerate(
        zip(contexts, plans, widths, strict=True)
    ):
        ell = p.ell

        def visit(value, offset, stride):
            if value.mode == "zero":
                return (graph.zero,) * 2, (graph.zero,) * ell
            if value.level == -1:
                tile = g * d + offset
                c0, c2 = (
                    graph.multiply(query[c], public("index", tile, c)) for c in range(2)
                )
                if paired_kernels:
                    anchors.extend((c0, c2))
                cross = graph.sub(
                    graph.sub(graph.multiply(query_sum, public("index-sum", tile)), c0),
                    c2,
                )
                digits = source(g, -1, offset, c2, 30)
                b, a = switch(digits, -1, 30)
                pair = tuple(
                    graph.permute(x, shift=1 - d)
                    for x in (graph.add(c0, b), graph.add(cross, a))
                )
                if local_boundaries:
                    anchors.extend(pair)
                if paired_kernels:
                    pairs.append(pair)
                state = None
                if value.mode == "seed":
                    gamma = factorization.power_rows(q, p.bits)
                    rows = [[] for _ in range(ell)]
                    for alpha in range(2):
                        for x in range(ell):
                            dq = graph.input(("query-digit", alpha, x))
                            for y in range(ell):
                                product = graph.multiply(
                                    dq,
                                    public("index-digit", tile, 1 - alpha, p.bits, y),
                                )
                                for j in range(ell):
                                    rows[j].append(
                                        graph.scale(product, gamma[x + y][j])
                                    )
                    for a, digit in enumerate(digits):
                        for j in range(ell):
                            rows[j].append(
                                graph.multiply(
                                    digit, public("relin-a-digit", a, p.bits, j)
                                )
                            )
                    state = tuple(
                        graph.permute(graph.sum(row), shift=1 - d) for row in rows
                    )
                return pair, state
            left, le = visit(value.left, offset, stride * 2)
            right, re = visit(value.right, offset + stride, stride * 2)
            h, bits = d >> (value.level + 1), row_widths[value.level]
            exponent = pow(1 + 2 * n // d, 1 << value.level, 2 * n)
            moved = tuple(graph.permute(a, shift=h) for a in right)
            plus = tuple(graph.add(a, b) for a, b in zip(left, moved, strict=True))
            minus = tuple(graph.sub(a, b) for a, b in zip(left, moved, strict=True))
            c0, z = (graph.permute(a, exponent) for a in minus)
            if value.mode == "derived":
                digits = tuple(
                    graph.permute(graph.sub(a, graph.permute(b, shift=h)), exponent)
                    for a, b in zip(le, re, strict=True)
                )
            else:
                digits = source(g, value.level, offset, z, bits)
            b, a = switch(digits, value.level, bits)
            pair = graph.sum((plus[0], c0, b)), graph.add(plus[1], a)
            if local_boundaries:
                anchors.extend(pair)
            if paired_kernels:
                pairs.append(pair)
            state = None
            if value.retain:
                if bits != p.bits:
                    raise ValueError("State cannot cross the enrolled radix boundary")
                correction = tuple(
                    graph.sum(
                        graph.multiply(
                            digit, public("key-a-digit", value.level, bits, k, j)
                        )
                        for k, digit in enumerate(digits)
                    )
                    for j in range(ell)
                )
                if value.mode == "canonical" and not value.right.count:
                    base = tuple(
                        graph.permute(digit, pow(exponent, -1, 2 * n))
                        for digit in digits
                    )
                else:
                    base = tuple(
                        graph.add(x, graph.permute(y, shift=h))
                        for x, y in zip(le, re, strict=True)
                    )
                state = tuple(
                    graph.add(x, y) for x, y in zip(base, correction, strict=True)
                )
            return pair, state

        output, _state = visit(plan, 0, 1)
        residuals.extend(
            graph.sub(row, graph.input(("output", g, c)))
            for c, row in enumerate(output)
        )
    return Shape(
        fusion.Graph(
            n,
            q,
            tuple(graph.nodes),
            tuple(residuals),
            tuple(sorted(set(anchors))),
            tuple(pairs),
        ),
        tuple(layouts),
        tuple(widths),
        len(plans),
    )


def concrete_constants(shape, index, canonical, rotations, q):
    """Resolve toy enrollment atoms; no HE product or private operation."""
    from experiments.bfv_search_lab import propagated_gadget_bgv as gadget

    constants = {}
    for node in shape.graph.nodes:
        if node.kind != "multiply" or node.value in constants:
            continue
        kind, *args = node.value.name
        if kind == "index":
            tile, c = args
            poly = index[tile].components[c]
        elif kind == "index-sum":
            (tile,) = args
            poly = tuple(
                (int(a) + int(b)) % q
                for a, b in zip(*index[tile].components, strict=True)
            )
        elif kind == "index-digit":
            tile, c, bits, j = args
            poly = gadget.canonical_digits(
                tuple(map(int, index[tile].components[c])), q, bits
            )[j]
        elif kind == "relin":
            _level, _bits, j, c = args
            poly = canonical.relin[j][c]
        elif kind == "rotation":
            level, bits, j, c = args
            poly = rotations[bits].rotations[level][1][j][c]
        elif kind == "relin-a-digit":
            a, bits, j = args
            poly = gadget.canonical_digits(
                tuple(map(int, canonical.relin[a][1])), q, bits
            )[j]
        elif kind == "key-a-digit":
            level, bits, a, j = args
            poly = gadget.canonical_digits(
                tuple(map(int, rotations[bits].rotations[level][1][a][1])), q, bits
            )[j]
        else:
            raise ValueError("Unknown enrolled public atom")
        constants[node.value] = tuple(map(int, poly))
    return constants


def direct_graph(graph):
    """Give unfused arithmetic the identical public-recipe resource API."""
    from experiments.bfv_search_lab.noise_cut_relation import Node

    return fusion.Graph(
        graph.n,
        graph.q,
        tuple(
            Node(
                node.kind,
                node.args,
                ((fusion.Monomial(0, ((node.value, 1),)), 1),)
                if node.kind == "multiply"
                else node.value,
            )
            for node in graph.nodes
        ),
        graph.residuals,
        graph.anchors,
        graph.pairs,
    )
