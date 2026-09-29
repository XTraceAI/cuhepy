"""E31: exact query directions shared along a public plaintext CRT tree.

At node v extract the intersection of descendant row spaces, modulo directions
already assigned to ancestors. Every leaf keeps its original rank. Ancestor
directions occupy a common prefix; disjoint subtrees reuse encrypted columns.
The resulting per-column correction can have degree 1, 2, 4, ..., S, while the
encryption secret and ring retain full degree N.

Finite-field intersections and hierarchical factorization are known algebra.
This is a bounded, variable-time owner-side experiment, not a new encryption
scheme or a proof of optimal private state. Tree/rank/form-equality metadata
is public; bases and anchors are private. Masks cover ALL declared coordinates.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct

import numpy as np

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import dyadic_crt as crt
from experiments.bfv_search_lab import folded_filter as folded
from experiments.bfv_search_lab import shared_query_basis as shared


def intersection(a: affine.Plan, b: affine.Plan) -> affine.Plan:
    """Exact row-space intersection using the left kernel of A modulo B.

    u*A belongs to B iff u*(A mod B)=0. RREF of the transposed residual
    gives those coefficient constraints. No Euclidean/approximate projection.
    Anchors do not participate: this intersects direction spaces only.
    """
    shared._inputs((a, b))
    d, t = a.dimension, a.prime
    if not a.rank or not b.rank:
        return shared._basis(np.empty((0, d), dtype=np.int64), d, t)
    if a.rank > b.rank:
        a, b = b, a
    constraints = shared._basis(shared._reduce(shared._matrix(a), b).T, a.rank, t)
    free = sorted(set(range(a.rank)) - set(constraints.pivots))
    kernel = np.zeros((len(free), a.rank), dtype=np.int64)
    for i, j in enumerate(free):
        kernel[i, j] = 1
        kernel[i, constraints.pivots] = -shared._matrix(constraints)[:, j] % t
    return shared._basis(kernel @ shared._matrix(a) % t, d, t)


@dataclass(frozen=True)
class Node:
    path: str
    basis: affine.Plan  # Anchor is always zero; local anchors are stored once below.


@dataclass(frozen=True)
class Plan:
    context: crt.Context
    dimension: int
    anchors: tuple[int, ...]
    nodes: tuple[Node, ...]  # Preorder, only nonzero-rank nodes.

    def chain(self, leaf: str) -> tuple[affine.Plan, ...]:
        return tuple(node.basis for node in self.nodes if leaf.startswith(node.path))

    @property
    def features(self) -> tuple[int, ...]:
        return tuple(max(1, sum(p.rank for p in self.chain(leaf.path))) for leaf in self.context.leaves)


def validate(plan: Plan) -> None:
    ctx = plan.context
    crt.validate(ctx)
    if not 1 <= plan.dimension <= 512 or len(plan.anchors) != len(ctx.leaves):
        raise ValueError("Invalid bounded hierarchy")
    for anchor in plan.anchors:
        folded._words(anchor, [], plan.dimension)
    paths = {leaf.path for leaf in ctx.leaves} | {split.path for split in ctx.splits}
    if (tuple(node.path for node in plan.nodes) != tuple(sorted({node.path for node in plan.nodes}))
            or any(node.path not in paths for node in plan.nodes)):
        raise ValueError("Expected distinct preorder nodes of the pinned CRT tree")
    for node in plan.nodes:
        affine.validate(node.basis)
        if (not node.basis.rank or node.basis.anchor
                or (node.basis.dimension, node.basis.prime) != (plan.dimension, ctx.prime)):
            raise ValueError("Invalid private node basis")
        ancestors = [p.basis for p in plan.nodes if p.path != node.path and node.path.startswith(p.path)]
        if any(row[j] for p in ancestors for j in p.pivots for row in node.basis.basis):
            raise ValueError("Descendants must vanish at ancestor pivots")


def prepare(ctx: crt.Context, maps: tuple[affine.Plan, ...], *, max_depth: int = 6) -> Plan:
    """Index-only exact intersections; max_depth bounds internal sharing.

    Leaves always receive their remaining directions. Minus one keeps only
    leaves (exact-row deduplication control). Depth zero is a true
    global-intersection control. Six admits every supported internal node.
    A complete intersection is extracted, not a rank-expanding common envelope.
    """
    crt.validate(ctx)
    shared._inputs(maps)
    if (len(maps) != len(ctx.leaves) or maps[0].prime != ctx.prime
            or type(max_depth) is not int or not -1 <= max_depth <= 6):
        raise ValueError("Invalid hierarchy geometry or sharing depth")
    d, t = maps[0].dimension, ctx.prime
    spaces = {leaf.path: shared._basis(shared._matrix(p), d, t)
              for leaf, p in zip(ctx.leaves, maps, strict=True)}
    for split in reversed(ctx.splits):
        spaces[split.path] = intersection(spaces[split.path + "0"], spaces[split.path + "1"])
    leaves = {leaf.path for leaf in ctx.leaves}
    nodes: list[Node] = []

    def visit(path: str, ancestor: affine.Plan) -> None:
        if path in leaves or len(path) <= max_depth:
            local = shared._basis(shared._reduce(shared._matrix(spaces[path]), ancestor), d, t)
            if local.rank:
                nodes.append(Node(path, local))
                ancestor = shared._basis(np.vstack((shared._matrix(ancestor), shared._matrix(local))), d, t)
        if path not in leaves:
            visit(path + "0", ancestor)
            visit(path + "1", ancestor)

    visit("", shared._basis(np.empty((0, d), dtype=np.int64), d, t))
    result = Plan(ctx, d, tuple(p.anchor for p in maps), tuple(nodes))
    validate(result)
    if result.features != tuple(p.features for p in maps):
        raise AssertionError("Intersection factorization changed a leaf rank")
    return result


def schedule(plan: Plan) -> tuple[tuple[tuple[int, ...], ...], tuple[tuple[int, ...], ...]]:
    """Public form IDs and private directions, deduplicating EXACT equal rows.

    Equality sharing across disconnected nodes is explicit additional metadata.
    It can reduce h without changing a column's subring unless siblings agree.
    IDs are canonical by first occurrence in leaf/feature order. A constant
    leaf uses a single zero feature and an independently masked dummy form.
    """
    validate(plan)
    ids: dict[tuple[int, ...], int] = {}
    result = []
    for leaf in plan.context.leaves:
        rows = tuple(row for p in plan.chain(leaf.path) for row in p.basis) or ((0,) * plan.dimension,)
        result.append(tuple(ids.setdefault(row, len(ids)) for row in rows))
    return tuple(result), tuple(ids)


def index_features(plan: Plan, group: int, rows: list[int]) -> list[list[int]]:
    """Sequential triangular solve, with exact reconstruction of every row."""
    validate(plan)
    if type(group) is not int or not 0 <= group < len(plan.anchors) or len(rows) > 32768:
        raise ValueError("Invalid bounded hierarchy enrollment")
    folded._words(0, rows, plan.dimension)
    width = (plan.dimension + 7) // 8
    bits = np.unpackbits(np.frombuffer(b"".join(x.to_bytes(width, "little") for x in rows), dtype=np.uint8)
                         .reshape(len(rows), width), axis=1, bitorder="little")[:, :plan.dimension].astype(np.int64)
    residual = (bits - np.asarray([(plan.anchors[group] >> j) & 1 for j in range(plan.dimension)])) % plan.context.prime
    parts = []
    for p in plan.chain(plan.context.leaves[group].path):
        coordinates = residual[:, p.pivots]
        parts.append(coordinates)
        residual = (residual - coordinates @ shared._matrix(p)) % p.prime
    if np.any(residual):
        raise ValueError("Row outside pinned hierarchical envelope")
    values = np.concatenate(parts, axis=1) if parts else np.zeros((len(rows), 1), dtype=np.int64)
    values[values > plan.context.prime // 2] -= plan.context.prime
    return [list(map(int, row)) for row in values]


@dataclass(frozen=True)
class Compiled:
    forms: affine.BitPlan
    anchors: tuple[int, ...]

    def query(self, query: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
        values, _ = affine.bit_query_features(self.forms, query)
        return tuple(values), tuple((query ^ anchor).bit_count() for anchor in self.anchors)


def compile_bits(plan: Plan) -> Compiled:
    _, directions = schedule(plan)
    # These directions form several subspaces, not one RREF. Compile the same
    # exact popcount contractions directly, without claiming a single basis.
    terms, biases = [], []
    for row in directions:
        masks: dict[int, int] = {}
        for j, value in enumerate(row):
            if value:
                c = value if value <= plan.context.prime // 2 else value - plan.context.prime
                masks[c] = masks.get(c, 0) | (1 << j)
        terms.append(tuple(sorted(masks.items())))
        biases.append(sum(c * mask.bit_count() for c, mask in masks.items()))
    forms = affine.BitPlan(plan.dimension, plan.context.prime, 0, tuple(terms), tuple(biases))
    return Compiled(forms, plan.anchors)


def canonical_map(plan: Plan) -> bytes:
    """Private node-map/anchor body, with exact-map deduplication and framing.

    No parser, heap-size or authentication claim. Public context and scheduling
    are charged separately. Bodies retain node pivots needed for enrollment;
    per-row coordinates and compiled duplicates are separate state.
    """
    validate(plan)
    bodies = tuple(dict.fromkeys(affine.canonical_map(node.basis) for node in plan.nodes))
    result = bytearray(struct.pack("<HIHH", plan.dimension, plan.context.prime, len(plan.anchors), len(bodies)))
    for anchor in plan.anchors:
        result.extend(anchor.to_bytes((plan.dimension + 7) // 8, "little"))
    for body in bodies:
        result.extend(struct.pack("<I", len(body)))
        result.extend(body)
    result.extend(struct.pack("<H", len(plan.nodes)))
    for node in plan.nodes:
        result.extend(struct.pack("<BBH", len(node.path), int(node.path or "0", 2),
                                  bodies.index(affine.canonical_map(node.basis))))
    return bytes(result)


def overlap_order(maps: tuple[affine.Plan, ...]) -> tuple[int, ...]:
    """Index-only balanced agglomeration for equal-capacity CRT leaves.

    At each level pair clusters greedily by exact intersection rank, breaking
    ties by sparse intersection body and original positions. Cluster metadata
    is only its common row space; anchors/counts do not affect pair selection.
    This is NOT optimal matching or a joint optimum of (h, W, map bytes).
    The caller must keep row membership/capacity and charge geometry leakage.
    """
    shared._inputs(maps)
    if len(maps) & (len(maps) - 1):
        raise ValueError("Balanced overlap grouping requires a power-of-two leaf count")
    clusters = [(tuple([i]), shared._basis(shared._matrix(p), p.dimension, p.prime)) for i, p in enumerate(maps)]
    memo: dict[tuple[affine.Plan, affine.Plan], affine.Plan] = {}
    while len(clusters) > 1:
        choices = []
        for i, (left, a) in enumerate(clusters):
            for j in range(i + 1, len(clusters)):
                right, b = clusters[j]
                key = (a, b)
                if key not in memo:
                    memo[key] = intersection(a, b)
                common = memo[key]
                choices.append((-common.rank, len(affine.canonical_map(common)), left, right, i, j, common))
        choices.sort(key=lambda item: item[:-1])
        used: set[int] = set()
        next_level = []
        for _, _, left, right, i, j, common in choices:
            if i not in used and j not in used:
                next_level.append((left + right, common))
                used.update((i, j))
        clusters = sorted(next_level, key=lambda item: item[0])
    return clusters[0][0]
