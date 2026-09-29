"""E30: an exact common/individual query basis over the plaintext field.

For block g, x = a_g + c*C + v*R_g. Common query forms C*(1-2q)
use scalar corrections; residual forms R_g*(1-2q) use the short CRT ring.
Only ranks/geometry are public. The bases and anchors stay with the owner.
Masks are uniform in the WHOLE declared common-plus-residual coordinate space,
not in the smaller, private image of the original query bits.

This is finite-field elimination and a bounded greedy basis heuristic, not a
new cryptographic primitive or an optimal subspace algorithm. Variable-time
owner arithmetic and additional rank/partition leakage remain research costs.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct

import numpy as np

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import folded_filter as folded


@dataclass(frozen=True)
class Plan:
    common: affine.Plan
    residuals: tuple[affine.Plan, ...]

    @property
    def shared(self) -> int:
        return self.common.rank

    @property
    def features(self) -> tuple[int, ...]:
        return tuple(max(1, self.shared + p.rank) for p in self.residuals)

    @property
    def dimension(self) -> int:
        return self.shared + sum(f - self.shared for f in self.features)


def _matrix(p: affine.Plan) -> np.ndarray:
    return np.asarray(p.basis, dtype=np.int64).reshape(p.rank, p.dimension)


def _basis(rows: np.ndarray, d: int, t: int, anchor: int = 0) -> affine.Plan:
    """Canonical finite-field RREF; no floating point or rank approximation."""
    work = np.asarray(rows, dtype=np.int64).reshape(-1, d).copy() % t
    pivots: list[int] = []
    for j in range(d):
        rank = len(pivots)
        choices = np.flatnonzero(work[rank:, j])
        if not len(choices):
            continue
        winner = rank + int(choices[0])
        work[[rank, winner]] = work[[winner, rank]]
        work[rank] = work[rank] * pow(int(work[rank, j]), -1, t) % t
        factors = work[:, j].copy()
        factors[rank] = 0
        work = (work - factors[:, None] * work[rank]) % t
        pivots.append(j)
    result = affine.Plan(d, t, anchor, tuple(pivots), tuple(tuple(map(int, row)) for row in work[:len(pivots)]))
    affine.validate(result)
    return result


def _reduce(rows: np.ndarray, basis: affine.Plan) -> np.ndarray:
    return (rows - rows[:, basis.pivots] @ _matrix(basis)) % basis.prime


def _inputs(plans: tuple[affine.Plan, ...]) -> None:
    if not 1 <= len(plans) <= 64:
        raise ValueError("Expected one to 64 private affine maps")
    first = plans[0]
    if not 1 <= first.dimension <= 512:
        raise ValueError("Shared-basis research dimension exceeds 512")
    for p in plans:
        affine.validate(p)
        if (p.dimension, p.prime) != (first.dimension, first.prime):
            raise ValueError("Inconsistent private affine fields")


def validate(plan: Plan) -> None:
    _inputs((plan.common,))
    _inputs(plan.residuals)
    c = plan.common
    if (c.anchor or any((p.dimension, p.prime) != (c.dimension, c.prime) for p in plan.residuals)
            or any(row[j] for p in plan.residuals for row in p.basis for j in c.pivots)):
        raise ValueError("Residual directions must vanish at common pivots")


def factor(plans: tuple[affine.Plan, ...], common: affine.Plan) -> Plan:
    """Project original affine directions into the quotient by a chosen C."""
    _inputs(plans)
    _inputs((common,))
    if common.anchor or (common.dimension, common.prime) != (plans[0].dimension, plans[0].prime):
        raise ValueError("Invalid common direction field or anchor")
    residuals = tuple(_basis(_reduce(_matrix(p), common), p.dimension, p.prime, p.anchor) for p in plans)
    result = Plan(common, residuals)
    validate(result)
    return result


def trajectory(plans: tuple[affine.Plan, ...], *, limit: int | None = None,
               strategy: str = "overlap") -> tuple[Plan, ...]:
    """Index-only candidate curve, including zero shared directions.

    The overlap pool consists of current residual RREF rows. Membership in ALL
    residual spaces, not just equality of basis rows, determines the benefit.
    Minimize the next maximum residual rank, then its sum, then direction nnz.
    This pool may miss an intersection spanned only by combinations; it is a
    heuristic, and tests retain such a counterexample. The raw control instead
    offers remaining standard coordinate directions. Neither sees queries.
    """
    _inputs(plans)
    d, t = plans[0].dimension, plans[0].prime
    if limit is None:
        limit = d
    if type(limit) is not int or not 0 <= limit <= d or strategy not in ("overlap", "raw"):
        raise ValueError("Invalid bounded common-basis search")
    c = _basis(np.empty((0, d), dtype=np.int64), d, t)
    result = [factor(plans, c)]
    for _ in range(limit):
        current = result[-1]
        if not any(p.rank for p in current.residuals):
            break
        rows = (list(dict.fromkeys(row for p in current.residuals for row in p.basis)) if strategy == "overlap"
                else [tuple(int(i == j) for i in range(d)) for j in range(d) if j not in c.pivots])
        candidates = np.asarray(rows, dtype=np.int64)
        memberships = np.asarray([np.all(_reduce(candidates, p) == 0, axis=1) for p in current.residuals])
        ranks = np.asarray([p.rank for p in current.residuals])[:, None] - memberships
        winner = min(range(len(rows)), key=lambda i: (int(ranks[:, i].max()), int(ranks[:, i].sum()),
                                                      sum(bool(x) for x in rows[i]), rows[i]))
        c = _basis(np.vstack((_matrix(c), candidates[winner])), d, t)
        result.append(factor(plans, c))
    return tuple(result)


def index_features(plan: Plan, group: int, rows: list[int]) -> list[list[int]]:
    """Certify every row in C+R_g; the caller separately pins its index epoch."""
    validate(plan)
    if type(group) is not int or not 0 <= group < len(plan.residuals):
        raise ValueError("Unknown private residual map")
    c, r = plan.common, plan.residuals[group]
    folded._words(0, rows, c.dimension)
    if len(rows) > 32768:
        raise ValueError("Shared-basis enrollment exceeds row bound")
    width = (c.dimension + 7) // 8
    bits = np.unpackbits(np.frombuffer(b"".join(x.to_bytes(width, "little") for x in rows), dtype=np.uint8)
                         .reshape(len(rows), width), axis=1, bitorder="little")[:, :c.dimension].astype(np.int64)
    anchor = np.asarray([(r.anchor >> j) & 1 for j in range(c.dimension)])
    differences = bits - anchor
    common = differences[:, c.pivots]
    residual = _reduce(differences, c)
    local = residual[:, r.pivots]
    if not np.array_equal(local @ _matrix(r) % c.prime, residual):
        raise ValueError("Row outside pinned common/residual envelope")
    coordinates = np.concatenate((common, local), axis=1) % c.prime
    coordinates[coordinates > c.prime // 2] -= c.prime
    return [list(map(int, row)) if len(row) else [0] for row in coordinates]


@dataclass(frozen=True)
class Compiled:
    common: affine.BitPlan
    residuals: tuple[affine.BitPlan, ...]

    def query(self, query: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
        common, _ = affine.bit_query_features(self.common, query)
        weights = common if self.common.terms else []
        offsets = []
        for p in self.residuals:
            values, offset = affine.bit_query_features(p, query)
            weights.extend(values if p.terms else ([] if self.common.terms else [0]))
            offsets.append(offset)
        return tuple(weights), tuple(offsets)


def compile_bits(plan: Plan) -> Compiled:
    validate(plan)
    return Compiled(affine.compile_bits(plan.common), tuple(affine.compile_bits(p) for p in plan.residuals))


def canonical_map(plan: Plan) -> bytes:
    """Retained private map body; includes anchors, bases and length framing.

    No per-row coordinates and no transport parser. Public geometry, stable ID
    ordering, HE keys, checker state and per-token material are separate costs.
    """
    validate(plan)
    bodies = [affine.canonical_map(p) for p in (plan.common, *plan.residuals)]
    return struct.pack("<H", len(bodies)) + b"".join(struct.pack("<I", len(b)) + b for b in bodies)
