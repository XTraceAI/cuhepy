"""E22 owner-only dictionary and physical-layout experiments.

Farthest-first column selection respects an explicit representative budget.
An optional medoid sweep minimizes (maximum row error, sum squared errors,
sum errors) with the initial groups fixed. Neither heuristic claims global
optimality. All residual radii are recomputed exactly, for every index row.
NumPy is preprocessing arithmetic only; encrypted evaluation remains homemade.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from experiments.bfv_search_lab import folded_filter as folded


@dataclass(frozen=True)
class Dictionary:
    plan: folded.FoldPlan
    initial_error_objective: tuple[int, int, int]
    final_error_objective: tuple[int, int, int]
    medoid_changes: int


def _objective(errors: np.ndarray) -> tuple[int, int, int]:
    return int(errors.max()), int(errors @ errors), int(errors.sum())


def prepare(
    rows: list[int], dimension: int, budget: int, *, tail_passes: int = 0,
) -> Dictionary:
    """Complement-invariant column k-center proposal, then exact certification.

    Tail sweeps may change representatives/complements within fixed groups,
    but only accept a strict improvement in the whole-index row-error objective.
    This is index preprocessing; no query or query label is used.
    """
    folded._words(0, rows, dimension)
    if (not 1 <= len(rows) <= 32768 or type(budget) is not int or not 1 <= budget <= dimension
            or type(tail_passes) is not int or not 0 <= tail_passes <= 4):
        raise ValueError("Invalid bounded dictionary workload")
    # Dense bits are bounded to <= 128 MiB; objectives fit int64 in this domain.
    width = (dimension + 7) // 8
    data = b"".join(row.to_bytes(width, "little") for row in rows)
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8).reshape(len(rows), width),
                         axis=1, bitorder="little")[:, :dimension]
    columns = [int.from_bytes(np.packbits(bits[:, j], bitorder="little").tobytes(), "little")
               for j in range(dimension)]
    distances = np.empty((dimension, dimension), dtype=np.int32)
    complements = np.zeros((dimension, dimension), dtype=np.uint8)
    for j, column in enumerate(columns):
        for k in range(j + 1):
            count = (column ^ columns[k]).bit_count()
            distances[j, k] = distances[k, j] = min(count, len(rows) - count)
            complements[j, k] = complements[k, j] = count > len(rows) // 2
    representatives = [int(np.argmin(distances.sum(axis=1)))]
    nearest = distances[:, representatives[0]].copy()
    while len(representatives) < budget and int(nearest.max()):
        chosen = int(np.argmax(nearest))
        representatives.append(chosen)
        nearest = np.minimum(nearest, distances[:, chosen])
    assignments = np.argmin(distances[:, representatives], axis=1)
    # Distinct chosen columns have positive distance modulo complements.
    groups = [np.flatnonzero(assignments == g) for g in range(len(representatives))]

    def group_error(members: np.ndarray, rep: int) -> np.ndarray:
        expected = bits[:, rep, None] ^ complements[rep, members][None, :]
        return np.count_nonzero(bits[:, members] != expected, axis=1).astype(np.int64)

    per_group = [group_error(members, rep) for members, rep in zip(groups, representatives, strict=True)]
    errors = sum(per_group, start=np.zeros(len(rows), dtype=np.int64))
    initial, changes = _objective(errors), 0
    for _ in range(tail_passes):
        changed = False
        for g, members in enumerate(groups):
            rest = errors - per_group[g]
            best, winner, replacement = _objective(errors), representatives[g], per_group[g]
            for candidate in members:
                if candidate == representatives[g]:
                    continue
                candidate_errors = group_error(members, int(candidate))
                score = _objective(rest + candidate_errors)
                if score < best:
                    best, winner, replacement = score, int(candidate), candidate_errors
            if winner != representatives[g]:
                representatives[g], per_group[g] = winner, replacement
                errors = rest + replacement
                changes += 1
                changed = True
        if not changed:
            break
    mapping = tuple((int(g), int(complements[representatives[int(g)], j])) for j, g in enumerate(assignments))
    plan = folded.FoldPlan(dimension, tuple(representatives), mapping, int(errors.max()))
    folded.validate(plan)
    # A separate integer reconstruction guards the preprocessing representation.
    exact = [(row ^ folded._template(plan, row)).bit_count() for row in rows]
    if exact != errors.tolist():
        raise AssertionError("Dictionary residuals disagree with integer templates")
    return Dictionary(plan, initial, _objective(errors), changes)


def metric_order(rows: list[int], dimension: int, leaf_size: int) -> tuple[int, ...]:
    """Owner-side balanced partitions by distance difference to two far pivots.

    Leaves are flattened into one physical row order; ordinary fixed-size
    ciphertext tiles may straddle leaf boundaries. No query guides this order.
    Returned values are original POSITIONs, not replacement stable row IDs.
    """
    folded._words(0, rows, dimension)
    if type(leaf_size) is not int or leaf_size < 1:
        raise ValueError("Invalid leaf size")

    def split(indices: list[int]) -> list[int]:
        if len(indices) <= leaf_size:
            return sorted(indices)
        first = indices[0]
        a = max(indices, key=lambda i: ((rows[first] ^ rows[i]).bit_count(), -i))
        b = max(indices, key=lambda i: ((rows[a] ^ rows[i]).bit_count(), -i))
        ordered = sorted(indices, key=lambda i: ((rows[i] ^ rows[a]).bit_count()
                                                - (rows[i] ^ rows[b]).bit_count(), i))
        middle = len(ordered) // 2
        return split(ordered[:middle]) + split(ordered[middle:])

    return tuple(split(list(range(len(rows)))))


def signature_order(plan: folded.FoldPlan, rows: list[int]) -> tuple[int, ...]:
    """Cheap lexicographic representative-bit control for the metric layout."""
    folded.validate(plan)
    folded._words(0, rows, plan.dimension)
    return tuple(sorted(range(len(rows)), key=lambda i: (
        sum(((rows[i] >> rep) & 1) << g for g, rep in enumerate(plan.representatives)), i)))
