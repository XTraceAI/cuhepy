"""E23: owner radius hints and a two-round exact refinement reference.

Encrypt only template scores. Owner-kept exact row radii yield lower AND upper
distance bounds; the kth upper pair safely supplies a threshold before exact
refinement. All requested original tiles can then be evaluated together.
This trades owner state and extra candidates for fewer dependent rounds.

Hints, map, index epoch and original IDs must be trusted/pinned. This module
is a local arithmetic oracle, not a MAC/proof, private routing protocol or
authority to decrypt an untrusted server's response. Its tile schedule leaks.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from experiments.bfv_search_lab import folded_filter as folded
from experiments.bfv_search_lab import linear_packing as packing


def inputs(
    plan: folded.FoldPlan, query: int, rows: list[int], n: int,
) -> tuple[list[int], list[list[int]], int, tuple[int, ...]]:
    """Owner preparation; radii stay with the owner, not inside the query/index."""
    groups = len(plan.representatives)
    weights = folded.query_features(plan, query)[:groups]
    features = folded.index_features(plan, rows)
    radii = tuple(row[-1] // 2 if plan.max_error else 0 for row in features)
    qp, tiles, padded = packing.pack(weights, [row[:groups] for row in features], n)
    return qp, tiles, padded, radii


def decode_templates(dots: list[int], dimension: int, prime: int) -> list[int]:
    """Field division followed by the known [0,d] template-distance interval."""
    if (type(dimension) is not int or not 1 <= dimension <= 4096
            or type(prime) is not int or prime <= dimension or not prime % 2
            or any(type(x) is not int or not 0 <= x < prime for x in dots)):
        raise ValueError("Invalid template-score context")
    scores = [(dimension - dot) * pow(2, -1, prime) % prime for dot in dots]
    if any(x > dimension for x in scores):
        raise ValueError("Local result outside template-distance range")
    return scores


def intervals(scores: list[int], radii: tuple[int, ...], dimension: int) -> tuple[list[int], list[int]]:
    if (type(dimension) is not int or dimension < 1 or len(scores) != len(radii)
            or any(type(x) is not int or not 0 <= x <= dimension for x in [*scores, *radii])):
        raise ValueError("Invalid template scores or trusted radii")
    return ([max(0, score - error) for score, error in zip(scores, radii, strict=True)],
            [min(dimension, score + error) for score, error in zip(scores, radii, strict=True)])


@dataclass(frozen=True)
class Selection:
    tiles: tuple[int, ...]
    threshold: tuple[int, int] | None
    candidate_count: int
    known_scores: tuple[tuple[int, int], ...]  # (physical position, exact score)


def _validate(lower: list[int], upper: list[int], row_ids: list[int], k: int, capacity: int) -> None:
    if (len(lower) != len(upper) or len(row_ids) != len(lower)
            or any(type(a) is not int or type(b) is not int or not 0 <= a <= b
                   for a, b in zip(lower, upper, strict=True))
            or any(type(i) is not int or i < 0 for i in row_ids) or len(set(row_ids)) != len(row_ids)
            or type(k) is not int or not 0 <= k <= len(lower) or type(capacity) is not int or capacity < 1):
        raise ValueError("Invalid interval-selection fixture")


def select_tiles(
    lower: list[int], upper: list[int], row_ids: list[int], capacity: int, *, k: int = 3,
    known_scores: dict[int, int] | None = None,
) -> Selection:
    """At least k true score/ID pairs are <= the kth upper pair (distinct IDs)."""
    _validate(lower, upper, row_ids, k, capacity)
    known = {} if known_scores is None else known_scores.copy()
    if any(type(i) is not int or not 0 <= i < len(lower) or type(d) is not int
           or not lower[i] <= d <= upper[i] for i, d in known.items()):
        raise ValueError("Known exact scores must match physical positions and certified intervals")
    if not k:
        return Selection((), None, 0, ())
    known.update((i, a) for i, (a, b) in enumerate(zip(lower, upper, strict=True)) if a == b)
    threshold = sorted((known.get(i, value), row_ids[i]) for i, value in enumerate(upper))[k - 1]
    candidates = [i for i, value in enumerate(lower) if (value, row_ids[i]) <= threshold]
    tiles = tuple(sorted({i // capacity for i in candidates if i not in known}))
    return Selection(tiles, threshold, len(candidates), tuple(sorted(known.items())))


def refine_once(
    lower: list[int], upper: list[int], row_ids: list[int], capacity: int,
    score_tiles: Callable[[tuple[int, ...]], list[tuple[int, int]]], *, k: int = 3,
    known_scores: dict[int, int] | None = None,
) -> tuple[tuple[tuple[int, int], ...], Selection, int]:
    """One batch of full tiles; return stable (distance, ID), plan and scored rows."""
    plan = select_tiles(lower, upper, row_ids, capacity, k=k, known_scores=known_scores)
    fetched = score_tiles(plan.tiles) if plan.tiles else []
    expected = {i for t in plan.tiles for i in range(t * capacity, min((t + 1) * capacity, len(lower)))}
    if (len(fetched) != len(expected) or {i for i, _ in fetched} != expected
            or any(type(i) is not int or type(d) is not int or not lower[i] <= d <= upper[i] for i, d in fetched)):
        raise ValueError("Refiner must return complete tiles with interval-consistent exact scores")
    scores = dict(plan.known_scores)
    if any(i in scores and scores[i] != d for i, d in fetched):
        raise ValueError("Refinement disagrees with a known exact score")
    scores.update(fetched)
    top = tuple(sorted((score, row_ids[i]) for i, score in scores.items())[:k])
    if len(top) != k:
        raise AssertionError("Certified intervals failed to cover k rows")
    return top, plan, len(fetched)


def owner_state_bytes(count: int, dimension: int, max_row_id: int, *, reordered: bool) -> dict[str, int]:
    """Simple fixed-width radius/permutation arrays; map/framing/metadata excluded."""
    if (type(count) is not int or count < 0 or type(dimension) is not int or dimension < 1
            or type(max_row_id) is not int or max_row_id < 0 or type(reordered) is not bool):
        raise ValueError("Invalid hint byte model")
    radii = count * ((dimension.bit_length() + 7) // 8)
    permutation = count * max(1, (max_row_id.bit_length() + 7) // 8) if reordered else 0
    return {"radius_bytes": radii, "permutation_bytes": permutation, "total_bytes": radii + permutation}
