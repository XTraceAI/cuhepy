"""E19/E22 local branch-and-bound oracle with ciphertext-tile accounting.

Bounds must already be correct for EVERY row. Refinement starts without a kth
distance, fetches complete existing index tiles, caches their scores, and uses
stable (distance, original ID) ordering. It never assumes free candidate
repacking. Requests/round counts are exposed: this is NOT a private protocol.
Authentication, coverage, hidden routing and padded schedules remain separate
obligations before this control flow may drive a remote decrypting client.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import heapq


@dataclass(frozen=True)
class Round:
    tiles: tuple[int, ...]
    scored_rows: int
    upper_before: tuple[int, int] | None
    upper_after: tuple[int, int] | None


@dataclass(frozen=True)
class Refinement:
    top: tuple[tuple[int, int], ...]  # (distance, original row ID)
    rounds: tuple[Round, ...]
    exact_rows: int
    fetched_tiles: int


def refine(
    lower: list[int], dimension: int, tile_capacity: int,
    score_tiles: Callable[[tuple[int, ...]], list[tuple[int, int]]],
    *, k: int = 3, batch_tiles: int = 1,
) -> Refinement:
    """Call score_tiles with original tile IDs; expect all (row ID, distance).

    This routine sees only supplied bounds and scores from requested tiles.
    The threshold is the kth best actually evaluated pair, not an oracle radius.
    Equality cannot discard a smaller ID. Neighboring scores in a fetched tile
    are useful work and immediately participate in the threshold.
    """
    if (type(dimension) is not int or dimension < 1 or type(tile_capacity) is not int
            or tile_capacity < 1 or type(batch_tiles) is not int or batch_tiles < 1
            or type(k) is not int or not 0 <= k <= len(lower)
            or any(type(x) is not int or x > dimension for x in lower)):
        raise ValueError("Invalid refinement fixture")
    if not k:
        return Refinement((), (), 0, 0)
    order = sorted(range(len(lower)), key=lambda i: (max(0, lower[i]), i))
    heap: list[tuple[int, int]] = []  # Negated (distance, ID): worst at root.
    fetched: set[int] = set()
    rounds: list[Round] = []
    exact_rows = 0
    at = 0

    def upper() -> tuple[int, int] | None:
        return (-heap[0][0], -heap[0][1]) if len(heap) == k else None

    while at < len(order):
        before = upper()
        chosen: set[int] = set()
        while at < len(order):
            i = order[at]
            tile = i // tile_capacity
            if tile in fetched or tile in chosen:
                at += 1
                continue
            if before is not None and (max(0, lower[i]), i) > before:
                break
            if len(chosen) == batch_tiles:
                break  # Leave this unrequested row at the head of the queue.
            chosen.add(tile)
            at += 1
        if not chosen:
            break
        tiles = tuple(sorted(chosen))
        expected = {i for tile in tiles
                    for i in range(tile * tile_capacity, min((tile + 1) * tile_capacity, len(lower)))}
        scores = score_tiles(tiles)
        if (len(scores) != len(expected) or {i for i, _ in scores} != expected
                or any(type(i) is not int or type(d) is not int or not 0 <= d <= dimension
                       or lower[i] > d for i, d in scores)):
            raise ValueError("Refiner must return each requested row once with a consistent exact score")
        for i, distance in scores:
            candidate = (-distance, -i)
            if len(heap) < k:
                heapq.heappush(heap, candidate)
            elif candidate > heap[0]:
                heapq.heapreplace(heap, candidate)
        fetched.update(tiles)
        exact_rows += len(scores)
        rounds.append(Round(tiles, len(scores), before, upper()))
    assert len(heap) == k
    top = tuple(sorted((-distance, -i) for distance, i in heap))
    return Refinement(top, tuple(rounds), exact_rows, len(fetched))
