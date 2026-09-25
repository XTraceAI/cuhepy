"""Plaintext cost oracle for certified block-weight filtering (E10).

For every block, |weight(x)-weight(q)| <= Hamming(x,q). Summing disjoint
blocks gives a lower bound; a candidate can be skipped only when its best
possible (distance,index) pair is worse than the current kth exact pair.

This is NOT an encrypted protocol: weights, ordering and selected accesses
are visible here. It measures bound quality before paying for protected
comparisons, interaction or an attested/oblivious access mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass
import heapq


@dataclass(frozen=True)
class FilterResult:
    top: tuple[tuple[int, int], ...]
    exact_evaluations: int
    weight_comparisons: int


def select(rows: list[int], query: int, dimension: int, *, block_bits: int = 32, k: int = 3) -> FilterResult:
    if (type(dimension) is not int or not 1 <= dimension <= 4096 or type(block_bits) is not int
        or not 1 <= block_bits <= dimension or type(k) is not int or not 0 <= k <= len(rows)
        or any(type(x) is not int or x < 0 or x.bit_length() > dimension for x in [query, *rows])):
        raise ValueError("Invalid block-weight filter fixture")
    if not k:
        return FilterResult((), 0, 0)
    mask = (1 << block_bits) - 1
    weights = [((query >> start) & mask).bit_count() for start in range(0, dimension, block_bits)]
    lower = []
    for i, row in enumerate(rows):
        bound = sum(abs(((row >> (j * block_bits)) & mask).bit_count() - weight) for j, weight in enumerate(weights))
        lower.append((bound, i))
    heap: list[tuple[int, int]] = []
    evaluated = 0
    for bound, i in sorted(lower):
        if len(heap) == k and (bound, i) > (-heap[0][0], -heap[0][1]):
            break  # All later lower-bound pairs are at least as large.
        distance = (query ^ rows[i]).bit_count()
        evaluated += 1
        candidate = (-distance, -i)
        if len(heap) < k:
            heapq.heappush(heap, candidate)
        elif candidate > heap[0]:
            heapq.heapreplace(heap, candidate)
    top = tuple((-i, -distance) for distance, i in sorted(heap, reverse=True))
    return FilterResult(top, evaluated, len(rows) * len(weights))
