"""E27: index-only rank-boundary repair with explicit private-map budgets.

Split only blocks exceeding a target rank, halving their plaintext component
capacity with each split. Median and optional binary-coordinate cuts compete.
This is a bounded greedy research heuristic, not an optimal partitioner. All
rows are certified; owner map bytes, imbalance, epoch changes and failed fits
remain costs. Complete row/ID storage is a distinct local-search control.

Groups/cuts are enrollment objects; online owner state consists of maps, pinned
public layout and common stable IDs. The local row-order checksum detects stale
fixtures, not malicious server output. External stable IDs need separate binding
in a real protocol. Private arithmetic has no side-channel assurance.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
import hashlib

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import dyadic_crt as crt
from experiments.bfv_search_lab import folded_filter as folded
from experiments.bfv_search_lab import linear_packing as packing


@dataclass(frozen=True)
class Block:
    path: str
    positions: tuple[int, ...]
    mapping: affine.Plan


@dataclass(frozen=True)
class Cut:
    path: str
    coordinate: int | None  # None means a median in the supplied index-only order.
    before_rank: int
    after_ranks: tuple[int, int]
    after_counts: tuple[int, int]


@dataclass(frozen=True)
class Candidate:
    layout: crt.Layout
    blocks: tuple[Block, ...]
    cuts: tuple[Cut, ...]
    source_digest: str
    dimension: int
    map_bytes: int
    target: int | None


def map_body_bytes(blocks: tuple[Block, ...]) -> int:
    """Replicated components share one canonical private map, not copies of it."""
    return sum(map(len, {affine.canonical_map(b.mapping) for b in blocks}))


def epoch_digest(rows: list[int], dimension: int) -> str:
    folded._words(0, rows, dimension)
    h = hashlib.sha256(b"cuhepy-affine-partition-local-v1\x00")
    h.update(dimension.to_bytes(2, "little"))
    h.update(len(rows).to_bytes(4, "little"))
    for row in rows:
        h.update(row.to_bytes((dimension + 7) // 8, "little"))
    return h.hexdigest()


def _options(
    rows: list[int], positions: tuple[int, ...], dimension: int, policy: str,
) -> Iterator[tuple[int | None, tuple[tuple[int, ...], tuple[int, ...]]]]:
    half = len(positions) // 2
    yield None, (positions[:half], positions[half:])
    if policy == "median":
        return
    counts = [(sum((rows[i] >> j) & 1 for i in positions), j) for j in range(dimension)]
    varying = [(abs(len(positions) - 2 * c), j) for c, j in counts if 0 < c < len(positions)]
    # Balanced cuts plus one rare direction probe; deduplicate complements.
    selected = sorted(varying)[:3] + sorted(varying, reverse=True)[:1]
    seen = {frozenset(positions[:half]), frozenset(positions[half:])}
    for _, coordinate in selected:
        pair = (tuple(i for i in positions if not (rows[i] >> coordinate) & 1),
                tuple(i for i in positions if (rows[i] >> coordinate) & 1))
        if frozenset(pair[0]) not in seen:
            seen.update(map(frozenset, pair))
            yield coordinate, pair


def prepare(
    rows: list[int], dimension: int, order: tuple[int, ...], *, initial_parts: int = 8,
    target: int | None = None, policy: str = "median", n: int = 16384, prime: int = 1153,
    max_depth: int = 6,
) -> Candidate:
    """Fit a complete candidate, then let select() apply the explicit byte budget.

    Premature map-byte pruning is avoided: a later split can make a formerly
    dense map sparse. Work is bounded by 64 leaves/depth 6 and the input size.
    Failure to meet the requested rank is returned as an explicit rejection.
    """
    folded._words(0, rows, dimension)
    if (not 1 <= len(rows) <= 32768 or len(rows) * dimension > 8 << 20
            or type(initial_parts) is not int or not 1 <= initial_parts <= min(64, len(rows))
            or initial_parts & (initial_parts - 1) or tuple(sorted(order)) != tuple(range(len(rows)))
            or policy not in ("median", "hybrid") or type(max_depth) is not int or not 0 <= max_depth <= 6
            or initial_parts.bit_length() - 1 > max_depth
            or target is not None and (type(target) is not int or target < 1 or target & (target - 1))):
        raise ValueError("Invalid bounded rank-partition workload")
    depth = initial_parts.bit_length() - 1
    paths = tuple(format(i, f"0{depth}b") for i in range(initial_parts)) if depth else ("",)
    crt.context(n, paths, prime)
    blocks = []
    for i, path in enumerate(paths):
        initial_positions = order[len(rows) * i // initial_parts:len(rows) * (i + 1) // initial_parts]
        blocks.append(Block(path, initial_positions, affine.prepare([rows[j] for j in initial_positions], dimension, prime)))
    cuts: list[Cut] = []
    while target is not None:
        bad = next((i for i, block in enumerate(blocks) if block.mapping.features > target), None)
        if bad is None:
            break
        block = blocks[bad]
        child_degree = n >> (len(block.path) + 1)
        if len(block.path) >= max_depth or len(blocks) >= 64 or child_degree < target:
            raise ValueError("Rank target cannot be met within the leaf/depth budget")
        proposals = []
        for coordinate, positions in _options(rows, block.positions, dimension, policy):
            if not all(positions):
                continue
            maps = tuple(affine.prepare([rows[j] for j in group], dimension, prime) for group in positions)
            ranks = tuple(p.rank for p in maps)
            if coordinate is not None and any(r >= block.mapping.rank for r in ranks):
                raise AssertionError("A varying binary coordinate must reduce affine dimension")
            sizes = tuple(map(len, positions))
            map_bytes = sum(len(affine.canonical_map(p)) for p in maps)
            # First reduce remaining rank violation. Once feasible, prefer lower
            # charged tile occupancy, then less map state. No optimality claim.
            score = (max(0, max(ranks) - target),
                     max((size * target + child_degree - 1) // child_degree for size in sizes),
                     map_bytes, -1 if coordinate is None else coordinate)
            proposals.append((score, coordinate, positions, maps))
        if not proposals:
            raise ValueError("No nonempty exact rank split")
        _, coordinate, positions, maps = min(proposals, key=lambda p: p[0])
        children = [Block(block.path + str(i), group, mapping)
                    for i, (group, mapping) in enumerate(zip(positions, maps, strict=True))]
        cuts.append(Cut(block.path, coordinate, block.mapping.rank,
                        (maps[0].rank, maps[1].rank), (len(positions[0]), len(positions[1]))))
        blocks[bad:bad + 1] = children
    ctx = crt.context(n, tuple(b.path for b in blocks), prime)
    plan = crt.layout(ctx, tuple(b.mapping.features for b in blocks), tuple(len(b.positions) for b in blocks))
    result = Candidate(plan, tuple(blocks), tuple(cuts), epoch_digest(rows, dimension), dimension,
                       map_body_bytes(tuple(blocks)), target)
    validate_epoch(result, rows)
    return result


def validate_epoch(candidate: Candidate, rows: list[int]) -> None:
    """Reject stale/reordered local inputs; this hash is NOT server authentication."""
    crt.validate_layout(candidate.layout)
    if epoch_digest(rows, candidate.dimension) != candidate.source_digest:
        raise ValueError("Stale affine partition epoch")
    positions = [i for block in candidate.blocks for i in block.positions]
    if (sorted(positions) != list(range(len(rows)))
            or tuple(b.path for b in candidate.blocks) != tuple(leaf.path for leaf in candidate.layout.context.leaves)
            or tuple(len(b.positions) for b in candidate.blocks) != candidate.layout.counts
            or tuple(b.mapping.features for b in candidate.blocks) != candidate.layout.features
            or any(b.mapping.dimension != candidate.dimension or b.mapping.prime != candidate.layout.context.prime
                   for b in candidate.blocks)
            or candidate.map_bytes != map_body_bytes(candidate.blocks)):
        raise ValueError("Partition omits, duplicates or changes its pinned row/map layout")
    for block in candidate.blocks:
        affine.index_features(block.mapping, [rows[i] for i in block.positions])


def select(candidates: list[Candidate], map_budget: int) -> Candidate | None:
    """Rank declared candidates; None is the unchanged full-scan fallback.

    Prefer replies, products, switches, then map bytes. Canonical maps are the
    explicitly budgeted category; Python objects, public layout, IDs and keys
    remain separate. This is selection among supplied heuristics, not a solver.
    """
    if type(map_budget) is not int or map_budget < 0:
        raise ValueError("Invalid owner map budget")
    if not candidates:
        return None
    first = candidates[0]
    count = sum(first.layout.counts)
    if any((c.source_digest, c.dimension, c.layout.context.n, c.layout.context.prime, sum(c.layout.counts))
           != (first.source_digest, first.dimension, first.layout.context.n, first.layout.context.prime, count)
           for c in candidates):
        raise ValueError("Cannot compare candidates from different index epochs or parameters")
    full = packing.packing_cost(first.dimension, count, first.layout.context.n)
    full_cost = (full.response_ciphertexts, full.input_tiles, full.switches)
    eligible = []
    for candidate in candidates:
        cost = candidate.layout.cost
        score = (cost.response_ciphertexts, cost.input_tiles, cost.switches)
        if candidate.map_bytes <= map_budget and score < full_cost:
            eligible.append(((*score, candidate.map_bytes, len(candidate.blocks)), candidate))
    return min(eligible, key=lambda p: p[0])[1] if eligible else None


def allocate_slots(counts: tuple[int, ...], slots: int, capacity: int) -> tuple[int, tuple[int, ...]]:
    """Exact minimum maximum tile count for fixed, equally sized slot quanta.

    At L tiles, group i needs ceil(count_i/(L*capacity)) slots. Feasibility is
    exactly their sum <= slots. This covers fixed maps/common D only, not the
    harder joint partition/rank choice. Every nonempty group gets a slot.
    """
    if (not counts or any(type(c) is not int or c < 1 for c in counts)
            or type(slots) is not int or not len(counts) <= slots <= 64
            or type(capacity) is not int or capacity < 1):
        raise ValueError("Invalid fixed-map capacity allocation")

    def needed(tiles: int) -> tuple[int, ...]:
        return tuple((count + tiles * capacity - 1) // (tiles * capacity) for count in counts)

    low, high = 1, (max(counts) + capacity - 1) // capacity
    while low < high:
        middle = (low + high) // 2
        if sum(needed(middle)) <= slots:
            high = middle
        else:
            low = middle + 1
    allocation = list(needed(low))
    # Extra slots do not change the proven optimum. Deterministic integer
    # cross-products prefer the largest current count/slot density.
    while sum(allocation) < slots:
        best = 0
        for i in range(1, len(counts)):
            if counts[i] * allocation[best] > counts[best] * allocation[i]:
                best = i
        allocation[best] += 1
    return low, tuple(allocation)


def reallocate(candidate: Candidate, rows: list[int], slots: int = 64, *, coalesce: bool = True) -> Candidate:
    """Decouple CRT capacity from the tree that discovered the private maps.

    Assign contiguous elementary slots by exact minimax allocation, coalesce
    same-map dyadic intervals, and split a group's encrypted coordinates across
    those leaves. Query weights/maps are shared by replicas. Leaf geometry and
    occupancy remain metadata. IDs and every zero tail remain charged.
    """
    validate_epoch(candidate, rows)
    n, padded, prime = candidate.layout.context.n, candidate.layout.padded, candidate.layout.context.prime
    if (type(slots) is not int or not 1 <= slots <= min(64, n // padded) or slots & (slots - 1)
            or type(coalesce) is not bool):
        raise ValueError("Invalid elementary CRT slot count")
    grouped: dict[affine.Plan, list[int]] = {}
    for block in candidate.blocks:
        grouped.setdefault(block.mapping, []).extend(block.positions)
    maps = list(grouped)
    positions = [tuple(grouped[mapping]) for mapping in maps]
    tiles, allocation = allocate_slots(tuple(map(len, positions)), slots, n // slots // padded)
    labels = [i for i, count in enumerate(allocation) for _ in range(count)]
    leaves: list[tuple[str, int]] = []

    def cover(path: str, start: int, stop: int) -> None:
        if stop - start == 1 or coalesce and all(label == labels[start] for label in labels[start:stop]):
            leaves.append((path, labels[start]))
        else:
            middle = (start + stop) // 2
            cover(path + "0", start, middle)
            cover(path + "1", middle, stop)

    cover("", 0, slots)
    offsets = [0] * len(maps)
    blocks = []
    for path, group in leaves:
        capacity = (n >> len(path)) // padded
        count = min(len(positions[group]) - offsets[group], tiles * capacity)
        piece = positions[group][offsets[group]:offsets[group] + count]
        offsets[group] += count
        blocks.append(Block(path, piece, maps[group]))
    assert offsets == list(map(len, positions))
    ctx = crt.context(n, tuple(path for path, _ in leaves), prime)
    plan = crt.layout(ctx, tuple(b.mapping.features for b in blocks), tuple(len(b.positions) for b in blocks))
    result = Candidate(plan, tuple(blocks), candidate.cuts, candidate.source_digest,
                       candidate.dimension, map_body_bytes(tuple(blocks)), candidate.target)
    assert result.layout.cost.input_tiles == tiles and result.map_bytes == candidate.map_bytes
    validate_epoch(result, rows)
    return result
