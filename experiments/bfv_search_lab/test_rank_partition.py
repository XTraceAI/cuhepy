"""Exact rank repair, fixed map budgets, stable IDs and stale-epoch rejection."""

from dataclasses import replace
from itertools import product

import pytest

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import dyadic_crt as crt
from experiments.bfv_search_lab import rank_partition as partition


def fixture():
    rows = [255] * 16 + list(range(16))
    rows[-1] ^= 16  # One independent direction crosses padded rank 4 -> 8.
    return rows


@pytest.mark.parametrize("policy", ["median", "hybrid"])
def test_repair_splits_only_bad_block_and_preserves_all_distances_and_stable_ties(policy):
    rows = fixture()
    old = partition.prepare(rows, 8, tuple(range(32)), initial_parts=2, n=128)
    new = partition.prepare(rows, 8, tuple(range(32)), initial_parts=2, n=128, target=4, policy=policy)
    assert old.layout.padded == 8 and new.layout.padded == 4
    assert tuple(b.path for b in new.blocks) == ("0", "10", "11")
    assert old.layout.cost.input_tiles == 2 and new.layout.cost.input_tiles == 1
    assert new.blocks[0] == old.blocks[0]
    for query in range(256):
        actual = []
        for block in new.blocks:
            features = affine.index_features(block.mapping, [rows[i] for i in block.positions])
            weights, offset = affine.query_features(block.mapping, query)
            scores = affine.decode(block.mapping, [sum(a * b for a, b in zip(w, weights, strict=True)) % 1153
                                                    for w in features], offset)
            actual.extend(zip(scores, block.positions, strict=True))
        expected = sorted(((query ^ row).bit_count(), i) for i, row in enumerate(rows))
        assert sorted(actual) == expected and sorted(actual)[:3] == expected[:3]


def test_strict_map_budget_and_no_improvement_use_full_scan_fallback():
    rows = fixture()
    base = partition.prepare(rows, 8, tuple(range(32)), initial_parts=2, n=128)
    repaired = partition.prepare(rows, 8, tuple(range(32)), initial_parts=2, n=128, target=4)
    assert partition.select([base], 10000) is None
    assert partition.select([base, repaired], repaired.map_bytes) == repaired
    assert partition.select([base, repaired], repaired.map_bytes - 1) is None
    assert partition.select([], 0) is None
    with pytest.raises(ValueError):
        partition.select([repaired], -1)


def test_epoch_pin_rejects_even_in_span_change_and_row_reordering():
    rows = fixture()
    candidate = partition.prepare(rows, 8, tuple(range(32)), initial_parts=2, n=128, target=4)
    changed = rows.copy()
    changed[16] = 1  # Fits its old affine space, but is not the enrolled index.
    block = candidate.blocks[1]
    affine.index_features(block.mapping, [changed[i] for i in block.positions])
    with pytest.raises(ValueError, match="epoch"):
        partition.validate_epoch(candidate, changed)
    swapped = rows.copy()
    swapped[16], swapped[17] = swapped[17], swapped[16]
    with pytest.raises(ValueError, match="epoch"):
        partition.validate_epoch(candidate, swapped)
    other = partition.prepare(changed, 8, tuple(range(32)), initial_parts=2, n=128, target=4)
    with pytest.raises(ValueError, match="epochs"):
        partition.select([candidate, other], 10000)


def test_omission_duplicate_and_map_accounting_mutations_rejected():
    rows = fixture()
    candidate = partition.prepare(rows, 8, tuple(range(32)), initial_parts=2, n=128, target=4)
    first = candidate.blocks[0]
    for mutated in (replace(candidate, map_bytes=0),
                    replace(candidate, blocks=(replace(first, positions=first.positions[:-1]), *candidate.blocks[1:])),
                    replace(candidate, blocks=(replace(first, positions=(*first.positions[:-1], 16)), *candidate.blocks[1:]))):
        with pytest.raises(ValueError):
            partition.validate_epoch(mutated, rows)


def test_depth_budget_and_invalid_partitions_fail_explicitly():
    rows = fixture()
    with pytest.raises(ValueError, match="budget"):
        partition.prepare(rows, 8, tuple(range(32)), initial_parts=2, n=128, target=4, max_depth=1)
    for kwargs in ({"initial_parts": 3}, {"target": 3}, {"policy": "query_fitted"}, {"max_depth": 7}):
        with pytest.raises(ValueError):
            partition.prepare(rows, 8, tuple(range(32)), n=128, **kwargs)
    with pytest.raises(ValueError):
        partition.prepare(rows, 8, (0,) * 32, n=128)


@pytest.mark.parametrize("counts,slots,capacity", [((30, 4, 2), 8, 2), ((32, 32, 1), 8, 4),
                                                ((1,), 1, 1), ((3, 3, 3), 3, 2)])
def test_capacity_minimax_matches_exhaustive_integer_allocations(counts, slots, capacity):
    tiles, allocation = partition.allocate_slots(counts, slots, capacity)
    choices = [a for a in product(range(1, slots + 1), repeat=len(counts)) if sum(a) <= slots]
    expected = min(max((c + a * capacity - 1) // (a * capacity) for c, a in zip(counts, alloc, strict=True))
                   for alloc in choices)
    assert tiles == expected and sum(allocation) == slots
    assert all(c <= a * tiles * capacity for c, a in zip(counts, allocation, strict=True))


def test_reallocation_preserves_complete_coverage_and_deduplicated_map_state():
    rows = fixture()
    candidate = partition.prepare(rows, 8, tuple(range(32)), initial_parts=2, n=128, target=4)
    allocated = partition.reallocate(candidate, rows, slots=16)
    flat = partition.reallocate(candidate, rows, slots=16, coalesce=False)
    assert len(flat.blocks) == 16
    assert flat.layout.cost.input_tiles == allocated.layout.cost.input_tiles
    assert flat.map_bytes == allocated.map_bytes
    partition.validate_epoch(flat, rows)
    assert allocated.map_bytes == candidate.map_bytes
    assert allocated.layout.cost.input_tiles <= candidate.layout.cost.input_tiles
    partition.validate_epoch(allocated, rows)
    for block in allocated.blocks:
        affine.index_features(block.mapping, [rows[i] for i in block.positions])
    with pytest.raises(ValueError):
        partition.reallocate(candidate, rows, slots=64)
    with pytest.raises(ValueError):
        partition.allocate_slots((1, 0), 8, 1)


def test_uneven_private_groups_need_capacity_reallocation_to_avoid_waste():
    # Deliberately fixed unequal groups, independent of the cut heuristic.
    rows = list(range(16)) * 16 + [i << 4 for i in range(16)]
    blocks = (partition.Block("0", tuple(range(256)), affine.prepare(rows[:256], 8)),
              partition.Block("1", tuple(range(256, 272)), affine.prepare(rows[256:], 8)))
    layout = crt.layout(crt.context(512, ("0", "1")), (4, 4), (256, 16))
    candidate = partition.Candidate(layout, blocks, (), partition.epoch_digest(rows, 8), 8,
                                    partition.map_body_bytes(blocks), 4)
    allocated = partition.reallocate(candidate, rows, slots=64)
    assert allocated.layout.cost.input_tiles < candidate.layout.cost.input_tiles
    assert allocated.map_bytes == candidate.map_bytes
    assert len({b.mapping for b in allocated.blocks}) == 2
