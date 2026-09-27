"""Exhaustive signed correction and canonical sparse hint encoding."""

from dataclasses import replace
import random
import struct

import pytest

from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import folded_filter as folded
from experiments.bfv_search_lab import owner_residuals as residuals


@pytest.mark.parametrize("budget", [1, 3, 8])
def test_sparse_owner_correction_exact_for_all_queries(budget):
    rows = [0, 255, 1, 254, 42, 172, 85, 143]
    plan = dictionary.prepare(rows, 8, budget).plan
    hint = residuals.prepare(plan, rows)
    prepared = residuals.compile_hint(hint)
    for query in range(256):
        scores = [(query ^ folded._template(plan, row)).bit_count() for row in rows]
        assert residuals.correct(prepared, query, scores) == [(query ^ row).bit_count() for row in rows]
    assert hint.body_bytes == 4 * (len(rows) + 1) + sum((row ^ folded._template(plan, row)).bit_count() for row in rows)
    assert prepared.python_mask_bytes > 0


@pytest.mark.parametrize("dimension", [1, 127, 128, 129, 512])
def test_position_width_boundaries_and_empty_index(dimension):
    rng = random.Random(2906)
    rows = [rng.getrandbits(dimension) for _ in range(17)]
    plan = dictionary.prepare(rows, dimension, min(4, dimension)).plan
    hint = residuals.prepare(plan, rows)
    prepared = residuals.compile_hint(hint)
    query = rng.getrandbits(dimension)
    scores = [(query ^ folded._template(plan, row)).bit_count() for row in rows]
    assert residuals.correct(prepared, query, scores) == [(query ^ row).bit_count() for row in rows]
    assert residuals.correct(residuals.compile_hint(residuals.prepare(plan, [])), query, []) == []


def test_hint_rejects_offsets_duplicates_noncanonical_order_and_ranges():
    hint = residuals.Hint(8, 1, struct.pack("<II", 0, 2), bytes((1, 3)))
    residuals.compile_hint(hint)
    for bad in (replace(hint, entries=bytes((3, 1))), replace(hint, entries=bytes((0, 1))),
                replace(hint, entries=bytes((0, 16))), replace(hint, offsets=struct.pack("<II", 1, 2)),
                replace(hint, offsets=b""), replace(hint, count=True), replace(hint, dimension=0)):
        with pytest.raises(ValueError):
            residuals.compile_hint(bad)
    with pytest.raises(ValueError):
        residuals.correct(residuals.compile_hint(hint), 256, [3])
    with pytest.raises(ValueError):
        residuals.correct(residuals.compile_hint(hint), 0, [8])


def test_residual_values_are_private_data_and_not_an_authentication_tag():
    plan = dictionary.prepare([0, 255, 1], 8, 1).plan
    rows = [0, 255, 1]
    state = residuals.compile_hint(residuals.prepare(plan, rows))
    # A malicious template response can yield plausible, wrong exact distances.
    true_scores = [folded._template(plan, row).bit_count() for row in rows]
    true_scores[0] += 1
    corrected = residuals.correct(state, 0, true_scores)
    assert corrected != [row.bit_count() for row in rows]
