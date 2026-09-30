"""Ring/capacity counts retain exact plaintext embedding and row coverage."""

from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import ring_capacity_frontier as rings


@pytest.fixture
def groups():
    rows = list(range(16))
    groups = fields.fit(rows, 4, tuple(range(16)), prime=17, n=64, target=2, initial_parts=8)
    return rows, groups


@pytest.mark.parametrize("n", (16, 32, 64, 128))
def test_counts_and_all_query_plaintext_outputs_are_exact(groups, n):
    rows, fitted = groups
    report = rings.describe(fitted, rows, n=n, slots=8)
    candidate = fields.allocate(replace(fitted, n=n), rows, 8)
    s = rings.public(candidate)
    assert report["response_body_bytes_model"] == 2 * n * 4 * report["replies"]
    assert report["encrypted_index_body_bytes_model"] == s.columns * report["response_body_bytes_model"]
    assert report["allocated_reply_coefficients"] >= 16
    assert report["requires_new_parameter_assurance"] == (n != 64)
    maps = tuple(dict.fromkeys(block.mapping for block in candidate.blocks))
    coordinates = [affine.index_features(block.mapping, [rows[i] for i in block.positions]) for block in candidate.blocks]
    for query in rows:
        transformed = [affine.query_features(mapping, query) for mapping in maps]
        values = tuple(x for weights, _ in transformed for x in weights)
        actual = space.scores(s, coordinates, values)
        # The encoder returns centered representatives; the decoder accepts
        # canonical plaintext residues, as after real HE decryption.
        replies = [[x % fitted.prime for x in reply] for reply in space.outputs(candidate.layout, actual)]
        assert tree.unpack(candidate.layout, replies) == actual
        decoded = []
        for block, group_values, group in zip(candidate.blocks, actual, s.map_ids, strict=True):
            decoded.extend(zip(affine.decode(maps[group], group_values, transformed[group][1]), block.positions, strict=True))
        assert sorted(decoded) == sorted(((query ^ row).bit_count(), i) for i, row in enumerate(rows))


def test_small_ring_does_not_bypass_rank_or_root_constraints(groups):
    rows, fitted = groups
    with pytest.raises(ValueError):
        rings.describe(fitted, rows, n=8, slots=8)
    with pytest.raises(ValueError):
        rings.describe(fitted, rows, n=64, slots=16)
    with pytest.raises(ValueError):
        rings.describe(fitted, rows, n=63, slots=8)
    with pytest.raises(ValueError):
        rings.describe(fitted, rows, n=64, slots=8, q_bits=24)


def test_same_grouping_and_source_digest_are_retained(groups):
    rows, fitted = groups
    changed = rows.copy()
    changed[0] = 15
    with pytest.raises(ValueError, match="Stale"):
        rings.describe(fitted, changed, n=64, slots=8)
