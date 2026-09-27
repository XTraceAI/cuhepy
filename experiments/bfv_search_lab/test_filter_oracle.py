"""Exhaustive tiny-domain and tie checks for the certified filtering oracle."""

import random

import pytest

from experiments.bfv_search_lab.filter_oracle import select


def test_exhaustive_binary_queries_and_bounds_keep_stable_winners():
    for dimension in range(1, 7):
        rows = list(range(1 << dimension))[::-1]
        for query in range(1 << dimension):
            exact = sorted(((i, (row ^ query).bit_count()) for i, row in enumerate(rows)), key=lambda p: (p[1], p[0]))
            for block in range(1, dimension + 1):
                for k in (0, 1, min(3, len(rows)), len(rows)):
                    result = select(rows, query, dimension, block_bits=block, k=k)
                    assert result.top == tuple(exact[:k])
                    assert k <= result.exact_evaluations <= len(rows)


def test_random_tail_blocks_duplicates_and_late_nearest_neighbor():
    rng = random.Random(1701)
    for dimension in (17, 127, 512):
        rows = [rng.getrandbits(dimension) for _ in range(200)]
        query = rng.getrandbits(dimension)
        rows.extend([query, query, query])
        for block in (1, 7, 17):
            assert select(rows, query, dimension, block_bits=block).top == ((200, 0), (201, 0), (202, 0))
    for rows, query, dimension in (([2], 0, 1), ([-1], 0, 3), ([True], 0, 3)):
        with pytest.raises(ValueError):
            select(rows, query, dimension, block_bits=1, k=1)
