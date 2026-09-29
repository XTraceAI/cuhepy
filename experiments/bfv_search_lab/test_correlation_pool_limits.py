"""Exact negative oracle for public linear expansion of one-use mask pools.

This deliberately rejected shortcut is not an encryption/token API. It shows
why independently encrypting a SMALL reusable bank does not on its own provide
unbounded private queries: public mixing relations also cancel the masks in
the visible query differences. Authentication or re-encrypting answers cannot
remove a relation already present in those differences.
"""

from collections import Counter
import itertools


def test_full_rank_mixing_reparameters_two_masks_without_expanding_the_pool():
    t = 5
    # Two independent scalar masks can be mixed by an invertible 2x2 matrix.
    # Exhaustive enumeration proves the joint distribution, not just marginals.
    for weights in itertools.product(range(t), repeat=2):
        observed = Counter(((weights[0] - a - b) % t, (weights[1] - a - 2 * b) % t)
                           for a, b in itertools.product(range(t), repeat=2))
        assert len(observed) == t ** 2 and set(observed.values()) == {1}


def test_third_public_linear_combination_leaks_query_relation_despite_uniform_marginals():
    t = 5
    # Rows (1,0), (0,1), (1,1) have a public left-kernel vector (-1,-1,1).
    # The third request reuses both earlier masks, though its token ID and
    # encrypted answer can be new. Every individual delta is still uniform.
    for weights in itertools.product(range(t), repeat=3):
        observed = [((weights[0] - a) % t, (weights[1] - b) % t, (weights[2] - a - b) % t)
                    for a, b in itertools.product(range(t), repeat=2)]
        assert all(set(Counter(row[j] for row in observed).values()) == {t} for j in range(3))
        assert all((d[2] - d[0] - d[1]) % t == (weights[2] - weights[0] - weights[1]) % t for d in observed)
        # Known transformed coordinates (e.g. public raw forms) reveal the third.
        assert all((d[2] - d[0] - d[1] + weights[0] + weights[1]) % t == weights[2] for d in observed)
