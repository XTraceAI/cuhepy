"""Exact coverage and tile/round accounting for the local refinement oracle."""

import random

import pytest

from experiments.bfv_search_lab import adaptive_refinement as adaptive


@pytest.mark.parametrize("capacity", [1, 3, 16, 128])
@pytest.mark.parametrize("batch", [1, 4, 32])
def test_refinement_discovers_threshold_and_preserves_stable_topk(capacity, batch):
    rng = random.Random(2803)
    distances = [rng.randrange(33) for _ in range(101)]
    lower = [rng.randrange(distance + 1) for distance in distances]
    seen = set()

    def fetch(tiles):
        assert not (set(tiles) & seen)
        seen.update(tiles)
        return [(i, distances[i]) for tile in tiles for i in range(tile * capacity, min((tile + 1) * capacity, 101))]

    result = adaptive.refine(lower, 32, capacity, fetch, batch_tiles=batch)
    assert result.top == tuple(sorted((distance, i) for i, distance in enumerate(distances))[:3])
    assert result.rounds[0].upper_before is None
    assert result.fetched_tiles == len(seen)
    assert result.exact_rows == sum(r.scored_rows for r in result.rounds)
    previous = None
    for r in result.rounds:
        assert len(r.tiles) <= batch
        assert r.upper_before == previous
        if previous is not None:
            assert r.upper_after <= previous
        previous = r.upper_after


def test_adversarial_ties_and_complete_tiles_do_not_omit_a_smaller_id():
    # A later ID looks best initially, but the tied earlier ID must be checked.
    distances = [3, 3, 3, 3, 3]
    lower = [3, 3, 3, 3, 0]
    requests = []

    def fetch(tiles):
        requests.extend(tiles)
        return [(i, distances[i]) for tile in tiles for i in range(tile * 2, min(tile * 2 + 2, 5))]

    result = adaptive.refine(lower, 8, 2, fetch, k=3)
    assert requests == [2, 0, 1]
    assert result.top == ((3, 0), (3, 1), (3, 2))
    assert result.exact_rows == 5


def test_duplicates_stop_safely_after_enough_small_ids_and_zero_k_does_no_work():
    def fetch(tiles):
        return [(i, 0) for t in tiles for i in range(t * 8, min(t * 8 + 8, 99))]

    result = adaptive.refine([0] * 99, 8, 8, fetch)
    assert result.top == ((0, 0), (0, 1), (0, 2))
    assert result.exact_rows == 8 and result.fetched_tiles == 1
    assert adaptive.refine([], 8, 8, lambda _: pytest.fail("unexpected fetch"), k=0).top == ()


def test_refiner_rejects_missing_duplicate_invalid_or_inconsistent_scores():
    for scores in ([], [(0, 0), (0, 0)], [(1, 0)], [(0, -1)], [(0, 9)], [(0, 0)]):
        with pytest.raises(ValueError):
            adaptive.refine([1], 8, 1, lambda _, scores=scores: scores, k=1)
    for lower, k, capacity, batch in (([0], 2, 1, 1), ([9], 1, 1, 1), ([0], 1, 0, 1), ([0], 1, 1, 0)):
        with pytest.raises(ValueError):
            adaptive.refine(lower, 8, capacity, lambda _: [], k=k, batch_tiles=batch)


def test_untrusted_bounds_are_not_an_omission_certificate():
    # Detecting bad returned scores is insufficient: a false high bound can
    # suppress the real winner before any exact score is requested.
    truth = [2, 0]
    result = adaptive.refine([0, 8], 8, 1, lambda tiles: [(i, truth[i]) for i in tiles], k=1)
    assert result.top == ((2, 0),)
    assert result.top != tuple(sorted((d, i) for i, d in enumerate(truth))[:1])
