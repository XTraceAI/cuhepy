"""Exact bounds, stable IDs, and independent public-fixture parsing oracles."""

from itertools import product
from pathlib import Path
import random

import pytest

from experiments.bfv_search_lab import adaptive_refinement as adaptive
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import folded_filter as folded
from experiments.bfv_search_lab import interval_filter as interval


@pytest.mark.parametrize("budget", [1, 3, 8])
@pytest.mark.parametrize("passes", [0, 2])
def test_dictionary_certifies_every_query_and_nonincreasing_tail_objective(budget, passes):
    rng = random.Random(2901)
    rows = [rng.randrange(256) for _ in range(19)]
    result = dictionary.prepare(rows, 8, budget, tail_passes=passes)
    plan = result.plan
    assert len(plan.representatives) <= budget
    assert result.final_error_objective <= result.initial_error_objective
    templates = [folded._template(plan, row) for row in rows]
    radii = tuple((a ^ b).bit_count() for a, b in zip(rows, templates, strict=True))
    assert max(radii) == plan.max_error
    for query in range(256):
        scores = [(query ^ row).bit_count() for row in templates]
        lo, hi = interval.intervals(scores, radii, 8)
        truth = [(query ^ row).bit_count() for row in rows]
        assert all(a <= d <= b for a, d, b in zip(lo, truth, hi, strict=True))
        assert folded.lower_bounds(plan, query, rows) == lo
        dots = [8 - 2 * score for score in scores]
        assert interval.decode_templates([x % 11 for x in dots], 8, 11) == scores


def test_dictionary_stops_at_exact_complement_equivalence_and_rejects_bad_sizes():
    result = dictionary.prepare([0b1010, 0b0101], 4, 4, tail_passes=2)
    assert result.plan.max_error == 0 and len(result.plan.representatives) == 1
    for rows, dimension, budget, passes in (([], 8, 2, 0), ([0], 8, 0, 0), ([0], 8, 9, 0),
                                           ([0], 8, 1, 5), ([256], 8, 2, 0)):
        with pytest.raises(ValueError):
            dictionary.prepare(rows, dimension, budget, tail_passes=passes)


def test_physical_layouts_preserve_stable_tie_breaking():
    rows = [3, 1, 7, 0, 3, 0, 4]
    ids = [100, 2, 20, 50, 99, 3, 1]
    plan = dictionary.prepare(rows, 3, 2).plan
    for order in (dictionary.metric_order(rows, 3, 2), dictionary.signature_order(plan, rows)):
        assert sorted(order) == list(range(len(rows)))
        truth = [rows[i].bit_count() for i in order]
        stable = [ids[i] for i in order]

        def fetch(tiles, truth=truth):
            return [(i, truth[i]) for t in tiles for i in range(t * 2, min(t * 2 + 2, len(rows)))]

        expected = tuple(sorted((row.bit_count(), i) for row, i in zip(rows, ids, strict=True))[:3])
        assert adaptive.refine([0] * len(rows), 3, 2, fetch, row_ids=stable).top == expected
        assert interval.refine_once([0] * len(rows), [3] * len(rows), stable, 2, fetch)[0] == expected
    assert dictionary.metric_order([], 3, 2) == ()
    assert dictionary.metric_order([0] * 9, 3, 2) == tuple(range(9))
    with pytest.raises(ValueError):
        adaptive.refine([0, 0], 3, 1, lambda _: [], row_ids=[1, 1], k=1)


@pytest.mark.parametrize("capacity", [1, 2, 8])
def test_interval_selection_exhaustive_small_distances_and_boundary_ties(capacity):
    ids = [9, 1, 4]
    for distances in product(range(3), repeat=3):
        choices = [[(a, b) for a in range(d + 1) for b in range(d, 3)] for d in distances]
        for bounds in product(*choices):
            lower, upper = map(list, zip(*bounds, strict=True))
            for k in (1, 3):
                def fetch(tiles, distances=distances):
                    return [(i, distances[i]) for t in tiles
                            for i in range(t * capacity, min((t + 1) * capacity, 3))]

                known = {2: distances[2]}
                top, _, _ = interval.refine_once(lower, upper, ids, capacity, fetch, k=k, known_scores=known)
                assert top == tuple(sorted(zip(distances, ids, strict=True))[:k])


def test_exact_hints_avoid_fetch_and_witnesses_do_not_certify_neighbor_rows():
    top, plan, count = interval.refine_once([1, 0, 0], [1, 0, 0], [0, 9, 2], 2,
                                          lambda _: pytest.fail("unexpected fetch"))
    assert top == ((0, 2), (0, 9), (1, 0)) and not plan.tiles and count == 0
    plan = interval.select_tiles([0] * 5, [8] * 5, [9, 8, 7, 6, 5], 2, known_scores={0: 1, 2: 1, 4: 1})
    assert plan.tiles == (0, 1)  # Witnesses cover positions, not whole original tiles.
    assert plan.threshold == (1, 9)
    assert interval.select_tiles([], [], [], 1, k=0).tiles == ()
    assert interval.owner_state_bytes(8192, 512, 8191, reordered=True)["total_bytes"] == 32768


def test_invalid_or_inconsistent_local_scores_rejected():
    for known in ({3: 0}, {0: 4}, {True: 0}):
        with pytest.raises(ValueError):
            interval.select_tiles([0] * 3, [3] * 3, [0, 1, 2], 2, known_scores=known)
    for scores in ([], [(0, 0), (0, 0), (2, 0)], [(0, 4), (1, 0), (2, 0)]):
        with pytest.raises(ValueError):
            interval.refine_once([0] * 3, [3] * 3, [0, 1, 2], 2, lambda _, scores=scores: scores)
    with pytest.raises(ValueError, match="disagrees"):
        interval.refine_once([0, 0], [3, 3], [0, 1], 2, lambda _: [(0, 2), (1, 1)],
                             k=1, known_scores={0: 1})
    with pytest.raises(ValueError):
        interval.decode_templates([1], 8, 19)
    with pytest.raises(ValueError):
        interval.intervals([1], (9,), 8)


def test_untrusted_radius_can_silently_omit_a_winner():
    # As with E22, range checks are not authentication. A false interval can
    # prune the true winner without ever requesting its exact score.
    truth = [2, 0]
    top, _, _ = interval.refine_once([0, 8], [2, 8], [0, 1], 1,
                                   lambda tiles: [(i, truth[i]) for i in tiles], k=1)
    assert top == ((2, 0),)


def test_fixture_encodings_discard_labels_and_preserve_stated_distance():
    pixels = ["0"] * 256
    pixels[1] = pixels[200] = "1"
    one = " ".join(pixels + ["1"] + ["0"] * 9)
    two = " ".join(pixels + ["0", "1"] + ["0"] * 8)
    assert fixtures.parse_semeion(one + "\n" + two) == ((1 << 1) | (1 << 200),) * 2
    categories = [a[0] for a in fixtures.MUSHROOM_CATEGORIES]
    first = ",".join(["e", *categories])
    same = ",".join(["p", *categories])
    categories[0] = fixtures.MUSHROOM_CATEGORIES[0][1]
    categories[10] = "?"
    changed = ",".join(["p", *categories])
    a, b, c = fixtures.parse_mushroom("\n".join((first, same, changed)))
    assert a == b and (a ^ c).bit_count() == 4 and a.bit_count() == c.bit_count() == 22
    assert sum(map(len, fixtures.MUSHROOM_CATEGORIES)) == 126
    for parser, invalid in ((fixtures.parse_semeion, "0"), (fixtures.parse_semeion, one.replace("1", "nan", 1)),
                            (fixtures.parse_mushroom, first.replace("b", "!", 1))):
        with pytest.raises(ValueError):
            parser(invalid)


def test_fixture_split_and_pinning(tmp_path: Path):
    data = fixtures.BinaryData("toy", 8, tuple(range(200)), "fixture")
    index, queries = fixtures.split(data, 2901)
    assert len(index) == 72 and len(queries) == 128
    assert not set(index) & set(queries) and sorted(index + queries) == list(range(200))
    bad = tmp_path / "bad.data"
    bad.write_text("0")
    with pytest.raises(ValueError, match="hash"):
        fixtures.load("semeion", bad)
