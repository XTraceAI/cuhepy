"""Exact finite optimization compared to unpruned generic/symbolic controls."""

from dataclasses import replace

import pytest

from experiments.bfv_search_lab import noise_cut_oracle as oracle
from experiments.bfv_search_lab import noise_cut_planner as planner

Q = int("ffffffffffc00020000003bffc0001", 16)


def profile(n=8, d=4, bits=18):
    p = (1 << 25) - 1
    p -= (p - Q) % 17
    if not p % 2:
        p -= 17
    return planner.Profile(
        n, d, Q, p, 17, 1, bits, n * 100**2 + 17 * n * 4 * ((1 << 30) - 1)
    )


def objective(v):
    return -v.removed, v.work, v.seeds, v.digit_key_levels.bit_count(), v.peak


@pytest.mark.parametrize("bits", [14, 18, 30])
@pytest.mark.parametrize("allow_seed", [False, True])
def test_exact_tree_frontier_matches_generic_exhaustive_and_symbolic_boxes(
    bits, allow_seed
):
    context = profile(bits=bits)
    for count in range(1, 5):
        values, stats = planner.frontier(context, count, allow_seed)
        best = planner.select(values)
        independent, raw = oracle.exhaustive(context, count, allow_seed)
        assert objective(best) == objective(independent)
        replay = planner.replay(context, best.plan)
        assert (replay.peak, replay.removed, replay.work, replay.seeds) == (
            best.peak,
            best.removed,
            best.work,
            best.seeds,
        )
        peak, coordinates = oracle.symbolic_box_peak(context, best.plan)
        assert peak == best.peak and coordinates == context.n
        assert (
            stats["exact_within_declared_grammar"]
            and raw["complete_no_dominance_pruning"]
        )


def test_state_availability_retention_and_limits_are_explicit():
    p = profile()
    opaque, zero = planner.leaf(p, True, False), planner.leaf(p, False, False)
    with pytest.raises(ValueError, match="both common states"):
        planner.node(p, 0, 1, opaque, zero, "derived", False)
    with pytest.raises(ValueError, match="plus state"):
        planner.node(p, 0, 2, opaque, opaque, "canonical", True)
    anchor = planner.node(p, 0, 1, opaque, zero, "canonical", True)
    discarded = replace(anchor, state=None)
    with pytest.raises(ValueError):
        planner.node(p, 1, 2, discarded, anchor, "derived", False)
    with pytest.raises(planner.PlannerLimit):
        planner.frontier(p, 3, True, merge_cap=0)
    with pytest.raises(planner.PlannerLimit):
        planner.frontier(p, 3, True, label_cap=0)
    with pytest.raises(ValueError, match="root"):
        planner.replay(p, opaque.plan)


def test_nesting_can_be_tighter_than_sum_of_unrelated_level_maxima():
    # Different levels peak in different final residue classes. The generic
    # boxes permit arbitrary correlated signs; no independence is assumed.
    p = profile(n=16, d=8)
    values, _ = planner.frontier(p, 5, True)
    found = False
    for v in values:
        rows, _, errors = oracle.plan_boxes(p, v.plan)
        maxima_sum = p.d * p.product_bound + sum(
            (p.d >> (level + 1))
            * max(
                (value for (at, _), value in errors.items() if at == level), default=0
            )
            for level in range(3)
        )
        assert max(rows) <= maxima_sum
        if max(rows) < maxima_sum:
            found = True
            assert oracle.symbolic_box_peak(p, v.plan)[0] == max(rows)
    assert found


@pytest.mark.parametrize(
    "field,value", [("d", 3), ("n", True), ("eta", -1), ("p", 5), ("product_bound", -1)]
)
def test_invalid_profiles(field, value):
    with pytest.raises(ValueError):
        replace(profile(), **{field: value})


@pytest.mark.parametrize("n,d", [(8, 4), (16, 8)])
def test_closed_form_terminal_limit_and_dead_state_rule(n, d):
    p = profile(n=n, d=d)
    upper = p.maximum_peak
    assert p.safe(upper) and not p.safe(upper + 1)
    assert p.live_state(0, upper)
    assert not p.live_state(1, upper)
    assert not p.live_state(None, 0)
    # Dropping an unusable old lift must still permit a canonical unary reset.
    opaque, zero = planner.leaf(p, True, False), planner.leaf(p, False, False)
    reset = planner.node(p, 0, 1, opaque, zero, "canonical", True)
    assert reset.state == p.digit_bound * p.factor


def test_foreign_child_is_a_clean_grammar_rejection():
    p = profile()
    plan = planner.select(planner.frontier(p, 3, False)[0]).plan
    with pytest.raises(ValueError, match="coverage"):
        planner.replay(p, replace(plan, left=object()))
