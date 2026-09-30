"""Checkpoint identity, outside-span correction and complete finite frontier."""

from dataclasses import replace
import random

import pytest

from experiments.bfv_search_lab import lifetime_planner as life
from experiments.bfv_search_lab import overlay_lifetime as overlay
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def fixture():
    w = Workload((0, 1), (100, 9), 3)
    entries = tuple(life.reserve(w, bits, 17, name=str(i)) for i, bits in enumerate(((), (1,), (1, 2))))
    trace = life.Trace((w, replace(w, rows=(0, 3)), replace(w, rows=(2, 7)), w), (1, 1, 1, 1), 6)
    return overlay.Problem(trace, entries, Profile(32, 17, eta=1))


def test_dp_frontier_matches_all_schedules_and_charges_every_unused_token():
    p = fixture()
    exact, counts = overlay.exhaustive(p)
    actual, dp_counts = overlay.dynamic_program(p)
    assert {x.cost for x in actual} == {x.cost for x in exact}
    assert dp_counts[-1] < counts[-1]
    start = p.starts()[0]
    fresh = start.cost.encrypted.fresh_ciphertext_coefficients
    assert fresh == 2 * 32 * (1 + 6)
    delta = next(x for x in p.successors(1, start) if x.actions[-1][1] == "client_delta")
    assert delta.cost.encrypted.fresh_ciphertext_coefficients == fresh
    assert delta.base_revision == 0
    refreshed = next(x for x in p.successors(1, start) if x.actions[-1][1] == "migrate")
    assert refreshed.cost.encrypted.fresh_ciphertext_coefficients - fresh == 2 * 32 * (2 + 5)


def test_current_outside_span_does_not_invalidate_the_frozen_encrypted_base():
    p = fixture()
    assert p.plans[1][0] is None
    first = p.starts()[0]
    next_paths = p.successors(1, first)
    assert any(x.entry == 0 and x.base_revision == 0 for x in next_paths)
    final, _ = overlay.dynamic_program(p)
    keep_base = [x for x in final if all(action[1] == "client_delta" for action in x.actions[1:])]
    assert keep_base
    # The trace returns to its original rows. Old exceptions disappear, but
    # previously incurred work and the peak private state remain charged.
    assert p.delta_cost(3, 0, 0).client_delta_popcounts == 0
    assert keep_base[0].cost.peak_private_delta_body_bytes_model > 64


def test_equal_exception_counts_do_not_identify_future_checkpoint_state():
    w = Workload((0, 1), (8, 2), 3)
    raw = oracle.Choice((oracle.Piece("", (0, 1), oracle.raw_map(3, 17), "raw"),))
    revisions = (w, replace(w, rows=(2, 1)), replace(w, rows=(3, 1)), replace(w, rows=(2, 1)))
    p = overlay.Problem(life.Trace(revisions, (1, 1, 1, 1), 6), (life.Entry("raw", raw, (1,)),), Profile(32, 17, eta=1))
    a, b = p.delta_cost(2, 0, 0), p.delta_cost(2, 0, 1)
    assert a == b  # Same current rank, exceptions and entire incremental vector.
    assert p.delta_cost(3, 0, 0).client_delta_popcounts == 4
    assert p.delta_cost(3, 0, 1).client_delta_popcounts == 0


def test_random_bounded_trace_frontiers_agree_with_unpruned_enumeration():
    rng = random.Random(5501)
    for _ in range(10):
        base = fixture()
        w = base.trace.revisions[0]
        revisions = (w, *(replace(w, rows=tuple(rng.randrange(8) for _ in w.rows)) for _ in range(3)))
        p = overlay.Problem(replace(base.trace, revisions=revisions), base.entries, base.profile)
        a, _ = overlay.dynamic_program(p)
        b, _ = overlay.exhaustive(p)
        assert {x.cost for x in a} == {x.cost for x in b}


def test_limits_reject_instead_of_choosing_an_unreported_beam():
    p = fixture()
    for algorithm in (overlay.dynamic_program, overlay.exhaustive):
        with pytest.raises(ValueError, match="work limit"):
            algorithm(p, work_limit=1)
