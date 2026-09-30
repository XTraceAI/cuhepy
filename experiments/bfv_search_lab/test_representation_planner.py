"""Exact DP compared to the independent exhaustive grammar, including ties."""

from dataclasses import replace

import pytest

from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import representation_planner as planner
from experiments.bfv_search_lab.representation_contract import Budget, Profile, Workload


@pytest.mark.parametrize("rows,d", [
    ((0, 1, 2, 3, 8, 9, 10, 11), 4),
    ((0, 0, 0, 0, 1, 1, 1, 1), 1),
    ((0, 5, 2, 7, 6, 1, 4, 3), 3),
])
@pytest.mark.parametrize("share", (False, True))
def test_boundary_dp_preserves_every_complete_resource_vector(rows, d, share):
    w = Workload(rows, tuple(range(len(rows))), d)
    root, profile = oracle.median_tree(w), Profile(32, 17, eta=1)
    exhaustive, _ = oracle.enumerate_plans(w, root, (profile,), slots=(1, 2, 4), equal_forms=share)
    result = planner.search(w, root, profile, slots=(1, 2, 4), equal_forms=share)
    assert result.exact
    assert {p.resources for p in result.plans} == {p.resources for p in exhaustive}
    # Separate all-pairs definition, rather than the incremental Pareto routine.
    expected = {p.resources.static_vector for p in exhaustive if not any(
        q.resources.static_vector != p.resources.static_vector
        and all(a <= b for a, b in zip(q.resources.static_vector, p.resources.static_vector, strict=True))
        for q in exhaustive)}
    assert {p.resources.static_vector for p in result.frontier} == expected
    for axis in range(8):
        assert min(p.resources.static_vector[axis] for p in result.plans) == min(
            p.resources.static_vector[axis] for p in exhaustive)


def test_client_state_budget_is_applied_after_geometry_and_full_checks():
    w = Workload(tuple(range(16)), tuple(range(16)), 4)
    root, profile = oracle.median_tree(w), Profile(32, 17, eta=1)
    full = planner.search(w, root, profile, slots=(1, 2, 4))
    limit = min(p.resources.client_audit_body_bytes_model for p in full.plans)
    bounded = planner.search(w, root, profile, slots=(1, 2, 4), budget=Budget(client_audit_body_bytes=limit))
    assert bounded.rejected and bounded.plans
    assert all(p.resources.client_audit_body_bytes_model <= limit for p in bounded.plans)
    none = planner.search(w, root, profile, slots=(1, 2, 4), budget=Budget(max_replies=0))
    assert not none.plans and not none.frontier and none.rejected


def test_beam_is_never_advertised_as_exact_or_parameter_security_trade():
    w = Workload((0, 1, 2, 3, 8, 9, 10, 11), tuple(range(8)), 4)
    root, profile = oracle.median_tree(w), Profile(32, 17, eta=1)
    heuristic = planner.search(w, root, profile, slots=(1, 2, 4), beam=1)
    assert not heuristic.exact and any(before > after for _, before, after in heuristic.node_state_counts)
    assert not planner.dominates(heuristic.plans[0], replace(heuristic.plans[0], profile=replace(profile, eta=2)))
    with pytest.raises(ValueError, match="work limit"):
        planner.search(w, root, profile, limit=1)
