"""E65 exact grammar versus independent Cartesian allocation and decoder."""

from dataclasses import replace

import pytest

from experiments.bfv_search_lab import decryption_support as support
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import representation_planner as planner
from experiments.bfv_search_lab.representation_contract import Profile, Workload
from experiments.bfv_search_lab import support_planner as supported


@pytest.mark.parametrize("rows,d", (((0, 1, 2, 4, 5, 6), 3), ((0, 1, 2, 3, 8, 9, 10, 11), 4)))
@pytest.mark.parametrize("share", (False, True))
def test_exact_boundary_grammar_cartesian_allocations_every_score_and_all_pairs_frontier(rows, d, share):
    w, p = Workload(rows, tuple(100 - i for i in range(len(rows))), d), Profile(32, 17, eta=1)
    root = oracle.median_tree(w, depth=1)
    original, _ = oracle.enumerate_plans(w, root, (p,), slots=(1, 2, 4), equal_forms=share)
    result = supported.search(w, root, p, slots=(1, 2, 4), equal_forms=share)
    assert result.exact
    expected = set()
    for full in original:
        assert set(supported.allocations(full)) == set(supported.cartesian_oracle_counts(full))
        for counts in supported.cartesian_oracle_counts(full):
            candidate = supported.view(supported.redistribute(full, counts))
            assert candidate.certificate == support.matrix_oracle(candidate.compiled.candidate.layout)
            expected.add((planner.signature(full.choice), full.allocation, counts, candidate.static_vector))
    observed = {(planner.signature(p.compiled.choice), p.compiled.allocation,
                 p.compiled.candidate.layout.counts, p.static_vector) for p in result.plans}
    assert observed == expected
    expected_front = {p.static_vector for p in result.plans if not any(
        q.static_vector != p.static_vector and all(x <= y for x, y in zip(q.static_vector, p.static_vector, strict=True))
        for q in result.plans)}
    assert {p.static_vector for p in result.frontier} == expected_front
    for view in result.plans:
        candidate = view.compiled
        # Every approved binary query through actual encode/unpack/private IDs.
        for word in range(1 << d):
            values, offsets = oracle.query(candidate, word)
            dots = space.scores(candidate.query_space, [[list(row) for row in group] for group in candidate.groups], values)
            polys = [[x % 17 for x in poly] for poly in space.outputs(candidate.candidate.layout, dots)]
            for poly, kept in zip(polys, view.certificate.kept_c0, strict=True):
                for i in range(len(poly)):
                    if i not in kept:
                        poly[i] = 0
            decoded = oracle.decode(candidate, polys, offsets)
            assert decoded == w.expected(word) and w.top_k(decoded) == w.top_k(w.expected(word))
        assert sum(map(len, view.certificate.kept_c0)) >= len(rows)  # Restricted coefficient-deletion rank floor.
    assert len(result.plans) >= len(result.original_controls)


def test_work_budget_no_cross_profile_dominance_and_invalid_group_redistribution():
    w, p = Workload((0, 1, 2, 3, 8, 9, 10, 11), tuple(range(8)), 4), Profile(32, 17, eta=1)
    root = oracle.median_tree(w, 1)
    result = supported.search(w, root, p)
    with pytest.raises(ValueError, match="work"):
        supported.search(w, root, p, limit=1)
    first = result.plans[0]
    assert not supported.dominates(first, replace(first, compiled=replace(first.compiled, profile=replace(p, eta=2))))
    full = next(view.compiled for view in result.plans if len(view.compiled.maps) == 2)
    with pytest.raises(ValueError, match="membership|coverage"):
        supported.redistribute(full, (len(w.rows), 0))
    with pytest.raises(ValueError, match="allocation"):
        supported.redistribute(full, (-1,) * len(full.query_space.map_ids))


def test_unequal_replicated_groups_price_every_allocation_and_report_simple_control():
    w = Workload((0, 1, 2, 3) * 3 + (8, 9, 10, 11), tuple(range(16)), 4)
    root = oracle.Node("", tuple(range(16)), (oracle.Node("0", tuple(range(12))), oracle.Node("1", tuple(range(12, 16)))))
    result = supported.search(w, root, Profile(32, 17, eta=1))
    for view in result.original_controls:
        assert set(supported.allocations(view.compiled)) == set(supported.cartesian_oracle_counts(view.compiled))
    # A negative is as valid as a gain; enumerate first, then compare controls.
    assert min(p.static_vector[0] for p in result.plans) <= min(p.static_vector[0] for p in result.balanced_controls)
    assert result.row_allocation_attempts == len(result.plans)
