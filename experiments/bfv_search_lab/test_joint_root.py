"""E122 bounded N2/N4 tests; no scientific N16/q97 context executes here."""

from collections import Counter
from dataclasses import replace
from itertools import combinations, product

import gmpy2
import pytest

from experiments.bfv_search_lab import joint_root as lab


@pytest.mark.parametrize("field", ("n", "q", "root"))
@pytest.mark.parametrize("alias", (True, 2.0, "2", gmpy2.mpz(2)))
def test_context_exact_integer_grammar(field, alias):
    with pytest.raises(ValueError):
        replace(lab.Context(2, 5, 2), **{field: alias}).validate()


@pytest.mark.parametrize("ctx", (
    lab.Context(2, 9, 2), lab.Context(4, 5, 2), lab.Context(4, 17, 4),
    lab.Context(2, 5, 1), lab.Context(2, 5, 5),
))
def test_false_field_or_root_order_rejected(ctx):
    with pytest.raises(ValueError):
        ctx.validate()


@pytest.mark.parametrize("n,q,expected", ((2, 5, 2), (4, 17, 2)))
def test_fixed_tiny_least_selector(n, q, expected):
    assert lab.least_root(n, q) == lab.Context(n, q, expected)


@pytest.mark.parametrize("roots", ((1, 1), (3, 1), (0,), (2,), (False,), (1.0,), [1], (9,)))
def test_rootset_grammar_and_distinctness(roots):
    with pytest.raises(ValueError):
        lab.action(lab.Context(4, 17, 2), roots, 1)


@pytest.mark.parametrize("n,q,root,roots", (
    (2, 5, 2, (1,)), (2, 5, 2, (1, 3)),
    (4, 17, 2, (1,)), (4, 17, 2, (1, 3)), (4, 17, 2, (1, 3, 5, 7)),
))
def test_mitm_matches_direct_raw_ternary_count(n, q, root, roots):
    ctx = lab.Context(n, q, root)
    #Direct powers and integer sums, not MITM columns or Horner helpers.
    accepted = []
    for coefficients in product((-1, 0, 1), repeat=n):
        if all(sum(value * pow(root, e * j, q) for j, value in enumerate(coefficients)) % q == 0
               for e in roots):
            accepted.append(coefficients)
    result = lab.count_roots(ctx, roots)
    assert result.total_count == len(accepted) == 1
    assert result.denominator == 3 ** n
    assert result.half_visits == 2 * 3 ** (n // 2)
    assert result.witness is None
    assert accepted == [(0,) * n]


def test_complete_tiny_orbit_coverage_and_inverse_signed_evaluation():
    ctx = lab.Context(4, 17, 2)
    inventory = lab.orbit_inventory(ctx, 2)
    assert {item[0] for item in inventory.assignments} == set(combinations((1, 3, 5, 7), 2))
    assert sum(len(orbit.members) for orbit in inventory.orbits) == 6
    assert all(len(orbit.members) * len(orbit.stabilizer) == 4 for orbit in inventory.orbits)
    source = (-1, 1, 0, 1)
    for g in (1, 3, 5, 7):
        transformed = lab.signed_action(source, g)
        for e in (1, 3, 5, 7):
            direct = sum(value * pow(2, e * j, 17) for j, value in enumerate(transformed)) % 17
            original = sum(value * pow(2, g * e * j, 17) for j, value in enumerate(source)) % 17
            assert direct == original
        assert lab.signed_action(transformed, pow(g, -1, 8)) == source
    assert lab.signed_action((0, 0, 1, 0), 3) == (0, 0, -1, 0)


@pytest.mark.parametrize("mutation", ("missing_assignment", "missing_member", "assignment_alias", "member_alias", "stabilizer_alias"))
def test_orbit_inventory_omissions_and_aliases_rejected(mutation):
    inventory = lab.orbit_inventory(lab.Context(4, 17, 2), 2)
    first = inventory.orbits[0]
    if mutation == "missing_assignment":
        bad = replace(inventory, assignments=inventory.assignments[:-1])
    elif mutation == "missing_member":
        bad = replace(inventory, orbits=(replace(first, members=first.members[:-1]),) + inventory.orbits[1:])
    elif mutation == "assignment_alias":
        item = inventory.assignments[0]
        bad = replace(inventory, assignments=(((float(item[0][0]), *item[0][1:]), item[1], item[2]),)
                      + inventory.assignments[1:])
    elif mutation == "member_alias":
        member = first.members[0]
        bad = replace(inventory, orbits=(replace(first, members=((float(member[0]), *member[1:]),)
                                                 + first.members[1:]),) + inventory.orbits[1:])
    else:
        bad = replace(inventory, orbits=(replace(first, stabilizer=(True,) + first.stabilizer[1:]),)
                      + inventory.orbits[1:])
    with pytest.raises(ValueError):
        bad.validate()


def test_histograms_retain_vector_multiplicity_and_lexicographic_order():
    columns = ((1, 0), (1, 0))
    table = lab.half_table(columns, 5, keep_samples=True)
    expected = Counter(((a + b) % 5, 0) for a, b in product((-1, 0, 1), repeat=2))
    assert table.counts == expected
    assert table.counts[(0, 0)] == 3
    assert table.samples[(0, 0)] == ((-1, 1), (0, 0))
    assert [assignment for assignment, _ in lab.half_vectors(columns, 5)] == list(product((-1, 0, 1), repeat=2))


def test_recovery_is_global_lexicographic_minimum_for_synthetic_projection():
    #A fixed generic projection fixture, not a cyclotomic root event.
    left_columns, right_columns = ((1,), (0,)), ((1,), (0,))
    right = lab.half_table(right_columns, 5, keep_samples=True)
    witness, visits, _ = lab.recover_nonzero(left_columns, right)
    candidates = [coefficients for coefficients in product((-1, 0, 1), repeat=4)
                  if any(coefficients) and (coefficients[0] + coefficients[2]) % 5 == 0]
    assert witness == min(candidates)
    assert visits == 1


def test_two_right_samples_exclude_unique_zero_in_predeclared_controller_fixture():
    #Deliberately synthetic witness-cache fixture: it asserts no field/root law.
    right = lab.HalfTable(1, 5, 1, {(0,): 2, (2,): 1},
                          {(0,): ((0,), (1,)), (2,): ((-1,),)}, 3, 0)
    witness, visits, _ = lab.recover_nonzero(((1,),), right)
    assert witness == (0, 1)
    assert visits == 2


@pytest.mark.parametrize("mutation", ("numeric_key_alias", "numeric_count_alias", "wrong_mass", "missing_sample"))
def test_half_table_strict_masses_and_witness_buckets(mutation):
    table = lab.half_table(((1,),), 5, keep_samples=True)
    if mutation == "numeric_key_alias":
        counts = {tuple(float(x) for x in key): count for key, count in table.counts.items()}
        bad = replace(table, counts=counts)
    elif mutation == "numeric_count_alias":
        bad = replace(table, counts={key: float(count) for key, count in table.counts.items()})
    elif mutation == "wrong_mass":
        bad = replace(table, counts={key: count + 1 for key, count in table.counts.items()})
    else:
        bad = replace(table, samples={})
    with pytest.raises(ValueError):
        bad.validate()


@pytest.mark.parametrize("mutation", ("count_alias", "even_count", "denominator_alias", "zero_missing", "visit_omission"))
def test_root_count_ledger_corruption_rejected(mutation):
    count = lab.count_roots(lab.Context(2, 5, 2), (1,))
    changes = {"count_alias": {"total_count": 1.0}, "even_count": {"total_count": 2},
               "denominator_alias": {"denominator": 9.0}, "zero_missing": {"total_count": 0},
               "visit_omission": {"half_visits": 5}}
    with pytest.raises(ValueError):
        replace(count, **changes[mutation]).validate()


@pytest.mark.parametrize("witness", ((0, 0), (2, 0), (True, 0), (1, 0)))
def test_witness_must_be_nonzero_strict_ternary_and_annihilate(witness):
    with pytest.raises(ValueError):
        lab.verify_witness(lab.Context(2, 5, 2), (1,), witness)


def synthetic_count(roots, nonzero=False):
    #A registered trusted-evaluator/controller simulation, never a root theorem.
    return lab.Count(roots, 3 if nonzero else 1, 81, 4, 18, 1, 1, 0,
                     1 if nonzero else 0, 0, (-1, 0, 0, 0) if nonzero else None)


@pytest.mark.parametrize("mode,expected", (
    ("first_counterexample", "counterexample_found"),
    ("prefix_limit", "bounded_prefix_inconclusive"),
    ("full_inventory", "full_fixed_inventory_no_counterexample"),
    ("timeout", "resource_bounded_inconclusive"),
))
def test_synthetic_first_prefix_timeout_statuses(mode, expected):
    visited = []

    def evaluate(roots):
        if mode == "timeout":
            raise TimeoutError("Predeclared synthetic stop")
        visited.append(roots)
        return synthetic_count(roots, mode == "first_counterexample" and roots == (3,))

    status, records = lab.scan_prefix(((1,), (3,), (5,)), evaluate,
                                      limit=1 if mode == "prefix_limit" else 64)
    assert status == expected
    scope = lab.mass_counter_scope(status)
    assert scope["counter_scope"] == "completed_mass_records_only"
    assert scope["interrupted_mass_work_unknown"] == (mode == "timeout")
    assert scope["total_work_counter_complete"] == (mode != "timeout")
    if mode == "first_counterexample":
        assert visited == [(1,), (3,)]
        assert records[-1].witness is not None
    if mode == "timeout":
        assert records == ()
