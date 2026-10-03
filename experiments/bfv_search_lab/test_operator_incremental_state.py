"""Q59 fixed-coins algebra/update controls; not protocol lifecycle tests."""

from dataclasses import replace
import random

import pytest

from experiments.bfv_search_lab import operator_incremental_state as update
from experiments.bfv_search_lab import operator_state_discriminator as state


def fixture(n, padded, tiles):
    graph = state.butterfly_graph(n, padded, tiles, 2)
    cuts = state.cuts_for(graph, "maximal-affine")
    equations = state.compile_equations(graph, cuts)
    rng = random.Random(1019+n+tiles)
    symbols = {a.symbol for expression in equations.values() for op in expression.values()
               for a, _ in op.terms if a.symbol}
    fixed = {s: tuple(rng.randrange(18721) for _ in range(n)) for s in sorted(symbols)}
    return graph, equations, fixed


@pytest.mark.parametrize("n,padded,tiles", [(8, 4, 1), (8, 4, 3), (8, 4, 4),
                                           (16, 8, 3), (16, 8, 8)])
@pytest.mark.parametrize("prime", [97, 193])
def test_every_actual_operator_adjoint_matches_dense_control(n, padded, tiles, prime):
    _, equations, fixed = fixture(n, padded, tiles)
    rng = random.Random(222+prime)
    vector = tuple(rng.randrange(prime) for _ in range(n))
    for expression in equations.values():
        for op in expression.values():
            assert update.adjoint(op, vector, fixed, prime) == update.dense_adjoint_control(op, vector, fixed, prime)


@pytest.mark.parametrize("policy", ["every-local", "product-cut", "maximal-affine"])
@pytest.mark.parametrize("changed_tiles", [frozenset((0,)), frozenset((1,)), frozenset((0, 2)),
                                           frozenset(range(3))])
def test_incremental_query_state_equals_fresh_with_identical_generic_control(policy, changed_tiles):
    graph, _, fixed = fixture(8, 4, 3)
    equations = state.compile_equations(graph, state.cuts_for(graph, policy))
    signature = update.index_dependency_invariant(equations)
    after = dict(fixed)
    rng = random.Random(444)
    for tile in changed_tiles:
        for component in range(2):
            name = f"index:{tile}:{component}"
            after[name] = tuple(rng.randrange(18721) for _ in range(graph.n))
    delta, _ = update.index_delta(fixed, after)
    for prime in (97, 193):
        for _ in range(3):
            coins = update.DiagnosticCoins(prime, tuple((name, rng.randrange(prime)) for name in equations),
                                           tuple(rng.randrange(prime) for _ in range(graph.n)))
            old = update.query_adjoints(equations, fixed, coins)
            new = update.query_adjoints(equations, after, coins)
            difference = update.query_adjoints(equations, delta, coins, delta=True)
            generic_difference = update.query_adjoints(equations, delta, coins, delta=True, dense_control=True)
            assert difference == generic_difference
            assert update.apply_delta(old, difference, prime) == new
    assert update.index_dependency_invariant(equations) == signature


def test_fresh_coins_do_not_reuse_old_delta_state():
    graph, equations, fixed = fixture(8, 4, 3)
    coins = update.DiagnosticCoins(97, tuple((name, i % 97) for i, name in enumerate(equations)),
                                   tuple(range(graph.n)))
    different = replace(coins, coefficient_weights=tuple((x+1) % 97 for x in coins.coefficient_weights))
    assert update.query_adjoints(equations, fixed, coins) != update.query_adjoints(equations, fixed, different)


def test_reject_graph_or_key_changes_as_index_delta():
    _, equations, fixed = fixture(8, 4, 3)
    after = dict(fixed)
    after["new-index"] = (0,)*8
    with pytest.raises(ValueError):
        update.index_delta(fixed, after)
    after = dict(fixed)
    key = next(k for k in after if not k.startswith("index:"))
    after[key] = tuple((x+1) % 18721 for x in after[key])
    with pytest.raises(ValueError):
        update.index_delta(fixed, after)
    name = next(iter(equations))
    corrupted = {**equations, name: {**equations[name], "digit:forbidden": state.Operator.convolution(8, "index:0:0")}}
    with pytest.raises(ValueError):
        update.index_dependency_invariant(corrupted)


@pytest.mark.parametrize("vectors", [8192, 32768])
def test_edit_scripts_bind_rows_to_exact_distinct_tiles(vectors):
    scripts = update.edit_scripts(vectors, 32)
    supports = {k: frozenset(row//32 for row in rows) for k, rows in scripts.items()}
    assert len(supports["one-row"]) == len(supports["one-tile"]) == 1
    assert len(supports["dispersed32-rows"]) == 32
    assert len(supports["whole-snapshot"]) == vectors//32


def test_dependency_closure_and_empty_update():
    graph = state.butterfly_graph(8, 4, 3, 2)
    empty = update.semantic_invalidation(graph, frozenset())
    assert empty["canonical_source_values"] == empty["query_adjoint_vectors_per_prime_round"] == 0
    changed = update.semantic_invalidation(graph, frozenset((0,)))
    assert changed["canonical_source_values"] == 3  # tileC2 and two actual rotation sources
    assert changed["terminal_polynomials"] == 2
    assert changed["nonquery_checking_coefficient_maps"] == 0
    with pytest.raises(ValueError):
        update.semantic_invalidation(graph, frozenset((3,)))
