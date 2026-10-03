"""Q57 exact algebra and complete small-graph tests; no performance claims."""

from itertools import product
import random

import pytest

from experiments.bfv_search_lab import operator_state_discriminator as state


def fixture(n=8, padded=4, tiles=4, digits=2, q=697):
    graph = state.butterfly_graph(n, padded, tiles, digits)
    rng = random.Random(1097+n+padded+tiles+digits)
    symbols = {a.symbol for node in graph.nodes for _, op in node.inputs
               for a, _ in op.terms if a.symbol}
    fixed = {s: tuple(rng.randrange(q) for _ in range(n)) for s in sorted(symbols)}
    query = tuple(tuple(rng.randrange(q) for _ in range(n)) for _ in range(2))
    return graph, query, fixed, q


@pytest.mark.parametrize("n,padded,tiles", [(8, 4, 1), (8, 4, 2), (8, 4, 3),
                                           (8, 4, 4), (16, 8, 1), (16, 8, 3),
                                           (16, 8, 5), (16, 8, 8), (8, 1, 1)])
def test_literal_native_schedule_and_complete_elimination(n, padded, tiles):
    graph, query, fixed, q = fixture(n, padded, tiles)
    values = state.evaluate_trace(graph, query, fixed, q, 5)
    actual = tuple(values[s] for s in graph.finals)
    assert actual == state.independent_butterfly(graph, query, fixed, q, 5)
    for policy in ("every-local", "product-cut", "maximal-affine"):
        cuts = state.cuts_for(graph, policy)
        equations = state.compile_equations(graph, cuts)
        residuals = state.evaluate_residuals(graph, equations, values, fixed, q)
        assert len(residuals) == len(cuts)
        assert all(not any(r) for r in residuals.values())
        # Every submitted target polynomial participates, including final tails.
        for name in cuts:
            changed = dict(values)
            changed[name] = ((values[name][0]+1) % q, *values[name][1:])
            assert any(any(r) for r in state.evaluate_residuals(graph, equations, changed, fixed, q).values())


@pytest.mark.parametrize("shift,auto", [(-15, 3), (-4, 5), (0, 7), (13, 15)])
def test_negacyclic_word_identities_against_coefficients(shift, auto):
    n, q, value, key = 8, 697, tuple(range(8)), (11, 3, 21, 5, 7, 8, 4, 9)
    sigma = state.Operator.automorphism(n, auto)
    convolution = state.Operator.convolution(n, "k")
    mono = state.Operator.monomial(n, shift)
    normalized = sigma.compose(mono.compose(convolution))
    expected = state.automorphism(state.monomial(state.multiply(key, value, q), shift, q), auto, q)
    assert normalized.evaluate(value, {"k": key}, q) == expected
    assert sigma.compose(state.Operator.automorphism(n, 3)).evaluate(value, {}, q) == state.automorphism(value, 3*auto, q)


def test_no_operator_can_cross_canonical_extraction():
    # Actual carry counterexample: digit(sum) != sum(digit) even modulo Q.
    q, base = 697, 32
    assert ((31+1) % q) % base != (31 % base+1 % base) % q
    graph = state.butterfly_graph(8, 4, 2, 2)
    with pytest.raises(ValueError):
        state.compile_equations(graph, frozenset(graph.finals))
    with pytest.raises(ValueError):
        state.Operator.convolution(8, "index").compose(state.Operator.convolution(8, "key"))
    assert all(not source.startswith("tensor:") for node in graph.nodes
               if node.name.startswith("rotation:") and ":out" in node.name
               for source, _ in node.inputs if source.startswith("digit:"))


@pytest.mark.parametrize("bad", [(6, 4, 2), (8, 3, 2), (8, 8, 2), (8, 4, 0),
                                  (8, 4, 5), (True, 1, 1), (8, 4, True)])
def test_strict_geometry(bad):
    with pytest.raises(ValueError):
        state.butterfly_graph(*bad)


@pytest.mark.parametrize("tiles", [1, 2, 3, 4])
def test_matrix_free_dictionary_matches_generic_full_expression(tiles):
    graph = state.butterfly_graph(8, 4, tiles, 2)
    for policy in ("every-local", "product-cut", "maximal-affine"):
        cuts = state.cuts_for(graph, policy)
        oracle = state.compile_equations(graph, cuts)
        atoms = {a for expression in oracle.values() for op in expression.values() for a, _ in op.terms}
        census = state.census(graph, cuts)
        assert census["all_atomic_operators"] == len(atoms)
        fixed = {a for a in atoms if not a.symbol.startswith("index:")}
        assert census["fixed_dictionary_sha256"] == state._digest_atoms(fixed)
        assert census["update_invalidation"]["key_basis_atoms"] == 0


def test_all_tiny_cut_choices_preserve_relation_and_generic_control():
    graph, query, fixed, q = fixture(8, 4, 2)
    choices = sorted(n for n in graph.optional if n.startswith("product:"))
    assert len(choices) == 4
    values = state.evaluate_trace(graph, query, fixed, q, 5)
    for flags in product((False, True), repeat=len(choices)):
        cuts = graph.mandatory | frozenset(n for n, yes in zip(choices, flags, strict=True) if yes)
        oracle = state.compile_equations(graph, cuts)
        assert all(not any(r) for r in state.evaluate_residuals(graph, oracle, values, fixed, q).values())
        census = state.census(graph, cuts)
        atoms = {a for expression in oracle.values() for op in expression.values() for a, _ in op.terms}
        assert census["all_atomic_operators"] == len(atoms)


def test_index_update_exact_dependency_and_linear_delta():
    graph, query, fixed, q = fixture(8, 4, 4)
    equations = state.compile_equations(graph, state.cuts_for(graph, "maximal-affine"))
    rng = random.Random(333)
    updated = dict(fixed)
    updated["index:1:0"] = tuple(rng.randrange(q) for _ in range(graph.n))
    delta = {s: (tuple((a-b) % q for a, b in zip(updated[s], fixed[s], strict=True))
                 if s == "index:1:0" else (0,)*graph.n) for s in fixed}
    zero = {s: (0,)*graph.n for s in fixed}
    for expression in equations.values():
        for source, op in expression.items():
            if source.startswith("query:"):
                x = query[int(source[-1])]
                old, new = op.evaluate(x, fixed, q), op.evaluate(x, updated, q)
                difference = tuple((a-b) % q for a, b in zip(new, old, strict=True))
                # Pure maps in an operator contribute a fixed affine intercept.
                delta_value = tuple((a-b) % q for a, b in zip(op.evaluate(x, delta, q), op.evaluate(x, zero, q), strict=True))
                assert difference == delta_value
            else:
                assert not any(a.symbol.startswith("index:") for a, _ in op.terms)


def test_partial_group_rotation_count_is_not_tiles_minus_one():
    assert state.butterfly_graph(16, 8, 1).rotations == 3
    assert state.butterfly_graph(16384, 512, 256).rotations == 511
    assert state.butterfly_graph(16384, 512, 512).rotations == 511


def test_whole_Q_ledger_pays_terminal_and_deterministic_digits():
    graph = state.butterfly_graph(8, 4, 2, 4)
    cuts = state.cuts_for(graph, "maximal-affine")
    ledger = state.body_ledger(graph, cuts)
    assert len(cuts) == graph.tiles+graph.rotations+2
    assert ledger["full_Q_canonical_body_bytes_model"] == len(cuts)*8*15
    assert ledger["terminal_full_Q_body_bytes_included"] == 2*8*15
    assert ledger["witness_digit_values_derived_not_transmitted"] == (graph.tiles+graph.rotations)*4*8
    assert ledger["static_models_not_timings_or_minimum_state"] is True


def test_nonunit_inputs_and_operator_aliases_reject():
    with pytest.raises(ValueError):
        state.Operator.make(8, ((state.Atom(argument=2), 1),))
    with pytest.raises(ValueError):
        state.Operator.identity(8).compose(state.Operator.identity(16))
    with pytest.raises(ValueError):
        state.cuts_for(state.butterfly_graph(8, 4, 2), "imaginary-policy")
    assert not (state.Operator.monomial(8, 8)+state.Operator.identity(8)).terms


def test_actual_cut_union_changes_choice_but_generic_obtains_same_gain():
    from benchmarks.operator_state_discriminator_lab import minimal_nonadditive
    initial, discriminator = minimal_nonadditive(1), minimal_nonadditive(3)
    assert initial["exact_selected"] == initial["additive_selected"]
    assert discriminator["fixed_state_mixed_difference"] == -2
    assert discriminator["exact_selected"] != discriminator["additive_selected"]
    assert discriminator["exact_selected"] == ["product:0:0", "product:0:1"]
    assert all(c["declared_static_objective"] == c["generic_same_objective"]
               for c in discriminator["cards"])
    assert discriminator["originality_survivor"] is False
