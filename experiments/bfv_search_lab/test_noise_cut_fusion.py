"""Exact generic fusion, safe caps, complete grammar and resource controls."""

from dataclasses import replace
import random

import pytest

from experiments.bfv_search_lab import noise_cut_fusion as fusion
from experiments.bfv_search_lab import noise_cut_relation as relation
from experiments.bfv_search_lab import noise_cut_shape as shape


def public_graph(n=8, q=18721):
    build = fusion.Builder(n, q)
    x, y = build.input(("x",)), build.input(("y",))
    a, b, c = (fusion.Public((name,)) for name in ("a", "b", "c"))
    state = build.add(build.multiply(x, a), build.multiply(y, b))
    moved = build.permute(state, 3, 7)
    first = build.multiply(moved, c)
    second = build.sub(build.permute(first, 5, 2), build.scale(x, 7))
    roots = (first, second, build.sub(first, second))
    return fusion.Graph(n, q, tuple(build.nodes), roots)


@pytest.mark.parametrize("seed", range(8))
def test_full_public_fused_vectors_equal_independent_direct_vectors(seed):
    graph = public_graph()
    rng = random.Random(seed)
    binding = {
        (name,): tuple(rng.randrange(graph.q) for _ in range(graph.n))
        for name in ("x", "y")
    }
    constants = {
        fusion.Public((name,)): tuple(rng.randrange(graph.q) for _ in range(graph.n))
        for name in ("a", "b", "c")
    }
    fused = fusion.fuse(graph)
    direct = shape.direct_graph(graph)
    actual = fusion.evaluate(
        fused.graph, binding, fusion.coefficients(fused.graph, constants)
    )
    expected = fusion.evaluate(direct, binding, fusion.coefficients(direct, constants))
    assert actual == expected
    # Compare mod both actual primes too; an arbitrary independent limb lift
    # was never supplied to normalization.
    assert all(
        tuple(x % p for x in a) == tuple(x % p for x in b)
        for p in (97, 193)
        for a, b in zip(actual, expected, strict=True)
    )


@pytest.mark.parametrize(
    "limits",
    [fusion.Limits(terms=1), fusion.Limits(monomials=1), fusion.Limits(degree=1)],
)
def test_local_caps_insert_exact_boundaries(limits):
    graph = public_graph()
    fused = fusion.fuse(graph, limits)
    assert any(
        reason not in ("input", "enrolled_shared_boundary")
        for _i, reason in fused.boundaries
    )
    values = {fusion.Public((name,)): tuple(range(graph.n)) for name in ("a", "b", "c")}
    binding = {("x",): tuple(range(graph.n)), ("y",): (7,) * graph.n}
    direct = shape.direct_graph(graph)
    assert fusion.evaluate(
        fused.graph, binding, fusion.coefficients(fused.graph, values)
    ) == fusion.evaluate(direct, binding, fusion.coefficients(direct, values))


@pytest.mark.parametrize("limits", [fusion.Limits(nodes=1), fusion.Limits(recipes=1)])
def test_global_caps_raise_without_a_partial_answer(limits):
    with pytest.raises(fusion.LimitReached):
        fusion.fuse(public_graph(), limits)


def test_odd_automorphism_and_signed_shift_compose_exactly():
    n, q = 8, 97
    p = fusion.Public(("p",))
    c = ((fusion.Monomial(7, ((p, 3),)), 11),)
    turned = fusion._turn(n, q, c, 5, 4)
    graph = fusion.Graph(
        n,
        q,
        (relation.Node("input", (), ("x",)), relation.Node("multiply", (0,), c)),
        (1,),
    )
    next_graph = replace(
        graph, nodes=(graph.nodes[0], replace(graph.nodes[1], value=turned))
    )
    raw = {p: tuple(range(n))}
    expected = fusion.turn(fusion.coefficients(graph, raw)[c], 5, 4, q)
    assert fusion.coefficients(next_graph, raw)[turned] == expected


@pytest.mark.parametrize(
    "fault", ["cycle", "unknown", "even", "public", "root", "anchor"]
)
def test_malformed_trusted_compiler_graph_rejects(fault):
    graph = public_graph()
    if fault == "cycle":
        graph = replace(
            graph, nodes=(replace(graph.nodes[0], args=(0,)), *graph.nodes[1:])
        )
    elif fault == "unknown":
        graph = replace(graph, nodes=(relation.Node("arbitrary", ()), *graph.nodes[1:]))
    elif fault == "even":
        at = next(i for i, node in enumerate(graph.nodes) if node.kind == "permute")
        graph = replace(
            graph,
            nodes=(
                *graph.nodes[:at],
                replace(graph.nodes[at], value=(2, 0)),
                *graph.nodes[at + 1 :],
            ),
        )
    elif fault == "public":
        at = next(i for i, node in enumerate(graph.nodes) if node.kind == "multiply")
        graph = replace(
            graph,
            nodes=(
                *graph.nodes[:at],
                replace(graph.nodes[at], value=[1]),
                *graph.nodes[at + 1 :],
            ),
        )
    elif fault == "root":
        graph = replace(graph, residuals=(len(graph.nodes),))
    else:
        graph = replace(graph, anchors=(True,))
    with pytest.raises(ValueError):
        fusion.fuse(graph)


def test_complete_resource_counts_use_pruned_graph_and_actual_dependencies():
    graph = public_graph()
    graph = replace(
        graph, nodes=(*graph.nodes, relation.Node("input", (), ("unreachable",)))
    )
    fused = fusion.fuse(graph)
    ledger = fusion.resource_ledger(fused.graph)
    assert ledger["online"]["complete_residual_polynomials"] == len(graph.residuals)
    assert ledger["online"]["distinct_bound_input_polynomials"] == 2
    assert ledger["online"]["fresh_row_field_elements"] == 3 * 2 * len(graph.residuals)
    assert ledger["cached_preparation"]["unique_public_composite_polynomials"] > 0
    assert (
        ledger["on_demand_public_preparation_per_query"][
            "per_query_public_atomic_forward_prime_NTTs"
        ]
        > 0
    )


def test_index_update_invalidation_includes_composite_automorphed_factors():
    build = fusion.Builder(8, 97)
    x = build.input(("x",))
    indexed = fusion.Public(("index", 4, 0))
    key = fusion.Public(("key", 0))
    left = build.multiply(build.permute(build.multiply(x, indexed), 3), key)
    right = build.multiply(x, key)
    graph = fusion.Graph(8, 97, tuple(build.nodes), (left, right))
    ledger = fusion.resource_ledger(fusion.fuse(graph).graph)
    assert ledger["fixed_position_index_update"] == [
        {
            "tile": 4,
            "invalidated_final_public_polynomials": 1,
            "invalidated_final_RNS_word_bytes": 8 * 2 * 8,
        }
    ]


def test_index_sum_invalidates_when_either_original_component_changes():
    build = fusion.Builder(8, 97)
    x = build.input(("x",))
    indexed_sum = fusion.Public(("index-sum", 5))
    root = build.multiply(x, indexed_sum)
    graph = fusion.Graph(8, 97, tuple(build.nodes), (root,))
    ledger = fusion.resource_ledger(fusion.fuse(graph).graph)
    assert ledger["fixed_position_index_update"] == [
        {
            "tile": 5,
            "invalidated_final_public_polynomials": 1,
            "invalidated_final_RNS_word_bytes": 128,
        }
    ]


def test_incompatible_paired_schedule_rejects_before_emission():
    build = fusion.Builder(8, 97)
    x = build.input(("x",))
    a, b, c = build.scale(x, 2), None, None
    b = build.scale(a, 3)
    c = build.scale(b, 4)
    graph = fusion.Graph(8, 97, tuple(build.nodes), (c,), (a, c), ((a, c),))
    with pytest.raises(ValueError, match="contraction"):
        fusion.fuse(graph)


def test_immutable_complete_source_grammar_rejects_before_preparation(monkeypatch):
    compiled = relation.Relation(8, 97, 1, ((0, -1, 0, 3),), (), (), (), "test")
    source = relation.Source(0, -1, 0, (0,) * 8)
    outputs = (((0,) * 8, (0,) * 8),)
    assert (
        fusion.bindings(compiled, (source,), outputs)["source-digit", 0, 0] == (0,) * 8
    )
    for sources, terminal in (
        ((), outputs),
        ((replace(source, polynomial=(97, *((0,) * 7))),), outputs),
        ((replace(source, group=True),), outputs),
        ((source,), list(outputs)),
        ((source,), (((0,) * 7, (0,) * 8),)),
    ):
        with pytest.raises(ValueError):
            fusion.bindings(compiled, sources, terminal)


def test_residual_roots_are_not_replaced_by_zero_weight_or_point_evaluation():
    graph = public_graph()
    assert len(fusion.fuse(graph).graph.residuals) == len(graph.residuals)
    assert not hasattr(fusion, "admit")
    assert not hasattr(fusion, "sign")
