"""Matched Karatsuba symbolic shape equals the earlier complete relation."""

from dataclasses import replace

import pytest

from experiments.bfv_search_lab import noise_cut_fusion as fusion
from experiments.bfv_search_lab import noise_cut_reference as reference
from experiments.bfv_search_lab import noise_cut_relation as relation
from experiments.bfv_search_lab import noise_cut_shape as shape
from experiments.bfv_search_lab import propagated_gadget_bgv as gadget
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.test_noise_cut_relation import (
    fixture as fixture,
)  # Shared test-only context.


@pytest.mark.parametrize("bits", [14, 18, 30])
@pytest.mark.parametrize("paired", [False, True])
def test_shape_and_fused_complete_residuals_equal_prior_schoolbook_relation(
    bits, paired, fixture
):
    pk, keys, query, index, cases = fixture
    compiled, sources, outputs, plans, _supplied = cases[bits]
    contexts = reference.profiles(query, index, 10, 5, pk, keys[30], keys[bits])
    template = shape.compile_shape(
        contexts, plans, local_boundaries=paired, paired_kernels=paired
    )
    assert template.source_layout == compiled.source_layout
    constants = shape.concrete_constants(template, index, keys[30], keys, int(pk.q))
    fused = fusion.fuse(template.graph)
    multipliers = fusion.coefficients(fused.graph, constants)
    inputs = fusion.bindings(compiled, sources, outputs)
    assert fusion.evaluate(fused.graph, inputs, multipliers) == relation.residuals(
        compiled, sources, outputs
    )


def test_shape_and_fusion_do_not_call_expected_response_HE_or_private_oracles(
    fixture, monkeypatch
):
    pk, keys, query, index, cases = fixture
    compiled, sources, outputs, plans, _supplied = cases[14]
    contexts = reference.profiles(query, index, 10, 5, pk, keys[30], keys[14])

    def forbidden(*_args, **_kwargs):
        pytest.fail("No HE replay or private work in the public adapter")

    for module, name in (
        (bgv, "multiply"),
        (bgv, "decrypt"),
        (gadget, "make_trace"),
        (gadget, "integer_product"),
        (gadget, "switched"),
        (reference, "make_trace"),
        (relation, "residuals"),
    ):
        monkeypatch.setattr(module, name, forbidden)
    template = shape.compile_shape(contexts, plans)
    constants = shape.concrete_constants(template, index, keys[30], keys, int(pk.q))
    fused = fusion.fuse(template.graph)
    assert all(
        not any(p)
        for p in fusion.evaluate(
            fused.graph,
            fusion.bindings(compiled, sources, outputs),
            fusion.coefficients(fused.graph, constants),
        )
    )


def test_unsafe_shape_rejects_before_builder_or_public_preparation(
    fixture, monkeypatch
):
    pk, keys, query, index, cases = fixture
    contexts = reference.profiles(query, index, 10, 5, pk, keys[30], keys[14])
    calls = []
    monkeypatch.setattr(fusion, "Builder", lambda *_args: calls.append(True))
    with pytest.raises(ValueError, match="Unsafe"):
        shape.compile_shape(
            (replace(contexts[0], product_bound=int(pk.q)),), cases[14][3]
        )
    assert not calls


def test_complete_shape_resource_counts_preserve_shared_Karatsuba_sum(fixture):
    pk, keys, query, index, cases = fixture
    contexts = reference.profiles(query, index, 10, 5, pk, keys[30], keys[30])

    def canonical(plan):
        if plan.mode == "zero":
            return plan
        if plan.level == -1:
            return replace(plan, mode="plain", retain=False)
        return replace(
            plan,
            mode="canonical",
            retain=False,
            left=canonical(plan.left),
            right=canonical(plan.right),
        )

    template = shape.compile_shape(contexts, tuple(canonical(p) for p in cases[30][3]))
    assert len(template.graph.anchors) == 1
    counts = fusion.resource_ledger(shape.direct_graph(template.graph))["online"][
        "operations"
    ]
    product_sources = sum(
        level == -1 for _g, level, _node, _bits in template.source_layout
    )
    rotations = len(template.source_layout) - product_sources
    ell = (int(pk.q).bit_length() + 29) // 30
    assert counts["multiply"] == (3 + 2 * ell) * product_sources + 2 * ell * rotations


def test_paired_fusion_keeps_three_tensor_products_and_reduces_scheduled_digit_lifetime(
    fixture,
):
    pk, keys, query, index, cases = fixture
    contexts = reference.profiles(query, index, 10, 5, pk, keys[30], keys[30])
    unpaired = shape.compile_shape(contexts, cases[30][3], local_boundaries=True)
    paired = shape.compile_shape(
        contexts, cases[30][3], local_boundaries=True, paired_kernels=True
    )
    assert len(paired.graph.pairs) > 0
    assert set(i for pair in paired.graph.pairs for i in pair) <= set(
        paired.graph.anchors
    )
    limits = fusion.Limits(64, 4096, 3, 400_000, 12_000_000)
    before = fusion.resource_ledger(fusion.fuse(unpaired.graph, limits).graph)
    after = fusion.resource_ledger(fusion.fuse(paired.graph, limits).graph)
    assert (
        after["online"]["operations"]["multiply"]
        <= before["online"]["operations"]["multiply"]
    )
    assert (
        after["online"]["scheduled_out_of_place_live_dynamic_polynomial_arrays"]
        < before["online"]["scheduled_out_of_place_live_dynamic_polynomial_arrays"]
    )


def test_suffix_lowering_preserves_cuts_and_has_no_derived_state_past_boundary(fixture):
    pk, keys, query, index, cases = fixture
    contexts = reference.profiles(query, index, 10, 5, pk, keys[30], keys[14])
    old = shape.compile_shape(contexts, cases[14][3])
    new = shape.compile_shape(contexts, cases[14][3], lowered=True)
    assert tuple(
        (g, level, node) for g, level, node, _bits in old.source_layout
    ) == tuple((g, level, node) for g, level, node, _bits in new.source_layout)
    assert len(new.graph.residuals) == len(old.graph.residuals)
    assert all(bits in (14, 30) for row in new.widths for bits in row)
