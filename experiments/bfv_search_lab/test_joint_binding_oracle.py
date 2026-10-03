"""E101 false traces, complete residuals, global digits and real E73 scores."""

from dataclasses import replace
from itertools import product

import pytest

from benchmarks.joint_binding_lab import actual_packed_case, relin_case, toy_relin
from experiments.bfv_search_lab import joint_binding_oracle as oracle


def test_generic_original_query_to_wire_matches_real_E73_scores_and_stable_IDs():
    case = actual_packed_case()
    assert case["all_scores_and_stable_ties_exact"] and case["generic_compiler_matches_E78_and_E73"]
    assert len(case["cases"]) == 4
    assert all(item["false_witness_kernel"]["nullity"] >= 64 for item in case["cases"])


def test_RNS_native_path_algebra_and_single_limb_rejection():
    case = relin_case()
    assert case["full_integer_reference_matches"] and case["single_limb_mutation_rejected"]
    assert case["other_limb_alone_would_accept"]


@pytest.mark.parametrize("fault", ["original_c0", "original_c1", "parent", "statement", "missing_cut",
                                  "cut_order", "digit", "range", "digit_type", "output_shape", "output_range"])
def test_false_trace_or_original_binding_rejected(fault):
    graph, query, parent, *_ = toy_relin()
    honest = oracle.honest_certificate(graph, query, parent)
    bad = honest
    if fault.startswith("original"):
        at = int(fault[-1])
        item = tuple((x + 1) % graph.q if i == 0 else x for i, x in enumerate(query[at]))
        query = tuple(item if k == at else p for k, p in enumerate(query))
    elif fault == "parent":
        parent = b"z" * 32
    elif fault == "statement":
        bad = replace(honest, statement=b"x" * 32)
    elif fault == "missing_cut":
        bad = replace(honest, cut_digits=honest.cut_digits[:-1])
    elif fault == "cut_order":
        bad = replace(honest, cut_digits=tuple(reversed(honest.cut_digits)))
    elif fault in ("digit", "range", "digit_type"):
        first = honest.cut_digits[0]
        value = (first[0][0] + 1) % 4 if fault == "digit" else 4 if fault == "range" else True
        bad = replace(honest, cut_digits=(((value, *first[0][1:]), *first[1:]), *honest.cut_digits[1:]))
    elif fault == "output_shape":
        bad = replace(honest, output=honest.output[:-1])
    else:
        bad = replace(honest, output=(((graph.q, *honest.output[0][0][1:]), honest.output[0][1]),
                                      *honest.output[1:]))
    assert not oracle.verify_exact(graph, query, parent, bad)


@pytest.mark.parametrize("reply,component,coefficient", product(range(2), range(2), range(2)))
def test_every_transmitted_coefficient_is_bound(reply, component, coefficient):
    graph, query, parent, *_ = toy_relin()
    honest = oracle.honest_certificate(graph, query, parent)
    output = [[list(poly) for poly in item] for item in honest.output]
    output[reply][component][coefficient] = (output[reply][component][coefficient] + 1) % graph.q
    bad = replace(honest, output=tuple(tuple(tuple(p) for p in item) for item in output))
    assert not oracle.verify_exact(graph, query, parent, bad)


def test_non_basis_output_preserving_kernel_requires_nonlinear_canonical_gate():
    graph, query, parent, *_ = toy_relin()
    honest = oracle.honest_certificate(graph, query, parent)
    bad, counts = oracle.false_witness_kernel(graph, query, parent, honest, 17)
    assert bad.output == honest.output and counts["nullity"] > 0
    assert not any(oracle.residuals(graph, query, parent, bad, canonical=False))
    assert not oracle.verify_exact(graph, query, parent, bad)


def test_globally_bounded_digits_below_radix_still_need_representative_less_than_Q():
    graph, query, parent, *_ = toy_relin()
    query = (query[0], (0, 0))  # Native C2=0, so representative Q is a residue alias.
    honest = oracle.honest_certificate(graph, query, parent)
    alternative = oracle.digits((graph.q, 0), 1023, graph.digit_bits)
    assert len(alternative) == len(honest.cut_digits[0])
    bad = replace(honest, cut_digits=(alternative, *honest.cut_digits[1:]))
    assert all(0 <= x < 4 for row in alternative for x in row)
    assert not oracle.verify_exact(graph, query, parent, bad)
    with pytest.raises(ValueError, match="representative"):
        oracle.features_of(graph, query, parent, bad)


def test_generic_transpose_equals_literal_residual_dot_in_each_prime():
    graph, query, parent, *_ = toy_relin()
    honest = oracle.honest_certificate(graph, query, parent)
    rows = oracle.constraint_rows(graph)
    features = oracle.features_of(graph, query, parent, honest)
    body = (0,) * (len(graph.cuts) * graph.n) + tuple(x for item in honest.output for p in item for x in p)
    for p in (17, 41):
        weights = tuple((7*i+3) % p for i in range(len(rows)))
        hints = oracle.adjoint(rows, weights, graph.feature_count, p)
        folded = (sum(a*b for a, b in zip(hints, features, strict=True))
                  - sum(a*b for a, b in zip(weights, body, strict=True))) % p
        literal = sum(a*b for a, b in zip(weights, oracle.residuals(graph, query, parent, honest), strict=True)) % p
        assert folded == literal == 0


def test_complete_nonzero_residual_exhaustion_and_linked_challenge_cancellation():
    result = oracle.uniform_field_exhaustion()
    assert result["checks"] == 15500 and result["non_basis_errors"] == 112
    assert result["max_accept_count"] == 25
    # Entire family of correlated rows misses this two-coordinate error.
    assert all((r-r) % 5 == 0 for r in range(5))
    assert oracle.feedback_exhaustion()["first_false_trace_accepts"] == 17


def test_strong_compiler_has_same_source_witness_and_digit_derivation_costs():
    card = oracle.cost_card(8192, 1, 128, 120, 30, relin=True)
    assert card["new_vs_equally_optimized_generic_control_ratio"] == [1, 1]
    assert card["cut_source_body_bytes"] == card["cut_digit_body_bytes"] == 15728640
    assert card["canonical_digit_coefficients_derived_or_supplied"] == 4194304
    assert card["source_cut_control_can_derive_digits_locally_too"]


def test_graphs_do_not_silently_mix_packed_expansion_and_native_relinearization():
    graph, query, parent, index, key = toy_relin()
    with pytest.raises(ValueError, match="Separate"):
        oracle.compile_graph(n=2, q=graph.q, digit_bits=2, index=index,
                             rotations=((3, key),), relin_key=key)
    honest = oracle.honest_certificate(graph, query, parent)
    changed = replace(graph, digest=b"z" * 32)
    assert not oracle.verify_exact(changed, query, parent, honest)


def test_mutable_statement_and_non_coprime_limb_are_not_valid_canonical_inputs():
    graph, query, parent, *_ = toy_relin()
    honest = oracle.honest_certificate(graph, query, parent)
    assert not oracle.verify_exact(graph, query, parent, replace(honest, statement=bytearray(honest.statement)))
    with pytest.raises(ValueError, match="coprimely"):
        oracle.false_witness_kernel(replace(graph, q=17**2), query, parent, honest, 17)
    with pytest.raises(ValueError):
        oracle.uniform_field_exhaustion(5, 0)
