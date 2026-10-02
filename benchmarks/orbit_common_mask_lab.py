#!/usr/bin/env python3
"""E88 exact orbit/block controls and CM auxiliary-key counts, no timings."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from fractions import Fraction
from itertools import product
import json
from pathlib import Path
from random import Random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import orbit_common_mask as orbit
from experiments.bfv_search_lab import test_orbit_common_mask as independent
from experiments.bfv_search_lab.test_batched_score_bridge import phase_reference


def exact_cards():
    phase_cards = []
    for count in (2, 3):
        cases, phase_checks, block_checks = 0, 0, 0
        for source in product(range(3), repeat=2):
            for values in product(range(3), repeat=2 * count):
                components = tuple(values[i:i + 2] for i in range(0, len(values), 2))
                block_checks += independent.check_blocks(components, source, 3)
                phase_checks += len(phase_reference(components, source, 3))
                cases += 1
        phase_cards.append({"N": 2, "Q": 3, "components": count, "all_component_source_cases": cases,
                            "original_phase_checks": phase_checks, "all_start_width_block_phase_checks": block_checks,
                            "public_restore_matches_every_component": True})
    for n in (4, 8, 16):
        rng, checks, support_checks = Random(n + 25), 0, 0
        for prefix in range(1, n + 1):
            source = tuple(rng.choice((-1, 0, 1)) for _ in range(prefix)) + (0,) * (n - prefix)
            components = tuple(tuple(rng.randrange(17) for _ in range(n)) for _ in range(3))
            checks += independent.check_blocks(components, source, 17)
            for width in range(1, n + 1):
                support = orbit.public_union_support(n, prefix, width)
                assert len(support) == min(n, prefix + width - 1)
                for row in orbit.orbit_rows(source, 17)[:width]:
                    assert all(x == 0 for j, x in enumerate(row) if j not in support)
                support_checks += 1
        phase_cards.append({"N": n, "Q": 17, "components": 3, "seeded_prefix_cases": n,
                            "all_start_width_block_phase_checks": checks, "all_public_prefix_width_support_checks": support_checks})
    laws = []
    for n in (2, 4, 8):
        matrices = {orbit.orbit_rows(secret, 17) for secret in product((-1, 0, 1), repeat=n)}
        assert len(matrices) == 3**n
        laws.append({"N": n, "all_ternary_original_secrets_and_distinct_orbit_matrices": len(matrices),
                     "independent_full_N_by_N_ternary_matrix_possible_count": 3**(n*n),
                     "not_an_independent_Matrix_LWE_key_law": True})
    diagonals = []
    for n in (2, 4, 8):
        space = tuple(product((0, 1), repeat=n))
        good = tuple(d for d in space if orbit.diagonal_commutes_shift(d, 17))
        assert good == ((0,) * n, (1,) * n)
        diagonals.append({"N": n, "entire_binary_diagonal_space_checked": len(space),
                          "negacirculant_diagonals": len(good), "nonconstant_diagonals_outside_ring_algebra": len(space)-len(good)})
    inputs = []
    for n in (2, 4):
        checks, failures = 0, 0
        for diagonal in product((0, 1), repeat=n):
            # Any candidate ring multiplier MUST have D's first column.
            multiplier = (diagonal[0],) + (0,) * (n - 1)
            for values in product(range(3), repeat=n):
                actual = independent.product_reference(multiplier, values, 3)
                expected = tuple(a * b % 3 for a, b in zip(diagonal, values, strict=True))
                failures += actual != expected
                checks += 1
        inputs.append({"N": n, "Q": 3, "all_diagonal_all_input_checks": checks,
                       "wrong_one_ring_multiplier_surrogate_results": failures})
    independent.test_same_mask_same_secret_shortcut_reveals_message_difference()
    return {"phase_and_block_cards": phase_cards, "entire_secret_law_cards": laws,
            "entire_binary_diagonal_cards": diagonals, "whole_input_surrogate_cards": inputs,
            "same_mask_same_secret_difference_leak_negative": True}


def key_card(profile, width, prefix):
    n, replies = profile["n"], profile["replies"]
    if prefix is None:
        dimension, ordinary_dimension, families, route = 2*n, 2*n, 2, "original_C1_C2_orbit"
    else:
        dimension = min(n, prefix + width - 1)
        ordinary_dimension, families, route = prefix, 1, "known_once_packed_partial_key_then_block_orbit"
    degree, rank, levels, element_bytes = 2048, 1, 4, 8
    # Paper's Table 7 unseeded formula; binary secret/gadget control only.
    cm_bsk = dimension * levels * (rank + width)**2 * degree
    shared_ordinary_bsk = ordinary_dimension * levels * (rank + 1)**2 * degree
    table7_seeded = dimension * levels * (rank + width) * degree
    literal_seeded = dimension * levels * (rank + width) * width * degree
    # Appendix C.1's FOUR reported compact-regeneration key terms, not zero.
    compact_parts = (width * levels * degree,
                     (degree.bit_length() - 1) * levels * rank * degree * (dimension + 1),
                     width * rank * (rank + width) * degree * degree,
                     width * rank * (rank + width)**2 * degree)
    groups = n // width * replies
    return {"dataset": profile["dataset"], "profile": profile["profile"], "N": n, "replies": replies,
            "route": route, "block_width": width, "public_partial_prefix": prefix,
            "common_input_dimension_after_public_support_trim": dimension,
            "ordinary_extracted_input_dimension": ordinary_dimension,
            "same_canonical_block_keys_reused_for_every_start": True,
            "naive_per_block_keys_are_NOT_the_comparison_baseline": True,
            "new_common_mask_coefficient_bytes_before_PBS": 0,
            "mask_slices_rotations_and_trim_views_no_scalar_rounding": True,
            "known_partial_switch_cost_required_first": prefix is not None,
            "original_or_packed_coefficient_body_cells": (families+1)*n*replies,
            "generic_independent_source_secret_matrix_cells": width*dimension,
            "actual_source_secret_generator_cells": n if prefix is None else prefix,
            "CM_input_source_key_law_is_orbit_correlated": True,
            "illustrative_PBS_degree": degree, "illustrative_PBS_rank": rank, "illustrative_PBS_levels": levels,
            "illustrative_B_bits": 64, "parameter_and_PBS_compatibility_approved": False,
            "CM_BSK_unseeded_u64_bytes_per_binary_indicator": cm_bsk*element_bytes,
            "shared_ordinary_BSK_unseeded_u64_bytes_per_binary_indicator": shared_ordinary_bsk*element_bytes,
            "CM_vs_shared_ordinary_unseeded_key_coefficient_ratio": str(Fraction(cm_bsk,shared_ordinary_bsk)),
            "published_Table7_seeded_CM_BSK_body_bytes_not_reproduced": table7_seeded*element_bytes,
            "literal_independently_seeded_CM_cipher_body_bytes": literal_seeded*element_bytes,
            "published_seeded_formula_vs_literal_requires_artifact_or_format_review": width>1,
            "CM_Appendix_C1_four_compact_regeneration_terms_u64_bytes": tuple(x*element_bytes for x in compact_parts),
            "CM_Appendix_C1_total_static_u64_bytes_not_runtime_residency": sum(compact_parts)*element_bytes,
            "CM_BSK_runtime_full_generation_scan_or_streaming_work_not_removed": True,
            "signed_ternary_two_indicator_families_would_double_base_keys": True,
            "direct_S_squared_multivalued_secret_needs_more_than_ternary_gates": prefix is None,
            "CM_PBS_blocks_required_for_all_coefficients": groups,
            "ordinary_PBS_scores_required_for_all_coefficients": n*replies,
            "dense_CM_external_product_products_unoptimized_per_indicator": groups*cm_bsk,
            "dense_ordinary_external_product_products_shared_key_per_indicator": n*replies*shared_ordinary_bsk,
            "dense_product_count_ratio_not_latency_prediction": str(Fraction(groups*cm_bsk,n*replies*shared_ordinary_bsk)),
            "CM_output_scalar_body_cells_before_winner_selection": groups*(rank*degree+width),
            "ordinary_output_scalar_cells_before_winner_selection": n*replies*(rank*degree+1),
            "client_downloading_intermediate_scores_is_NOT_assumed": True,
            "compact_authentication_and_stable_ID_winner_trace_costs": None,
            "new_complete_encrypted_selection_or_proof_supplied": False,
            "scope": "Conditional CM format/key counts with generic Table7/AppendixC1 controls. Key rotation/support arithmetic is exact; secure noise, auxiliary-key privacy, actual CM/PBS execution, optimized external products and proof/coverage cost are uninstantiated. No whole-family performance rejection."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", required=True, type=Path)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new immutable result path")
    profile_path = ROOT / "benchmarks/results/publication-encrypted-query-gate-control-20261001.json"
    result = metadata([Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", profile_path,
                       ROOT / "experiments/bfv_search_lab/orbit_common_mask.py",
                       ROOT / "experiments/bfv_search_lab/test_orbit_common_mask.py",
                       ROOT / "experiments/bfv_search_lab/batched_score_bridge.py",
                       ROOT / "experiments/bfv_search_lab/test_batched_score_bridge.py",
                       ROOT / "docs/research/orbit-common-mask-preregistration-20261002.md"])
    profiles = json.loads(profile_path.read_text())["retained_geometry_count_screens"]
    result.update(kind="E88_original_ring_orbit_common_mask_control", exact=exact_cards(),
                  paid_key_geometry_cards=[key_card(p,w,prefix) for p in profiles
                                           for w in (1,4,8,32) for prefix in (None,512,1024)],
                  decision="Keep exact original-ring and reusable block-orbit views, including public partial-key union trimming. Stop free independent-key/one-ring-slot-diagonal PBS shortcuts; ordinary shared PBS and generic CM compact keys remain strong controls. No original complete authenticated selection mechanism selected; return to R6 for a proof/coverage-native candidate.",
                  scope="Homemade exact bounded phase/secret-law/diagonal controls and deterministic conditional key counts only; no CM-PBS encryption, secure parameters, succinct proof, timing or production assurance.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({"output":str(args.json_out),
                      "original_phase_checks":sum(c.get("original_phase_checks",0) for c in result["exact"]["phase_and_block_cards"]),
                      "all_block_phase_checks":sum(c["all_start_width_block_phase_checks"] for c in result["exact"]["phase_and_block_cards"]),
                      "entire_secret_law_cases":sum(c["all_ternary_original_secrets_and_distinct_orbit_matrices"] for c in result["exact"]["entire_secret_law_cards"]),
                      "all_binary_diagonals":sum(c["entire_binary_diagonal_space_checked"] for c in result["exact"]["entire_binary_diagonal_cards"]),
                      "paid_key_cards":len(result["paid_key_geometry_cards"])}))


if __name__ == "__main__":
    main()
