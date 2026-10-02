#!/usr/bin/env python3
"""E90 exact public remainder/carry oracles and paid hoisting counts, no timings."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from dataclasses import replace
from fractions import Fraction
from itertools import product
import json
from pathlib import Path
from random import Random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import orbit_remainder_trace as lab
from experiments.bfv_search_lab import test_orbit_remainder_trace as independent


def interval_count(q, b, target):
    # Independent exact rounding-cell interval enumeration, not the closed formula.
    length, total = b // target, 0
    for j in range(target):
        center = (2 * j + 1) * length // 2
        lower = max(0, ((2 * center - 1) * q) // (2 * b) + 1)
        upper = min(q - 1, ((2 * center + 1) * q - 1) // (2 * b))
        total += max(0, upper - lower + 1)
    return total


def exact_cards():
    signed, original, grid_cards, grid_values = 0, 0, 0, 0
    for power in range(2, 9):
        b = 1 << power
        for stages in range(1, min(power - 1, 4) + 1):
            p = independent.profile(b, (2,) * stages)
            for value in range(b):
                trace = lab.scalar_trace(value, p)
                assert trace == independent.reference(value, p)
                original += 1
                for sign in (-1, 1):
                    assert lab.signed_trace(value, trace, sign, p) == independent.reference(
                        value if sign == 1 else (-value) % b, p)
                    signed += 1
    for q in range(3, 130, 2):
        for power in range(2, 10):
            b = 1 << power
            for a_power in range(1, power):
                a, length = 1 << a_power, b // (1 << a_power)
                ties = 0
                for value in range(q):
                    converted = lab.rounded_grid(value, q, b)
                    assert lab.rounded_grid((-value) % q, q, b) == (-converted) % b
                    ties += converted % length == length // 2
                    grid_values += 1
                assert ties == lab.grid_tie_count(q, b, a) == interval_count(q, b, a)
                assert (ties == 0) == (q < length)
                grid_cards += 1
    phase_cards, full_output_cells = [], 0
    for families in (2, 3):
        p, cases, phases = independent.profile(4, (2,)), 0, 0
        for values in product(range(4), repeat=2 * families):
            components = tuple(tuple(values[2 * j:2 * j + 2]) for j in range(families))
            approved = lab.Approved(p, components, ((0, 1), (1, 1)))
            for secret in product((-1, 0, 1), repeat=2):
                secrets = (secret,) if families == 2 else (secret, independent.integer_product(secret, secret))
                phases += independent.check_blocks(approved, secrets)
                full_output_cells += 2 * ((families - 1) * 2 + 1)
                cases += 1
        phase_cards.append({"N": 2, "B": 4, "families_including_body": families,
                            "entire_component_ternary_source_cases": cases, "whole_integer_phase_equalities": phases})
    for n, stages, families in product((2, 4, 8, 16), (1, 2, 3), (2, 3)):
        rng, phases, cases = Random(90000 + n * 10 + stages + families), 0, 0
        p = independent.profile(1024, (2,) * stages)
        components = tuple(tuple(rng.randrange(p.modulus) for _ in range(n)) for _ in range(families))
        secret = tuple(rng.choice((-1, 0, 1)) for _ in range(n))
        secrets = (secret,) if families == 2 else (secret, independent.integer_product(secret, secret))
        for start in range(n):
            for width in range(1, n - start + 1):
                phases += independent.check_blocks(lab.Approved(p, components, ((start, width),)), secrets)
                full_output_cells += ((families - 1) * n + width) * stages
                cases += 1
        phase_cards.append({"N": n, "B": p.modulus, "stages": stages, "families_including_body": families,
                            "all_start_width_seeded_cards": cases, "whole_integer_phase_equalities": phases})
    independent.test_stage_half_tie_sets_disjoint_not_independent()
    independent.test_half_bits_previous_stage_and_canonical_lift_are_necessary()
    independent.test_grid_formula_does_not_cover_even_sources()
    return {"original_trace_equalities": original, "signed_multistage_equalities": signed,
            "odd_source_grid_cards": grid_cards, "all_grid_residues_and_negation_checks": grid_values,
            "closed_count_matches_independent_interval_and_residue_oracles": True,
            "full_public_output_step_cells_compared": full_output_cells,
            "phase_cards": phase_cards, "distinct_stage_half_tie_sets_disjoint": True,
            "half_ties_not_assumed_independent": True,
            "exact_negatives": {"B64_targets4_4_x8_plain_sign_and_previous_half_omission_fail": True,
                                "B64_x63_modular_first_quotient_reconstructs_minus1_instead_of63": True,
                                "even_Q6_B8_A2_count0_but_odd_formula2": True}}


def receiver_cards():
    approved, rejected, called = independent.approved_example(), 0, []
    good = lab.build(approved)
    assert lab.verify_and_release(approved, good, lambda _: "accepted") == "accepted"
    def reject(bad):
        nonlocal rejected
        try:
            lab.verify_and_release(approved, bad, lambda value: called.append(value))
        except ValueError:
            rejected += 1
        else:
            raise AssertionError("Corrupt integer trace accepted")
    def mutations(step, length):
        return (replace(step, quotient=step.quotient + 1),
                replace(step, remainder=(step.remainder + 1 + length // 2) % length - length // 2),
                replace(step, half=1 - step.half))
    lengths = lab.divisors(approved.profile)
    for family, poly in enumerate(good.original):
        for coefficient, trace in enumerate(poly):
            for stage, step in enumerate(trace):
                for changed in mutations(step, lengths[stage]):
                    array = [list(p) for p in good.original]
                    array[family][coefficient] = (*trace[:stage], changed, *trace[stage + 1:])
                    reject(replace(good, original=tuple(tuple(p) for p in array)))
    for index, block in enumerate(good.blocks):
        for kind, arrays in (("bodies", (block.bodies,)), ("masks", block.masks)):
            for family, poly in enumerate(arrays):
                for coefficient, trace in enumerate(poly):
                    for stage, step in enumerate(trace):
                        for changed in mutations(step, lengths[stage]):
                            array = [list(p) for p in arrays]
                            array[family][coefficient] = (*trace[:stage], changed, *trace[stage + 1:])
                            replacement = tuple(tuple(p) for p in array)
                            altered = replace(block, **{kind: replacement[0] if kind == "bodies" else replacement})
                            reject(replace(good, blocks=(*good.blocks[:index], altered, *good.blocks[index + 1:])))
    for bad in (replace(good, original=good.original[:-1]), replace(good, blocks=good.blocks[:-1]),
                replace(good, blocks=good.blocks[::-1]), replace(good, anchor="0" * 64)):
        reject(bad)
    assert not called
    return {"accepted_owner_approved_transcripts": 1, "corrupt_transcripts_rejected": rejected,
            "coverage": "Every single original/output step quotient, centered remainder and bit altered, plus framing; not all multi-error vectors",
            "private_callback_invocations_on_rejected_inputs": len(called),
            "authentication_mode": "Owner-approved complete inputs and paid full public recomputation",
            "upstream_original_score_PBS_ID_proof_supplied": False}


def cost_card(n, masks, stages, width, selected, queries):
    blocks = (selected + width - 1) // width
    independent_scalar = queries * selected * (masks * n + 1) * stages
    reference_shared = queries * (masks + 1) * n * stages
    strong_hoisted = queries * (masks * n + selected) * stages
    output_cells = queries * (blocks * masks * n + selected) * stages
    shared_bitmap = (reference_shared + 7) // 8
    # Counts model explicit 64-bit quotient/remainder arrays, not a implemented codec.
    return {"N": n, "mask_families": masks, "stages": stages, "block_width": width,
            "selected_public_positions": selected, "queries": queries,
            "independent_scalar_divrem_cells": independent_scalar,
            "reference_full_original_divrem_cells": reference_shared,
            "strong_hoisted_mask_and_selected_body_divrem_cells": strong_hoisted,
            "reference_to_strong_hoisted_divrem_ratio": str(Fraction(reference_shared, strong_hoisted)),
            "independent_to_strong_hoisted_ratio_NOT_speedup_or_novelty": str(Fraction(independent_scalar, strong_hoisted)),
            "materialized_block_output_step_cells": output_cells,
            "full_materialized_original_and_output_u64_word_bytes": 16 * (reference_shared + output_cells),
            "shared_original_stage_bit_bitmap_bytes": shared_bitmap,
            "per_coefficient_tie_stage_code_bits_for_zero_or_one_half": stages.bit_length(),
            "streaming_one_block_u64_word_bytes": 16 * (masks * n + min(width, selected)) * stages,
            "approved_original_ciphertext_body_bytes": queries * (masks + 1) * n * 8,
            "verifier_full_original_and_output_check_cells": reference_shared + output_cells,
            "existing_hoisted_verifier_can_have_identical_source_output_sharing": True,
            "decomp_reuse_across_different_queries_assumed": False,
            "downloading_original_trace_IS_NOT_mandatory_wire": True,
            "minimal_full_recomputation_can_regenerate_trace_without_transmitting_it": True,
            "known_compact_TruncRepeat_degree": 2048, "illustrative_TruncRepeat_T": 32,
            "illustrative_TruncRepeat_beta": 8, "illustrative_TruncRepeat_epsilon": 191,
            "known_compact_TruncRepeat_gadget_levels": 4,
            "known_compact_TruncRepeat_RLev_groups": 11,
            "known_compact_TruncRepeat_key_u64_body_bytes": 2 * 11 * 4 * 2048 * 8,
            "known_compact_TruncRepeat_gadget_polynomial_product_count_per_call": 11 * 4,
            "known_repeated_beta_epsilon_can_reuse_keys": True,
            "actual_key_generation_signed_key_compatibility_noise_cost": None,
            "relin_switch_unit_conversion_HomTruncRepeat_PBS_costs_removed": False,
            "original_input_and_stable_ID_winner_proof_costs": None,
            "owner_new_client_state_setup_roundtrips_updates_paid_complete": False,
            "full_scores_and_permitted_cache_controls_retained": True,
            "complete_mechanism_or_new_work_reduction_against_strong_hoist": False,
            "scope": "Exact array/work counts for the bounded public subrelation; known illustrative packing terms only. No timing, secure parameters or whole latency/traffic improvement."}


def grid_geometry(profiles):
    cards = []
    for p, b_power, degree, stages in product(profiles, (64, 128), (2048, 8192), (1, 3)):
        b, cumulative = 1 << b_power, 1
        targets = (2 * degree,) + (8,) * (stages - 1)
        counts = []
        for target in targets:
            cumulative *= target
            # B128 is a count-only alternative, not supported by the bounded reference.
            length = b // cumulative
            ties = 2 * ((p["modeled_Q"] + length) // (2 * length))
            counts.append({"cumulative_target": cumulative, "remaining_modulus": length,
                           "all_odd_source_residue_ties": ties, "no_tie_for_any_odd_source_residue": p["modeled_Q"] < length,
                           "uniform_odd_residue_tie_fraction_NOT_evaluated_cipher_law": str(Fraction(ties, p["modeled_Q"]))})
        cards.append({"dataset": p["dataset"], "profile": p["profile"], "N": p["n"],
                      "modeled_Q": p["modeled_Q"], "B_bits": b_power, "PBS_degree": degree,
                      "targets": targets, "stages": counts,
                      "uniform_odd_grid_any_stage_ties_disjoint": sum(c["all_odd_source_residue_ties"] for c in counts),
                      "B128_private_arithmetic_keys_wire_not_free": True,
                      "reference_B128_or_PBS_implemented": False,
                      "evaluated_cipher_uniformity_and_key_conditioning_approved": False})
    return cards


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", required=True, type=Path)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    profile_path = ROOT / "benchmarks/results/publication-encrypted-query-gate-control-20261001.json"
    result = metadata([Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", profile_path,
                       ROOT / "experiments/bfv_search_lab/orbit_remainder_trace.py",
                       ROOT / "experiments/bfv_search_lab/test_orbit_remainder_trace.py",
                       ROOT / "docs/research/orbit-remainder-preregistration-20261002.md"])
    profiles = json.loads(profile_path.read_text())["retained_geometry_count_screens"]
    exact = exact_cards()
    result.update(kind="E90_exact_signed_multistage_remainder_control", exact=exact,
                  full_recomputation_receivers=receiver_cards(),
                  paid_hoisting_cards=[cost_card(n,f,s,w,k,q) for n,f,s,w,mode,q in
                                      product((2048,16384),(1,2),(1,3),(1,8,32),("sparse","dense"),(1,16))
                                      for k in (3 if mode == "sparse" else n,)],
                  conditional_rounded_grid_geometry_cards=grid_geometry(profiles),
                  decision="Keep exact signed carries and the sharp odd-grid tie count. Hoisting is already a strong standard control; full public recomputation is not a succinct authenticated selector. Return to R6 for an orbit-aware deterministic drift certificate that respects S-squared dependence, not independent-secret Gaussian heuristics.",
                  scope="Homemade finite arithmetic/complete public subrelation checks and conditional counts only; no new timing, original complete protocol, PBS, approved security parameters or production claim.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "signed_trace_checks": exact["signed_multistage_equalities"],
                      "grid_cards": exact["odd_source_grid_cards"], "grid_residues": exact["all_grid_residues_and_negation_checks"],
                      "integer_phase_checks": sum(c["whole_integer_phase_equalities"] for c in exact["phase_cards"]),
                      "corrupt_transcripts": result["full_recomputation_receivers"]["corrupt_transcripts_rejected"],
                      "hoisting_cards": len(result["paid_hoisting_cards"]),
                      "grid_geometry_cards": len(result["conditional_rounded_grid_geometry_cards"])}))


if __name__ == "__main__":
    main()
