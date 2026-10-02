#!/usr/bin/env python3
"""E87 exact switching controls and paid geometry counts; no HE timings."""

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

from gmpy2 import is_prime

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import batched_score_bridge as bridge
from experiments.bfv_search_lab import convolution_certificate_oracle as certificate
from experiments.bfv_search_lab import test_batched_score_bridge as independent


def arithmetic_cards():
    residues, cards = 0, []
    for q, radix in ((3, 3), (5, 3), (17, 3), (17, 5), (19, 9), (51, 3), (257, 17), (323, 257)):
        for x in range(q):
            digits = bridge.digits(x, q, radix)
            assert sum(d * radix**level for level, d in enumerate(digits)) == bridge.centered(x, q)
            assert bridge.digits((-x) % q, q, radix) == tuple(-d for d in digits)
            residues += 1
    for count in (2, 3):
        inputs, coordinates, phases = 0, 0, 0
        for source in product(range(3), repeat=2):
            keys = independent.make_keys(source, (1,), 3, 3, count, Random(31 + sum(source)))
            for values in product(range(3), repeat=2 * count):
                components = tuple(values[i:i + 2] for i in range(0, len(values), 2))
                cells, coefficients = independent.check_phase(components, source, (1,), *keys)
                coordinates += cells
                phases += 2 * coefficients  # separate column and packed key/error families
                inputs += 1
        cards.append({"N": 2, "Q": 3, "components": count, "all_input_source_key_cases": inputs,
                      "literal_vs_column_all_output_coordinate_equalities": coordinates,
                      "independent_original_plus_error_phase_equalities": phases,
                      "keys_and_errors_seeded_independently_of_inputs": True})
    for q, radix, n, count in ((17, 3, 4, 3), (51, 5, 4, 2), (323, 9, 8, 3), (65537, 257, 16, 3)):
        rng = Random(q + radix + n)
        source, target = tuple(rng.choice((-1, 0, 1)) for _ in range(n)), (1, -1)
        keys = independent.make_keys(source, target, q, radix, count, rng)
        coordinates, phases = 0, 0
        for _ in range(12):
            components = tuple(tuple(rng.randrange(q) for _ in range(n)) for _ in range(count))
            cells, coefficients = independent.check_phase(components, source, target, *keys)
            coordinates += cells
            phases += 2 * coefficients
        cards.append({"N": n, "Q": q, "radix": radix, "components": count, "seeded_cases": 12,
                      "literal_vs_column_all_output_coordinate_equalities": coordinates,
                      "independent_original_plus_error_phase_equalities": phases})
    return {"complete_residue_reconstruction_and_negation_cases": residues, "phase_cards": cards}


def receiver_cards():
    cards = []
    for packed_mode in (False, True):
        column, _, packed, _ = independent.make_keys((1, -1), (1,), 17, 3, 3, Random(8))
        keys = packed if packed_mode else column
        approved = bridge.register("owner-epoch-7", ((1, 2), (9, 3), (4, 8)), keys, (0, 1))
        correct = bridge.recompute(approved)
        assert bridge.verify_recomputation(approved, correct)
        bad = [replace(correct, epoch="owner-epoch-8"), replace(correct, input_digest="0" * 64),
               replace(correct, positions=(1, 0)), replace(correct, positions=(0,)),
               replace(correct, digit_polys=correct.digit_polys[:1]),
               replace(correct, digit_polys=(correct.digit_polys[0][:-1], correct.digit_polys[1])),
               replace(correct, output=correct.output[:-1])]
        # Every nonzero residue corruption at every output cell, not just a basis scan.
        for row in range(len(correct.output)):
            coordinates = len(correct.output[row]) if packed_mode else len(correct.output[row].a) + 1
            for v in range(coordinates):
                for delta in range(1, 17):
                    changed = list(correct.output)
                    values = list(changed[row]) if packed_mode else list((*changed[row].a, changed[row].b))
                    values[v] = (values[v] + delta) % 17
                    changed[row] = tuple(values) if packed_mode else bridge.Scalar(tuple(values[:-1]), values[-1])
                    bad.append(replace(correct, output=tuple(changed)))
        alternate_column, _, alternate_packed, _ = independent.make_keys((1, -1), (1,), 17, 3, 3, Random(9))
        other = bridge.register(approved.epoch, approved.components,
                                alternate_packed if packed_mode else alternate_column, approved.positions)
        bad.append(replace(bridge.recompute(other), input_digest=approved.digest))
        components = (approved.components[0], (8, 3), approved.components[2])
        other = bridge.register(approved.epoch, components, keys, approved.positions)
        bad.append(replace(bridge.recompute(other), input_digest=approved.digest))
        assert all(not bridge.verify_recomputation(approved, transcript) for transcript in bad)
        cards.append({"route": "packed_partial_GLWE" if packed_mode else "scalar_columns",
                      "accepted_complete_correct_transcripts": 1, "rejected_corrupt_transcripts": len(bad),
                      "full_recomputation_and_full_owner_approved_inputs_required": True,
                      "private_callback_or_succinct_PBS_search_proof": False})
    return cards


def geometry(profile, radix, dimension, relin):
    n, q, replies, t, bound = (profile[k] for k in ("n", "modeled_Q", "replies", "t", "phase_bound"))
    levels, families, coords = bridge.context(q, radix), 1 if relin else 2, dimension + 1
    bits, half = q.bit_length(), radix // 2
    column_cells, packed_cells = families * levels * n * coords, 2 * families * levels * n
    key_error = families * levels * n * half  # illustrative |key error| <=1, NOT secure parameter
    unit_error = Fraction(bound, t)
    margin = Fraction(q, 2 * t) - unit_error
    routes = []
    for required in (3, n // 2, n):
        for batches in (1, 16):
            transforms = families * levels + coords
            packed_transforms = families * levels + 2
            routes.append({"required_coefficients_per_reply": required, "query_batches": batches,
                           "sparse_3_does_not_prove_full_search_coverage": required == 3,
                           "literal_scalar_multiply_add_contributions": batches * replies * required * families * levels * n * coords,
                           "column_shared_pointwise_products": batches * replies * families * levels * n * coords,
                           "column_shared_online_transforms": batches * replies * transforms,
                           "column_shared_radix2_butterflies": batches * replies * transforms * (n // 2) * (n.bit_length() - 1),
                           "packed_shared_pointwise_products": batches * replies * 2 * families * levels * n,
                           "packed_shared_online_transforms": batches * replies * packed_transforms,
                           "packed_shared_radix2_butterflies": batches * replies * packed_transforms * (n // 2) * (n.bit_length() - 1),
                           "column_materialized_u64_output_bytes": batches * replies * required * coords * 8,
                           "packed_cipher_materialized_u64_bytes": batches * replies * 2 * n * 8,
                           "streamed_one_scalar_output_u64_bytes": coords * 8,
                           "scalar_extraction_or_PBS_work_not_removed": batches * replies * required,
                           "full_recomputation_receiver_column_schoolbook_products": batches * replies * families * levels * coords * n * n,
                           "full_recomputation_receiver_packed_schoolbook_products": batches * replies * 2 * families * levels * n * n})
    rounds = certificate.rounds_for(q, 2 * n - 1, 1024, 128) if is_prime(q) else None
    torus = []
    for target_bits in (32, 64):
        target = 1 << target_bits
        error = Fraction(target, q) * (unit_error + key_error) + Fraction(1 + dimension, 2)
        denominator = target - t * (1 + dimension)
        minimum_q = (2 * target * (bound + t * key_error)) // denominator + 1 if denominator > 0 else None
        torus.append({"B_bits": target_bits, "illustrative_ternary_target_L1_bound": dimension,
                      "post_unit_and_KS_and_rounding_bound": str(error), "message_radius": str(Fraction(target, 2 * t)),
                      "existing_Q_satisfies_sufficient_bound": error < Fraction(target, 2 * t),
                      "necessary_new_Q_above_this_sufficient_model": minimum_q,
                      "minimum_Q_bits_before_NTT_prime_rounding": minimum_q.bit_length() if minimum_q else None,
                      "additional_relinearization_and_PBS_noise_not_in_bound": True})
    return {"dataset": profile["dataset"], "profile": profile["profile"], "N": n, "replies": replies,
            "modeled_Q": q, "Q_bits": bits, "t": t, "radix": radix, "exact_levels": levels,
            "illustrative_target_dimension_not_approved": dimension,
            "route": "once_relinearize_then_switch" if relin else "direct_S_and_S_squared_switch",
            "auxiliary_key_message_and_partial_secret_security_unreviewed": True,
            "column_key_coefficients": column_cells, "packed_key_coefficients": packed_cells,
            "column_key_bitpacked_body_bytes": (column_cells * bits + 7) // 8,
            "packed_key_bitpacked_body_bytes": (packed_cells * bits + 7) // 8,
            "column_key_u64_residency_bytes": column_cells * 8, "packed_key_u64_residency_bytes": packed_cells * 8,
            "key_coefficient_ratio_for_DIFFERENT_key_distributions": str(Fraction(coords, 2)),
            "column_key_pretransform_count": families * levels * coords,
            "packed_key_pretransform_count": 2 * families * levels,
            "per_context_key_scan_and_transfer_coefficient_lower_storage_model": {"column": column_cells, "packed": packed_cells},
            "NTT_field_storage_model_not_FFT_error_or_multilimb_assurance": True,
            "Q_is_NTT_friendly_prime": bool(is_prime(q) and (q - 1) % (2 * n) == 0),
            "once_relin_additional_key_coefficients_conditional_same_gadget": 2 * levels * n if relin else 0,
            "once_relin_additional_pointwise_products_per_reply_conditional_same_gadget": 2 * levels * n if relin else 0,
            "once_relin_additional_forward_and_inverse_transforms_per_reply": levels + 2 if relin else 0,
            "once_relin_noise_bound_known": False if relin else None,
            "illustrative_key_noise_absolute_bound_1_NOT_secure": key_error,
            "existing_Q_unit_only_remaining_radius": str(margin),
            "existing_Q_unit_plus_illustrative_KS_sufficient_radius": margin > key_error,
            "torus_rounding_cards": torus,
            "execution_modes": routes,
            "full_recomputation_original_input_body_bytes": (3 * n * replies * bits + 7) // 8,
            "full_recomputation_column_output_body_bytes": (n * coords * replies * bits + 7) // 8,
            "full_recomputation_packed_output_body_bytes": (2 * n * replies * bits + 7) // 8,
            "optional_digit_witness_body_bytes": (families * levels * n * replies * radix.bit_length() + 7) // 8,
            "digit_witness_wire_avoidable_by_client_recomputing_from_full_approved_C": True,
            "full_recomputation_extra_RTTs_beyond_request_response": 0,
            "known_post_output_quotient_rounds_count_only": rounds,
            "known_quotient_witness_body_bytes_without_binding_or_PBS": (rounds * (n - 1) * replies * bits + 7) // 8 if rounds else None,
            "known_column_public_batch_weight_bytes_without_binding_or_PBS": (rounds * coords * replies * bits + 7) // 8 if rounds else None,
            "known_packed_public_batch_weight_bytes_without_binding_or_PBS": (rounds * 2 * replies * bits + 7) // 8 if rounds else None,
            "known_post_output_batch_additional_RTTs": 1,
            "compact_digit_original_score_binding_PBS_ID_coverage_prover_verifier_wire_costs": None,
            "compact_complete_authenticated_selection_implemented": False,
            "scope": "Deterministic component counts. Full same-input recomputation is implemented only at toy shapes. Packed/scalar keys differ; secure parameters, RNS expansion, relin/PBS/proof work, native timing and whole search effectiveness are not established."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", required=True, type=Path)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new immutable result path")
    profiles_path = ROOT / "benchmarks/results/publication-encrypted-query-gate-control-20261001.json"
    result = metadata([Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", profiles_path,
                       ROOT / "experiments/bfv_search_lab/batched_score_bridge.py",
                       ROOT / "experiments/bfv_search_lab/test_batched_score_bridge.py",
                       ROOT / "experiments/bfv_search_lab/convolution_certificate_oracle.py",
                       ROOT / "experiments/bfv_search_lab/reduction_oracles.py",
                       ROOT / "experiments/bfv_search_lab/bgv_unit_bridge.py",
                       ROOT / "experiments/bfv_search_lab/score_phase_bridge_oracle.py",
                       ROOT / "experiments/bfv_search_lab/shallow_bgv.py",
                       ROOT / "docs/research/batched-score-bridge-preregistration-20261002.md"])
    profiles = json.loads(profiles_path.read_text())["retained_geometry_count_screens"]
    result.update(kind="E87_known_batched_and_packed_switching_controls",
                  arithmetic=arithmetic_cards(), full_recomputation_receivers=receiver_cards(),
                  fresh_homemade_BGV_product_differential=independent.fresh_bgv_differential(),
                  paid_geometry_cards=[geometry(p, radix, d, relin) for p in profiles
                                       for radix in (3, 257) for d in (512, 1024) for relin in (False, True)],
                  exact_negative_controls={"unsigned_binary_negation": "d(-1 mod17) != -d(1)",
                                           "digit_evaluation": "(0,1) and (2,0) agree at z=2 over F17 but low radix3 digits do not",
                                           "modular_range_only": "-8 and +9 have distinct in-range radix3 digits, same residue 9 mod17",
                                           "disclosed_point": "Nonzero X-z error passes that point; full recomputation rejects"},
                  decision="Keep known exact shared convolution and once-packed partial-GLWE controls. No new compact authenticated digit/input/PBS/coverage step supplied; do not select Q6 or claim conference novelty. Return to R6 and examine an original-coefficient/orbit-native interface instead of independent scalar materialization.",
                  scope="Homemade exact bounded arithmetic, explicit full recomputation receiver and deterministic paid counts only. No timing, GPU speedup, succinct proof, encrypted top3, secure parameters or production release assurance.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "residue_cases": result["arithmetic"]["complete_residue_reconstruction_and_negation_cases"],
                      "all_output_coordinates": sum(c["literal_vs_column_all_output_coordinate_equalities"] for c in result["arithmetic"]["phase_cards"]),
                      "phase_equalities": sum(c["independent_original_plus_error_phase_equalities"] for c in result["arithmetic"]["phase_cards"]),
                      "rejected_transcripts": sum(c["rejected_corrupt_transcripts"] for c in result["full_recomputation_receivers"]),
                      "paid_cards": len(result["paid_geometry_cards"])}))


if __name__ == "__main__":
    main()
