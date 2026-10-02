#!/usr/bin/env python3
"""E85 exact phase controls and separately charged conversion counts, no timings."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from fractions import Fraction
from itertools import product
import json
from pathlib import Path
import sys

from gmpy2 import is_prime

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import score_phase_bridge_oracle as oracle


def extraction_control():
    cards = []
    for count in (2, 3):
        checked = 0
        for values in product(range(3), repeat=2 * count):
            components = tuple(values[i:i + 2] for i in range(0, len(values), 2))
            for secret in product(range(3), repeat=2):
                phase = oracle.ring_phase(components, secret, 3)
                flat = sum(oracle.secret_powers(secret, 3, count), ())
                for k in range(2):
                    assert oracle.sample_phase(oracle.extract(components, k, 3), flat) == phase[k]
                    checked += 1
        cards.append({"n": 2, "Q": 3, "ciphertext_components": count,
                      "all_ring_coefficient_phases_checked": checked,
                      "includes_all_ciphertexts_and_all_ternary_keys": True,
                      "extracted_dimension": (count - 1) * 2,
                      "C2_uses_correlated_derived_secret_S_squared": count == 3})
    return cards


def bfv_control():
    q, t, target, checked = 101, 5, 256, 0
    for a in product((0, 1, 50, 100), repeat=2):
        for secret in product((-1, 0, 1), repeat=2):
            for message, noise in product(range(t), (-1, 0, 1)):
                b = (q // t * message + noise - sum(x * s for x, s in zip(a, secret, strict=True))) % q
                sample = oracle.Sample(a, b, q)
                assert oracle.decode_scaled(oracle.sample_phase(sample, secret), q, t) == message
                changed = oracle.scale_sample(sample, target, q)
                assert oracle.decode_scaled(oracle.sample_phase(changed, secret), target, t) == message
                checked += 1
    bound = oracle.bfv_switch_bound(q, t, target, 1, 2)
    return {"Q": q, "t": t, "torus_modulus_B": target, "noise_bound": 1,
            "maximum_signed_secret_L1": 2, "mask_choices_per_coordinate": [0, 1, 50, 100],
            "exact_roundtrip_cases": checked,
            "conditional_error_bound": str(bound["error_bound"]),
            "nearest_message_margin": str(bound["nearest_message_margin"]),
            "sufficient_strict_margin": bound["sufficient_strict_margin"],
            "keyswitch_PBS_padding_parameter_security_included": False}


def bgv_controls():
    q, t, target, secret = 101, 5, 256, (1,)
    sample = oracle.Sample((0,), 1, q)
    zero, wrapped = oracle.Sample((0,), 0, q), oracle.Sample((100,), 1, q)
    assert oracle.sample_phase(zero, secret) == oracle.sample_phase(wrapped, secret) == 0
    wrong = oracle.decode_scaled(oracle.sample_phase(oracle.scale_sample(sample, target, q), secret), target, t)
    carry_wrong = oracle.decode_scaled(oracle.sample_phase(oracle.scale_sample(wrapped, target, t), secret), target, t)
    assert wrong == 0 and carry_wrong == 1
    return {"Q": q, "t": t, "B": target,
            "ordinary_Q_to_B_switch": {"intended_BGV_message": 1, "scaled_decode": wrong},
            "naive_B_over_t_scaling": {"both_original_phases": 0,
                                        "no_Q_carry_scaled_decode": 0,
                                        "one_Q_carry_scaled_decode": carry_wrong},
            "scope": "Counterexamples to two proposed cheap adapters, not an attack or impossibility for published BGV conversion."}


def split_count(profile):
    n, t, eta, width = (profile[k] for k in ("n", "t", "eta", "columns"))
    new_t = max(1, (t - 1) // (2 * n)) * (2 * n) + 1
    while new_t <= t or not is_prime(new_t):
        new_t += 2 * n
    old_bound = n * width * (t // 2 + t * eta) ** 2
    assert old_bound == profile["phase_bound"]
    new_bound = n * width * (new_t // 2 + new_t * eta) ** 2
    return {"dataset": profile["dataset"], "profile": profile["profile"],
            "n": n, "old_t": t, "fully_split_t": new_t,
            "fully_split_t_is_1_mod_2N": new_t % (2 * n) == 1,
            "same_E72_fresh_phase_bound_law": "N*columns*(floor(t/2)+t*eta)^2",
            "old_one_product_bound": old_bound, "new_one_product_bound": new_bound,
            "bound_expansion_fraction": str(Fraction(new_bound, old_bound)),
            "old_modeled_Q_bits": profile["modeled_Q"].bit_length(),
            "new_minimum_Q_before_NTT_prime_rounding": 2 * new_bound + 1,
            "new_minimum_Q_bits_before_NTT_prime_rounding": (2 * new_bound + 1).bit_length(),
            "same_circuit_only": True, "additional_selection_depth_paid": False,
            "changes_keys_index_and_correctness_context": True,
            "new_security_parameters_or_timings_approved": False}


def extraction_count(n, selected_coefficients, q_bits, count):
    dimension = (count - 1) * n
    return {"n": n, "selected_coefficients": selected_coefficients,
            "input_Q_bits": q_bits, "ciphertext_components": count,
            "extracted_input_dimension": dimension,
            "expanded_sample_public_values": selected_coefficients * (dimension + 1),
            "optional_materialized_bitpacked_body_bytes": (selected_coefficients * (dimension + 1) * q_bits + 7) // 8,
            "optional_materialized_u64_body_bytes": selected_coefficients * (dimension + 1) * 8,
            "materialization_is_not_required": True,
            "not_a_wire_or_work_lower_bound": True,
            "shared_ring_storage_views_and_fused_or_batched_switch_are_controls": True,
            "missing_paid_costs": ["once-per-packed-output relinearization for two-component route",
                                    "actual supported derived-secret keyswitch/PBS and its noise/security",
                                    "bootstrap LUT padding and complete stable-ID selection",
                                    "original score/index/query/epoch execution proof and coverage"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new immutable result path")
    profiles_path = ROOT / "benchmarks/results/publication-encrypted-query-gate-control-20261001.json"
    sources = [Path(__file__), profiles_path, ROOT / "benchmarks/dictionary_layout_lab.py",
               ROOT / "benchmarks/encrypted_query_certificate_lab.py", ROOT / "src/cuhepy/bfv/scheme.py",
               ROOT / "experiments/bfv_search_lab/shallow_bgv.py",
               ROOT / "experiments/bfv_search_lab/score_phase_bridge_oracle.py",
               ROOT / "experiments/bfv_search_lab/test_score_phase_bridge_oracle.py",
               ROOT / "docs/research/score-phase-bridge-preregistration-20261002.md"]
    result = metadata(sources)
    profiles = json.loads(profiles_path.read_text())["retained_geometry_count_screens"]
    count_cards = []
    for p in profiles:
        for components in (2, 3):
            card = extraction_count(p["n"], p["n"] * p["replies"], p["modeled_Q"].bit_length(), components)
            card.update(dataset=p["dataset"], profile=p["profile"],
                        extraction_domain="Every reply coefficient as a declared dense control, not the number of useful Hamming scores")
            count_cards.append(card)
    table = (1, 1, 1, 0)
    full = tuple(oracle.negacyclic_lookup(table, i) for i in range(8))
    assert full[:4] == tuple(int(h < 3) for h in range(4)) and full != tuple(int(h < 3) for h in range(8))
    for value in range(323):
        assert oracle.crt_value((value % 17, value % 19), (17, 19)) == value
        assert oracle.crt_value(((value + 1) % 17, value % 19), (17, 19)) != value
    result.update(kind="E85_known_phase_bridge_and_paid_selection_interface_screen",
                  exhaustive_extraction_cards=extraction_control(), bfv_scaled_switch_control=bfv_control(),
                  bgv_shortcut_counterexamples=bgv_controls(), exact_CRT_reconstructions=323,
                  canonical_one_limb_substitutions_change_phase=323,
                  negacyclic_threshold_control={"table": table, "full_domain_read": full,
                                                "full_domain_exact_threshold": False,
                                                "first_half_padded_domain_exact": True,
                                                "PBS_implemented": False},
                  fully_split_plaintext_count_cards=[split_count(p) for p in profiles],
                  retained_dense_coefficient_extraction_cards=count_cards,
                  separate_declared_8192_score_design_point=[extraction_count(16384, 8192, 64, c) for c in (2, 3)],
                  coverage_interface={"server_has_plaintext_witness": False,
                                      "linear_ciphertext_check_alone_binds_plaintext_winners": False,
                                      "fully_bound_integer_lookup_proof_implemented": False,
                                      "E84_extension_challenge_is_not_a_score_binding_proof": True},
                  decision="No shared new conversion/coverage step selected. Keep known BFV extraction baseline; stop both naive BGV rescaling adapters. A supported paid BGV carry/programmable-conversion relation is still required.",
                  scope="Finite homemade public arithmetic and deterministic count bounds only; no actual keyswitch/PBS, secure parameter set, encrypted top3, timing benchmark, remote release gate or novelty assurance.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out),
                      "ring_phases": sum(c["all_ring_coefficient_phases_checked"] for c in result["exhaustive_extraction_cards"]),
                      "BFV_switch_cases": result["bfv_scaled_switch_control"]["exact_roundtrip_cases"],
                      "split_cards": len(result["fully_split_plaintext_count_cards"]),
                      "known_controls_only": True}))


if __name__ == "__main__":
    main()
