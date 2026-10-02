#!/usr/bin/env python3
"""E82 exact secret/shared-mask laws and multi-coordinate PCF cost screen."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import secret_code_mask_oracle as oracle


def fraction(value):
    return {"numerator": value.numerator, "denominator": value.denominator, "decimal": float(value)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new immutable result path")
    files = [Path(__file__), ROOT / "experiments/bfv_search_lab/secret_code_mask_oracle.py",
             ROOT / "experiments/bfv_search_lab/test_secret_code_mask_oracle.py",
             ROOT / "benchmarks/results/publication-fixed-function-control-cards-20261002.json"]
    result = metadata(files)
    zero, other = (0, 0, 0), (1, 0, 0)
    privacy = []
    for offset in (False, True):
        for left_queries, right_queries, label in (
            ((zero,), (other,), "one_query"),
            ((zero, zero), (other, other), "unknown_constant_query"),
            ((zero, zero), (zero, other), "known_then_challenge"),
            ((zero,) * 3, (other,) * 3, "three_unknown_constant_queries"),
        ):
            left = oracle.secret_line_transcript_law(left_queries, 3, affine_offset=offset)
            right = oracle.secret_line_transcript_law(right_queries, 3, affine_offset=offset)
            privacy.append({"field": 3, "dimension": 3, "queries": len(left_queries),
                            "affine_offset": offset, "case": label,
                            "enumerated_source_samples_per_world": sum(left.values()),
                            "total_variation": fraction(oracle.total_variation(left, right))})
    support = []
    for bits, prime in ((2, 3), (3, 5), (4, 5), (5, 3), (6, 3)):
        actual = set(oracle.enumerate_minimal_supports(bits, prime))
        assert actual == set(oracle.predicted_minimal_supports(bits))
        support.append({"bits": bits, "field": prime, "all_source_codewords": prime ** (bits + 1),
                        "minimal_supports": len(actual), "formula_agrees": True})
    simulation = []
    for bits, prime in ((2, 3), (3, 5)):
        real, simulated = oracle.bitline_real_and_simulated_laws(bits, prime)
        assert real == simulated
        simulation.append({"bits": bits, "field": prime, "target_plus_extra_view_samples": sum(real.values()),
                           "independent_simulation_exact": True})
    counts = [oracle.bitline_counts(p) for p in (17, 193, 257, 1031, 1153, 65537)]
    assert all(c["sender_minimal_support_keys"] > c["ordinary_line_sender_keys"] for c in counts)
    result.update(kind="E82_finite_projection_and_distribution_screen", secret_line_distributions=privacy,
                  bitline_minimal_support_checks=support, bitline_recipient_simulation_checks=simulation,
                  field_key_count_cards=counts,
                  joint_rank_control={"projection": [[1, 0], [0, 1], [1, 1]], "field": 3,
                                      "joint_rank": 2, "output_coordinates": 3,
                                      "each_marginal_uniform": True, "joint_exact_syndrome": True},
                  decision="Stop specified shared/noiseless masks and bit-line PCF recipe. Multi-coordinate algebra simulates, but minimal-support work exceeds the ordinary line control. No family-wide impossibility.",
                  complete_token_adapter_implemented=False, direct_authenticated_backend_implemented=False,
                  scope="Homemade exhaustive tiny-field oracle and exact count screen only. No production pad, PCF/MAC/HE implementation, parameter assurance, runtime benchmark or security theorem.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "distribution_pairs": len(privacy),
                      "enumerated_codewords": sum(c["all_source_codewords"] for c in support),
                      "simulated_view_samples": sum(c["target_plus_extra_view_samples"] for c in simulation),
                      "key_counts": [(c["field"], c["sender_minimal_support_keys"]) for c in counts]}))


if __name__ == "__main__":
    main()
