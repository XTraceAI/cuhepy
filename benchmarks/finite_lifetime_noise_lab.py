#!/usr/bin/env python3
"""E102 restricted exact noise laws and paid counts, never HE timings."""

# ruff: noqa: E402 -- standalone research runner.

from argparse import ArgumentParser
from datetime import UTC, datetime
from fractions import Fraction
import hashlib
from itertools import product
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.bfv_search_lab import finite_lifetime_noise as lab
from experiments.bfv_search_lab.test_finite_lifetime_noise import (
    actual_api_cases, exact_distribution_cases, falsifiers, rotation_dependency, small_laws,
)


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=ROOT/"benchmarks/results/publication-finite-lifetime-noise-20261003.json")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Preserve prior raw outputs; choose a new path instead of overwriting")
    sources = [Path(__file__), ROOT/"experiments/bfv_search_lab/finite_lifetime_noise.py",
               ROOT/"experiments/bfv_search_lab/test_finite_lifetime_noise.py",
               ROOT/"docs/research/finite-lifetime-noise-preregistration.md",
               ROOT/"src/cuhepy/bfv/scheme.py",
               *(ROOT/f"experiments/bfv_search_lab/{name}.py" for name in
                 ("shallow_bgv", "trace_bgv", "seeded_bgv", "owner_bgv", "compact_bgv",
                  "committed_precision_epoch", "owner_bound_rounding", "gadget_dependency"))]
    metadata = {"utc": datetime.now(UTC).isoformat(), "command": sys.argv,
                "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "python": platform.python_version(), "platform": platform.platform(),
                "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}}
    small = small_laws()
    print("E102: complete N2 seeded laws finished", file=sys.stderr, flush=True)
    exact = exact_distribution_cases()
    print("E102: exact CBD/absolute-CBD laws finished", file=sys.stderr, flush=True)
    actual, rotation = actual_api_cases(), rotation_dependency()
    print("E102: synthetic actual-API score/rotation fixtures finished", file=sys.stderr, flush=True)
    cards = [lab.model_card(*geometry) for geometry in product((8, 32, 128), (1, 2, 3), (2, 4),
                                                              (2, 4), (1, 8, 64), (8, 16, 32),
                                                              ("seeded-owner", "public-key"))]
    assert len(cards) == 648
    improved_setup = [c for c in cards if c["complete_uniform_setup_phase"] < c["complete_E94_with_support_maintenance_phase"]]
    feasible = [c for c in cards if c["fixed_level_geometry_can_cover_required_Q"]]
    result = {"kind": "E102_restricted_finite_lifetime_noise_exact_and_count_screen",
              "scope": "secret degree two/one product, seeded owner and conditional public-key query; same-key relinearization/trace; no production changes",
              "metadata": metadata,
              "preregistered_components": {"theorem_dependency_components": 2, "finite_count_components": 1},
              "complete_small_ring_laws": small, "independent_exact_distribution_checks": exact,
              "synthetic_actual_API_score_cases": actual, "synthetic_rotation_dependency_slice": rotation,
              "freshness_and_setup_falsifiers": falsifiers(),
              "model_cards": cards,
              "summary": {"model_cards": len(cards), "standard_adapter_equal_cards": sum(c["known_adapter_identical"] for c in cards),
                          "setup_L1_smaller_than_full_support_cards": len(improved_setup),
                          "conditional_source_smaller_than_support_cards": sum(c["conditional_original_phase"] < c["original_phase_support"] for c in cards),
                          "fixed_radix_level_geometry_feasible_cards": len(feasible),
                          "raw_model_max_phase_ratio_against_E94_support_maintenance": str(max(Fraction(c["complete_E94_with_support_maintenance_phase"], c["complete_uniform_setup_phase"]) for c in cards)),
                          "model_correctness_gains_are_known_controls": True,
                          "same_coin_rotations_not_affine_fresh_setup_errors": True,
                          "candidate_status": "STOP_as_original_generic_control_containment",
                          "restricted_correctness_control_retained": True,
                          "new_original_mechanisms_accepted": 0,
                          "approved_parameters": 0, "security_reductions": 0,
                          "native_GPU_WAN_timing_panels": 0,
                          "complete_authenticated_resource_gate_passed": False},
              "unproved_or_uninstantiated": ["computational HE/key-cycle/sampler assurance", "honest setup/query entropy provenance",
                                             "compact whole-trace authenticated release", "durable attempt/epoch state",
                                             "actual changed-Q RNS/key generation and new enrollment",
                                             "terminal/PBS precision/proof resource consequence", "private-side constant time"],
              "public_input_binding_is_not_sampling_or_order_proof": True,
              "all_probabilities_exact_or_outward_integer_bounds": True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()
