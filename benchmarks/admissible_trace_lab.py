#!/usr/bin/env python3
"""E81 exhaustive bounded-alias correctness and exact search/control ledger."""

# ruff: noqa: E402 -- standalone research runner.

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from benchmarks.packed_query_expansion_lab import count_screen as packed_count
from experiments.bfv_search_lab import admissible_trace_oracle as admitted
from experiments.bfv_search_lab.test_admissible_trace_oracle import encrypted_case
from experiments.bfv_search_lab.test_supported_decoder import CASES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("New immutable output path required")
    prior = ROOT / "benchmarks/results/publication-structured-operator-screen-20260930.json"
    profiles = []
    for profile in json.loads(prior.read_text())["recorded_geometry_count_screens"]:
        paid = packed_count(profile, digit_bits=5)
        profiles.append({"dataset": profile["dataset"], "profile": profile["profile"],
                         "same_base_canonical_Q": paid["packed_correctness_model_Q"],
                         "same_base_canonical_key_body_bytes": paid["unseeded_public_evaluation_key_body_bytes"],
                         "same_base_canonical_query_reply_body_bytes": paid["full_public_online_body_upper_bound_bytes"],
                         "counts": admitted.count_delta(paid["n"], paid["columns"], paid["replies"], paid["packed_Q_bits"], paid["digit_bits"]),
                         "approved_or_measured_profile": False})
    paths = [Path(__file__), prior, ROOT / "docs/research/admissible-trace-preregistration-20261001.md",
             ROOT / "benchmarks/dictionary_layout_lab.py", ROOT / "benchmarks/packed_query_expansion_lab.py",
             ROOT / "benchmarks/encrypted_query_gate_lab.py", ROOT / "benchmarks/encrypted_query_certificate_lab.py",
             ROOT / "src/cuhepy/bfv/scheme.py", ROOT / "src/cuhepy/types.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "admissible_trace_oracle", "test_admissible_trace_oracle", "seed_composition_relation", "test_seed_composition_relation",
        "test_supported_decoder", "packed_query_expansion", "seed_affine_gate", "encrypted_query_gate", "encrypted_query_certificate",
        "trace_bgv", "reduction_oracles", "decryption_support", "owner_bgv", "seeded_bgv", "shallow_bgv", "crt_masked_bgv",
        "crt_query_space", "dyadic_crt", "score_layout", "verification_lifetime", "coefficient_body"))
    result = metadata(paths)
    cases = [encrypted_case(c) for c in CASES]
    result.update(kind="E81_global_bounded_noncanonical_BGV_trace_exactness_known_method_control",
                  exhaustive_scalar=admitted.exhaustive_scalar(), negative_controls=admitted.negative_controls(), cases=cases,
                  retained_equal_base_count_screens=profiles,
                  conditional_lemma="Globally shared boxed digits recomposing mod Q alter phase only by t times bounded key-error convolution; full public no-wrap induction preserves exact BGV decode.",
                  decision="Retain scoped exactness lemma/control. No measured proof bottleneck or novel complete mechanism established; strongest published relaxed ring/range methods are controls, and digit-box work remains. Return to selection review.",
                  scope="Homemade full trace recomputation with synthetic research keys, exact decoder checks after public relation, scalar exhaustive algebra and equal-base counts. No cryptographic proof/backend, universal proof review, approved parameters, adaptive/private-timing/durability assurance or original primitive claim. Independent per-limb digits and unbounded carries explicitly fail.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "scalar_cases": result["exhaustive_scalar"]["cases"],
                      "exact_canonical_searches": sum(c["canonical_queries"] for c in cases),
                      "exact_alternative_searches": sum(c["admitted_alternative_queries"] for c in cases),
                      "different_full_ciphertext_outputs": sum(c["alternative_full_outputs_differing_from_canonical"] for c in cases),
                      "retained_equal_base_profiles": len(profiles)}))


if __name__ == "__main__":
    main()
