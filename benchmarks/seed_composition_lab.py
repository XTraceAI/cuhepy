#!/usr/bin/env python3
"""E78 exact composed trace and strong three-design cost/interface screen."""

# ruff: noqa: E402 -- standalone research runner.

from dataclasses import asdict
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from benchmarks.packed_query_expansion_lab import count_screen as packed_count
from experiments.bfv_search_lab import encrypted_query_gate as gate
from experiments.bfv_search_lab import seed_composition_relation as relation
from experiments.bfv_search_lab.test_seed_composition_relation import encrypted_case
from experiments.bfv_search_lab.test_supported_decoder import CASES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new immutable output path")
    prior = ROOT / "benchmarks/results/publication-structured-operator-screen-20260930.json"
    recorded = []
    for profile in json.loads(prior.read_text())["recorded_geometry_count_screens"]:
        old = packed_count(profile)
        rounds = gate.rounds_for(old["packed_correctness_model_Q"], 1024, 128)
        counted = relation.count_designs(old["n"], old["columns"], old["replies"], old["packed_Q_bits"], old["digit_bits"], rounds)
        recorded.append({"dataset": old["dataset"], "profile": old["profile"],
                         "packed_correctness_model_Q": old["packed_correctness_model_Q"],
                         "setup_evaluation_key_body_bytes": old["unseeded_public_evaluation_key_body_bytes"],
                         "full_model_not_approved_or_measured": True, "counts": counted})
    paths = [Path(__file__), prior, ROOT / "docs/research/seed-composition-preregistration-20261001.md",
             ROOT / "benchmarks/dictionary_layout_lab.py", ROOT / "benchmarks/packed_query_expansion_lab.py",
             ROOT / "benchmarks/encrypted_query_gate_lab.py", ROOT / "benchmarks/encrypted_query_certificate_lab.py",
             ROOT / "src/cuhepy/bfv/scheme.py", ROOT / "src/cuhepy/types.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "seed_composition_relation", "test_seed_composition_relation", "test_supported_decoder",
        "packed_query_expansion", "seed_affine_gate", "encrypted_query_gate", "encrypted_query_certificate",
        "trace_bgv", "reduction_oracles", "coefficient_body", "decryption_support", "owner_bgv",
        "seeded_bgv", "shallow_bgv", "crt_masked_bgv", "crt_query_space", "dyadic_crt", "score_layout", "verification_lifetime"))
    result = metadata(paths)
    cases = [encrypted_case(c) for c in CASES]
    result.update(kind="E78_composed_original_query_to_output_relation_no_proof_backend", cases=cases,
                  exact_queries=sum(c["exact_queries"] for c in cases),
                  representative_typed_DAG=[asdict(n) for n in relation.relation_dag(32, 4, 1, 32, 4)],
                  retained_geometry_count_screens=recorded,
                  decision="Retain exact original-input/canonical relation and affine circuit observations. Stop generic composed wrapper and transposed seed-gate state as originality/usefulness winners. Backend costs/private-beta interfaces are not free; no paper construction selected.",
                  scope="Independent homemade arithmetic full-trace oracle, costly public recomputation and design counts. No cryptographic PCS, proof bytes/timings, security reduction, parameter/private-timing assurance, measured deployment frontier or new generic fusion claim. A public seed certificate alone cannot supply private beta; strengthened controls share the same linear folding/batching.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "exact_queries": result["exact_queries"],
                      "canonical_switch_witnesses": sum(c["canonical_switch_witnesses_checked"] for c in cases),
                      "digit_coefficients_checked": sum(c["digit_coefficients_checked"] for c in cases),
                      "retained_profiles": len(recorded),
                      "retained_transposed_seed_state_ratio_range": [
                          min(c["counts"]["designs"][2]["transposed_seed_state_ratio_to_E77_expanded_fingerprints"] for c in recorded),
                          max(c["counts"]["designs"][2]["transposed_seed_state_ratio_to_E77_expanded_fingerprints"] for c in recorded)]}))


if __name__ == "__main__":
    main()
