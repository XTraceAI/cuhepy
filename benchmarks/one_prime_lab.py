#!/usr/bin/env python3
"""E113 exact arithmetic/count screen; no timing, GPU or parameter estimator."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from experiments.bfv_search_lab.one_prime_bounds import Profile, byte_card, greatest_drop  # noqa: E402
from experiments.bfv_search_lab.one_prime_oracle import evaluate_fixture, make_fixture  # noqa: E402

WORK = REPO.parent / "research-data/one-prime-20261003"
RAW = REPO / "benchmarks/results/publication-one-prime-20261003.json"
SOURCE_PATHS = [
    "docs/research/one-prime-preregistration.md",
    "experiments/bfv_search_lab/one_prime_bounds.py",
    "experiments/bfv_search_lab/one_prime_oracle.py",
    "experiments/bfv_search_lab/test_one_prime_bounds.py", "benchmarks/one_prime_lab.py",
    "experiments/bfv_search_lab/shallow_bgv.py", "experiments/bfv_search_lab/seeded_bgv.py",
    "experiments/bfv_search_lab/owner_bgv.py", "experiments/bfv_search_lab/compressed_query_bgv.py",
    "experiments/bfv_search_lab/trace_bgv.py", "experiments/bfv_search_lab/butterfly_bgv.py",
    "experiments/bfv_search_lab/support_bounds_bgv.py", "experiments/bfv_search_lab/compact_bgv.py",
    "experiments/bfv_search_lab/native_bgv.py", "src/cuhepy/bfv/scheme.py",
    "src/cuhepy/bfv/_cpu_ext/rns_ntt.h", "experiments/bfv_search_lab/_native/residue_trace.h",
    "experiments/bfv_search_lab/_native/bindings.cpp",
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    receipt = json.loads((WORK / "preregistration-receipt.json").read_text())
    if sha(REPO / SOURCE_PATHS[0]) != receipt["sha256"]:
        raise ValueError("Frozen preregistration changed")
    fixture_path = WORK / "frozen-tiny-fixture.json"
    if not fixture_path.exists():
        fixture = make_fixture()
        fixture["utc_before_main"] = datetime.now(UTC).isoformat()
        fixture["preregistration_sha256"] = receipt["sha256"]
        fixture_path.write_text(json.dumps(fixture, indent=2)+"\n")
    fixture = json.loads(fixture_path.read_text())
    if fixture["preregistration_sha256"] != receipt["sha256"]:
        raise ValueError("Wrong frozen tiny fixture")
    results = []
    for n in (8192, 16384, 32768):
        for count in (8192, 32768):
            for bits in (10, 12, 15, 18, 19, 30):
                profile = Profile(n, 512, count, digit_bits=bits)
                item = {"profile": asdict(profile)}
                for name, mode, relaxed in (("canonical_owner", "owner", False),
                                            ("relaxed_owner", "owner", True),
                                            ("canonical_public_index", "public", False),
                                            ("relaxed_public_index", "public", True)):
                    result = greatest_drop(profile, index_mode=mode, relaxed=relaxed)
                    selected = result["greatest_feasible"]
                    if selected:
                        result["selected_byte_card"] = byte_card(profile, selected)
                    item[name] = result
                results.append(item)
    tiny = evaluate_fixture(fixture)
    tiny["byte_card"] = byte_card(Profile(**tiny["profile"]), tiny["bound"])
    if any(x["full_packet_bytes"] != tiny["byte_card"]["response_complete_compact_v1_packet_bytes"]
           for x in tiny["observations"]):
        raise AssertionError("Independent packet byte ledger mismatched actual API")
    summary = {"large_profiles": len(results),
               "frozen_drop_tests_per_relation": 60,
               "relations_per_profile": 4,
               "owner_canonical_drop0_pass_profiles": sum(x["canonical_owner"]["baseline_drop0"]["owner_bound_feasible"] for x in results),
               "owner_relaxed_drop0_pass_profiles": sum(x["relaxed_owner"]["baseline_drop0"]["owner_bound_feasible"] for x in results),
               "public_index_drop0_pass_profiles": sum(x["canonical_public_index"]["baseline_drop0"]["owner_bound_feasible"] for x in results),
               "large_general_keygen_guard_pass_profiles": sum(x["canonical_owner"]["baseline_drop0"]["general_keygen_guard_admitted"] for x in results),
               "factor2_pass_profiles": sum(x["canonical_owner"]["baseline_drop0"]["factor2_verified"] for x in results),
               "actual_tiny_observations": tiny["observation_count"],
               "candidate_control_count_ratio": 1,
               "outcome": "known_owner_only_mathematical_feasibility; current_large_general_keygen_API_blocks; no_originality_pass"}
    output = {"kind": "E113_bounded_complete_one_prime_integer_feasibility_and_actual_tiny_differential",
              "utc": datetime.now(UTC).isoformat(),
              "evidence_parent": "8fdc431aa480634cd26bee8e3f73a53ef41b6d4c",
              "current_repo_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
              "preregistration_sha256": receipt["sha256"],
              "fixture_path": str(fixture_path), "fixture_sha256": sha(fixture_path),
              "source_sha256": {str(path): sha(REPO/path) for path in SOURCE_PATHS},
              "python": sys.version, "summary": summary, "large_count_panel": results,
              "tiny_existing_API_differential": tiny,
              "scope": {"timing_measured": False, "GPU_executed": False, "native_kernel_executed": False,
                        "large_key_generated": False, "guard_modified": False, "proof_executed": False,
                        "parameter_or_security_approval": False,
                        "bounds_uniform_over_admitted_owner_errors_and_common_bounded_digits": True,
                        "range_or_authentication_protocol_implemented": False,
                        "complete_proof_and_peak_memory_costs": "unknown; explicit byte-card exclusions",
                        "nonpositional_IDs": "owner-local mapped finish; no remote ID protocol claim"},
              "development_failures": ["system python lacked gmpy2 before public arithmetic; switched to repo venv",
                                       "first scoped test run: boundary example too smallQ and mpz/plain-int diagnostic shape; corrected local fixture/oracle types; no production code changed",
                                       "peer review: public prime64 diagnostic rejected genuine small primes dividing a Miller-Rabin base; skip zero bases and add independent trial-division regressions; selected60-bit primes and frozen scientific results unchanged"]}
    RAW.parent.mkdir(parents=True, exist_ok=True)
    RAW.write_text(json.dumps(output, indent=2)+"\n")
    print(json.dumps(summary, indent=2))
    print("raw", RAW, "sha256", sha(RAW))
    print("fixture", fixture_path, "sha256", sha(fixture_path))


if __name__ == "__main__":
    main()
