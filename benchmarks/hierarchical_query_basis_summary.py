#!/usr/bin/env python3
"""Audit retained E31 results and export curves/lifetime models; no new timings.

Also export a prospective CBD tail-bound calculation, explicitly NOT a new
encryption profile. Its independence/lifetime assumptions need a separate
review and experiment before changing deterministic phase-bound metadata.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def write_csv(path, rows):
    with path.open("w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=ROOT / "benchmarks/results")
    parser.add_argument("--stamp", default="20260929")
    args = parser.parse_args()
    curves, lifetimes, tails, audits, artifacts = [], [], [], [], []
    total_searches = 0
    setup_keys = ("order_s", "fit_s", "allocation_s", "hierarchy_fit_s", "regroup_s", "coordinate_enroll_s",
                  "query_compile_s", "key_gen_s", "transposed_index_s", "native_prepare_s", "conditional_checker_prepare_s")
    for dataset in ("mushroom", "semeion"):
        for seed in (3001, 3002):
            path = args.results_dir / f"hierarchical_query_basis_{dataset}_{seed}_{args.stamp}.json"
            report = json.loads(path.read_text())
            artifacts.extend((path, path.with_suffix(".log")))
            for source, expected in report["source_sha256"].items():
                actual = hashlib.sha256((ROOT / source).read_bytes()).hexdigest()
                assert actual == expected, source
                tracked = not source.endswith(".so")
                if tracked:
                    blob = subprocess.check_output(["git", "show", f"{report['git_head']}:{source}"], cwd=ROOT)
                    assert hashlib.sha256(blob).hexdigest() == expected, (source, "commit")
                audits.append({"report": path.name, "source": source, "sha256": expected, "matched_commit": tracked})
            cases = report["encrypted_cases"]
            digests = {}
            for case in cases:
                assert case["all_distances_and_stable_top3_exact"] and case["all_gmp_native_ciphertext_coefficients_equal"]
                assert case["conditional_check_before_decryption"]
                owner = case["owner_state_model"]
                assert owner["epoch_body_total_bytes"] == sum(owner["epoch_body_components"].values())
                for sample in (case["warmup"], *case["samples"]):
                    total_searches += 1
                    qid, digest = sample["query_id"], sample["score_digest"]
                    assert digests.setdefault(qid, digest) == digest, (seed, case["layout"], qid)
                model = case["cost_model"]
                setup_s = sum(case["setup"].get(k, 0.0) for k in setup_keys)
                token_s = statistics.median(s["owner_answer_prepare_s"] + s["trusted_answer_fingerprint_s"]
                                            for s in case["offline_samples"])
                online_s = statistics.median(s["online_native_local_s"] for s in case["samples"])
                token_bytes = case["offline_samples"][0]["answer_seeded_packet_bytes"]
                online_bytes = model["online_query_body_bytes"] + model["online_response_body_bytes"]
                for queries in (1, 10, 1000):
                    for used_in_ten in (10, 5, 1):
                        prepared = (queries * 10 + used_in_ten - 1) // used_in_ten
                        lifetimes.append({"dataset": dataset, "seed": seed, "layout": case["layout"],
                                          "completed_queries": queries, "utilization": used_in_ten / 10,
                                          "prepared_tokens": prepared, "measured_setup_stage_sum_s": setup_s,
                                          "median_offline_work_per_token_s": token_s, "median_online_work_s": online_s,
                                          "modeled_serial_stage_work_s": setup_s + prepared * token_s + queries * online_s,
                                          "seeded_index_packet_bytes": case["setup"]["index_seeded_packet_bytes"],
                                          "offline_packet_plus_online_body_bytes_per_query": prepared * token_bytes / queries + online_bytes,
                                          "index_and_token_packets_plus_online_bodies_bytes": case["setup"]["index_seeded_packet_bytes"]
                                          + prepared * token_bytes + queries * online_bytes,
                                          "online_owner_epoch_body_bytes": owner["epoch_body_total_bytes"],
                                          "offline_owner_coordinate_u16_bytes": owner["offline_plaintext_coordinate_u16_body_bytes"]})
            info = report["curves"]
            records = [(name, r) for name, r in info["controls"].items()]
            records += [(f"depth{r['max_depth']}", r) for r in info["sharing_depth_curve"]]
            records += [(r["label"], r) for r in info["geometry_curve"]]
            for label, r in records:
                c = r["cost_model"]
                assert c["query_coordinates"] <= c["correction_coefficients"]
                curves.append({"dataset": dataset, "seed": seed, "layout": label, "F": c["coordinate_columns"],
                               "h": c["query_coordinates"], "W": c["correction_coefficients"], "q_bits": c["q_bits"],
                               "encrypted_index_body_bytes": c["expanded_index_body_bytes"],
                               "query_body_bytes": c["online_query_body_bytes"], "reply_body_bytes": c["online_response_body_bytes"],
                               "private_map_body_bytes": r["private_map_body_bytes"],
                               "checker_body_bytes": c["checker_epoch_seeded_body_bytes"],
                               "public_space_json_bytes": r["public_space_json_bytes"],
                               "maps_checker_geometry_body_bytes": r["maps_checker_geometry_body_bytes"],
                               "laminar_coordinate_count": r.get("laminar_coordinate_count", ""),
                               "fit_s": r.get("hierarchy_fit_s", ""), "regroup_s": r.get("regroup_s", "")})
                # Correctness-only PROJECTION: fixed or error-independent
                # corrections, independent CBD(eta) symmetric errors, one
                # index epoch with B requests. No changed parameter defaults.
                # ln(2*N*R*B/epsilon) < 0.7*(bit_length(2*N*R*B)+lambda).
                n, t, w, eta, budget, failure_bits = c["n"], c["t"], c["correction_coefficients"], 21, 1024, 128
                b = t // 2
                message = b * (1 + w * b)
                log2_upper = (2 * n * max(1, c["replies"]) * budget).bit_length() + failure_bits
                numerator = t * t * eta * (1 + w * b * b) * 7 * log2_upper
                tail = math.isqrt((numerator + 9) // 10)
                if 10 * tail * tail < numerator:
                    tail += 1
                q32 = 4294475777  # Full N=16384 prime used in E30/E31 q32 controls.
                assert n == 16384 and 10 * tail * tail >= numerator
                tails.append({"dataset": dataset, "seed": seed, "layout": label, "W": w,
                              "deterministic_current_phase_bound": c["worst_case_phase_bound"],
                              "message_carry_bound": message, "prospective_cbd_tail_bound": tail,
                              "prospective_total_bound": message + tail, "candidate_q32": q32,
                              "fits_q32_under_stated_independence_assumptions": 2 * (message + tail) < q32,
                              "failure_budget_bits_correctness_only": failure_bits, "epoch_query_budget": budget,
                              "profile_implemented": False})
    outputs = {"curves": curves, "lifetime": lifetimes, "prospective_noise": tails}
    for name, rows in outputs.items():
        path = args.results_dir / f"hierarchical_query_basis_{name}_{args.stamp}.csv"
        write_csv(path, rows)
        artifacts.append(path)
    artifacts.append(args.results_dir / "hierarchical_basis_validation_pytest.txt")
    artifacts.append(Path(__file__))
    manifest = {"benchmark_source_commit": sorted({json.loads(p.read_text())["git_head"] for p in artifacts if p.suffix == ".json"}),
                "source_audits": audits, "source_audit_count": len(audits), "exact_encrypted_searches": total_searches,
                "csv_rows": {k: len(v) for k, v in outputs.items()},
                "artifact_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts},
                "lifetime_scope": "Serial sum of recorded stages, not elapsed/pipelined latency. Omits uncaptured orchestration, selection sweeps, "
                                  "transport/authentication, provisioning and durable state. Includes unused tokens. No new timing samples.",
                "noise_projection_scope": "Unimplemented correctness hypothesis for independent CBD symmetric errors and error-independent "
                                          "correction vectors. Requires lifetime/mask/seed analysis and independent review; not RLWE security bits."}
    path = args.results_dir / f"hierarchical_basis_manifest_{args.stamp}.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"manifest": str(path), "source_checks": len(audits), "searches": total_searches,
                      "csv_rows": manifest["csv_rows"]}))


if __name__ == "__main__":
    main()
