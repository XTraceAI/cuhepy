#!/usr/bin/env python3
"""Audit E32 observations and export stage/body/unused-batch models.

No new encrypted timings. Scheduling stays fixed: utilization models use a
subset of the SAME nine predeclared requests, never append adaptive requests.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from math import isqrt
from pathlib import Path
import statistics
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def write_csv(path, rows):
    with path.open("w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def median(samples, key):
    return statistics.median(s[key] for s in samples)


def audit_certificate(case):
    """Independent exact inequality check of the universal bound in the JSON."""
    model, profile = case["cost_model"], case["fixed_profile"]
    n, t, w, eta = case["n"], case["t"], model["correction_coefficients"], case["eta"]
    b = t // 2
    exponent = (2 * n * max(1, model["replies"]) * profile["query_budget"]).bit_length() + profile["correctness_bits"]
    numerator = t * t * eta * (1 + w * b * b) * 7 * exponent
    tail = isqrt(numerator // 10)
    tail += int(10 * tail * tail < numerator)
    assert profile["squared_weight_norm"] == w * b * b
    assert profile["message_bound"] == b * (1 + w * b)
    assert profile["tail_bound"] == tail
    assert profile["total"] == profile["message_bound"] + tail
    assert 2 * profile["total"] < int(case["q"])
    assert case["queries_and_corrections_fixed_before_enrollment"]
    # A check on the model's scope, not a mathematical proof of independence.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=ROOT / "benchmarks/results")
    parser.add_argument("--stamp", default="20260929")
    args = parser.parse_args()
    rows, lifetimes, comparisons, source_audits, artifacts, commits = [], [], [], [], [], set()
    searches, coefficient_checks, unique_queries = 0, 0, set()
    for dataset in ("mushroom", "semeion"):
        for seed in (3001, 3002):
            path = args.results_dir / f"fixed_batch_noise_{dataset}_{seed}_{args.stamp}.json"
            report = json.loads(path.read_text())
            commits.add(report["git_head"])
            artifacts.extend((path, path.with_suffix(".log")))
            for source, expected in report["source_sha256"].items():
                assert hashlib.sha256((ROOT / source).read_bytes()).hexdigest() == expected, source
                tracked = not source.endswith(".so")
                if tracked:
                    blob = subprocess.check_output(["git", "show", f"{report['git_head']}:{source}"], cwd=ROOT)
                    assert hashlib.sha256(blob).hexdigest() == expected, (source, "recorded commit")
                source_audits.append({"report": path.name, "source": source, "sha256": expected,
                                      "matched_commit": tracked})
            result = report["result"]
            digests, summaries = {}, {}
            for case in result["cases"]:
                audit_certificate(case)
                samples, model, setup = case["samples"], case["cost_model"], case["setup"]
                all_samples = (case["warmup"], *samples)
                assert len(all_samples) == case["fixed_request_count"] == len(result["query_ids_with_warmup"])
                assert tuple(s["query_id"] for s in all_samples) == tuple(result["query_ids_with_warmup"])
                for sample in all_samples:
                    searches += 1
                    coefficient_checks += case["n"] * model["replies"]
                    unique_queries.add((dataset, sample["query_id"]))
                    assert sample["all_distances_and_stable_top3_exact"] and sample["all_gmp_native_coefficients_equal"]
                    qid, digest = sample["query_id"], sample["score_digest"]
                    assert digests.setdefault(qid, digest) == digest, (dataset, seed, qid)
                    phase = sample["phase"]
                    assert phase["all_integer_phase_coefficients_match_ciphertext"]
                    assert phase["statistical_certificate_total"] == phase["message_carry_bound"] + phase["cbd_tail_bound"]
                    assert phase["maximum_unreduced_integer_phase"] <= phase["statistical_certificate_total"]
                    assert 2 * phase["statistical_certificate_total"] < int(case["q"])
                    assert sample["response_coefficient_body_bytes"] == model["online_response_body_bytes"]
                    assert sample["query_body_bytes"] == model["online_query_body_bytes"]
                # All stages except explicitly separate diagnostic work and
                # token-pool work; the latter is charged once for the full pool.
                setup_s = sum(v for k, v in setup.items() if k.endswith("_s")
                              and k not in ("integer_phase_oracle_prepare_s", "offline_answer_pool_s", "offline_answer_check_pool_s"))
                pool_s = setup["offline_answer_pool_s"] + setup["offline_answer_check_pool_s"]
                online_s = median(samples, "native_local_online_s")
                response = model["online_response_body_bytes"]
                certificate_bytes = case["additional_statistical_certificate_body_bytes"]
                online_body = model["online_query_body_bytes"] + response + certificate_bytes
                row = {"dataset": dataset, "seed": seed, "layout": case["layout"], "rows": result["count"],
                       "dimension": result["dimension"], "F": model["coordinate_columns"], "h": model["query_coordinates"],
                       "W": model["correction_coefficients"], "q_bits": model["q_bits"], "checker_rounds": case["rounds"],
                       "query_body_bytes": model["online_query_body_bytes"], "response_body_bytes": response,
                       "additional_certificate_body_bytes_model": certificate_bytes, "online_body_bytes_model": online_body,
                       "expanded_index_body_bytes_model": model["expanded_index_body_bytes"],
                       "seeded_index_packet_bytes": setup["seeded_index_packet_bytes"],
                       "seeded_answer_packet_bytes": case["seeded_answer_packet_bytes"][0],
                       "fixed_schedule_body_bytes_model": setup["fixed_batch_construct_body_bytes"],
                       "fixed_request_count": case["fixed_request_count"],
                       "universal_correctness_certificate": case["fixed_profile"]["total"],
                       "maximum_measured_unreduced_phase_with_warmup": max(s["phase"]["maximum_unreduced_integer_phase"] for s in all_samples),
                       "maximum_measured_phase_fraction_of_half_q_with_warmup": max(s["phase"]["phase_margin_fraction_of_half_q"] for s in all_samples),
                       "measured_setup_stage_sum_s": setup_s, "measured_complete_pool_stage_sum_s": pool_s}
                row.update({f"median_{k}": median(samples, k) for k in (
                    "gmp_server_s", "native_server_s", "verification_s", "decrypt_s", "decode_select_s",
                    "response_pack_s", "native_local_online_s", "gmp_local_online_s")})
                rows.append(row)
                summaries[case["layout"]] = row
                for used in (1, 4, case["fixed_request_count"]):
                    lifetimes.append({"dataset": dataset, "seed": seed, "layout": case["layout"],
                                      "fixed_requests_prepared": case["fixed_request_count"], "completed_queries": used,
                                      "utilization": used / case["fixed_request_count"],
                                      "modeled_serial_recorded_stage_work_s": setup_s + pool_s + used * online_s,
                                      "modeled_index_token_packets_plus_online_body_bytes": setup["seeded_index_packet_bytes"]
                                      + sum(case["seeded_answer_packet_bytes"]) + used * online_body,
                                      "fixed_schedule_body_bytes_model": setup["fixed_batch_construct_body_bytes"]})
            old, new = summaries["deterministic_q40"], summaries["fixed_cbd_q32"]
            saved_bytes = old["online_body_bytes_model"] - new["online_body_bytes_model"]
            extra_s = new["median_native_local_online_s"] - old["median_native_local_online_s"]
            comparisons.append({"dataset": dataset, "seed": seed,
                                "online_body_bytes_saved_with_certificate_model": saved_bytes,
                                "online_body_reduction_fraction_with_certificate_model": saved_bytes / old["online_body_bytes_model"],
                                "extra_checked_native_local_s": extra_s,
                                "serial_payload_only_link_break_even_megabits_s_model": 8 * saved_bytes / (1e6 * extra_s) if extra_s > 0 else ""})
    exports = {"stages": rows, "utilization": lifetimes, "comparisons": comparisons}
    for name, entries in exports.items():
        path = args.results_dir / f"fixed_batch_noise_{name}_{args.stamp}.csv"
        write_csv(path, entries)
        artifacts.append(path)
    artifacts.extend((Path(__file__), args.results_dir / "fixed_cbd_validation_pytest.txt"))
    manifest = {"benchmark_source_commits": sorted(commits), "source_audit_count": len(source_audits),
                "source_audits": source_audits, "exact_full_size_encrypted_searches": searches,
                "distinct_dataset_query_ids": len(unique_queries), "unreduced_integer_phase_coefficients_checked": coefficient_checks,
                "csv_rows": {k: len(v) for k, v in exports.items()},
                "artifact_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts},
                "model_scope": "Measured medians exclude one warmup per case. Stage/body models are not network, "
                               "elapsed, pipelined or security measurements. A complete fixed pool is charged even if unused. "
                               "No query extension; certificate bodies are modeled, not a new wire parser. "
                               "No RLWE security or adaptive-correctness assurance; integer-phase audits are diagnostics outside online timing."}
    path = args.results_dir / f"fixed_batch_noise_manifest_{args.stamp}.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"manifest": str(path), "source_checks": len(source_audits), "searches": searches,
                      "distinct_dataset_query_ids": len(unique_queries), "phase_coefficients": coefficient_checks,
                      "csv_rows": manifest["csv_rows"]}))


if __name__ == "__main__":
    main()
