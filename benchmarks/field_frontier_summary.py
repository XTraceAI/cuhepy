#!/usr/bin/env python3
"""Audit E34/E35 retained observations and export paired stages and cost models.

No new encrypted timings. This audits recorded data, not cryptographic proofs.
Pool-utilization and link break-even exports are serial accounting models.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
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


def frontier_row(dataset, seed, entry, profile):
    p = entry["profiles"][profile]
    cost = p["cost"]
    return {"dataset": dataset, "seed": seed, "candidate": entry["label"], "profile_model": profile,
            **{k: entry[k] for k in ("t", "n", "target", "F", "h", "W", "slots", "replies",
                                    "groups", "discovery_depth", "private_map_body_bytes")},
            "phase_bound_model": p["bound"], "minimum_analytic_q_bits_model": p["minimum_analytic_q_bits_model"],
            "implemented_api_minimum_q_bits": p["implemented_api_minimum_q_bits"], "q": p["q"], "rounds": p["rounds"],
            **{k: cost[k] for k in ("online_query_body_bytes", "online_response_body_bytes", "expanded_index_body_bytes",
                                   "offline_seeded_answer_body_bytes_per_token", "native_ntt_index_word_bytes",
                                   "checker_epoch_residue_body_bytes", "checker_epoch_seeded_body_bytes")},
            "scope": "Field/geometry models only; fixed_cbd requires its separate fixed-before-enrollment contract."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=ROOT / "benchmarks/results")
    parser.add_argument("--stamp", default="20260929")
    args = parser.parse_args()
    stages, utilization, comparisons, accepted, rejected = [], [], [], [], []
    artifacts, source_audits, commits, ideal_models = [], [], set(), None
    searches, coefficients, distinct_queries = 0, 0, set()
    for dataset in ("mushroom", "semeion"):
        for seed in (3001, 3002):
            path = args.results_dir / f"field_frontier_{dataset}_{seed}_{args.stamp}.json"
            report = json.loads(path.read_text())
            assert report["kind"] == "adaptive_masking_and_joint_field_frontier"
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
            if ideal_models is None:
                ideal_models = report["ideal_masks"]
            assert ideal_models == report["ideal_masks"]
            assert {m["mode"]: m["error_delta_independence_tv"] for m in ideal_models} == {
                "fresh": "0/1", "reuse": "11/16", "early_linear": "5/8", "select": "9/50"}
            result = report["result"]
            assert (result["dataset"], result["split_seed"]) == (dataset, seed)
            frontier = result["frontier"]
            for entry in frontier["rows"]:
                accepted.extend(frontier_row(dataset, seed, entry, p) for p in ("deterministic", "fixed_cbd"))
            for entry in frontier["rejected"]:
                rejected.append({"dataset": dataset, "seed": seed, "t": entry["t"],
                                 "target": entry.get("target", ""), "slots": entry.get("slots", ""),
                                 "stage": entry["stage"], "reason": entry["reason"]})
            selected = frontier["selected"]
            assert selected in frontier["rows"]
            eligible = [r for r in frontier["rows"] if r["label"].startswith("local_") and
                        r["profiles"]["deterministic"]["cost"]["expanded_index_body_bytes"] <= frontier["index_cap_bytes"]]
            def objective(r):
                cost = r["profiles"]["deterministic"]["cost"]
                return (cost["online_query_body_bytes"] + cost["online_response_body_bytes"],
                        cost["expanded_index_body_bytes"], r["private_map_body_bytes"], r["W"],
                        r["t"], r["target"], r["slots"])
            assert selected == min(eligible, key=objective)
            digests, query_path, summaries = {}, None, {}
            for case in result["cases"]:
                samples, model, setup = case["samples"], case["cost_model"], case["setup"]
                all_samples = (case["warmup"], *samples)
                pool_count = len(case["seeded_answer_packet_bytes"])
                assert pool_count == len(all_samples) == len(result["heldout_candidate_ids"]) // 2
                assert len(samples) == 8 and pool_count == 9
                assert case["queries_chosen_after_index_and_entire_answer_pool"]
                assert case["correctness_uses_absolute_phase_bound_not_fixed_cbd"]
                n, t, q, eta = case["n"], case["t"], int(case["q"]), case["eta"]
                assert n == 16384 and eta == 21 and t > result["dimension"]
                assert q % (2 * n) == 1 and q.bit_length() == model["q_bits"]
                assert q ** case["rounds"] >= 1024 * (1 << 128)
                assert q ** (case["rounds"] - 1) < 1024 * (1 << 128)
                bound = (t // 2 + t * eta) * (1 + model["correction_coefficients"] * (t // 2))
                assert bound == model["worst_case_phase_bound"] and 2 * bound < q
                this_path, previous = [], 0
                for i, sample in enumerate(all_samples):
                    qid = sample["query_id"]
                    assert qid == result["heldout_candidate_ids"][2 * i + (previous & 1)]
                    previous = sample["next_policy_authenticated_winner_id"]
                    this_path.append((qid, previous))
                    searches += 1
                    coefficients += n * model["replies"]
                    distinct_queries.add((dataset, qid))
                    assert sample["all_distances_and_stable_top3_exact"] and sample["all_gmp_native_coefficients_equal"]
                    assert sample["all_request_and_response_body_coefficients_roundtrip"]
                    assert digests.setdefault(qid, sample["score_digest"]) == sample["score_digest"]
                    phase = sample["phase"]
                    assert phase["all_integer_phase_coefficients_match_ciphertext"]
                    assert phase["maximum_unreduced_integer_phase"] <= phase["maximum_deterministic_response_bound"] <= bound
                    assert 2 * phase["maximum_deterministic_response_bound"] < q
                    assert sample["query_body_bytes"] == model["online_query_body_bytes"]
                    assert sample["response_coefficient_body_bytes"] == model["online_response_body_bytes"]
                    common = sum(sample[k] for k in ("owner_transform_and_request_s", "query_pack_s", "public_query_parse_s",
                                 "response_pack_s", "public_response_parse_s", "verification_s", "decrypt_s", "decode_select_s"))
                    for backend in ("native", "gmp"):
                        assert abs(sample[f"{backend}_local_online_s"] - common - sample[f"{backend}_server_s"]) < 1e-12
                if query_path is None:
                    query_path = this_path
                assert query_path == this_path
                setup_s = sum(v for k, v in setup.items() if k.endswith("_s") and k not in (
                    "integer_phase_audit_prepare_s", "offline_answer_pool_s", "offline_answer_check_pool_s"))
                pool_s = setup["offline_answer_pool_s"] + setup["offline_answer_check_pool_s"]
                row = {"dataset": dataset, "seed": seed, "layout": case["layout"], "rows": result["count"],
                       "dimension": result["dimension"], "t": t, "q_bits": model["q_bits"], "rounds": case["rounds"],
                       "F": model["coordinate_columns"], "h": model["query_coordinates"], "W": model["correction_coefficients"],
                       "query_body_bytes": model["online_query_body_bytes"], "response_body_bytes": model["online_response_body_bytes"],
                       "query_plus_response_body_bytes": model["online_query_body_bytes"] + model["online_response_body_bytes"],
                       "expanded_index_body_bytes_model": model["expanded_index_body_bytes"],
                       "seeded_index_packet_bytes": setup["seeded_index_packet_bytes"],
                       "seeded_answer_packet_bytes": case["seeded_answer_packet_bytes"][0],
                       "private_map_body_bytes": case["private_map_body_bytes"],
                       "owner_plaintext_coordinate_2bit_body_model": case["owner_plaintext_coordinate_2bit_body_model"],
                       "full_plaintext_cache_raw_body_bytes_control": result["full_plaintext_cache_control"]["raw_row_body_bytes"],
                       "full_plaintext_cache_zlib_body_bytes_control": result["full_plaintext_cache_control"]["zlib_row_body_bytes"],
                       "universal_absolute_phase_bound": bound,
                       "maximum_measured_unreduced_phase_with_warmup": max(s["phase"]["maximum_unreduced_integer_phase"] for s in all_samples),
                       "maximum_measured_phase_fraction_of_half_q_with_warmup": max(s["phase"]["phase_fraction_of_half_q"] for s in all_samples),
                       "recorded_standalone_setup_stage_sum_s_model": setup_s, "complete_pool_stage_sum_s": pool_s}
                row.update({f"median_{k}": median(samples, k) for k in (
                    "owner_transform_and_request_s", "query_pack_s", "public_query_parse_s", "gmp_server_s", "native_server_s",
                    "response_pack_s", "public_response_parse_s", "verification_s", "decrypt_s", "decode_select_s",
                    "native_local_online_s", "gmp_local_online_s", "full_plaintext_cache_s_control")})
                stages.append(row)
                summaries[case["layout"]] = row
                for used in (1, 4, pool_count):
                    utilization.append({"dataset": dataset, "seed": seed, "layout": case["layout"],
                                        "one_use_tokens_prepared": pool_count, "completed_queries": used, "utilization": used / pool_count,
                                        "serial_recorded_stage_work_s_model": setup_s + pool_s + used * row["median_native_local_online_s"],
                                        "index_token_packets_plus_online_bodies_bytes_model": setup["seeded_index_packet_bytes"]
                                        + sum(case["seeded_answer_packet_bytes"]) + used * row["query_plus_response_body_bytes"],
                                        "owner_private_mask_seed_bytes_model": 32 * pool_count,
                                        "stored_expanded_answer_bytes_model": model["stored_expanded_answer_bytes_per_token"] * pool_count,
                                        "scope": "All nine tokens charged; standalone stage model, no pipelining/network or adaptive extension measured."})
            old, new = summaries["baseline_t1153_q40"], summaries["selected_deterministic"]
            assert new["t"] == selected["t"]
            assert new["expanded_index_body_bytes_model"] == selected["profiles"]["deterministic"]["cost"]["expanded_index_body_bytes"]
            assert old["expanded_index_body_bytes_model"] == frontier["index_cap_bytes"]
            if frontier["controls"]["refit_matches_selected_layout_and_maps"]:
                assert "fixed_membership_refit" not in summaries
                refit = frontier["controls"]["refit"]
                assert all(refit[k] == selected[k] for k in ("t", "F", "h", "W", "slots", "replies", "private_map_body_bytes", "profiles"))
            saved = old["query_plus_response_body_bytes"] - new["query_plus_response_body_bytes"]
            extra = new["median_native_local_online_s"] - old["median_native_local_online_s"]
            comparisons.append({"dataset": dataset, "seed": seed, "selected": selected["label"],
                                "accepted_candidates": len(frontier["rows"]), "rejected_candidates": len(frontier["rejected"]),
                                "same_membership_refit_matches_selected": frontier["controls"]["refit_matches_selected_layout_and_maps"],
                                "legacy_root_limited_fit_succeeded": frontier["controls"]["legacy_root_limited_fit"]["succeeded"],
                                "query_plus_response_body_bytes_saved": saved,
                                "query_plus_response_body_reduction_fraction": saved / old["query_plus_response_body_bytes"],
                                "extra_checked_native_local_s": extra,
                                "serial_payload_only_link_break_even_megabits_s_model": 8 * saved / (1e6 * extra) if extra > 0 else ""})
    assert len(commits) == 1
    exports = {"stages": stages, "utilization": utilization, "comparisons": comparisons,
               "accepted_models": accepted, "rejected_models": rejected}
    for label, rows in exports.items():
        path = args.results_dir / f"field_frontier_{label}_{args.stamp}.csv"
        write_csv(path, rows)
        artifacts.append(path)
    artifacts.extend((Path(__file__), args.results_dir / "field_frontier_validation_pytest.txt",
                      args.results_dir / "field_frontier_validation.md"))
    manifest = {"benchmark_source_commits": sorted(commits), "source_audit_count": len(source_audits), "source_audits": source_audits,
                "exact_full_size_encrypted_searches": searches, "distinct_dataset_query_ids": len(distinct_queries),
                "unreduced_integer_phase_coefficients_checked": coefficients, "ideal_mask_model": ideal_models,
                "csv_rows": {k: len(v) for k, v in exports.items()},
                "artifact_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts},
                "scope": "Measured medians exclude one warmup per case, include body packing/parsing, and use absolute honest-circuit "
                         "correctness bounds. No fixed-CBD profile promoted to adaptive correctness. Finite field/geometry search and "
                         "utilization/link models are not globally optimal, elapsed/pipelined/network or security measurements. "
                         "Baseline recorded same-field preparation and selected full frontier search are standalone stage accounting. "
                         "Complete token pool paid even if unused. Ideal-mask TV is not HE distinguishing advantage. "
                         "Source/artifact auditing is reproducibility checking, not protocol/RLWE/side-channel review."}
    path = args.results_dir / f"field_frontier_manifest_{args.stamp}.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"manifest": str(path), "source_checks": len(source_audits), "searches": searches,
                      "distinct_dataset_query_ids": len(distinct_queries), "phase_coefficients": coefficients,
                      "csv_rows": manifest["csv_rows"]}))


if __name__ == "__main__":
    main()
