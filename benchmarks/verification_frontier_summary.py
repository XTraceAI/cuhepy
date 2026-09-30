#!/usr/bin/env python3
"""Audit E36--E40 and export stage/body/contract models; no new HE timing."""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
import csv
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.bfv_search_lab import answer_summary_limits as limits
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import polynomial_fingerprint as polynomial
from experiments.bfv_search_lab import portfolio_costs as planning
from experiments.bfv_search_lab import schema_metric_oracles as schema


def csv_out(path, rows):
    with path.open("w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def med(samples, key):
    return statistics.median(sample[key] for sample in samples)


def audit_sources(report, path, source_audits):
    for name, expected in report["source_sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, name
        tracked = not name.endswith(".so")
        if tracked:
            blob = subprocess.check_output(["git", "show", f"{report['git_head']}:{name}"], cwd=ROOT)
            assert hashlib.sha256(blob).hexdigest() == expected, (name, "recorded commit")
        source_audits.append({"report": path.name, "source": name, "sha256": expected, "matched_commit": tracked})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=ROOT / "benchmarks/results")
    parser.add_argument("--stamp", default="20260930")
    args = parser.parse_args()
    stages, norms, scenarios, comparisons, gates, rings, ring_rejections = [], [], [], [], [], [], []
    sources, artifacts, commits = [], [], set()
    searches, phase_coefficients, query_ids, generator_coefficients = 0, 0, set(), 0
    for dataset in ("mushroom", "semeion"):
        for seed in (3001, 3002):
            path = args.results_dir / f"correction_image_{dataset}_{seed}_{args.stamp}.json"
            report = json.loads(path.read_text())
            assert report["kind"] == "uniform_correction_image_bounds"
            artifacts.extend((path, path.with_suffix(".log")))
            audit_sources(report, path, sources)
            for case in report["result"]["cases"]:
                analysis = case["analysis"]
                assert analysis["uniform_norm_lower"] <= analysis["uniform_norm_upper"] <= analysis["cube_norm_bound"]
                assert case["minimum_analytic_q_bits_from_upper_model"] <= case["minimum_analytic_q_bits_from_cube_model"]
                generator_coefficients += case["entire_generator_coefficients_compared"]
                norms.append({"dataset": dataset, "seed": seed, "t": case["t"], "F": case["F"], "h": case["h"], "W": case["W"],
                              "nonzero_forms": analysis["nonzero_forms"], "norm_lower": analysis["uniform_norm_lower"],
                              "norm_upper": analysis["uniform_norm_upper"], "cube_norm": analysis["cube_norm_bound"],
                              "upper_improvement_fraction": 1 - analysis["uniform_norm_upper"] / analysis["cube_norm_bound"],
                              "cube_minimum_q_bits_model": case["minimum_analytic_q_bits_from_cube_model"],
                              "image_minimum_q_bits_model": case["minimum_analytic_q_bits_from_upper_model"],
                              "q32_impossible_for_this_bounding_method": case["q32_impossible_for_this_norm_times_fresh_method"]})
            path = args.results_dir / f"verification_frontier_{dataset}_{seed}_{args.stamp}.json"
            report = json.loads(path.read_text())
            assert report["kind"] == "complete_verifier_lossless_precision_frontier"
            commits.add(report["git_head"])
            artifacts.extend((path, path.with_suffix(".log")))
            audit_sources(report, path, sources)
            result = report["result"]
            assert (result["dataset"], result["split_seed"]) == (dataset, seed)
            digests, shared_path, candidate_models, profile_rows = {}, None, [], {}
            for case in result["cases"]:
                samples, model = case["samples"], case["cost_model"]
                all_samples = (case["warmup"], *samples)
                assert len(samples) == 8 and len(all_samples) == len(case["seeded_answer_packet_bytes"]) == 9
                n, q, t, bits = case["n"], int(case["q"]), case["t"], case["q_bits"]
                assert n == 16384 and case["eta"] == 21 and q % (2 * n) == 1 and q.bit_length() == bits
                assert q ** case["rounds"] >= 1024 * (1 << 128) > q ** (case["rounds"] - 1)
                bound = (t // 2 + 21 * t) * (1 + model["correction_coefficients"] * (t // 2))
                assert model["worst_case_phase_bound"] == bound and 2 * bound < q
                degree = case["polynomial_degree"]
                probability = case["polynomial_collision_bound"]
                probability = Fraction(int(probability["numerator"]), int(probability["denominator"]))
                assert probability == polynomial.collision(q, degree, 2 * n * model["replies"], 1024)
                assert degree == polynomial.choose(q, 2 * n * model["replies"], budget=1024)
                assert probability <= Fraction(1, 1 << 128)
                this_path, previous = [], 0
                for i, sample in enumerate(all_samples):
                    qid = sample["query_id"]
                    assert qid == result["heldout_candidate_ids"][2 * i + (previous & 1)]
                    previous = sample["next_policy_authenticated_winner_id"]
                    this_path.append((qid, previous))
                    assert digests.setdefault(qid, sample["score_digest"]) == sample["score_digest"]
                    for flag in ("all_four_gates_accept_before_secret_decryption", "all_distances_and_stable_top3_exact",
                                 "all_gmp_native_coefficients_equal", "both_lossless_body_roundtrips_and_gmp_reference_equal",
                                 "both_native_hashes_and_gmp_references_equal"):
                        assert sample[flag]
                    phase = sample["phase"]
                    assert phase["all_integer_phase_coefficients_match_ciphertext"]
                    assert phase["maximum_unreduced_integer_phase"] <= phase["maximum_deterministic_response_bound"] <= bound
                    common = sum(sample[k] for k in ("owner_transform_and_request_s", "query_pack_s", "public_query_parse_s",
                                                     "native_server_s", "decrypt_s", "decode_select_s"))
                    for name, variant in sample["variants"].items():
                        assert abs(variant["local_online_s_stage_sum"] - common - sum(variant[k] for k in (
                            "verification_s", "response_pack_s", "response_parse_s"))) < 1e-12
                        transport = name.rsplit("_", 1)[1]
                        expected = 2 * n * model["replies"] * ((bits + 7) // 8) if transport == "byte" else (
                            2 * n * model["replies"] * bits + 7) // 8
                        assert variant["response_body_bytes"] == expected
                        assert variant["query_body_bytes"] == model["online_query_body_bytes"]
                    searches += 1
                    phase_coefficients += n * model["replies"]
                    query_ids.add((dataset, qid))
                if shared_path is None:
                    shared_path = this_path
                assert this_path == shared_path
                setup = case["setup"]
                shared_setup_s = sum(value for name, value in setup.items() if name.endswith("_s") and name not in (
                    "offline_answer_pool_s", "integer_phase_audit_prepare_s"))
                # Seeded index/T packet encodings already bit-pack c0 at exact Q bits.
                index_packet = setup["seeded_index_packet_bytes"]
                pool_packet = sum(case["seeded_answer_packet_bytes"])
                ids_model = result["count"] * 4
                profile_rows[case["layout"]] = {}
                for name in all_samples[0]["variants"]:
                    checker = name.rsplit("_", 1)[0]
                    variant_samples = [sample["variants"][name] for sample in samples]
                    state = case["private_check_fingerprint_coefficient_counts"][checker] * ((bits + 7) // 8)
                    key_bytes = case["private_check_key_body_model_bytes"][checker]
                    row = {"dataset": dataset, "seed": seed, "profile": case["layout"], "variant": name,
                           "rows": result["count"], "dimension": result["dimension"], "t": t, "q_bits": bits,
                           "rounds": case["rounds"], "polynomial_degree": degree,
                           "query_bytes": model["online_query_body_bytes"], "response_bytes": variant_samples[0]["response_body_bytes"],
                           "canonical_index_bytes_model": model["expanded_index_body_bytes"], "seeded_index_packet_bytes": index_packet,
                           "native_ntt_index_word_bytes_model": model["native_ntt_index_word_bytes"],
                           "seeded_answer_packet_bytes": case["seeded_answer_packet_bytes"][0],
                           "private_map_bytes": case["private_map_body_bytes"], "fingerprint_residue_bytes_model": state,
                           "check_key_bytes_model": key_bytes, "owner_coordinate_bytes_model": case["owner_plaintext_coordinate_2bit_body_model"],
                           "setup_s_stage_sum_model": shared_setup_s + case["gate_setup"][checker]["checker_prepare_s"],
                           "pool_s_stage_sum": setup["offline_answer_pool_s"] + case["gate_setup"][checker]["offline_answer_check_pool_s"],
                           "median_local_s_stage_sum": med(variant_samples, "local_online_s_stage_sum"),
                           "median_verify_s": med(variant_samples, "verification_s"), "median_pack_s": med(variant_samples, "response_pack_s"),
                           "median_parse_s": med(variant_samples, "response_parse_s"),
                           "median_native_server_s": med(samples, "native_server_s"), "median_gmp_server_s": med(samples, "gmp_server_s"),
                           "median_owner_request_s": med(samples, "owner_transform_and_request_s"), "median_decrypt_s": med(samples, "decrypt_s"),
                           "median_decode_select_s": med(samples, "decode_select_s"), "median_plaintext_cache_s_control": med(samples, "full_plaintext_cache_s_control")}
                    # Canonical BODY model only, not Python/native resident memory:
                    # maps, stable IDs, epoch fingerprints/key, 9 pending seeds and tags.
                    check_coordinates = degree if checker.startswith("polynomial") else case["rounds"]
                    private = case["private_map_body_bytes"] + ids_model + state + key_bytes + 9 * (32 + check_coordinates * ((bits + 7) // 8))
                    row["canonical_client_body_bytes_model"] = private
                    stages.append(row)
                    profile_rows[case["layout"]][name] = row
                    candidate_models.append(planning.Candidate(case["layout"] + "/" + name, row["median_local_s_stage_sum"],
                        row["query_bytes"], row["response_bytes"], index_packet, row["setup_s_stage_sum_model"],
                        row["pool_s_stage_sum"], pool_packet, 9, private, row["owner_coordinate_bytes_model"]))
                gates.append({"dataset": dataset, "seed": seed, "profile": case["layout"], "q": str(q), "rounds": case["rounds"],
                              "polynomial_degree": degree, "polynomial_collision_numerator": str(probability.numerator),
                              "polynomial_collision_denominator": str(probability.denominator)})
            for profile, rows in profile_rows.items():
                original, native_control, alternative = (rows[k] for k in ("vector_gmp_byte", "vector_native_bit", "polynomial_native_bit"))
                comparisons.append({"dataset": dataset, "seed": seed, "profile": profile,
                                    "native_complete_check_speedup": original["median_verify_s"] / native_control["median_verify_s"],
                                    "polynomial_speedup_over_native_control": native_control["median_verify_s"] / alternative["median_verify_s"],
                                    "local_native_control_speedup": original["median_local_s_stage_sum"] / native_control["median_local_s_stage_sum"],
                                    "local_polynomial_speedup": original["median_local_s_stage_sum"] / alternative["median_local_s_stage_sum"],
                                    "byte_to_bit_body_reduction": 1 - native_control["response_bytes"] / original["response_bytes"]})
            contract = planning.Contract(allow_unreviewed_research=True)
            candidates = tuple(candidate_models)
            for completed in (1, 4, 9):
                for link in (1, 10, 100, 1000):
                    for objective in ("online_serial_s_model", "amortized_serial_s_model"):
                        selected, cost = planning.choose(candidates, contract, completed=completed, upload_mbps=link,
                                                        download_mbps=link, rtt_ms=40, objective=objective)
                        scenarios.append({"dataset": dataset, "seed": seed, "completed": completed, "link_mbps": link,
                                          "objective": objective, "selected": selected.name, **cost,
                                          "scope": "Recorded-stage/body serial model, nine-token limit, all unused tokens paid; no wire/network/throughput prediction."})
            assert all(planning.rejection(c, planning.Contract()) for c in candidates)
    assert len(commits) == 1
    path = args.results_dir / f"ring_capacity_frontier_{args.stamp}.json"
    ring_report = json.loads(path.read_text())
    assert ring_report["kind"] == "fixed_map_ring_capacity_models"
    artifacts.extend((path, path.with_suffix(".log")))
    audit_sources(ring_report, path, sources)
    for result in ring_report["results"]:
        for entry in result["accepted_models"]:
            assert entry["response_body_bytes_model"] == 8 * entry["n"] * entry["replies"]
            assert entry["allocated_reply_coefficients"] == entry["n"] * entry["replies"] >= result["count"]
            assert entry["encrypted_index_body_bytes_model"] == entry["F"] * entry["response_body_bytes_model"]
            assert 2 * entry["honest_phase_bound_model"] < int(entry["q"])
            assert entry["requires_new_parameter_assurance"] == (entry["n"] != 16384)
            rings.append({"dataset": result["dataset"], "seed": result["seed"], "count": result["count"], **entry})
        ring_rejections.extend({"dataset": result["dataset"], "seed": result["seed"], **entry}
                               for entry in result["rejected_models"])
    widths = tuple(map(len, fixtures.MUSHROOM_CATEGORIES))
    oracles = {"schema_small": schema.exhaustive((5, 5), 5), "schema_mushroom": schema.frontier(widths, slots=32),
               "answer_summary_limits": limits.describe(),
               "native_polynomial_batch_degree": {str(count): polynomial.choose(4294475777, count * 32768, budget=1024)
                                                  for count in (1, 2, 16, 256)}}
    path = args.results_dir / f"verification_frontier_oracles_{args.stamp}.json"
    path.write_text(json.dumps(oracles, indent=2) + "\n")
    artifacts.append(path)
    for label, rows in (("stages", stages), ("norms", norms), ("comparisons", comparisons), ("scenarios", scenarios),
                        ("gates", gates), ("ring_models", rings), ("ring_rejections", ring_rejections)):
        path = args.results_dir / f"verification_frontier_{label}_{args.stamp}.csv"
        csv_out(path, rows)
        artifacts.append(path)
    for name in ("verification_frontier_validation_pytest_20260930.txt", "verification_fingerprint_asan_20260930.txt",
                 "verification_fingerprint_ubsan_20260930.txt", "verification_frontier_validation_20260930.md",
                 "verification_frontier_plot_environment_20260930.txt", "verification_frontier_figures_20260930.json"):
        artifacts.append(args.results_dir / name)
    artifacts.extend((Path(__file__), ROOT / "benchmarks/verification_frontier_plot.py"))
    artifacts.extend(ROOT / name for name in (
        "docs/research/verification-frontier-results.md", "docs/research/research-synthesis-and-system-roadmap.md",
        "docs/research/creative-experiment-priorities.md", "docs/research/encrypted-search-literature-agenda.md",
        "experiments/bfv_search_lab/README.md"))
    artifacts.extend(sorted((ROOT / "docs/research/figures").glob("verification-frontier-*-20260930.*")))
    manifest = {"benchmark_source_commits": sorted(commits), "source_audit_count": len(sources), "source_audits": sources,
                "exact_full_size_encrypted_searches": searches, "distinct_dataset_query_ids": len(query_ids),
                "unreduced_integer_phase_coefficients_checked": phase_coefficients,
                "entire_correction_generator_coefficients_compared": generator_coefficients,
                "oracle_source_sha256": {str((ROOT / f"experiments/bfv_search_lab/{name}.py").relative_to(ROOT)):
                                        hashlib.sha256((ROOT / f"experiments/bfv_search_lab/{name}.py").read_bytes()).hexdigest()
                                        for name in ("answer_summary_limits", "schema_metric_oracles", "portfolio_costs", "test_answer_summary_limits",
                                                     "test_schema_metric_oracles", "test_portfolio_costs")},
                "ring_model_source_commit": ring_report["git_head"],
                "csv_rows": {"stages": len(stages), "norms": len(norms), "comparisons": len(comparisons),
                             "scenarios": len(scenarios), "gates": len(gates), "ring_models": len(rings),
                             "ring_rejections": len(ring_rejections)},
                "artifact_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts},
                "scope": "Local exactness/source audit and conditional known fingerprint families, not novelty, whole HE privacy, "
                         "parameter assurance or private timing. Medians exclude warmup; totals are paired shared-stage sums. "
                         "Link and utilization choices are serial models with canonical bodies and incomplete deployment setup. "
                         "Below-32-bit norm/schema results are models. All production-ineligible candidates fail the planner's default contract."}
    path = args.results_dir / f"verification_frontier_manifest_{args.stamp}.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({k: manifest[k] for k in ("source_audit_count", "exact_full_size_encrypted_searches", "csv_rows")}))


if __name__ == "__main__":
    main()
