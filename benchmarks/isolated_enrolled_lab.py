#!/usr/bin/env python3
"""E79 matched three-process bootstrap/RPC/cache evaluation, pilot or final.

Loopback/application/resource measurements only, no approved HE deployment,
WAN inference, update frontier, p95 or new cryptographic construction.
"""

# ruff: noqa: E402 -- standalone research runner.

import argparse
import json
import math
from pathlib import Path
import random
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import isolated_enrolled as isolated

MODES = {"he": ("he", None, None), "snapshot_raw_raw": ("cache", None, "raw"),
         "snapshot_zlib1_raw": ("cache", 1, "raw"), "snapshot_zlib9_raw": ("cache", 9, "raw"),
         "snapshot_zlib1_compressed": ("cache", 1, "compressed"), "snapshot_zlib9_compressed": ("cache", 9, "compressed")}


def interval(values):
    rng = random.Random(79001)
    means = sorted(statistics.mean(rng.choices(values, k=len(values))) for _ in range(4000))
    return {"process_repetitions": len(values), "mean": statistics.mean(values), "median": statistics.median(values),
            "min": min(values), "max": max(values), "process_cluster_bootstrap_mean_95_interval": [means[100], means[3899]],
            "small_sample_interval_provisional": len(values) < 20}


def summarize(trials):
    groups = {}
    for trial in trials:
        key = (trial["job"]["dataset"], trial["job"]["mode_label"])
        groups.setdefault(key, []).append(trial)
    result = []
    for (dataset, mode), rows in groups.items():
        values = {"returning_query_wall_s": [], "returning_client_query_cpu_s": [],
                  "new_client_bootstrap_acquisition_first_query_s": [], "owner_setup_wall_s": [],
                  "owner_setup_cpu_s": [], "cold_controller_wall_including_startup_s": [],
                  "owner_peak_RSS_bytes": [], "client_peak_RSS_bytes": [], "server_peak_RSS_bytes": [],
                  "private_envelope_bytes": [], "returning_query_application_bytes": [],
                  "retained_owner_raw_query_wall_s": [], "server_query_CPU_s": []}
        for trial in rows:
            owner, client, server = trial["owner"], trial["client"], trial["server"]
            values["returning_query_wall_s"].append(statistics.mean(s["query_wall_s"] for s in client["samples"][1:]))
            values["returning_client_query_cpu_s"].append(statistics.mean(s["client_query_cpu_s"] for s in client["samples"][1:]))
            values["new_client_bootstrap_acquisition_first_query_s"].append(client["first_query_after_bootstrap_wall_s"])
            values["owner_setup_wall_s"].append(owner["owner_setup_wall_s"])
            values["owner_setup_cpu_s"].append(owner["owner_setup_cpu_s"])
            values["cold_controller_wall_including_startup_s"].append(trial["controller_wall_including_process_startup_s"])
            for role, object_ in (("owner", owner), ("client", client), ("server", server)):
                values[role + "_peak_RSS_bytes"].append(object_["final"]["process_peak_RSS_bytes"])
            values["private_envelope_bytes"].append(owner["private_envelope_bytes"])
            values["returning_query_application_bytes"].append(statistics.mean(s["application_bytes"] for s in client["samples"][1:]))
            values["retained_owner_raw_query_wall_s"].append(statistics.mean(s["wall_s"] for s in owner["retained_owner_raw_samples"][1:]))
            calls = [c for c in server["calls"] if c["role"] == "client" and c["command"] == "Q"]
            values["server_query_CPU_s"].append(statistics.mean(c["process_cpu_s"] for c in calls[1:] or calls))
        result.append({"dataset": dataset, "mode": mode, "queries_per_process": len(rows[0]["client"]["samples"]),
                       "metrics": {k: interval(v) for k, v in values.items()},
                       "all_private_state_actual_and_all_scores_IDs_top3_exact": True})
    return result


def pilot_requirement(pilot):
    recommendations = []
    for group in pilot["summary"]:
        # Derive from the raw independent process means, not within-process
        # query observations treated as independent process samples.
        values = [statistics.mean(s["query_wall_s"] for s in row["client"]["samples"][1:])
                  for row in pilot["trials"] if (row["job"]["dataset"], row["job"]["mode_label"]) == (group["dataset"], group["mode"])]
        cv = statistics.stdev(values) / statistics.mean(values) if len(values) > 1 else 0
        requested = max(5, math.ceil((1.96 * cv / .10)**2))
        recommendations.append({"dataset": group["dataset"], "mode": group["mode"], "pilot_processes": len(values),
                                "pilot_process_mean_CV": cv, "normal_approx_requested_processes": requested,
                                "capped_selected_processes": min(12, requested), "precision_guaranteed": False})
    return recommendations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--datasets", nargs="+", choices=tuple(fixtures.SOURCES), default=["mushroom", "semeion"])
    parser.add_argument("--modes", nargs="+", choices=tuple(MODES), default=list(MODES))
    parser.add_argument("--process-repetitions", type=int, default=3)
    parser.add_argument("--queries", type=int, default=6)
    parser.add_argument("--pilot-json", type=Path)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists() or not 1 <= args.process_repetitions <= 12 or not 2 <= args.queries <= 32:
        parser.error("Fresh output and bounded process/query counts required")
    selected, recommendations = args.process_repetitions, []
    if args.pilot_json:
        recommendations = pilot_requirement(json.loads(args.pilot_json.read_text()))
        selected = max(c["capped_selected_processes"] for c in recommendations)
    paths = [Path(__file__), ROOT / "docs/research/isolated-enrolled-preregistration-20261001.md",
             ROOT / "benchmarks/dictionary_layout_lab.py", ROOT / "benchmarks/enrolled_service_lab.py", ROOT / "benchmarks/field_frontier_lab.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "private_provision", "test_private_provision", "isolated_enrolled", "enrolled_rpc", "loopback_exchange", "loopback_transfer",
        "binary_fixtures", "affine_dictionary", "field_frontier", "rank_partition", "representation_oracle", "representation_contract",
        "cache_snapshot", "coordinate_cache", "coordinate_factory", "native_linear_check", "crt_linear_check", "crt_native_bgv",
        "coefficient_body", "owner_bgv", "seeded_bgv", "shallow_bgv", "crt_masked_bgv", "crt_query_space", "dyadic_crt", "score_layout", "verification_lifetime"))
    paths.extend((ROOT / "src/cuhepy/bfv/scheme.py", ROOT / "src/cuhepy/types.py"))
    if args.pilot_json:
        paths.append(args.pilot_json.resolve())
    result = metadata(paths)
    trials = []
    for repetition in range(selected):
        # Rotate mode order between independent-process repetitions.
        modes = args.modes[repetition % len(args.modes):] + args.modes[:repetition % len(args.modes)]
        for dataset in args.datasets:
            for label in modes:
                mode, level, retained = MODES[label]
                job = {"dataset": dataset, "fixture_path": str((args.cache_dir / fixtures.SOURCES[dataset]["member"]).resolve()),
                       "mode": mode, "mode_label": label, "level": level, "retained": retained,
                       "queries": args.queries, "budget": 1024, "process_repetition": repetition}
                trial = isolated.run_trial(job)
                trials.append(trial)
                print(dataset, label, repetition, "exact", file=sys.stderr, flush=True)
    result.update(kind="E79_three_process_authenticated_private_bootstrap_and_full_RPC_control",
                  selected_process_repetitions=selected, pilot_process_sample_recommendations=recommendations,
                  final_sample_selected_from_pilot=bool(args.pilot_json), trials=trials, summary=summarize(trials),
                  exact_mode_queries=sum(len(c["client"]["samples"]) for c in trials),
                  scope="Actual separate-process owner/server/client loopback acquisition, full-Q HE gate and authorized cache controls. Owner authentication root is supplied through trusted local controller IPC and counted. Import baselines, process CPU/current/peak Linux RSS, fixed public padding, every network application byte and raw-owner control are exposed. No WAN/TLS/update/scale/GPU frontier, approved HE/private-timing/durability assurance, p95 or new cryptographic contribution.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "process_trials": len(trials), "exact_mode_queries": result["exact_mode_queries"],
                      "selected_process_repetitions": selected, "all_scores_IDs_top3_exact": True}))


if __name__ == "__main__":
    main()
