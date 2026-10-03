#!/usr/bin/env python3
"""E103 exact owner-summary and fixed traffic counts; no HE/PIR/timing claims."""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import UTC, datetime
import hashlib
import json
from math import ceil
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import connect4_fixture as connect4
from experiments.bfv_search_lab import owner_summary_oracle as lab
from experiments.bfv_search_lab.test_owner_summary_oracle import exhaustive_cases, reference

PREREG = ROOT / "docs/research/owner-summary-preregistration.md"
CONTRACT = ROOT / "docs/research/owner-summary-contract.md"
EPOCH = bytes(range(32))


def summarize(values):
    return {"min": min(values), "median": statistics.median(values),
            "mean": statistics.mean(values), "max": max(values)}


def synthetic():
    rng = random.Random(9103)
    rows = tuple((i, rng.getrandbits(64)) for i in range(1024))
    queries = tuple(rng.getrandbits(64) for _ in range(16))
    yield "uniform-1024x64", 64, rows, queries, None, {"seed": 9103, "rule": "independent uniform words and queries"}
    rng = random.Random(9104)
    centers = tuple(rng.getrandbits(32) for _ in range(16))
    rows = tuple((16 * j + k, center if k < 8 else center ^ (1 << (k - 8)))
                 for j, center in enumerate(centers) for k in range(16))
    yield "favorable-duplicate-clusters-256x32", 32, rows, centers, None, {
        "seed": 9104, "rule": "16 random centers; 8 duplicates and 8 one-bit flips per center; center queries"}
    rows = tuple((i, i) for i in range(256))
    groups = tuple((rows[i], rows[i ^ 255]) for i in range(128))
    yield "adversarial-complement-pairs-256x8", 8, rows, tuple(range(256)), groups, {
        "seed": None, "rule": "full binary universe; forced complementary pairs; every query"}


def count_case(name, dimension, records, queries, groups, layout, source, assignment_cost=0):
    owner = lab.enroll(records, groups, dimension, EPOCH)
    cache = lab.MutableCache(records, dimension)
    manifest, slots = owner.manifest, len(owner.blocks)
    budgets = sorted({1, ceil(slots / 4), ceil(slots / 2), slots})
    samples = []
    for query in queries:
        expected = reference(records, query)
        assert cache.query(query) == expected
        oracle = lab.search(manifest, query, owner.fetch)
        assert oracle.certified and oracle.top3 == expected
        fixed = []
        for budget in budgets:
            result = lab.search(manifest, query, owner.fetch, budget=budget)
            assert result.paid_slots == budget
            assert result.record_distance_evaluations == budget * manifest.capacity
            assert not result.certified or result.top3 == expected
            fixed.append({"public_budget": budget, **asdict(result)})
        samples.append({"query": query, "top3": expected, "variable_oracle": asdict(oracle), "fixed_schedules": fixed})
    body = cache.serialized_body_bytes_model
    summaries = []
    for budget in budgets:
        fixed = [next(item for item in sample["fixed_schedules"] if item["public_budget"] == budget) for sample in samples]
        downloaded = budget * lab.padded_packet_bytes(manifest)
        summaries.append({"public_budget": budget, "certified_queries": sum(item["certified"] for item in fixed),
                          "queries": len(queries), "all_observed_queries_exact": all(item["certified"] for item in fixed),
                          "paid_record_distance_evaluations": budget * manifest.capacity,
                          "paid_summary_distance_evaluations": slots,
                          "record_packet_bytes_model": downloaded,
                          "record_packet_over_raw_cache_body_ratio": downloaded / body,
                          "client_summary_plus_download_over_raw_cache_body_ratio": (len(manifest.serialize()) + downloaded) / body,
                          "PIR_request_proof_hint_crypto_RTT_costs": "unknown_not_implemented"})
    # Demonstrate a real mutation path and explicitly rebuild summaries. This is
    # not an incremental authenticated update algorithm or update timing.
    cache.delete(records[0][0])
    cache.put(max(cache.rows, default=0) + 1, records[0][1] ^ 1)
    live = tuple(cache.rows.items())
    if layout == "prototype16":
        revised_groups, revised_assignment = lab.prototype_layout(live)
    else:
        revised_groups, revised_assignment = lab.balanced_layout(live), 0
    revised = lab.enroll(live, revised_groups, dimension, bytes([99]) * 32)
    try:
        lab.pin_candidate(manifest, revised.manifest)
    except ValueError:
        stale_rejected = True
    else:
        raise AssertionError("Stale summaries accepted")
    assert lab.search(revised.manifest, queries[0], revised.fetch).top3 == reference(live, queries[0])
    return {"dataset": name, "source": source, "dimension": dimension, "count": len(records),
            "distinct_record_words": len({row for _, row in records}), "layout": layout,
            "group_count": slots, "public_capacity": manifest.capacity,
            "nonempty_groups": sum(bool(group.count) for group in manifest.groups),
            "radii": summarize([group.radius for group in manifest.groups]),
            "raw_mutable_cache_serialized_body_bytes_model": body,
            "client_pinned_manifest_actual_serialized_bytes": len(manifest.serialize()),
            "client_pinned_manifest_over_raw_cache_body_ratio": len(manifest.serialize()) / body,
            "owner_enrollment_counts": {"assignment_distance_evaluations": assignment_cost,
                                        "centroid_bit_visits": owner.owner_centroid_bit_visits,
                                        "radius_distance_evaluations": owner.owner_radius_distance_evaluations},
            "variable_fetched_records": summarize([sample["variable_oracle"]["fetched_records"] for sample in samples]),
            "variable_fetched_groups": summarize([len(sample["variable_oracle"]["fetched_groups"]) for sample in samples]),
            "strong_cache_per_query_distance_evaluations": len(records),
            "fixed_budget_summaries": summaries, "samples": samples,
            "update_screen": {"raw_cache_logical_mutations": cache.mutations, "new_live_count": len(live),
                              "known_summary_full_rebuild_assignment_distances": revised_assignment,
                              "known_summary_full_rebuild_centroid_bit_visits": revised.owner_centroid_bit_visits,
                              "known_summary_full_rebuild_radius_distances": revised.owner_radius_distance_evaluations,
                              "new_manifest_bytes": len(revised.manifest.serialize()), "stale_pin_rejected": stale_rejected,
                              "adversarial_pair_update_uses_declared_balanced_rebuild_control": layout == "complement-pairs"}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--connect4", type=Path)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    receipt = json.loads(args.receipt.read_text())
    assert not receipt["execution_started"]
    for path, digest in receipt["source_sha256"].items():
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == digest
    exact_queries = 0
    for records, owner, query in exhaustive_cases():
        expected = reference(records, query)
        assert lab.search(owner.manifest, query, owner.fetch).top3 == expected
        assert lab.search(owner.manifest, query, owner.fetch, budget=len(owner.blocks)).top3 == expected
        exact_queries += 1
    assert exact_queries == 9360
    cases, input_files = [], []
    data_sources = []
    for name, source in fixtures.SOURCES.items():
        path = args.cache / source["member"]
        data_sources.append((fixtures.load(name, path), None))
        input_files.append({"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    if args.connect4 is not None:
        data_sources.append((connect4.load(args.connect4), 4096))
        input_files.append({"path": str(args.connect4.resolve()), "sha256": hashlib.sha256(args.connect4.read_bytes()).hexdigest()})
    inputs = list(synthetic())
    for data, cap in data_sources:
        ids, heldout = fixtures.split(data, 3001)
        if cap is not None:
            ids = ids[:cap]
        records = tuple((stable_id, data.rows[stable_id]) for stable_id in ids)
        queries = tuple(data.rows[i] for i in heldout[32:40])
        inputs.append((data.name, data.dimension, records, queries, None,
                       {"fixture_sha256": data.sha256, "split_seed": 3001, "heldout_slice": [32, 40],
                        "index_prefix_cap": cap, "all_possible_query_geometry_exhausted": False}))
    for name, dimension, records, queries, forced, source in inputs:
        layouts = [("sorted128", lab.balanced_layout(records), 0)]
        groups, assignment = lab.prototype_layout(records)
        layouts.append(("prototype16", groups, assignment))
        if forced is not None:
            layouts.append(("complement-pairs", forced, 0))
        for layout, groups, assignment in layouts:
            cases.append(count_case(name, dimension, records, queries, groups, layout, source, assignment))
            print(name, layout, "variable rows", cases[-1]["variable_fetched_records"], file=sys.stderr)
    paths = [Path(__file__), PREREG, CONTRACT,
             ROOT / "experiments/bfv_search_lab/owner_summary_oracle.py",
             ROOT / "experiments/bfv_search_lab/test_owner_summary_oracle.py",
             ROOT / "experiments/bfv_search_lab/binary_fixtures.py",
             ROOT / "experiments/bfv_search_lab/connect4_fixture.py"]
    report = {"utc": datetime.now(UTC).isoformat(), "command": sys.argv,
              "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "python": platform.python_version(), "platform": platform.platform(),
              "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths},
              "preregistration_receipt_sha256": hashlib.sha256(args.receipt.read_bytes()).hexdigest(),
              "kind": "E103_known_owner_summary_complete_coverage_exact_count_screen", "input_files": input_files,
              "exhaustive_small_universe": {"dimension": 3, "ordered_dataset_lengths": [0, 1, 2, 3],
                                            "all_binary_queries": 8, "layouts_per_dataset": 2,
                                            "dataset_layout_query_cases": exact_queries,
                                            "variable_and_full_fixed_results_checked": 2 * exact_queries},
              "cases": cases, "literal_mechanism_gate": "STOP_known_triangle_radius_min_ID_plus_owner_pinned_coverage",
              "scope": "Plaintext exact/count oracle only. No PIR, HE, cryptographic authentication/proof, networking, GPU, "
                       "constant-time/privacy, peak RSS, benchmark latency, new novelty or security-parameter claim. "
                       "Fixed schedules charge public rounds/padded records and summary distances; all unimplemented PIR costs unknown. "
                       "Owner may retain full plaintext; raw mutable cache is a permitted control. Held-out maxima do not prove all-query budgets. "
                       "This count model does not instantiate the pre-decryption gate required for malicious outer HE PIR replies."}
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cases": len(cases), "exhaustive_cases": exact_queries,
                      "mechanism_gate": report["literal_mechanism_gate"]}))


if __name__ == "__main__":
    main()
