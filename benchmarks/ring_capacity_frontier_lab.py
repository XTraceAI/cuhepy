#!/usr/bin/env python3
"""E40 fixed-map capacity trajectories; no encrypted timing or profile change."""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import ring_capacity_frontier as rings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    paths = [Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", ROOT / "benchmarks/certified_filter_lab.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "ring_capacity_frontier", "test_ring_capacity_frontier", "field_frontier", "crt_query_space", "dyadic_crt", "rank_partition",
        "affine_dictionary", "folded_dictionary", "folded_filter", "binary_fixtures", "crt_noise_budget", "linear_packing"))
    report = metadata(paths)
    results = []
    for dataset in ("mushroom", "semeion"):
        data = fixtures.load(dataset, args.cache_dir / fixtures.SOURCES[dataset]["member"])
        for seed in (3001, 3002):
            ids, _ = fixtures.split(data, seed)
            rows = [data.rows[i] for i in ids]
            groups = fields.fit(rows, data.dimension, dictionary.metric_order(rows, data.dimension, 32),
                                prime=193 if dataset == "mushroom" else 257, target=32)
            slots = 32 if dataset == "mushroom" else 64
            accepted, rejected = [], []
            for n in (512, 1024, 2048, 4096, 8192, 16384, 32768):
                try:
                    accepted.append(rings.describe(groups, rows, n=n, slots=slots))
                except ValueError as error:
                    rejected.append({"n": n, "reason": str(error)})
            results.append({"dataset": dataset, "seed": seed, "fixture_sha256": data.sha256, "count": len(rows),
                            "dimension": data.dimension, "accepted_models": accepted, "rejected_models": rejected})
    report.update(kind="fixed_map_ring_capacity_models", results=results,
                  scope="Fixed independently certified private grouping, new exact plaintext allocation per N. "
                        "Changed N requires new parameter assessment. No new HE keys/timing/decryption or runtime gate changes.")
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "accepted_models": sum(len(r["accepted_models"]) for r in results),
                      "rejected_models": sum(len(r["rejected_models"]) for r in results)}))


if __name__ == "__main__":
    main()
