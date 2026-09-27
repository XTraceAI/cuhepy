#!/usr/bin/env python3
"""E27 index-only rank repair/capacity allocation: exact oracle and cost model.

No HE timings. Both failures and map-budget/full-scan fallback are retained.
Queries use a disjoint heldout window and never choose cuts or capacities.
"""

# ruff: noqa: E402 -- standalone research benchmark.

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random
import sys
import time
import zlib

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import structured_fixture
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import dyadic_crt as crt
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import linear_packing as packing
from experiments.bfv_search_lab import rank_partition as partition


def uneven_rows():
    counts = (4096, 2048, 1024, 512, 256, 128, 64, 64)
    return [x for i, count in enumerate(counts) for x in structured_fixture(count, 512, 48, 0, 3110 + i)[1]], counts


def given_candidate(rows, dimension, counts, n=16384):
    """Explicit synthetic generative boundaries, not a learned clustering claim."""
    depth = len(counts).bit_length() - 1
    if sum(counts) != len(rows) or 1 << depth != len(counts):
        raise ValueError("Invalid given generative blocks")
    paths = tuple(format(i, f"0{depth}b") for i in range(len(counts)))
    blocks, start = [], 0
    for path, count in zip(paths, counts, strict=True):
        blocks.append(partition.Block(path, tuple(range(start, start + count)), affine.prepare(rows[start:start + count], dimension)))
        start += count
    layout = crt.layout(crt.context(n, paths), tuple(b.mapping.features for b in blocks), counts)
    candidate = partition.Candidate(layout, tuple(blocks), (), partition.epoch_digest(rows, dimension), dimension,
                                    partition.map_body_bytes(tuple(blocks)), None)
    partition.validate_epoch(candidate, rows)
    return candidate


def audit(candidate, rows, ids, queries):
    maps = list(dict.fromkeys(b.mapping for b in candidate.blocks))
    bodies = b"".join(affine.canonical_map(p) for p in maps)
    assert len(bodies) == candidate.map_bytes
    features = [np.asarray(affine.index_features(b.mapping, [rows[i] for i in b.positions]), dtype=np.int64)
                .reshape(len(b.positions), b.mapping.features) for b in candidate.blocks]
    for query in queries:
        actual = []
        transforms = {p: affine.query_features(p, query) for p in maps}
        for block, values in zip(candidate.blocks, features, strict=True):
            weights, offset = transforms[block.mapping]
            dots = (values @ np.asarray(weights, dtype=np.int64) % block.mapping.prime).tolist()
            actual.extend(zip(affine.decode(block.mapping, dots, offset), (ids[i] for i in block.positions), strict=True))
        expected = sorted(((query ^ row).bit_count(), i) for row, i in zip(rows, ids, strict=True))
        assert sorted(actual) == expected and sorted(actual)[:3] == expected[:3]
    return {"cost": asdict(candidate.layout.cost), "padded": candidate.layout.padded,
            "leaf_paths": [b.path for b in candidate.blocks], "counts": candidate.layout.counts,
            "ranks": [b.mapping.rank for b in candidate.blocks], "unique_maps": len(maps),
            "map_body_bytes": candidate.map_bytes, "map_zlib9_bytes": len(zlib.compress(bodies, 9)),
            "map_sha256": hashlib.sha256(bodies).hexdigest(), "local_epoch_digest": candidate.source_digest,
            "full_affine_cache_modeled_bytes": candidate.map_bytes + sum((len(b.positions) * b.mapping.rank + 7) // 8
                                                                         for b in candidate.blocks),
            "cut_count": len(candidate.cuts), "coordinate_cut_count": sum(c.coordinate is not None for c in candidate.cuts),
            "all_distances_and_stable_top3_exact": True}


def workload(name, rows, ids, queries, dimension, orders, targets, query_ids=None, counts=None):
    entries, candidates, names = [], [], []
    raw = b"".join(x.to_bytes((dimension + 7) // 8, "little") for x in rows)

    def retain(label, factory):
        started = time.perf_counter()
        try:
            candidate = factory()
        except ValueError as error:
            entries.append({"name": label, "rejected": str(error), "fit_s": time.perf_counter() - started})
            return
        fit_s = time.perf_counter() - started
        entries.append({"name": label, "fit_s": fit_s, "result": audit(candidate, rows, ids, queries)})
        candidates.append(candidate)
        names.append(label)
        # Reallocation is an independent fixed-map construction; retain the
        # unallocated control even when it loses or exceeds the state budget.
        started = time.perf_counter()
        allocated = partition.reallocate(candidate, rows, min(64, candidate.layout.context.n // candidate.layout.padded))
        entries.append({"name": label + "/allocated", "allocation_s": time.perf_counter() - started,
                        "result": audit(allocated, rows, ids, queries)})
        candidates.append(allocated)
        names.append(label + "/allocated")

    for label, order in orders.items():
        parts = (8, 16, 32) if label == "metric" else (8,)
        for count in parts:
            print(name, label, "uniform", count, flush=True, file=sys.stderr)
            retain(f"{label}/uniform{count}", lambda count=count, order=order: partition.prepare(
                rows, dimension, order, initial_parts=count))
        for target in targets:
            policies = ("median", "hybrid") if label == "metric" else ("hybrid",)
            for policy in policies:
                print(name, label, target, policy, flush=True, file=sys.stderr)
                retain(f"{label}/repair{target}/{policy}", lambda target=target, policy=policy, order=order: partition.prepare(
                    rows, dimension, order, target=target, policy=policy))
    if counts is not None:
        retain("given_boundaries", lambda: given_candidate(rows, dimension, counts))
    choices = {}
    for budget in (4096, 8192, 16384, 32768):
        choice = partition.select(candidates, budget)
        choices[str(budget)] = names[next(i for i, c in enumerate(candidates) if c is choice)] if choice is not None else "full_scan"
    return {"name": name, "count": len(rows), "dimension": dimension, "unique_rows": len(set(rows)),
            "query_ids": query_ids, "queries": len(queries), "query_equals_index": sum(q in set(rows) for q in queries),
            "full_scan": asdict(packing.packing_cost(dimension, len(rows))), "raw_rows_bytes": len(raw),
            "raw_rows_input_order_zlib9_bytes": len(zlib.compress(raw, 9)),
            "common_stable_id_bytes": len(ids) * max(1, (max(ids).bit_length() + 7) // 8),
            "variants": entries, "selection_by_canonical_map_budget": choices}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    paths = [Path(__file__), ROOT / "benchmarks/certified_filter_lab.py", ROOT / "benchmarks/dictionary_layout_lab.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "dyadic_crt", "rank_partition", "affine_dictionary", "binary_fixtures", "folded_dictionary", "linear_packing"))
    output = metadata(paths)
    output.update({"kind": "dyadic_rank_capacity_model", "datasets": fixtures.SOURCES, "results": [],
                   "notes": "Exact oracle/counts, not HE latency. Index-only maps/layouts. Model holdout 80:96; native 120:128 separately. "
                            "Greedy rank cuts are not optimal; slot allocation is exact for FIXED maps and common padded D. "
                            "Map budget counts unique canonical maps, not Python objects/IDs/public geometry/keys. "
                            "No authentication, timing assurance, incremental update system or novel-primitive claim."})
    for name, seeds in (("mushroom", (3001, 3002, 3101)), ("semeion", (3101,))):
        data = fixtures.load(name, args.cache_dir / fixtures.SOURCES[name]["member"])
        for seed in seeds:
            ids, holdout = fixtures.split(data, seed)
            rows = [data.rows[i] for i in ids]
            query_ids = holdout[80:96]
            orders = {"metric": dictionary.metric_order(rows, data.dimension, 32), "input": tuple(range(len(rows)))}
            result = workload(f"{name}/{seed}", rows, ids, [data.rows[i] for i in query_ids], data.dimension, orders,
                              (64, 32) if name == "mushroom" else (128, 64), query_ids)
            result["split_seed"], result["fixture_sha256"] = seed, data.sha256
            output["results"].append(result)
    rows, counts = uneven_rows()
    rng = random.Random(3104)
    output["results"].append(workload("uneven_given", rows, list(range(len(rows))), [rng.getrandbits(512) for _ in range(16)],
                                         512, {}, (), counts=counts))
    # Full-size adverse control: do not run expensive branching where ordinary
    # median fits already reveal that rank reduction is nearly plaintext caching.
    rows = [rng.getrandbits(512) for _ in range(8192)]
    output["results"].append(workload("uniform_random", rows, list(range(len(rows))), [rng.getrandbits(512) for _ in range(16)],
                                         512, {"input": tuple(range(len(rows)))}, ()))
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
