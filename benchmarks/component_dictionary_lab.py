#!/usr/bin/env python3
"""E26 exact block dictionaries and polynomial CRT: cost/state rejection tests.

All field results are checked against binary XOR/popcount. No HE timings here.
Native encrypted measurements live in component_bgv_native.py. Maps fit index
rows only; no radius, residual array or query-dependent routing is retained.
"""

# ruff: noqa: E402 -- standalone research entry point.

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
from experiments.bfv_search_lab import crt_multiplex as crt
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import linear_packing as packing
from experiments.bfv_search_lab import private_residual_lookup as lookup


def piecewise_rows(count=8192, dimension=512, parts=8, features=48, seed=3003):
    """Different exact column maps in each public contiguous synthetic block."""
    if count % parts:
        raise ValueError("Synthetic fixture needs balanced whole blocks")
    return [row for i in range(parts) for row in structured_fixture(count // parts, dimension, features, 0, seed + i)[1]]


def groups_for(rows, ids, parts, order):
    ordered = [rows[i] for i in order]
    stable = [ids[i] for i in order]
    groups = [ordered[len(rows) * i // parts:len(rows) * (i + 1) // parts] for i in range(parts)]
    names = [stable[len(rows) * i // parts:len(rows) * (i + 1) // parts] for i in range(parts)]
    return groups, names


def representation(groups, dimension, n=16384, prime=1153):
    started = time.perf_counter()
    plans = [affine.prepare(rows, dimension, prime) for rows in groups]
    owner_s = time.perf_counter() - started
    ctx = crt.context(n, len(groups), prime)
    layout = crt.layout(ctx, tuple(p.features for p in plans), tuple(map(len, groups)))
    maps = b"".join(affine.canonical_map(p) for p in plans)
    return plans, layout, {"enroll_s": owner_s, "ranks": [p.rank for p in plans],
                           "map_body_bytes": len(maps), "map_zlib9_bytes": len(zlib.compress(maps, 9)),
                           "map_sha256": hashlib.sha256(maps).hexdigest(),
                           "dense_field_basis_elements": sum(p.rank * dimension for p in plans),
                           "owner_state_scaling": "O(parts*dimension^2) field entries; no per-row values. Stable IDs/permutation separate."}


def evaluate(rows, ids, queries, dimension, parts, order):
    groups, stable = groups_for(rows, ids, parts, order)
    plans, layout, state = representation(groups, dimension)
    features = [affine.index_features(p, g) for p, g in zip(plans, groups, strict=True)]
    for query in queries:
        result = []
        for plan, values, names in zip(plans, features, stable, strict=True):
            weights, offset = affine.query_features(plan, query)
            # Independent exact field dot products, not CRT encoding/decoding.
            dots = (np.asarray(values, dtype=np.int64) @ np.asarray(weights, dtype=np.int64) % plan.prime).tolist()
            result.extend(zip(affine.decode(plan, dots, offset), names, strict=True))
        expected = sorted(((query ^ row).bit_count(), i) for row, i in zip(rows, ids, strict=True))
        assert sorted(result) == expected and sorted(result)[:3] == expected[:3]
    separate = [packing.packing_cost(layout.padded, len(g)) for g in groups]
    raw = b"".join(rows[i].to_bytes((dimension + 7) // 8, "little") for i in order)
    return {"parts": parts, "padded": layout.padded, "counts": layout.counts,
            "full_scan": asdict(packing.packing_cost(dimension, len(rows))), "crt": asdict(layout.cost),
            "separate": {"products": sum(c.input_tiles for c in separate), "switches": sum(c.switches for c in separate),
                         "queries": parts, "responses": sum(c.response_ciphertexts for c in separate)},
            "private_representation": state, "plaintext_body_bytes": len(raw),
            "plaintext_zlib9_bytes": len(zlib.compress(raw, 9)),
            "stable_id_array_bytes": len(ids) * max(1, (max(ids).bit_length() + 7) // 8),
            "all_distances_and_stable_top3_exact": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--queries", type=int, default=16)
    args = parser.parse_args()
    if not 1 <= args.queries <= 16:
        parser.error("Reserve heldout queries 64:80 for this model")
    paths = [Path(__file__), ROOT / "benchmarks/certified_filter_lab.py", ROOT / "benchmarks/dictionary_layout_lab.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "affine_dictionary", "crt_multiplex", "private_residual_lookup", "binary_fixtures", "folded_dictionary", "linear_packing"))
    output = metadata(paths)
    output.update({"kind": "exact_affine_component_model", "datasets": fixtures.SOURCES,
                   "notes": "Exact integer/field oracle, not encrypted latency. Fixed public T partitions, common worst-block padding, "
                            "CRT virtual padding, index-only metric order. Map bytes include anchors and sparse nonpivot field relations. "
                            "Stable ID arrays, encrypted setup, epoch binding, private arithmetic and authentication remain separate costs.",
                   "results": []})
    for name, source in fixtures.SOURCES.items():
        data = fixtures.load(name, args.cache_dir / source["member"])
        for seed in (3001, 3002):
            indices, holdout = fixtures.split(data, seed)
            rows = [data.rows[i] for i in indices]
            query_ids = holdout[64:64 + args.queries]
            queries = [data.rows[i] for i in query_ids]
            metric = dictionary.metric_order(rows, data.dimension, 32)
            variants = []
            for label, order in (("input", tuple(range(len(rows)))), ("metric", metric)):
                for parts in (1, 4, 8, 16, 32):
                    print(f"{name} seed={seed} {label} parts={parts}", file=sys.stderr, flush=True)
                    variants.append({"layout": label, "result": evaluate(rows, indices, queries, data.dimension, parts, order)})
            output["results"].append({"name": name, "seed": seed, "count": len(rows), "dimension": data.dimension,
                                      "unique_rows": len(set(rows)), "query_ids": query_ids,
                                      "heldout_queries_equal_index_row": sum(q in set(rows) for q in queries), "variants": variants})
    rng = random.Random(3004)
    for name, rows, part_counts in (("piecewise_exact", piecewise_rows(), (1, 4, 8, 16)),
                                    ("uniform_random", [rng.getrandbits(512) for _ in range(8192)], (8, 32))):
        queries = [rng.getrandbits(512) for _ in range(args.queries)]
        variants = []
        for parts in part_counts:
            print(f"{name} parts={parts}", file=sys.stderr, flush=True)
            variants.append({"layout": "input", "result": evaluate(rows, list(range(len(rows))), queries, 512, parts, tuple(range(len(rows))))})
        output["results"].append({"name": name, "count": len(rows), "dimension": 512,
                                  "unique_rows": len(set(rows)), "query_seed": 3004, "variants": variants})
    output["scalar_hidden_lookup_control"] = lookup.cost(512, 8192, 2)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
