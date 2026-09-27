#!/usr/bin/env python3
"""E22-E24 exact plaintext oracle and charged circuit counts, NOT HE timings.

Queries 32:64 of a 128-row holdout follow an exploratory 0:16 pilot. Dictionary,
layout and fixed witness sampling see only index rows. Stable IDs are source
line numbers. Two public datasets, two split seeds, positive/negative synthetic
controls, and all declared variants are retained, including regressions.
"""

# ruff: noqa: E402 -- standalone research benchmark.

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import structured_fixture
from experiments.bfv_search_lab import adaptive_refinement as adaptive
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import folded_filter as folded
from experiments.bfv_search_lab import interval_filter as interval
from experiments.bfv_search_lab import linear_packing as packing
from experiments.bfv_search_lab import witness_packing as witness


def metadata(paths):
    return {"utc": datetime.now(UTC).isoformat(), "command": sys.argv,
            "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "python": platform.python_version(), "platform": platform.platform(),
            "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}}


def summary(samples):
    return {key: {"mean": statistics.mean(s[key] for s in samples),
                  "median": statistics.median(s[key] for s in samples),
                  "min": min(s[key] for s in samples), "max": max(s[key] for s in samples)}
            for key in samples[0]}


def evaluate(rows, ids, queries, dimension, plan, order, witnesses, n):
    ordered = [rows[i] for i in order]
    stable = [ids[i] for i in order]
    reverse = {i: j for j, i in enumerate(order)}
    templates = [folded._template(plan, row) for row in ordered]
    radii = tuple((x ^ z).bit_count() for x, z in zip(ordered, templates, strict=True))
    groups = len(plan.representatives)
    full = packing.packing_cost(dimension, len(rows), n)
    coarse = packing.packing_cost(groups, len(rows), n)
    inband = packing.packing_cost(plan.features, len(rows), n)
    capacity = n // full.padded
    witness_costs = {w: packing.packing_cost(dimension, w, n) for w in witnesses}
    placements = {}
    for w in witnesses:
        try:
            placements[w] = asdict(witness.place(n, coarse.padded, len(rows), full.padded, w))
        except ValueError:
            placements[w] = None  # Charge a separate reply when this construction cannot place it.
    samples = {name: [] for name in ["adaptive_inband", "interval_hints", *(f"witness_{w}" for w in witnesses)]}
    for query in queries:
        exact = [(query ^ row).bit_count() for row in ordered]
        expected = tuple(sorted(zip(exact, stable, strict=True))[:3])
        scores = [(query ^ z).bit_count() for z in templates]
        lower, upper = interval.intervals(scores, radii, dimension)
        assert all(a <= d <= b for a, d, b in zip(lower, exact, upper, strict=True))

        def fetch(tiles, exact=exact):
            return [(i, exact[i]) for t in tiles for i in range(t * capacity, min((t + 1) * capacity, len(rows)))]

        result = adaptive.refine(lower, dimension, capacity, fetch, batch_tiles=4, row_ids=stable)
        assert result.top == expected
        costs = [packing.packing_cost(dimension, r.scored_rows, n) for r in result.rounds]
        samples["adaptive_inband"].append({
            "products": inband.input_tiles + sum(c.input_tiles for c in costs),
            "switches": inband.switches + sum(c.switches for c in costs),
            "response_ciphertexts": inband.response_ciphertexts + sum(c.response_ciphertexts for c in costs),
            "query_ciphertexts": 1 + bool(costs), "rounds": 1 + len(costs),
            "refinement_tiles": result.fetched_tiles, "exact_rows": result.exact_rows})
        for w in (0, *witnesses):
            known = {reverse[i]: exact[reverse[i]] for i in witnesses[w]} if w else None
            top, selected, fetched = interval.refine_once(lower, upper, stable, capacity, fetch, known_scores=known)
            assert top == expected
            refinement = packing.packing_cost(dimension, fetched, n)
            witness_cost = witness_costs[w] if w else packing.packing_cost(dimension, 0, n)
            first_responses = coarse.response_ciphertexts + (int(placements[w] is None) if w else 0)
            samples[f"witness_{w}" if w else "interval_hints"].append({
                "products": coarse.input_tiles + witness_cost.input_tiles + refinement.input_tiles,
                "switches": coarse.switches + witness_cost.switches + refinement.switches,
                "response_ciphertexts": first_responses + refinement.response_ciphertexts,
                "query_ciphertexts": 1 + bool(w or fetched), "rounds": 1 + bool(fetched),
                "refinement_tiles": len(selected.tiles), "exact_rows": fetched,
                "candidate_rows": selected.candidate_count})
    return {"full_scan": asdict(full), "inband_filter": asdict(inband), "hint_filter": asdict(coarse),
            "witness_indexes": {w: asdict(c) for w, c in witness_costs.items()}, "placements": placements,
            "samples": samples, "summary": {k: summary(v) for k, v in samples.items()},
            "all_bounds_and_stable_top3_exact": True}


def workload(name, rows, ids, queries, query_ids, dimension, budgets, seed, n):
    started = time.perf_counter()
    metric = dictionary.metric_order(rows, dimension, n // packing.packing_cost(dimension, len(rows), n).padded)
    layout_s = time.perf_counter() - started
    candidates = list(range(len(rows)))
    random.Random(seed + 19000).shuffle(candidates)
    witnesses = {w: candidates[:w] for w in (128, 256)}
    variants = []
    for budget, passes in budgets:
        print(f"{name} seed={seed} budget={budget} passes={passes}", file=sys.stderr, flush=True)
        started = time.perf_counter()
        model = dictionary.prepare(rows, dimension, budget, tail_passes=passes)
        build_s = time.perf_counter() - started
        for layout, order in (("identity", tuple(range(len(rows)))), ("signature", dictionary.signature_order(model.plan, rows)),
                              ("metric", metric)):
            result = evaluate(rows, ids, queries, dimension, model.plan, order, witnesses, n)
            variants.append({"budget": budget, "tail_passes": passes, "layout": layout,
                             "dictionary_s": build_s, "groups": len(model.plan.representatives),
                             "initial_objective": model.initial_error_objective, "final_objective": model.final_error_objective,
                             "medoid_changes": model.medoid_changes,
                             "owner_arrays": interval.owner_state_bytes(len(rows), dimension, max(ids), reordered=layout != "identity"),
                             "result": result})
    return {"name": name, "seed": seed, "count": len(rows), "dimension": dimension, "n": n,
            "query_ids": query_ids, "query_count": len(queries), "unique_index_rows": len(set(rows)),
            "heldout_queries_equal_to_an_index_row": sum(q in set(rows) for q in queries),
            "metric_layout_s": layout_s, "witness_selection": "fixed index-only shuffled sample, seed+19000",
            "variants": variants}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--queries", type=int, default=32)
    parser.add_argument("--seeds", type=int, nargs="+", default=[2901, 2902])
    parser.add_argument("--skip-synthetic", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.queries <= 32:
        parser.error("Reserve holdout 32:64 for this declared evaluation")
    paths = [Path(__file__), ROOT / "benchmarks/certified_filter_lab.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "binary_fixtures", "folded_dictionary", "folded_filter", "interval_filter", "witness_packing", "adaptive_refinement", "linear_packing"))
    output = metadata(paths)
    output.update({"kind": "dictionary_layout_exact_oracle_circuit_counts", "datasets": fixtures.SOURCES,
                   "notes": "No HE latency measured. Counts include original full index, coarse index, separately packed witness index, "
                            "whole original refinement tiles and all dependent response rounds. Queries reused within a search. "
                            "Owner hint/permutation arrays exclude map/framing/epoch metadata. Native subset preparation, "
                            "authentication and hidden routing remain unimplemented/unpriced. No security or novelty claim.",
                   "results": []})
    for name, source in fixtures.SOURCES.items():
        data = fixtures.load(name, args.cache_dir / source["member"])
        first = 63 if name == "semeion" else 31
        budgets = [(first, 0), (first, 2), (first + 1, 2), (2 * first + 1, 2), (2 * first + 2, 2)]
        for seed in args.seeds:
            indices, holdout = fixtures.split(data, seed)
            query_ids = holdout[32:32 + args.queries]
            output["results"].append(workload(name, [data.rows[i] for i in indices], indices,
                                                [data.rows[i] for i in query_ids], query_ids,
                                                data.dimension, budgets, seed, 16384))
    if not args.skip_synthetic:
        _, rows = structured_fixture(8192, 512, 48, 2, 2903)
        rng = random.Random(2904)
        for name, queries in (("synthetic_near", [rows[rng.randrange(len(rows))] ^ rng.getrandbits(16) for _ in range(args.queries)]),
                              ("synthetic_unrelated", [rng.getrandbits(512) for _ in range(args.queries)])):
            output["results"].append(workload(name, rows, list(range(len(rows))), queries, [], 512, [(63, 0), (64, 2)], 2903, 16384))
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
