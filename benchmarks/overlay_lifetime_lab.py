#!/usr/bin/env python3
"""E55 small finite checkpoint frontier, count model only."""

# ruff: noqa: E402 -- standalone research entry point.

from dataclasses import asdict, replace
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import lifetime_planner as life
from experiments.bfv_search_lab import overlay_lifetime as overlay
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    w = Workload((0, 1, 0, 1), (7, 2, 100, 9), 3)
    start = time.perf_counter()
    entries = tuple(life.reserve(w, bits, 17, name=name) for name, bits in (
        ("frozen-fit", ()), ("reserve-1", (1,)), ("reserve-all", (1, 2))))
    catalog_s = time.perf_counter() - start
    cases = []
    for name, rows in (("outside-span-and-restore", ((0, 3, 2, 1), (2, 7, 0, 3), w.rows)),
                       ("persistent-growth", ((0, 3, 0, 1), (0, 3, 4, 1), (2, 3, 4, 7)))):
        trace = life.Trace((w, *(replace(w, rows=row) for row in rows)), (1, 2, 1, 2), 8)
        start = time.perf_counter()
        p = overlay.Problem(trace, entries, Profile(32, 17, eta=1))
        compile_s = time.perf_counter() - start
        start = time.perf_counter()
        exact, counts = overlay.exhaustive(p)
        exhaustive_s = time.perf_counter() - start
        start = time.perf_counter()
        frontier, dp_counts = overlay.dynamic_program(p)
        dp_s = time.perf_counter() - start
        assert {x.cost for x in exact} == {x.cost for x in frontier}
        cases.append({"name": name, "trace": asdict(trace), "compile_s": compile_s,
                      "exhaustive_s": exhaustive_s, "dp_s": dp_s, "exhaustive_prefixes": counts,
                      "dp_prefixes": dp_counts, "frontier": [asdict(x) for x in frontier], "exact_agreement": True})
    result = metadata([Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "overlay_lifetime", "lifetime_planner", "representation_oracle", "representation_contract", "client_delta"))])
    result.update(kind="exact_checkpoint_exception_frontier_model", catalog_fitting_s=catalog_s, cases=cases,
                  scope="Finite hindsight count oracle; all unused fresh replacement tokens charged. "
                        "No native performance, online policy, global optimum, production proof or novelty is inferred.")
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "frontiers": [len(c["frontier"]) for c in cases]}))


if __name__ == "__main__":
    main()
