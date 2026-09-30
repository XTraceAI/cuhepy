#!/usr/bin/env python3
"""E52 finite reserve/noise/token model and exhaustive hindsight reference."""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import lifetime_planner as life
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    cases = []
    for name, rows, changed in (("rank_state_trap", (0, 1), ((0, 3), (0, 7))),
                                ("repeated_sparse_edits", (0, 1) * 8, ((0, 3) + (0, 1) * 7,
                                                                       (0, 3, 0, 5) + (0, 1) * 6))):
        w = Workload(rows, tuple(range(len(rows))), 3)
        catalog_s, entries = timed(lambda w=w: tuple(life.reserve(w, bits, 17, name=str(i))
                                                for i, bits in enumerate(((), (1,), (2,), (1, 2)))))
        trace = life.Trace((w, *(replace(w, rows=r) for r in changed)), (1, 2, 1), 8)
        compile_s, problem = timed(life.Problem, trace, entries, Profile(32, 17, eta=1))
        dp_s, (frontier, dp_counts) = timed(life.dynamic_program, problem)
        exhaustive_s, (reference, exhaustive_counts) = timed(life.exhaustive, problem)
        assert {p.cost for p in frontier} == {p.cost for p in reference}
        cases.append({"name": name, "trace": asdict(trace), "profile": asdict(problem.profile),
                      "catalog_rank": {e.name: e.choice.pieces[0].mapping.rank for e in entries},
                      "catalog_discovery_s": catalog_s, "exact_catalog_certification_s": compile_s,
                      "dp_s": dp_s, "exhaustive_s": exhaustive_s, "dp_retained_counts": dp_counts,
                      "exhaustive_unpruned_counts": exhaustive_counts,
                      "dp_equals_complete_schedule_cost_frontier": True,
                      "frontier": [asdict(p) for p in frontier]})
    result = metadata([Path(__file__), ROOT / "experiments/bfv_search_lab/lifetime_planner.py",
                       ROOT / "experiments/bfv_search_lab/representation_oracle.py",
                       ROOT / "experiments/bfv_search_lab/representation_contract.py"])
    result.update(kind="exact_hindsight_lifetime_model", cases=cases,
                  scope="MODELED finite-catalog fixed-ID reserve/repair/refresh/migration oracle, not runtime savings. "
                        "Costs retain all unused tokens, complete output/checks, accumulated universal phase and key/state bodies. "
                        "Compiler/discovery runtime recorded separately. Rank-equal maps have different future span feasibility. "
                        "DP Pareto-prunes only identical exact catalog/noise boundaries; exhaustive schedules never prune prefixes. "
                        "No online policy, learned predictor, deployed migration, insertion/deletion, GPU or novelty proof.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cases": len(cases)}))


if __name__ == "__main__":
    main()
