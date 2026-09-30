#!/usr/bin/env python3
"""E41/E42/E47 finite-frontier models and exact counterexamples (not timings)."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.bfv_search_lab import backend_frontier as codes
from experiments.bfv_search_lab import ciphertext_linear_oracle as outer
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import representation_planner as planner
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def record(plan):
    return {"choice": plan.choice.name, "allocation": plan.allocation, "binding_owner_local": plan.binding,
            "equal_forms": plan.equal_forms, "resources_model": asdict(plan.resources)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    fixtures = {
        "shared_affine_planes": tuple((i % 4) | ((i // 8) << 5) for i in range(32)),
        "unrelated_affine_planes": tuple((i % 4) << (2 * (i // 8)) for i in range(32)),
        "random_negative_control": tuple(random.Random(17 + i).randrange(256) for i in range(32)),
        "constant_negative_control": (17,) * 32,
    }
    cases = []
    for name, rows in fixtures.items():
        w = Workload(rows, tuple(range(32)), 8)
        root, profile = oracle.median_tree(w), Profile(64, 97, eta=1)
        start = time.perf_counter()
        exact = planner.search(w, root, profile)
        search_s = time.perf_counter() - start
        unshared = planner.search(w, root, profile, equal_forms=False)
        beam = planner.search(w, root, profile, beam=1)
        selected = {
            "rank_first_with_equal_form_tie_break": min(exact.plans, key=lambda p: (p.resources.columns, p.resources.query_coordinates)),
            "minimum_complete_verifier": min(exact.plans, key=lambda p: p.resources.verifier_products_model),
            "minimum_client_state_body": min(exact.plans, key=lambda p: p.resources.client_audit_body_bytes_model),
            "raw_global": next(p for p in exact.plans if p.choice.name == "root:raw" and p.allocation == (1,)),
            "affine_global": next(p for p in exact.plans if p.choice.name == "root:affine" and p.allocation == (1,))
                if any(p.choice.name == "root:affine" for p in exact.plans)
                else next(p for p in exact.plans if len(p.choice.pieces) == 1 and p.allocation == (1,)),
            "unshared_minimum_rank": min(unshared.plans, key=lambda p: (p.resources.columns, p.resources.query_coordinates)),
        }
        for plan in {p.binding: p for p in selected.values()}.values():
            for q in range(256):
                assert oracle.exact_scores(plan, q) == w.expected(q)
        vectors = {p.resources.static_vector for p in exact.frontier}
        beam_vectors = {p.resources.static_vector for p in beam.frontier}
        cases.append({"fixture": name, "workload_digest_owner_local": w.digest, "profile": asdict(profile),
                      "exact_plan_count": len(exact.plans), "rejected_count": len(exact.rejected),
                      "rejections": exact.rejected, "node_boundary_states": exact.node_state_counts,
                      "owner_search_elapsed_s": search_s,
                      "selected_controls": {k: record(p) for k, p in selected.items()},
                      "static_frontier": [record(p) for p in exact.frontier],
                      "rank_beam_one_is_uncertified": True,
                      "exact_frontier_resource_vectors_missed_by_rank_beam_one": len(vectors - beam_vectors),
                      "all_selected_plans_all_binary_queries_exact": True,
                      "code_floor_controls": [codes.code_cost(b, (32,), (f,)) for b in (codes.EMVP, codes.BNTM) for f in (8, 2)],
                      "literal_outer_matrix": outer.cost(selected["minimum_client_state_body"].query_space, profile.q),
                      "novelty_gate_b_passed": False,
                      "classification": "Exact count tradeoff; shared-plane gains use known equality merging/affine algebra. "
                                        "No matched practical gain or originality proof from these small cases."})
    paths = [Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{p}.py" for p in (
        "representation_contract", "representation_oracle", "representation_planner", "backend_frontier", "ciphertext_linear_oracle"))]
    report = {"kind": "publication_joint_frontier_exact_count_oracles", "cases": cases,
              "source_hashes": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
              "scope": "Restricted fixed median tree raw/affine/contiguous-slot grammar, research-only profiles, "
                        "static body/operation models. Search time is owner-side measurement; model axes are not latency or RSS. "
                        "No production, outer vLHE implementation or new primitive claim."}
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "fixtures": len(cases), "classification": "oracle_and_model"}))


if __name__ == "__main__":
    main()
