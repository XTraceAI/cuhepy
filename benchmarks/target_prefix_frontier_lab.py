#!/usr/bin/env python3
"""E96 exact sample oracle and coupled precision counts after target screening."""

# ruff: noqa: E402 -- standalone research runner.

from argparse import ArgumentParser
from fractions import Fraction
import json
from math import isqrt
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab.test_target_prefix_samples import exact_small_equations


def bounds(n, q, t, eta, phase, life, replies, dense, skip, prefix, degree):
    # Independent integer recomputation; no import of E95 precision/switching.
    target, half, radix = 2*degree, q//2, 257
    ceiling = q//2
    levels = 1
    while (radix**levels-1)//2 < ceiling:
        levels += 1
    rows = 2*levels-skip
    events = 2*replies*(n if dense else 1)
    confidence = 129+(life-1).bit_length()+(2*events-1).bit_length()
    def threshold(proxy):
        square = proxy*confidence
        root = isqrt(square)
        return root+(root*root < square)
    key_error = eta*rows*n*128
    residual = n*n*((radix**skip-1)//2)
    statistical = threshold(2*half*half*prefix+eta*target*target)
    candidate = half+min(statistical, prefix*half+target*eta)+target*(key_error+residual)
    deterministic = half+prefix*half+target*(key_error+residual)
    fresh = half+min(threshold(2*half*half*prefix+eta*target*target*rows*n*128**2),
                     prefix*half+target*key_error)+target*residual
    budget = q*Fraction(2*((degree//t-1)//2)-1, 2)-Fraction(target*phase, t)
    return {"degree": degree, "late_zero_bound": candidate, "deterministic_no_zero_bound": deterministic,
            "fresh_target_bound": fresh, "finite_odd_budget": str(budget),
            "late_zero_pass": candidate < budget, "deterministic_no_zero_pass": deterministic < budget,
            "fresh_target_pass": fresh < budget}


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    e94_path = ROOT / "benchmarks/results/publication-adaptive-query-phase-screen-20261002.json"
    e95_path = ROOT / "benchmarks/results/publication-late-owner-precision-screen-20261002.json"
    screen_path = ROOT / "benchmarks/results/publication-target-prefix-security-isolated-01-20261002.json"
    e94, e95, screen = (json.loads(p.read_text()) for p in (e94_path, e95_path, screen_path))
    assert screen["complete"]
    sources = {(c["dataset"], c["profile"], c["policy"]["max_fresh_queries"]): c for c in e94["cards"]}
    estimates = {(p["source_ring_N"], p["exact_Q"], p["unknown_target_prefix"]): p for p in screen["profiles"]}
    cards, reproduced = [], 0
    for old in e95["cards"]:
        policy = old["policy"]
        s = sources[old["dataset"], old["profile"], policy["max_fresh_queries"]]
        n, q = policy["n"], s["modeled_original_depth_one_Q"]
        args_base = (n, q, policy["t"], policy["eta"], s["bound"]["whole_lifetime_phase"],
                     policy["max_fresh_queries"], policy["replies"], old["dense"], old["skipped_C2_levels"])
        for point in old["points"]:
            got = bounds(*args_base, 512, point["degree"])
            assert all(point[k] == v for k, v in got.items())
            reproduced += 1
        for prefix in sorted({p for p in (512, 1024, 2048, 4096, n) if p <= n}):
            estimate = estimates.get((n, q, prefix))
            points = [bounds(*args_base, prefix, 1 << bits) for bits in range(11, 23)]
            if estimate is None:
                status = "unestimated_full_ring_control"
            elif estimate["below_128_in_named_heuristic_screen"]:
                status = "stop_sub128_named_classical_screen"
            elif all(v["status"] == "finite_heuristic" for v in estimate["attacks"].values()):
                status = "passes_only_the_four_named_classical_estimates_NOT_approved"
            else:
                status = "above128_returned_but_missing_named_attacks_NOT_approved"
            cards.append({"dataset": old["dataset"], "profile": old["profile"], "source_N": n, "Q": q,
                          "lifetime": policy["max_fresh_queries"], "dense": old["dense"],
                          "skipped_C2_levels": old["skipped_C2_levels"], "target_prefix": prefix,
                          "target_screen_status": status,
                          "minimum_returned_classical_log2_rop": None if estimate is None else estimate["minimum_returned_log2_rop"],
                          "target_independent_zero_samples_at_registered_4096_lifetime": None if estimate is None else estimate["available_independent_samples"],
                          "points": points,
                          "first_late_zero_degree": next((x["degree"] for x in points if x["late_zero_pass"]), None),
                          "first_deterministic_no_zero_degree": next((x["degree"] for x in points if x["deterministic_no_zero_pass"]), None),
                          "first_fresh_target_degree": next((x["degree"] for x in points if x["fresh_target_pass"]), None),
                          "same_strong_known_shared_zero_frontier": True,
                          "parameter_or_quantum_protocol_PBS_private_assurance": False})
    assert reproduced == 1600 and len(cards) == 720
    paths = [Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", e94_path, e95_path, screen_path,
             ROOT / "experiments/bfv_search_lab/target_prefix_samples.py",
             ROOT / "experiments/bfv_search_lab/test_target_prefix_samples.py",
             ROOT / "experiments/bfv_search_lab/test_source_phase_budget.py",
             ROOT / "experiments/bfv_search_lab/source_phase_budget.py",
             ROOT / "docs/research/target-prefix-security-preregistration-20261002.md",
             ROOT / "docs/research/target-prefix-isolation-preregistration-20261002.md"]
    result = metadata(paths)
    result.update(kind="E96_exact_disjoint_sample_and_coupled_security_precision_controls",
                  exact=exact_small_equations(), old_E95_points_independently_reproduced=reproduced,
                  coupled_contexts=len(cards), expanded_grid_points=len(cards)*12, cards=cards,
                  decision="Keep the exact law and exclude p512/p1024 from 128-bit target design claims under the named model. Larger supports need full assurance; equally shared known controls remain identical. No original main selected.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({"output": str(args.json_out), "exact": result["exact"], "old_points": reproduced,
                      "contexts": len(cards), "expanded_points": len(cards)*12, "parameter_approvals": 0}))


if __name__ == "__main__":
    main()
