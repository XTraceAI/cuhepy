#!/usr/bin/env python3
"""E93D independent public degree-frontier counts; no encrypted PBS or timings."""

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


def point(card, degree):
    q, n, eta = card["Q"], card["N"], card["eta"]
    radix, levels, capacity = 257, 0, 1
    while capacity < q:
        levels, capacity = levels + 1, capacity * radix
    rows, target = 2 * levels - card["skipped_C2_levels"], 2 * degree
    squares = rows * n * 128**2
    # Independent integer root implementation reproduces the registered MGF.
    twice_proxy = 2 * card["target_prefix"] * (q // 2)**2 + eta * target**2 * squares
    argument = twice_proxy * (128 + (2 * card["whole_family_events"] - 1).bit_length())
    root = isqrt(argument)
    statistical = root + int(root * root != argument)
    deterministic = card["target_prefix"] * (q // 2) + target * eta * rows * n * 128
    residual = n**2 * ((radix**card["skipped_C2_levels"] - 1) // 2)
    actual_stat = q // 2 + min(statistical, deterministic) + target * residual
    actual_det = q // 2 + deterministic + target * residual
    allowed = (degree // card["t"] - 1) // 2
    budget = q * Fraction(2 * allowed - 1, 2) - Fraction(target * card["phase_bound"], card["t"])
    return {"degree": degree, "statistical_bound": actual_stat, "deterministic_bound": actual_det,
            "finite_budget": str(budget), "statistical_pass": actual_stat < budget,
            "deterministic_pass": actual_det < budget}


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    source = ROOT / "benchmarks/results/publication-committed-precision-epoch-screen-20261002.json"
    inputs = json.loads(source.read_text())["cards"]
    grouped = {}
    for card in inputs:
        p = point(card, card["bootstrap_degree"])
        assert p["statistical_bound"] == card["statistical_bound"]
        assert p["deterministic_bound"] == card["deterministic_bound"]
        assert p["finite_budget"] == card["finite_odd_budget"]
        assert p["statistical_pass"] == card["statistical_finite_margin"]
        assert p["deterministic_pass"] == card["deterministic_finite_margin"]
        key = (card["dataset"], card["profile"], card["context_phase_multiplier"],
               card["committed_batch"], card["selected_mode"], card["skipped_C2_levels"])
        grouped.setdefault(key, card)
    results = []
    for key, card in sorted(grouped.items()):
        points = [point(card, 1 << bits) for bits in range(11, 21)]
        first_stat = next((p["degree"] for p in points if p["statistical_pass"]), None)
        first_det = next((p["degree"] for p in points if p["deterministic_pass"]), None)
        results.append({"context_batch_output_skip": key, "points": points,
                        "first_statistical_degree_in_declared_grid": first_stat,
                        "first_deterministic_degree_in_declared_grid": first_det,
                        "all_prior_four_points_reproduced": True,
                        "strong_known_shared_epoch_has_same_frontier": True})
    result = metadata([Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", source,
                       ROOT / "docs/research/committed-precision-refinement-preregistration-20261002.md"])
    result.update(kind="E93D_conditional_degree_frontier_and_independent_initial_card_reproduction",
                  initial_cards_reproduced=len(inputs), context_tuples=len(results),
                  total_new_grid_points=10 * len(results), frontiers=results,
                  decision="Any smaller sufficient degree is credited equally to the strong known shared-epoch/MGF control. No complete original mechanism, measured PBS speed or assured parameter follows.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    improved = [r for r in results if r["first_statistical_degree_in_declared_grid"] is not None and
                (r["first_deterministic_degree_in_declared_grid"] is None or
                 r["first_statistical_degree_in_declared_grid"] < r["first_deterministic_degree_in_declared_grid"])]
    print(json.dumps({"output": str(args.json_out), "prior_cards_reproduced": len(inputs),
                      "tuples": len(results), "points": 10 * len(results), "smaller_statistical_degree_tuples": len(improved)}))


if __name__ == "__main__":
    main()
