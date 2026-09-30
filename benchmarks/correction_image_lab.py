#!/usr/bin/env python3
"""E36 public-data image-norm intervals and modulus-bound obstructions.

This is analysis of every correction, not online HE timing. Old encryption
gates remain unchanged. Field/discovery decisions reproduce E35's two controls.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata
from benchmarks.field_frontier_lab import public_space
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import correction_image_bounds as bounds
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import folded_dictionary as dictionary


def minimum_bits(n, phase):
    for bits in range(max(16, n.bit_length() + 1), 57):
        try:
            if 2 * phase < fields.modulus(n, bits):
                return bits
        except ValueError:
            continue
    raise ValueError("Modeled phase exceeds bounded modulus search")


def run(args):
    data = fixtures.load(args.dataset, args.cache_dir / fixtures.SOURCES[args.dataset]["member"])
    ids, _ = fixtures.split(data, args.seed)
    rows = [data.rows[i] for i in ids]
    _, order = timed(dictionary.metric_order, rows, data.dimension, 32)
    results = []
    for t in (1153, 193 if data.name == "mushroom" else 257):
        fit_s, groups = timed(fields.fit, rows, data.dimension, order, prime=t, target=32)
        allocate_s, candidate = timed(fields.allocate, groups, rows, 32 if data.name == "mushroom" else 64)
        _, s = public_space(candidate)
        analysis_s, analysis = timed(bounds.space_bounds, s, seed=args.seed)
        generated = bounds.generators(s)
        compared = 0
        # Check the entire generator against the independent established
        # correction API, rather than just a few favorable sampled vectors.
        for coordinate in range(s.dimension):
            e = tuple(int(j == coordinate) for j in range(s.dimension))
            reference = crt.corrections(s, e)
            for short, (variables, image) in zip(reference, generated, strict=True):
                actual = tuple(row[variables.index(coordinate)] if coordinate in variables else 0 for row in image.forms)
                assert actual == tuple(x % t for x in short)
                compared += len(short)
        fresh = t // 2 + t * 21
        phase_lower = fresh * (1 + analysis["uniform_norm_lower"])
        phase_upper = fresh * (1 + analysis["uniform_norm_upper"])
        phase_cube = fresh * (1 + analysis["cube_norm_bound"])
        assert phase_cube == crt.cost(s)["worst_case_phase_bound"]
        entry = {"t": t, "F": s.columns, "h": s.dimension, "W": sum(s.column_degrees),
                 "fit_s_diagnostic": fit_s, "allocation_s_diagnostic": allocate_s, "norm_analysis_s_diagnostic": analysis_s,
                 "entire_generator_coefficients_compared": compared, "analysis": analysis,
                 "phase_bound_from_proved_norm_upper": phase_upper,
                 "lower_limit_of_this_norm_times_fresh_method": phase_lower,
                 "old_cube_phase_bound": phase_cube,
                 "minimum_analytic_q_bits_from_upper_model": minimum_bits(s.layout.context.n, phase_upper),
                 "minimum_analytic_q_bits_from_cube_model": minimum_bits(s.layout.context.n, phase_cube),
                 "can_certify_q32_with_this_upper": 2 * phase_upper < fields.modulus(s.layout.context.n, 32),
                 "q32_impossible_for_this_norm_times_fresh_method": 2 * phase_lower >= fields.modulus(s.layout.context.n, 32),
                 "scope": "A lower limit on this PARTICULAR L1*source-phase bounding method, not a lower bound on actual HE noise. "
                          "Below-32-bit moduli modeled only; no encryption gate relaxed."}
        results.append(entry)
        print(data.name, args.seed, t, "Z/lower/upper/cube", analysis["nonzero_forms"], analysis["uniform_norm_lower"],
              analysis["uniform_norm_upper"], analysis["cube_norm_bound"], "Qbits model",
              entry["minimum_analytic_q_bits_from_cube_model"], entry["minimum_analytic_q_bits_from_upper_model"],
              file=sys.stderr, flush=True)
    return {"dataset": data.name, "split_seed": args.seed, "fixture_sha256": data.sha256,
            "count": len(rows), "dimension": data.dimension, "cases": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--dataset", choices=tuple(fixtures.SOURCES), required=True)
    parser.add_argument("--seed", type=int, default=3001)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    paths = [Path(__file__), ROOT / "benchmarks/field_frontier_lab.py", ROOT / "benchmarks/certified_filter_lab.py",
             ROOT / "benchmarks/dictionary_layout_lab.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "correction_image_bounds", "test_correction_image_bounds", "field_frontier", "crt_query_space", "dyadic_crt",
        "rank_partition", "affine_dictionary", "folded_dictionary", "folded_filter", "binary_fixtures", "crt_noise_budget"))
    report = metadata(paths)
    report.update(kind="uniform_correction_image_bounds", result=run(args),
                  scope="Uniform algebraic norm bounds and explicit lower obstructions; diagnostic CPU analysis only. "
                        "No HE timing, new security profile, parameter assurance or production authorization.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out)}))


if __name__ == "__main__":
    main()
