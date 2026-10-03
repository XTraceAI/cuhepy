#!/usr/bin/env python3
"""Q65 bounded public algebra/noise/resource screen, explicitly not HE timings."""

# ruff: noqa: E402 -- standalone research runner.

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import admissible_trace_oracle as admitted
from experiments.bfv_search_lab import propagated_gadget_bgv as propagated
from experiments.bfv_search_lab.test_propagated_gadget_bgv import algebra_trial


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    marker, out = args.out_dir / "Q65-started.json", args.out_dir / "Q65-oracle.json"
    if marker.exists() or out.exists():
        parser.error("New immutable run directory required")
    registration = ROOT / "docs/research/gadget-cut-preregistration-20261003.json"
    paths = [
        Path(__file__),
        registration,
        ROOT / "experiments/bfv_search_lab/propagated_gadget_bgv.py",
        ROOT / "experiments/bfv_search_lab/test_propagated_gadget_bgv.py",
        ROOT / "experiments/bfv_search_lab/native_boundary_oracle.py",
        ROOT / "src/cuhepy/bfv/scheme.py",
    ]
    result = metadata(paths)
    marker.write_text(
        json.dumps(
            {
                "utc": datetime.now(UTC).isoformat(),
                "source_sha256": result["source_sha256"],
                "registration_sha256": hashlib.sha256(
                    registration.read_bytes()
                ).hexdigest(),
            },
            indent=2,
        )
        + "\n"
    )
    reg = json.loads(registration.read_text())["Q65"]
    trials = []
    for n in reg["rings"]:
        rng = random.Random(reg["public_oracle_seed"] + n)
        trials.extend(
            algebra_trial(n, rng, g["Q"], g["digit_bits"])
            for g in reg["gadgets"]
            for _ in range(reg["public_trials_per_ring"])
        )
    profiles = []
    for geometry in reg["large_models"]:
        g = geometry
        n, t, eta, d = g["N"], g["t"], g["eta"], g["D"]
        tiles, groups = (
            (g["vectors"] + n // d - 1) // (n // d),
            (g["vectors"] + n - 1) // n,
        )
        models = []
        for stages in reg["continuation_stages_after_anchor"]:
            per_group = [
                propagated.model(
                    n,
                    int(g["Q_hex"], 16),
                    t,
                    eta,
                    d,
                    min(d, tiles - i * d),
                    g["digit_bits"],
                    t // 2 + t * eta,
                    t // 2 + t * eta * (2 * n + 1),
                    propagated_stages=stages,
                    terminal=g["P"],
                )
                for i in range(groups)
            ]
            models.append(
                {
                    "propagated_stages": stages,
                    "groups": per_group,
                    "Q_and_P_all_groups_guarded": all(
                        m["Q_guard"] and m["terminal_guard"] for m in per_group
                    ),
                    "whole_full_source_and_terminal_Q_body_bytes": sum(
                        m["full_source_and_terminal_Q_body_bytes"] for m in per_group
                    ),
                    "whole_body_saving_bytes": sum(
                        m["body_saving_bytes"] for m in per_group
                    ),
                    "whole_removed_cuts": sum(
                        m["removed_source_cuts"] for m in per_group
                    ),
                    "whole_fused_extra_online_ring_products": sum(
                        m["fused_extra_online_ring_products"] or 0 for m in per_group
                    ),
                }
            )
        profiles.append({"geometry": g, "policies": models})
    result.update(
        kind="Q65_bounded_common_integer_propagation_known_algebra_system_screen",
        registration_sha256=hashlib.sha256(registration.read_bytes()).hexdigest(),
        algebra_trials=trials,
        models=profiles,
        retained_known_negative_controls=admitted.negative_controls(),
        radix_componentwise_negative={
            "B": 16,
            "a": 17,
            "b": 17,
            "componentwise_recomposed": 17,
            "correct_product": 289,
        },
        binary_anchor_negative="(left,right)=(X^h*u,u) and(0,0) have identical minus source0 but different plus2*X^h*u; a plus/input witness must be charged.",
        scope="Exact tiny common-integer/modular/fused relations and public worst-case models only. No HE timings, private/noise-derived admission, secure deployment, original primitive or full native verifier claim.",
    )
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                "out": str(out),
                "algebra_trials": len(trials),
                "switch_relations": sum(t["switches_checked"] for t in trials),
                "modular_coefficients": sum(
                    t["full_modular_coefficients_checked"] for t in trials
                ),
                "fused_correction_coefficients": sum(
                    t["fused_correction_coefficients_checked"] for t in trials
                ),
                "models": [
                    {
                        "vectors": p["geometry"]["vectors"],
                        "policies": [
                            {
                                k: m[k]
                                for k in (
                                    "propagated_stages",
                                    "Q_and_P_all_groups_guarded",
                                    "whole_removed_cuts",
                                    "whole_body_saving_bytes",
                                    "whole_fused_extra_online_ring_products",
                                )
                            }
                            for m in p["policies"]
                        ],
                    }
                    for p in profiles
                ],
            }
        )
    )


if __name__ == "__main__":
    main()
