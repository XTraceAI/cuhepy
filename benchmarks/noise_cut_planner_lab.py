#!/usr/bin/env python3
"""Q70 registered exact finite planner/control screen, not HE timings."""

# ruff: noqa: E402 -- standalone research runner.

import argparse
from dataclasses import asdict
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import noise_cut_oracle as oracle
from experiments.bfv_search_lab import noise_cut_planner as planner


def terminal(q, t):
    p = (1 << 25) - 1
    p -= (p - q) % t
    return p if p % 2 else p - t


def profile(n, d, bits, q, t, eta, p):
    qb, ib = t // 2 + t * eta, t // 2 + t * eta * (2 * n + 1)
    relin = t * eta * n * ((q.bit_length() + 29) // 30) * ((1 << 30) - 1)
    return planner.Profile(n, d, q, p, t, eta, bits, n * qb * ib + relin)


def objective(value):
    return (
        -value.removed,
        value.work,
        value.seeds,
        value.digit_key_levels.bit_count(),
        value.peak,
    )


def label(value):
    return {
        name: getattr(value, name)
        for name in ("state", "peak", "removed", "seeds", "work", "digit_key_levels")
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--part", choices=("tiny", "large"), required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    marker, output = args.out_dir / "started.json", args.out_dir / "planner-screen.json"
    if marker.exists() or output.exists():
        parser.error("Fresh immutable run directory required")
    registration = ROOT / "docs/research/gadget-cut-planner-registration-20261003.json"
    reg = json.loads(registration.read_text())
    refinement = ROOT / "docs/research/gadget-cut-planner-refinement-20261003.json"
    paths = [
        Path(__file__),
        registration,
        refinement,
        ROOT / "benchmarks/dictionary_layout_lab.py",
        ROOT / "src/cuhepy/bfv/scheme.py",
    ]
    paths.extend(
        ROOT / f"experiments/bfv_search_lab/{name}.py"
        for name in (
            "noise_cut_planner",
            "noise_cut_oracle",
            "test_noise_cut_planner",
            "test_support_bounds_bgv",
            "support_bounds_bgv",
            "tensor_gadget_seed",
            "propagated_gadget_bgv",
        )
    )
    result = metadata(paths)
    marker.write_text(
        json.dumps(
            {
                "utc": datetime.now(UTC).isoformat(),
                "part": args.part,
                "registration_sha256": hashlib.sha256(
                    registration.read_bytes()
                ).hexdigest(),
                "source_sha256": result["source_sha256"],
                "no_HE_keys_or_timing_cohort": True,
            },
            indent=2,
        )
        + "\n"
    )
    with tarfile.open(args.out_dir / "executed-source.tar.gz", "x:gz") as archive:
        for p in paths:
            archive.add(p, arcname=str(p.relative_to(ROOT)))
    cases = []
    card_dir = args.out_dir / "cards"
    card_dir.mkdir()
    spec = reg[args.part]
    q = int(spec["Q_hex"], 16)
    shapes = (
        [
            (n, d, count)
            for n, d in spec["rings_and_padded"]
            for count in range(1, d + 1)
        ]
        if args.part == "tiny"
        else [(spec["N"], spec["D"], count) for count in spec["tiles"]]
    )
    for n, d, count in shapes:
        for bits in spec["radices"]:
            for allow_seed in spec["seed_modes"]:
                card = {
                    "N": n,
                    "D": d,
                    "tiles": count,
                    "radix_bits": bits,
                    "allow_seed": allow_seed,
                }
                context = profile(
                    n,
                    d,
                    bits,
                    q,
                    spec["t"],
                    spec["eta"],
                    spec.get("P", terminal(q, spec["t"])),
                )
                try:
                    values, stats = planner.frontier(
                        context,
                        count,
                        allow_seed,
                        label_cap=reg["caps"]["pareto_labels_per_subproblem"],
                        merge_cap=reg["caps"]["candidate_merges_per_profile"],
                    )
                    selected = planner.select(values)
                    assert planner.replay(context, selected.plan).peak == selected.peak
                    rows, _, _ = oracle.plan_boxes(context, selected.plan)
                    assert max(rows) == selected.peak
                    card.update(
                        status="complete_declared_grammar",
                        selected=label(selected),
                        ledger=planner.ledger(context, selected),
                        plan=asdict(selected.plan),
                        stats=stats,
                        root_frontier=[label(v) for v in values],
                        residue_envelope=list(rows),
                    )
                    if args.part == "tiny":
                        control, exhaustive_stats = oracle.exhaustive(
                            context,
                            count,
                            allow_seed,
                            cap=spec["independent_exhaustive_max_choices"],
                        )
                        assert objective(control) == objective(selected)
                        peak, coordinates = oracle.symbolic_box_peak(
                            context, selected.plan
                        )
                        assert peak == selected.peak
                        card.update(
                            exhaustive=exhaustive_stats,
                            exact_optimum_matches_generic=True,
                            symbolic_coordinates=coordinates,
                        )
                except planner.PlannerLimit as error:
                    card.update(
                        status="registered_planner_limit_no_exact_optimum",
                        reason=str(error),
                    )
                name = f"n{n}-d{d}-m{count}-b{bits}-s{int(allow_seed)}.json"
                p = card_dir / name
                p.write_text(json.dumps(card, indent=2) + "\n")
                cases.append(
                    {
                        "card": str(p),
                        "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                        **{
                            k: card[k]
                            for k in (
                                "N",
                                "D",
                                "tiles",
                                "radix_bits",
                                "allow_seed",
                                "status",
                            )
                        },
                    }
                )
                print(
                    json.dumps(
                        {
                            **{
                                k: card[k]
                                for k in (
                                    "N",
                                    "D",
                                    "tiles",
                                    "radix_bits",
                                    "allow_seed",
                                    "status",
                                )
                            },
                            "removed": card.get("selected", {}).get("removed"),
                            "merges": card.get("stats", {}).get("candidate_merges"),
                        }
                    ),
                    flush=True,
                )
    result.update(
        kind="Q70_exact_finite_noise_cut_planner_and_known_controls",
        part=args.part,
        registration_sha256=hashlib.sha256(registration.read_bytes()).hexdigest(),
        cases=cases,
        scope="Known-method finite optimization/box-envelope control. No fresh HE keys, native admission, measured server/client performance, production assurance or originality acceptance. Capped cases have no claimed exact optimum.",
    )
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                "completed": len(cases),
                "limits": sum(c["status"].startswith("registered") for c in cases),
                "output": str(output),
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
