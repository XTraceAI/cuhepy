#!/usr/bin/env python3
"""Q70 matched suffix-key cost lowering of immutable completed planner cards."""

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
from benchmarks.noise_cut_planner_lab import profile
from benchmarks.propagated_gadget_encrypted_lab import write_new
from experiments.bfv_search_lab import noise_cut_lowering as lowering
from experiments.bfv_search_lab import noise_cut_planner as planner


def plan_from_dict(value):
    fields = {"level", "count", "mode", "retain", "left", "right"}
    if type(value) is not dict or set(value) != fields:
        raise ValueError("Exact serialized plan fields required")
    return planner.Plan(
        value["level"],
        value["count"],
        value["mode"],
        value["retain"],
        None if value["left"] is None else plan_from_dict(value["left"]),
        None if value["right"] is None else plan_from_dict(value["right"]),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    marker, out = args.out_dir / "started.json", args.out_dir / "lowering-screen.json"
    if marker.exists() or out.exists():
        parser.error("Fresh immutable output directory required")
    registration = (
        ROOT / "docs/research/gadget-cut-suffix-lowering-registration-20261003.json"
    )
    original_registration = (
        ROOT / "docs/research/gadget-cut-planner-registration-20261003.json"
    )
    spec = json.loads(original_registration.read_text())["large"]
    paths = [
        Path(__file__),
        registration,
        original_registration,
        ROOT / "benchmarks/dictionary_layout_lab.py",
        ROOT / "benchmarks/noise_cut_planner_lab.py",
        ROOT / "benchmarks/propagated_gadget_encrypted_lab.py",
    ]
    paths.extend(
        ROOT / f"experiments/bfv_search_lab/{name}.py"
        for name in (
            "noise_cut_lowering",
            "noise_cut_planner",
            "noise_cut_oracle",
            "tensor_gadget_seed",
            "propagated_gadget_bgv",
            "test_support_bounds_bgv",
            "support_bounds_bgv",
        )
    )
    result = metadata(paths)
    source = json.loads(args.input.read_text())
    inputs = [
        {
            "file": str(args.input),
            "sha256": hashlib.sha256(args.input.read_bytes()).hexdigest(),
        }
    ]
    for card in source["cases"]:
        body = Path(card["card"]).read_bytes()
        assert hashlib.sha256(body).hexdigest() == card["sha256"]
        inputs.append({"file": card["card"], "sha256": card["sha256"]})
    write_new(
        marker,
        json.dumps(
            {
                "utc": datetime.now(UTC).isoformat(),
                "source_sha256": result["source_sha256"],
                "registration_sha256": hashlib.sha256(
                    registration.read_bytes()
                ).hexdigest(),
                "input_receipts_before_lowering": inputs,
                "no_new_search_HE_keys_or_timing": True,
            },
            indent=2,
        ).encode()
        + b"\n",
    )
    with tarfile.open(args.out_dir / "executed-source.tar.gz", "x:gz") as archive:
        for path in paths:
            archive.add(path, arcname=str(path.relative_to(ROOT)))
    cases = []
    for card in source["cases"]:
        raw = json.loads(Path(card["card"]).read_text())
        entry = {k: raw[k] for k in ("N", "D", "tiles", "radix_bits", "allow_seed")}
        entry["input_card"] = card
        if raw["status"] != "complete_declared_grammar":
            entry.update(
                status="ineligible_parent_limit_no_optimum", reason=raw["reason"]
            )
            cases.append(entry)
            continue
        assert (raw["N"], raw["D"]) == (spec["N"], spec["D"])
        context = profile(
            raw["N"],
            raw["D"],
            raw["radix_bits"],
            int(spec["Q_hex"], 16),
            spec["t"],
            spec["eta"],
            spec["P"],
        )
        plan = plan_from_dict(raw["plan"])
        original = planner.replay(context, plan)
        assert (
            original.peak,
            original.removed,
            original.seeds,
            original.work,
        ) == tuple(raw["selected"][k] for k in ("peak", "removed", "seeds", "work"))
        value, ledger, rows = lowering.lower(context, plan)
        entry.update(
            status="complete_safe_lowering"
            if context.safe(value.peak)
            else "unsafe_lowering_preserved",
            original_uniform_ledger=raw["ledger"],
            lowered_ledger=ledger,
            changed_phase_envelope=value.peak != original.peak,
            original_plan_unchanged=True,
            profile=asdict(context),
            residue_envelope=rows,
        )
        cases.append(entry)
    result.update(
        kind="Q70_registered_known_suffix_lowering_cost_control",
        input_receipts=inputs,
        cases=cases,
        completed_lowering_models=sum(
            c["status"] == "complete_safe_lowering" for c in cases
        ),
        unsafe_models=sum(c["status"] == "unsafe_lowering_preserved" for c in cases),
        inherited_parent_limits=sum(
            c["status"] == "ineligible_parent_limit_no_optimum" for c in cases
        ),
        scope=json.loads(registration.read_text())["scope"],
    )
    write_new(out, json.dumps(result, indent=2).encode() + b"\n")
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "completed_lowering_models",
                    "unsafe_models",
                    "inherited_parent_limits",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
