#!/usr/bin/env python3
"""Q70 registered public factorization/known-control screen; no HE timings."""

# ruff: noqa: E402 -- standalone research runner.

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import random
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import tensor_gadget_factorization as factor
from experiments.bfv_search_lab.test_tensor_gadget_factorization import trial


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out, marker = (
        args.out_dir / "Q70-factorization.json",
        args.out_dir / "Q70-factorization-started.json",
    )
    if out.exists() or marker.exists():
        parser.error("New immutable run directory required")
    registration = (
        ROOT / "docs/research/gadget-cut-factorization-registration-20261003.json"
    )
    reg = json.loads(registration.read_text())
    refinement = (
        ROOT / "docs/research/gadget-cut-factorization-fused-registration-20261003.json"
    )
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
            "tensor_gadget_factorization",
            "test_tensor_gadget_factorization",
            "tensor_gadget_seed",
            "propagated_gadget_bgv",
            "native_boundary_oracle",
        )
    )
    result = metadata(paths)
    marker.write_text(
        json.dumps(
            {
                "utc": datetime.now(UTC).isoformat(),
                "registration_sha256": hashlib.sha256(
                    registration.read_bytes()
                ).hexdigest(),
                "source_sha256": result["source_sha256"],
                "no_HE_keys_generated": True,
            },
            indent=2,
        )
        + "\n"
    )
    with tarfile.open(
        args.out_dir / "Q70-factorization-executed-source.tar.gz", "x:gz"
    ) as archive:
        for p in paths:
            archive.add(p, arcname=str(p.relative_to(ROOT)))
    trials = []
    for context in reg["contexts"]:
        n, bits = context["N"], context["bits"]
        q = context["Q"] if "Q" in context else int(context["Q_hex"], 16)
        rng = random.Random(reg["public_seed"] + n + bits)
        trials.extend(trial(n, q, bits, rng) for _ in range(reg["trials_per_context"]))
    result.update(
        kind="Q70_grouped_power_and_shared_composite_key_known_control",
        registration_sha256=hashlib.sha256(registration.read_bytes()).hexdigest(),
        refinement_sha256=hashlib.sha256(refinement.read_bytes()).hexdigest(),
        trials=trials,
        models=factor.resource_models(reg["large_models"], reg["selected_tensor_bits"]),
        scope="Finite exact public algebra and sufficient-state/pointwise operation models. No fresh HE keys, native/controller change, timings, originality acceptance or production security.",
    )
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                "trials": len(trials),
                "seed_coefficients": sum(t["seed_coefficients"] for t in trials),
                "switch_coefficients": sum(t["switch_coefficients"] for t in trials),
                "models": result["models"],
            }
        )
    )


if __name__ == "__main__":
    main()
