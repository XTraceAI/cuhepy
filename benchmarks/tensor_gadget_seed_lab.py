#!/usr/bin/env python3
"""Q69 fixed public tensor-seed/mixed-gadget screen; no HE measurements."""

# ruff: noqa: E402 -- standalone research runner.

from datetime import UTC, datetime
import argparse
import hashlib
import json
from pathlib import Path
import random
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import tensor_gadget_seed as seed
from experiments.bfv_search_lab.test_tensor_gadget_seed import trial


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out, marker = args.out_dir / "Q69-screen.json", args.out_dir / "Q69-started.json"
    if out.exists() or marker.exists():
        parser.error("New immutable run directory required")
    registration = ROOT / "docs/research/gadget-cut-followup-registration-20261003.json"
    reg = json.loads(registration.read_text())
    paths = [
        Path(__file__),
        registration,
        ROOT / "benchmarks/dictionary_layout_lab.py",
        ROOT / "src/cuhepy/bfv/scheme.py",
    ]
    paths.extend(
        ROOT / f"experiments/bfv_search_lab/{name}.py"
        for name in (
            "tensor_gadget_seed",
            "test_tensor_gadget_seed",
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
                "no_HE_key_generation": True,
            },
            indent=2,
        )
        + "\n"
    )
    with tarfile.open(args.out_dir / "Q69-executed-source.tar.gz", "x:gz") as archive:
        for p in paths:
            archive.add(p, arcname=str(p.relative_to(ROOT)))
    trials = []
    for n in reg["tiny_rings"]:
        rng = random.Random(reg["public_seed"] + n)
        trials.extend(
            trial(
                n,
                rng,
                reg["tiny_Q"],
                reg["tiny_seed_digit_bits"],
                reg["tiny_relin_digit_bits"],
            )
            for _ in range(reg["trials_per_ring"])
        )
    models = [
        m for b in reg["radices"] for m in seed.source_models(reg["source_context"], b)
    ]
    result.update(
        kind="Q69_known_common_gadget_tensor_seed_and_mixed_early_rotation_screen",
        registration_sha256=hashlib.sha256(registration.read_bytes()).hexdigest(),
        public_trials=trials,
        models=models,
        scope="Exact tiny public integer/modular algebra and worst-case fixed-Q/P models. No encrypted cohort, native implementation for these two follow-ups, secure service or originality/usefulness acceptance. Query/index data are canonical public ciphertext components, not plaintext user vectors.",
    )
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                "public_trials": len(trials),
                "models": len(models),
                "passing_model_cards": sum(m["all_guards_pass"] for m in models),
                "feasible_rules": [
                    {
                        k: m[k]
                        for k in (
                            "vectors",
                            "rule",
                            "digit_bits",
                            "removed_source_cuts",
                            "saving_fraction",
                            "compiled_query_matrix_Q_body_bytes",
                        )
                    }
                    for m in models
                    if m["all_guards_pass"]
                ],
            }
        )
    )


if __name__ == "__main__":
    main()
