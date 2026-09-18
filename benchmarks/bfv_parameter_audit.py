#!/usr/bin/env python3
"""Export the actual BFV profile and run a pinned, external lattice estimator.

Use the SDK Python for `manifest`, and a Sage Python for `estimate`.
This reports heuristic attack costs, not a certificate for BFV or its protocol.
It never generates or exports cryptographic keys.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
ESTIMATOR_REVISION = "53da5982597709ba0fdf94ea37a84d822310fd84"


def revision(path: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=path, check=True, capture_output=True, text=True
    ).stdout.strip()


def manifest(profile: str) -> dict[str, Any]:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from cuhepy.hamming.bfv import BFVClient
    from cuhepy.hamming.bfv_assurance import bfv_review_policy, hamming_noise_bound
    from cuhepy.hamming.bfv_security import BFVExecutionPolicy
    from cuhepy.bfv.scheme import _parameter_modulus, _rns_coefficient_primes

    policy = BFVExecutionPolicy() if profile == "original" else bfv_review_policy()
    client = BFVClient(**policy.config(), skip_key_gen=True)
    params = policy.params
    n = params.poly_modulus_degree
    rotations = {pow(3, s % (n // 2), 2 * n) for s in client._rotation_steps()} - {1}
    digits = (
        params.coeff_modulus_bits + params.decomposition_bits - 1
    ) // params.decomposition_bits
    sources = [
        "src/cuhepy/bfv/scheme.py",
        "src/cuhepy/hamming/bfv.py",
        "src/cuhepy/hamming/bfv_security.py",
        "src/cuhepy/hamming/bfv_assurance.py",
        "src/cuhepy/types.py",
    ]
    return {
        "schema": 1,
        "profile": profile,
        "config": policy.config(),
        "q": str(_parameter_modulus(params)),
        "q_primes": _rns_coefficient_primes(n, params.coeff_modulus_bits),
        "secret": {"distribution": "uniform", "inclusive_bounds": [-1, 1]},
        "error": {
            "distribution": "centered_binomial",
            "eta": params.error_eta,
            "variance": params.error_eta / 2,
        },
        "ephemeral_u": {"distribution": "uniform", "inclusive_bounds": [-1, 1]},
        "evaluation_keys": {
            "galois_exponents": sorted(rotations),
            "digits_per_key": digits,
            "key_switch_pairs": (1 + len(rotations)) * digits,
            "note": "Encryptions of gadget-scaled s^2 and automorphic secrets. Ordinary LWE estimates do not justify these circular/key-dependent-message assumptions.",
        },
        "sdk_revision": revision(REPO_ROOT),
        "worst_supported_hamming_bound": hamming_noise_bound(policy, policy.max_vectors).as_dict(),
        "source_sha256": {
            p: hashlib.sha256((REPO_ROOT / p).read_bytes()).hexdigest() for p in sources
        },
    }


def estimate(args: argparse.Namespace) -> dict[str, Any]:
    root = args.estimator.resolve()
    actual_revision = revision(root)
    if actual_revision != ESTIMATOR_REVISION:
        raise ValueError(
            f"Expected reviewed estimator revision {ESTIMATOR_REVISION}, got {actual_revision}"
        )
    if subprocess.run(
        ["git", "diff", "--exit-code", "HEAD"], cwd=root, capture_output=True
    ).returncode:
        raise ValueError("Estimator tracked sources must match the pinned revision")
    data = json.loads(args.manifest.read_text())
    if data["schema"] != 1 or data["secret"] != {
        "distribution": "uniform",
        "inclusive_bounds": [-1, 1],
    }:
        raise ValueError("Unsupported parameter manifest")
    if data["error"]["distribution"] != "centered_binomial":
        raise ValueError("Unsupported error distribution")
    sys.path.insert(0, str(root))
    from sage.all import ZZ, log, oo
    from sage.env import SAGE_VERSION
    from estimator import LWE, ND, RC
    from estimator.reduction import ADPS16

    n, q = data["config"]["poly_modulus_degree"], ZZ(data["q"])
    models = {
        "MATZOV-classical": RC.MATZOV,
        "ADPS16-classical": ADPS16(),
        "ADPS16-quantum": ADPS16(mode="quantum"),
    }
    attacks = {
        "primal_usvp": LWE.primal_usvp,
        "primal_bdd": LWE.primal_bdd,
        "dual": LWE.dual,
        "dual_hybrid": LWE.dual_hybrid,
    }
    selected_models = args.models.split(",")
    selected_attacks = args.attacks.split(",")
    if any(m not in models for m in selected_models) or any(
        a not in attacks for a in selected_attacks
    ):
        raise ValueError("Unknown cost model or attack")
    runs: list[dict[str, Any]] = []
    output = {
        "utc": datetime.now(UTC).isoformat(),
        "sage": SAGE_VERSION,
        "python": platform.python_version(),
        "estimator_revision": actual_revision,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "manifest": data,
        "command": sys.argv,
        "interpretation": "Heuristic generic LWE attack estimates with Gaussian-shape approximation for centered binomial errors. Reports m=N and unbounded independent samples; RLWE structure, evaluation-key assumptions, decryption failures, implementation leakage and protocol attacks are not certified. ADPS16-quantum is a quantum sieving cost sensitivity model, not a complete quantum security analysis. Unlisted attacks are not evaluated.",
        "runs": runs,
        "complete": False,
    }
    for sample_label, samples in (("N", n), ("unbounded", oo)):
        params = LWE.Parameters(
            n=n, q=q, Xs=ND.Uniform(-1, 1), Xe=ND.CenteredBinomial(data["error"]["eta"]), m=samples
        )
        for model_name in selected_models:
            for attack_name in selected_attacks:
                print(
                    f"Estimating {sample_label} samples / {model_name} / {attack_name}", flush=True
                )
                kwargs = {"red_cost_model": models[model_name]}
                if attack_name.startswith("primal"):
                    kwargs["red_shape_model"] = "gsa"
                start = time.perf_counter()
                cost = attacks[attack_name](params, **kwargs)
                record = {
                    "samples": sample_label,
                    "model": model_name,
                    "attack": attack_name,
                    "seconds": time.perf_counter() - start,
                    "log2_rop": float(log(cost["rop"], 2)) if cost["rop"] != oo else None,
                    "cost": {str(k): str(v) for k, v in cost.items()},
                }
                runs.append(record)
                print(json.dumps(record), flush=True)
                args.json_out.write_text(json.dumps(output, indent=2) + "\n")
    output["complete"] = True
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    make = sub.add_parser("manifest")
    make.add_argument("--json-out", type=Path, required=True)
    make.add_argument("--profile", choices=("original", "review"), default="original")
    run = sub.add_parser("estimate")
    run.add_argument("--manifest", type=Path, required=True)
    run.add_argument("--estimator", type=Path, required=True)
    run.add_argument("--json-out", type=Path, required=True)
    run.add_argument("--models", default="MATZOV-classical,ADPS16-classical,ADPS16-quantum")
    run.add_argument("--attacks", default="primal_usvp,primal_bdd,dual,dual_hybrid")
    args = parser.parse_args()
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    output = manifest(args.profile) if args.mode == "manifest" else estimate(args)
    args.json_out.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
