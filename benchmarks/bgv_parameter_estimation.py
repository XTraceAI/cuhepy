#!/usr/bin/env python3
"""Pinned Sage/lattice-estimator screening of the *full* E29 BGV ring.

Run with Sage Python, not the SDK venv. The error is CBD_eta, NOT t*CBD_eta:
for a known plaintext sample, multiplying both components by t^{-1} mod Q
normalizes the RLWE equation to that distribution. Small public CRT factors
are never substituted for the dimension of the secret-key ring.

Heuristic generic LWE attack costs are not parameter or protocol assurance.
Failures/missing attacks remain visible; no production profile is approved.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time

ESTIMATOR_REVISION = "53da5982597709ba0fdf94ea37a84d822310fd84"
ROOT = Path(__file__).resolve().parents[1]


def revision(path):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=path,
                          check=True, capture_output=True, text=True).stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estimator", type=Path, required=True)
    parser.add_argument("--n", type=int, nargs="+", required=True)
    parser.add_argument("--q-bits", type=int, nargs="+", default=[32])
    parser.add_argument("--eta", type=int, default=21)
    parser.add_argument("--mode", choices=("full", "rough"), default="full")
    parser.add_argument("--model", choices=("MATZOV-classical", "ADPS16-quantum"), default="MATZOV-classical")
    parser.add_argument("--samples", choices=("N", "unbounded"), default="unbounded")
    parser.add_argument("--attack-timeout-s", type=int, default=45)
    parser.add_argument("--attacks", default="usvp,bdd,dual,dual_hybrid,bkw,bdd_hybrid,bdd_mitm_hybrid,arora-gb")
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    root = args.estimator.resolve()
    if (revision(root) != ESTIMATOR_REVISION or subprocess.run(
            ["git", "diff", "--exit-code", "HEAD"], cwd=root, capture_output=True).returncode):
        raise ValueError("Estimator tracked sources must match the pinned revision")
    if (any(n < 512 or n > 32768 or n & (n - 1) for n in args.n)
            or any(b < 32 or b > 56 for b in args.q_bits) or not 1 <= args.eta <= 64
            or not 1 <= args.attack_timeout_s <= 600
            or (args.mode == "rough" and args.model != "MATZOV-classical")):
        raise ValueError("Invalid bounded profile or rough-mode model override")
    sys.path.insert(0, str(root))
    from sage.all import ZZ, log, oo
    from sage.env import SAGE_VERSION
    from estimator import LWE, ND, RC
    from estimator import conf
    from estimator.reduction import ADPS16

    expected = ("usvp", "bdd", "dual", "dual_hybrid", "bkw", "bdd_hybrid", "bdd_mitm_hybrid", "arora-gb")
    selected = tuple(args.attacks.split(","))
    if len(set(selected)) != len(selected) or set(selected) - set(expected):
        raise ValueError("Unknown/repeated attack selection")
    def timeout(signum, frame):
        raise TimeoutError("Per-attack research time budget exceeded")
    signal.signal(signal.SIGALRM, timeout)

    output = {"schema": 1, "utc": datetime.now(UTC).isoformat(), "command": sys.argv,
              "sdk_revision": revision(ROOT), "sage": SAGE_VERSION, "python": platform.python_version(),
              "estimator_revision": ESTIMATOR_REVISION, "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "estimator_conf_sha256": hashlib.sha256((root / "estimator/conf.py").read_bytes()).hexdigest(),
              "mode": args.mode, "model": "ADPS16-classical/Core-SVP (rough override)" if args.mode == "rough" else args.model,
              "shape_model": "gsa", "configured_max_beta": conf.max_beta,
              "sample_count": args.samples, "secret_distribution": "uniform {-1,0,1}, full encryption ring",
              "attack_selection": selected, "per_attack_time_budget_s": args.attack_timeout_s,
              "error_distribution": f"centered binomial eta={args.eta}, variance={args.eta / 2}",
              "normalization": "Subtract a known message then multiply both ct components by inverse(t) mod Q; error is CBD_eta, not t*CBD_eta.",
              "scope": "Generic independent-sample LWE heuristic screening only. Unlimited independent samples are a conservative model, "
                       "not a proof for correlated RLWE rotations, published-seed SHAKE samples, adaptive protocol transcripts or implementation leakage. "
                       "All returned finite attack costs, missing/failed attacks and beta-limit caveats must be read. "
                       "Quantum ADPS16 is a sensitivity model, not complete quantum assurance. No research profile is production-approved.",
              "profiles": [], "complete": False}
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    for n in args.n:
        for bits in args.q_bits:
            # Same largest-prime NTT search as field_frontier.modulus; using
            # Sage keeps this runner independent of SDK crypto imports.
            q = ((1 << bits) - 2) // (2 * n) * (2 * n) + 1
            while not ZZ(q).is_prime():
                q -= 2 * n
            params = LWE.Parameters(n=n, q=ZZ(q), Xs=ND.Uniform(-1, 1),
                                    Xe=ND.CenteredBinomial(args.eta), m=n if args.samples == "N" else oo)
            record = {"n": n, "q_bits": bits, "q": q, "eta": args.eta, "params": repr(params), "attacks": {}}
            output["profiles"].append(record)
            args.json_out.write_text(json.dumps(output, indent=2) + "\n")
            print(f"Estimating full N={n} Q={q} eta={args.eta} {args.mode}/{args.model}", flush=True)
            start = time.perf_counter()
            try:
                if args.mode == "rough":
                    results = LWE.estimate.rough(params, jobs=1, quiet=True, catch_exceptions=True)
                    expected = ("usvp", "dual_hybrid", "arora-gb")
                else:
                    model = RC.MATZOV if args.model == "MATZOV-classical" else ADPS16(mode="quantum")
                    from functools import partial
                    # Individual calls match the pinned full API's attack
                    # configuration, but checkpoint before/after EVERY call.
                    functions = {
                        "usvp": partial(LWE.primal_usvp, red_cost_model=model, red_shape_model="gsa"),
                        "bdd": partial(LWE.primal_bdd, red_cost_model=model, red_shape_model="gsa"),
                        "dual": partial(LWE.dual, red_cost_model=model),
                        "dual_hybrid": partial(LWE.dual_hybrid, red_cost_model=model),
                        "bkw": LWE.coded_bkw,
                        "bdd_hybrid": partial(LWE.primal_hybrid, mitm=False, babai=False,
                                              red_cost_model=model, red_shape_model="gsa"),
                        "bdd_mitm_hybrid": partial(LWE.primal_hybrid, mitm=True, babai=True,
                                                   red_cost_model=model, red_shape_model="gsa"),
                        "arora-gb": LWE.guess_composition(LWE.arora_gb),
                    }
                    results = {}
                    for name in selected:
                        print(f"  {name}", flush=True)
                        call_start = time.perf_counter()
                        signal.alarm(args.attack_timeout_s)
                        try:
                            cost = functions[name](params)
                            results[name] = cost
                            rop = cost.get("rop", oo)
                            record["attacks"][name] = {
                                "log2_rop": float(log(rop, 2)) if rop not in (oo, 0) else None,
                                "status": "finite_heuristic" if rop not in (oo, 0) else "not_finite_or_not_applicable",
                                "cost": {str(k): str(v) for k, v in cost.items()},
                            }
                        except Exception as error:
                            record["attacks"][name] = {"status": "timeout_or_failed", "error": f"{type(error).__name__}: {error}"}
                        finally:
                            signal.alarm(0)
                        record["attacks"][name]["elapsed_s"] = time.perf_counter() - call_start
                        args.json_out.write_text(json.dumps(output, indent=2) + "\n")
                attacks = {}
                for name, cost in results.items():
                    rop = cost.get("rop", oo)
                    attacks[name] = {"log2_rop": float(log(rop, 2)) if rop not in (oo, 0) else None,
                                     "status": "finite_heuristic" if rop not in (oo, 0) else "not_finite_or_not_applicable",
                                     "cost": {str(k): str(v) for k, v in cost.items()}}
                finite = [a["log2_rop"] for a in attacks.values() if a["log2_rop"] is not None]
                record["attacks"].update({name: {**record["attacks"].get(name, {}), **value} for name, value in attacks.items()})
                record.update(missing_or_failed_attacks=sorted(set(expected) - set(attacks)),
                              minimum_returned_log2_rop=min(finite) if finite else None,
                              parameter_assurance="unreviewed/research-only")
            except Exception as error:
                record.update(error=f"{type(error).__name__}: {error}", parameter_assurance="failed/unreviewed")
            record["elapsed_s"] = time.perf_counter() - start
            args.json_out.write_text(json.dumps(output, indent=2) + "\n")
            print(json.dumps({k: record[k] for k in ("n", "q", "elapsed_s", "minimum_returned_log2_rop") if k in record}), flush=True)
    output["complete"] = True
    args.json_out.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
