#!/usr/bin/env python3
"""E96 hard-isolated Sage estimates on genuine independent known-prefix zero samples.

This runs a cost estimator, not a lattice/secret-recovery attack. Its estimates
are heuristics and omissions/beta caps remain visible. No parameter is approved.
"""

# ruff: noqa: E402 -- standalone research/Sage runner.

from argparse import ArgumentParser
from datetime import UTC, datetime
from functools import partial
import hashlib
import json
from pathlib import Path
import platform
import multiprocessing
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.bfv_search_lab.target_prefix_samples import sample_count


REVISION = "53da5982597709ba0fdf94ea37a84d822310fd84"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root).decode().strip()


def isolated_call(function, params, budget):
    """Kill only this owned worker; Sage/C cannot swallow the parent deadline."""
    def calculate(send):
        from sage.all import log, oo
        try:
            cost = function(params)
            rop = cost.get("rop", oo)
            send.send({"status": "finite_heuristic" if rop not in (oo, 0) else "not_finite_or_not_applicable",
                       "log2_rop": float(log(rop, 2)) if rop not in (oo, 0) else None,
                       "cost": {str(k): str(v) for k, v in cost.items()}})
        except Exception as error:
            send.send({"status": "timeout_or_failed", "error": f"{type(error).__name__}: {error}"})
        finally:
            send.close()
    context = multiprocessing.get_context("fork")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=calculate, args=(send,))
    start = time.monotonic()
    process.start()
    send.close()
    process.join(budget)
    if process.is_alive():
        process.terminate()
        process.join(2)
        if process.is_alive():
            process.kill()
            process.join(2)
        if process.is_alive():
            raise RuntimeError("Owned estimator worker did not stop")
        result = {"status": "timeout_or_failed", "error": "Parent-enforced estimator deadline"}
    else:
        try:
            result = receive.recv() if receive.poll() else {"status": "timeout_or_failed", "error": "Worker exited without result"}
        except EOFError:
            result = {"status": "timeout_or_failed", "error": "Worker pipe closed without result"}
    receive.close()
    result["worker_exit_code"] = process.exitcode
    result["estimator_execution_seconds_NOT_crypto_runtime"] = time.monotonic()-start
    return result


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--estimator", type=Path, required=True)
    parser.add_argument("--prefixes", type=int, nargs="+", default=[512, 1024, 2048, 4096])
    parser.add_argument("--lifetime", type=int, default=4096)
    parser.add_argument("--attack-timeout-s", type=int, default=10)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh result path; completed results are immutable")
    if (not args.prefixes or len(set(args.prefixes)) != len(args.prefixes)
            or any(p not in (512, 1024, 2048, 4096) for p in args.prefixes)
            or args.lifetime != 4096 or not 1 <= args.attack_timeout_s <= 10):
        parser.error("Outside the registered known-prefix screen")
    estimator = args.estimator.resolve()
    if (git(estimator, "rev-parse", "HEAD") != REVISION
            or subprocess.run(["git", "diff", "--exit-code", "HEAD"], cwd=estimator, capture_output=True).returncode):
        raise ValueError("Estimator tracked source is not the pinned unchanged revision")
    estimator_hashes = {p: sha(estimator / p) for p in git(estimator, "ls-files").splitlines()}
    sys.path.insert(0, str(estimator))
    from sage.all import ZZ
    from sage.env import SAGE_VERSION
    from estimator import LWE, ND, RC, conf

    source_path = ROOT / "benchmarks/results/publication-adaptive-query-phase-screen-20261002.json"
    contexts = {}
    for c in json.loads(source_path.read_text())["cards"]:
        if c["policy"]["max_fresh_queries"] == args.lifetime:
            key = (c["policy"]["n"], c["modeled_original_depth_one_Q"])
            contexts.setdefault(key, []).append({"dataset": c["dataset"], "profile": c["profile"]})
    assert len(contexts) == 6
    paths = (Path(__file__), ROOT / "experiments/bfv_search_lab/target_prefix_samples.py",
             ROOT / "experiments/bfv_search_lab/test_target_prefix_samples.py",
             ROOT / "docs/research/target-prefix-security-preregistration-20261002.md",
             ROOT / "docs/research/target-prefix-isolation-preregistration-20261002.md", source_path)
    output = {"utc": datetime.now(UTC).isoformat(), "command": sys.argv,
              "kind": "E96_isolated_known_prefix_independent_zero_sample_cost_screen",
              "git_head": git(ROOT, "rev-parse", "HEAD"), "python": platform.python_version(),
              "sage": SAGE_VERSION, "source_sha256": {str(p.relative_to(ROOT)): sha(p) for p in paths},
              "estimator_revision": REVISION, "estimator_tracked_sha256": estimator_hashes,
              "model": "MATZOV-classical", "shape": "gsa", "configured_max_beta": conf.max_beta,
              "published_zero_lifetime": args.lifetime, "per_call_timeout_s": args.attack_timeout_s,
              "secret": "IID uniform ternary at p publicly unknown prefix positions; suffix publicly zero",
              "error": "CBD_eta21, variance10.5; negated zero error has identical law",
              "independent_sample_relation": "Disjoint no-wrap mask windows per honest fresh zero, not all ring rotations",
              "scope": "Generic LWE attack-cost heuristics on an exact independent sample subset. No lattice reduction or recovery executed; no quantum, complete attacks, parameter, key-graph, sampling/proof/private assurance.",
              "execution_isolation": "parent hard deadline for forked estimator workers",
              "complete": False, "profiles": []}
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    def save():
        args.json_out.write_text(json.dumps(output, indent=2)+"\n")
    functions = {
        "usvp": partial(LWE.primal_usvp, red_cost_model=RC.MATZOV, red_shape_model="gsa"),
        "bdd": partial(LWE.primal_bdd, red_cost_model=RC.MATZOV, red_shape_model="gsa"),
        "dual": partial(LWE.dual, red_cost_model=RC.MATZOV),
        "dual_hybrid": partial(LWE.dual_hybrid, red_cost_model=RC.MATZOV),
    }
    save()
    for (n, q), labels in contexts.items():
        assert ZZ(q).is_prime()
        for prefix in args.prefixes:
            if prefix > n:
                continue
            count = sample_count(n, prefix, args.lifetime)
            params = LWE.Parameters(n=prefix, q=ZZ(q), Xs=ND.Uniform(-1, 1), Xe=ND.CenteredBinomial(21), m=count)
            record = {"source_ring_N": n, "exact_Q": q, "Q_bits": q.bit_length(), "labels": labels,
                      "unknown_target_prefix": prefix, "independent_rows_per_zero": n//prefix,
                      "available_independent_samples": count, "params": repr(params), "attacks": {}}
            output["profiles"].append(record)
            save()
            for name, function in functions.items():
                print(f"N={n} p={prefix} Qbits={q.bit_length()} m={count} {name}", flush=True)
                record["attacks"][name] = isolated_call(function, params, args.attack_timeout_s)
                save()
            finite = [v["log2_rop"] for v in record["attacks"].values() if v.get("log2_rop") is not None]
            record["minimum_returned_log2_rop"] = min(finite) if finite else None
            record["below_128_in_named_heuristic_screen"] = bool(finite and min(finite) < 128)
            record["parameter_approved"] = False
            save()
    output["complete"] = True
    save()
    print(json.dumps({"output": str(args.json_out), "profiles": len(output["profiles"]),
                      "below_128": sum(p["below_128_in_named_heuristic_screen"] for p in output["profiles"]),
                      "p512_all_fail_named_screen": all(p["below_128_in_named_heuristic_screen"] for p in output["profiles"] if p["unknown_target_prefix"] == 512),
                      "parameter_approvals": 0}))


if __name__ == "__main__":
    main()
