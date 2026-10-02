#!/usr/bin/env python3
"""E98 finite-sample applicability audit and pinned budget-aware DH follow-up."""

# ruff: noqa: E402 -- standalone research/Sage runner.

from argparse import ArgumentParser
from datetime import UTC, datetime
from fractions import Fraction
from functools import partial
import json
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.target_prefix_security_isolated_lab import REVISION, git, isolated_call, sha
from experiments.bfv_search_lab import estimator_sample_budget as audit


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--estimator", type=Path, required=True)
    parser.add_argument("--attack-timeout-s", type=int, default=10)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    if not 1 <= args.attack_timeout_s <= 10:
        parser.error("Outside the registered isolated cost budget")
    estimator = args.estimator.resolve()
    if git(estimator, "rev-parse", "HEAD") != REVISION or git(estimator, "diff", "--name-only", "HEAD"):
        raise ValueError("Estimator tracked source is not unchanged pinned revision")
    estimator_hashes = {p: sha(estimator / p) for p in git(estimator, "ls-files").splitlines()}
    sys.path.insert(0, str(estimator))
    from sage.all import QQ, RR, ZZ, sqrt
    from sage.env import SAGE_VERSION
    from estimator import LWE, ND, RC, conf
    from estimator.lwe_dual import dual_hybrid as limited_hybrid

    raw_paths = [ROOT / f"benchmarks/results/publication-switch-key-prefix-security-{cohort}-20261002.json"
                 for cohort in ("01", "02")]
    sources = [json.loads(p.read_text()) for p in raw_paths]
    assert all(s["complete"] and len(s["profiles"]) == 44 for s in sources)
    paths = [Path(__file__), *raw_paths, ROOT / "benchmarks/target_prefix_security_isolated_lab.py",
             ROOT / "experiments/bfv_search_lab/estimator_sample_budget.py",
             ROOT / "experiments/bfv_search_lab/test_estimator_sample_budget.py",
             ROOT / "docs/research/switch-key-sample-budget-preregistration-20261002.md"]
    descriptor = sources[0]["Xe_descriptor"]
    variance, density = Fraction(descriptor["variance_exact"]), Fraction(descriptor["nonzero_density_exact"])
    xe = ND.NoiseDistribution(stddev=RR(sqrt(QQ(variance.numerator)/variance.denominator)), mean=0,
                              bounds=tuple(descriptor["bounds"]), is_Gaussian_like=False,
                              _density=QQ(density.numerator)/density.denominator)
    output = {"utc": datetime.now(UTC).isoformat(), "command": sys.argv,
              "kind": "E98_registered_original_sample_budget_applicability_and_DH_followup",
              "git_head": git(ROOT, "rev-parse", "HEAD"), "python": platform.python_version(), "sage": SAGE_VERSION,
              "source_sha256": {str(p.relative_to(ROOT)): sha(p) for p in paths},
              "estimator_revision": REVISION, "estimator_tracked_sha256": estimator_hashes,
              "model": "MATZOV-classical reduction costs; distinct finite-sample DH algorithm",
              "algorithm": "estimator.lwe_dual.dual_hybrid, exhaustive-search, opt_step8, fftFalse, noMITM",
              "configured_max_beta": conf.max_beta, "per_call_timeout_s": args.attack_timeout_s,
              "Xe_descriptor": descriptor, "original_default_alias": "LWE.dual_hybrid=matzov; cost defaults m=n instead of params.m",
              "scope": "Sample-budget applicability only. Exact gapped error summary; algorithm's reduced Gaussian/simulation heuristics unchanged. Not complete noise/algorithm/security/quantum/key-graph/private assurance or executed attack.",
              "original_cohort_audits": [[audit.audit(c) for c in s["profiles"]] for s in sources],
              "complete": False, "profiles": []}
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    def save():
        args.json_out.write_text(json.dumps(output, indent=2)+"\n")
    save()
    function = partial(limited_hybrid, red_cost_model=RC.MATZOV, opt_step=8, fft=False, mitm_optimization=False)
    for c, old in zip(sources[0]["profiles"], output["original_cohort_audits"][0], strict=True):
        q, n, samples = c["exact_Q"], c["target_prefix"], c["available_independent_samples"]
        params = LWE.Parameters(n=n, q=ZZ(q), Xs=ND.Uniform(-1, 1), Xe=xe, m=samples)
        assert params.normalize() == params and xe.stddev > params.Xs.stddev
        print(f"N={c['source_N']} p={n} Qbits={q.bit_length()} skip={c['skipped_C2_levels']} m={samples} limited-DH", flush=True)
        result = isolated_call(function, params, args.attack_timeout_s)
        budget = audit.check("dual_hybrid_limited", result, n, samples)
        minima = [v for v in (old["applicable_original_partial_minimum"],
                             result.get("log2_rop") if budget["applicable_finite_cost"] else None) if v is not None]
        output["profiles"].append({k: v for k, v in c.items() if k not in (
            "attacks", "minimum_returned_log2_rop", "below_128_in_named_heuristic_screen")} | {
                "original_budget_audit": old, "limited_DH": result, "limited_DH_budget_check": budget,
                "qualified_minimum_returned_log2_rop": min(minima) if minima else None,
                "qualified_below128": bool(minima and min(minima) < 128), "parameter_approved": False})
        save()
    output["complete"] = True
    save()
    print(json.dumps({"output": str(args.json_out), "profiles": 44,
                      "qualified_below128": sum(c["qualified_below128"] for c in output["profiles"]),
                      "parameter_approvals": 0}))


if __name__ == "__main__":
    main()
