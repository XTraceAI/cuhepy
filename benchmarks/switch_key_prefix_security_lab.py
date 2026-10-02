#!/usr/bin/env python3
"""E98 setup-only exact scaled-CBD summary, pinned isolated heuristic estimates."""

# ruff: noqa: E402 -- standalone research/Sage runner.

from argparse import ArgumentParser
from datetime import UTC, datetime
from fractions import Fraction
from functools import partial
import hashlib
import json
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.target_prefix_security_isolated_lab import REVISION, git, isolated_call, sha
from experiments.bfv_search_lab.switch_key_prefix_samples import error_distribution


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--estimator", type=Path, required=True)
    parser.add_argument("--attack-timeout-s", type=int, default=10)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    if not 1 <= args.attack_timeout_s <= 10:
        parser.error("Outside the registered parent-enforced cost budget")
    estimator = args.estimator.resolve()
    if git(estimator, "rev-parse", "HEAD") != REVISION or git(estimator, "diff", "--name-only", "HEAD"):
        raise ValueError("Estimator tracked source is not the pinned unchanged revision")
    estimator_hashes = {p: sha(estimator / p) for p in git(estimator, "ls-files").splitlines()}
    sys.path.insert(0, str(estimator))
    from sage.all import QQ, RR, ZZ, sqrt
    from sage.env import SAGE_VERSION
    from estimator import LWE, ND, RC, conf

    exact_path = ROOT / "benchmarks/results/publication-switch-key-prefix-screen-20261002.json"
    source_path = ROOT / "benchmarks/results/publication-adaptive-query-phase-screen-20261002.json"
    source = json.loads(exact_path.read_text())
    counts, denominator = error_distribution(21, 257)
    variance = Fraction(sum(x*x*c for x, c in counts.items()), denominator)
    density = 1-Fraction(counts[0], denominator)
    mass_sha = hashlib.sha256(json.dumps(sorted(counts.items()), separators=(",", ":")).encode()).hexdigest()
    assert mass_sha == source["error_distribution"]["ordered_integer_mass_sha256"]
    distribution = ND.NoiseDistribution(stddev=RR(sqrt(QQ(variance.numerator)/variance.denominator)), mean=0,
                                        bounds=(min(counts), max(counts)), is_Gaussian_like=False,
                                        _density=QQ(density.numerator)/density.denominator)
    paths = [Path(__file__), ROOT / "benchmarks/target_prefix_security_isolated_lab.py",
             ROOT / "benchmarks/switch_key_prefix_lab.py", exact_path, source_path,
             ROOT / "experiments/bfv_search_lab/switch_key_prefix_samples.py",
             ROOT / "experiments/bfv_search_lab/test_switch_key_prefix_samples.py",
             ROOT / "experiments/bfv_search_lab/target_prefix_samples.py",
             ROOT / "experiments/bfv_search_lab/batched_score_bridge.py",
             ROOT / "docs/research/switch-key-prefix-preregistration-20261002.md"]
    output = {"utc": datetime.now(UTC).isoformat(), "command": sys.argv,
              "kind": "E98_isolated_known_prefix_setup_row_cost_screen",
              "git_head": git(ROOT, "rev-parse", "HEAD"), "python": platform.python_version(), "sage": SAGE_VERSION,
              "source_sha256": {str(p.relative_to(ROOT)): sha(p) for p in paths},
              "estimator_revision": REVISION, "estimator_tracked_sha256": estimator_hashes,
              "model": "MATZOV-classical", "shape": "gsa", "configured_max_beta": conf.max_beta,
              "per_call_timeout_s": args.attack_timeout_s, "source_error_distribution": source["error_distribution"],
              "Xe_descriptor": {"class": "ND.NoiseDistribution", "stddev": str(distribution.stddev),
                                "mean": "0", "variance_exact": str(variance), "bounds": list(distribution.bounds),
                                "is_Gaussian_like": False, "nonzero_density_exact": str(density)},
              "noise_model_limit": "Summary-statistic attack-cost heuristics, not an exact-noise security theorem. Gapped mass/digit structure not proved modeled; tool internal normalization/simulation assumptions unchanged.",
              "secret": "IID uniform ternary in p unknown prefix positions, suffix publicly zero",
              "sample_relation": "Disjoint adjacent honest uniform diagnostic setup rows, then disjoint no-wrap mask windows; not overlapping pairs/all rotations/repeated query samples",
              "scope": "Estimator computations only. No lattice reduction, recovery, quantum/all-attack, seeded-mask, key-graph, protocol/proof or private assurance and no parameter approval.",
              "execution_isolation": "parent hard deadline for serial owned estimator workers",
              "complete": False, "profiles": [], "full_ring_inventory": source["full_ring_inventory"]}
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
    for c in source["profiles"]:
        q, prefix, samples = c["exact_Q"], c["target_prefix"], c["available_independent_samples"]
        assert ZZ(q).is_prime()
        params = LWE.Parameters(n=prefix, q=ZZ(q), Xs=ND.Uniform(-1, 1), Xe=distribution, m=samples)
        record = c | {"params": repr(params), "attacks": {}}
        output["profiles"].append(record)
        save()
        for name, function in functions.items():
            print(f"N={c['source_N']} p={prefix} Qbits={q.bit_length()} skip={c['skipped_C2_levels']} m={samples} {name}", flush=True)
            record["attacks"][name] = isolated_call(function, params, args.attack_timeout_s)
            save()
        finite = [a["log2_rop"] for a in record["attacks"].values() if a.get("log2_rop") is not None]
        record["minimum_returned_log2_rop"] = min(finite) if finite else None
        record["below_128_in_named_heuristic_screen"] = bool(finite and min(finite) < 128)
        record["parameter_approved"] = False
        save()
    assert len(output["profiles"]) == 44
    output["complete"] = True
    save()
    print(json.dumps({"output": str(args.json_out), "profiles": 44,
                      "below_128": sum(c["below_128_in_named_heuristic_screen"] for c in output["profiles"]),
                      "parameter_approvals": 0}))


if __name__ == "__main__":
    main()
