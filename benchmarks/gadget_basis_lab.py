#!/usr/bin/env python3
"""E99 public gadget-lattice LLL control; no HE timing or private key recovery.

Run with Sage. Integer gadget construction/atom accounting is homemade; only
the standard small public-basis reduction is an external comparison tool.
"""

# ruff: noqa: E402 -- standalone Sage research runner.

from argparse import ArgumentParser
from datetime import UTC, datetime
import hashlib
import json
from math import gcd
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sage.all import QQ, ZZ, matrix
from sage.env import SAGE_VERSION
from experiments.bfv_search_lab import gadget_dependency as lab


def info(q, rows):
    g = lab.gram(rows)
    return {"rows": rows, "noise_Gram_for_independent_CBD_atoms": g,
            "eta21_covariance": [[str(21*QQ(x)/2) for x in row] for row in g],
            "squared_row_norms": [g[j][j] for j in range(len(rows))],
            "worst_absolute_CBD21_row_noise_bounds": [21*sum(map(abs, row)) for row in rows],
            "individual_uniform_mask_rows": [lab.mask_surjective(q, (row,)) for row in rows],
            "joint_uniform_independent_masks": lab.mask_surjective(q, rows),
            "subset_inventory": lab.independent_inventory(q, rows),
            "correlated_or_sparse_secret_cost_model_executed": False}


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    source = ROOT / "benchmarks/results/publication-adaptive-query-phase-screen-20261002.json"
    old = ROOT / "benchmarks/results/publication-owner-bound-rounding-screen-20261002.json"
    contexts = sorted({(c["policy"]["n"], c["modeled_original_depth_one_Q"])
                       for c in json.loads(source.read_text())["cards"] if c["policy"]["max_fresh_queries"] == 4096})
    assert len(contexts) == 6
    assert set(contexts) == {(c["source_N"], c["Q"]) for c in json.loads(old.read_text())["cards"] if c["lifetime"] == 4096}
    inventory, shapes = [], set()
    for n, q in contexts:
        assert gcd(q, 257) == 1
        levels, capacity = 0, 1
        while capacity < q:
            capacity *= 257
            levels += 1
        for skip in (0, 1):
            inventory.append({"N": n, "Q": q, "radix": 257, "eta": 21, "C2_skip": skip,
                              "source_family_retained_levels": [levels, levels-skip],
                              "retained_source_multiplier_unit_mod_Q": True,
                              "all_adjacent_uniform_mask_polynomials": 2*levels-skip-2,
                              "disjoint_original_CBD_IID_polynomials": levels//2+(levels-skip)//2,
                              "not_multiplied_by4096_queries": True})
            shapes.update(((q, levels), (q, levels-skip)))
    controls = []
    for q, levels in sorted(shapes):
        gadget = tuple(257**j for j in range(levels))
        ordinary = lab.adjacent(levels, 257)
        assert lab.mask_surjective(q, ordinary)
        choices = (("canonical_kernel", lab.canonical_basis(q, 257, levels)),
                   ("standard_unsigned_Q_digits", lab.modular_basis(q, 257, levels, balanced=False)),
                   ("standard_balanced_Q_digits", lab.modular_basis(q, 257, levels)))
        reductions = []
        for name, rows in choices:
            original = matrix(ZZ, rows)
            assert abs(int(original.det())) == q == abs(lab.determinant(rows))
            reduced, transform = original.LLL(delta=QQ(99)/100, algorithm="fpLLL:proved", transformation=True)
            assert transform*original == reduced and abs(int(transform.det())) == 1
            after = tuple(tuple(int(x) for x in row) for row in reduced.rows())
            assert abs(lab.determinant(after)) == q
            source_forms = [sum(a*b for a, b in zip(row, gadget, strict=True)) for row in after]
            assert all(x % q == 0 for x in source_forms)
            before_gram = original*original.transpose()
            assert reduced*reduced.transpose() == transform*before_gram*transform.transpose()
            reductions.append({"standard_control": name, "before": info(q, rows), "after_LLL": info(q, after),
                               "unimodular_row_transform": [[int(x) for x in row] for row in transform.rows()],
                               "integer_source_forms_after": source_forms,
                               "kernel_determinant_Q_and_exact_Gram_transform_verified": True})
        controls.append({"Q": q, "radix": 257, "retained_levels": levels,
                         "all_adjacent": info(q, ordinary), "controls": reductions,
                         "strong_generic_compiler_has_same_atom_rank_noise_and_resources": True})
    paths = [Path(__file__), source, old, ROOT / "experiments/bfv_search_lab/gadget_dependency.py",
             ROOT / "docs/research/gadget-dependency-preregistration-20261002.md"]
    output = {"utc": datetime.now(UTC).isoformat(), "command": sys.argv,
              "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "python": platform.python_version(), "platform": platform.platform(), "Sage": SAGE_VERSION,
              "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
              "kind": "E99_small_public_gadget_basis_control_not_key_recovery_or_HE_timing",
              "public_LLL_options": {"delta": "99/100", "algorithm": "fpLLL:proved", "transformation": True},
              "source_setup_inventory": inventory, "public_basis_shapes": controls,
              "parameter_or_original_main_approval": False,
              "decision": "Known complete gadget/basis/atom control contains the adapter. Small row noise alone does not justify correlated IID counting or security costs; retain exact sample tradeoffs and return to R6."}
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(output, indent=2)+"\n")
    print(json.dumps({"output": str(args.json_out), "inventory": len(inventory),
                      "public_shapes": len(controls), "reductions": sum(len(c["controls"]) for c in controls),
                      "Sage": SAGE_VERSION}))


if __name__ == "__main__":
    main()
