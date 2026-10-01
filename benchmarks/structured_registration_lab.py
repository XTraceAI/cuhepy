#!/usr/bin/env python3
"""E68 distinct-field registration/projection identities and retained counts.

Ideal trusted state only: no outer encryption, packing, extraction or proof.
"""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import structured_operator_oracle as operator
from experiments.bfv_search_lab import structured_registration_oracle as registration


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator-raw", type=Path, default=ROOT / "benchmarks/results/publication-structured-operator-screen-20260930.json")
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new immutable result path")
    cases = []
    for n, degrees in ((8, (1, 2)), (16, (2, 4)), (32, (1, 4, 8))):
        rng, q, outer = random.Random(68071 + n), 97, 65537
        generators = tuple(tuple(tuple(rng.randrange(-q//2 + 1, q//2 + 1) for _ in range(n))
                                 for _ in range(2)) for _ in degrees)
        op = operator.Operator(n, q, 1, degrees, generators)
        crs = tuple(tuple(rng.randrange(outer) for _ in range(3)) for _ in range(op.width))
        for rows in (tuple(range(op.rows)), tuple(i for i in range(op.rows) if i % 3 != 0)):
            c = tuple(tuple(rng.randrange(2) for _ in rows) for _ in range(4))
            state = registration.registration(op, crs, c, outer, b"r" * 32, selected_rows=rows)
            assert registration.check_registration(state, state.fingerprints, state.binding)
            queries = []
            # Independently build signed entries, without operator.forward.
            dense = []
            for output in rows:
                block, position = divmod(output, n)
                row = []
                for degree, column in zip(degrees, generators, strict=True):
                    for k in range(degree):
                        shift = k*(n//degree)
                        row.append(column[block][(position-shift) % n] * (1 if position >= shift else -1))
                dense.append(tuple(row))
            expected_h = tuple(tuple(sum(a*b for a, b in zip(row, col, strict=True)) % outer
                                     for col in zip(*crs, strict=True)) for row in dense)
            expected_z = tuple(tuple(sum(beta*row[j] for beta, row in zip(challenge, dense, strict=True))
                                     for j in range(op.width)) for challenge in c)
            assert state.hint == expected_h and state.fingerprints == expected_z
            for _ in range(8):
                u = tuple(rng.randrange(outer) for _ in range(op.width))
                output = tuple(sum(a*b for a, b in zip(row, u, strict=True)) % outer for row in dense)
                assert registration.check_online_identity(state, u, output)
                queries.append({"exact_identity": True})
            cases.append({"n": n, "degrees": degrees, "inner_q": q, "outer_q": outer,
                          "full_rows": op.rows, "selected_rows": len(rows), "width": op.width,
                          "d_algebra_only": 3, "kappa_toy": 4, "honest_Z_bound": state.honest_norm_bound,
                          "owner_public_binding": state.binding, "independent_H_Z_exact": True, "queries": queries})
    retained = json.loads(args.operator_raw.read_text())["recorded_geometry_count_screens"]
    screens = []
    for profile in retained:
        count = registration.count_screen(rows=profile["rows"], width=profile["width"], columns=profile["columns"],
                                          inner_q=profile["inner_q"], outer_q=2**61-1, d=2048)
        screens.append({"dataset": profile["dataset"], "profile": profile["profile"],
                        "demonstration_outer_q": 2**61-1, "d_count_only": 2048, "ell_count_only": 3,
                        "parameter_choice_assured": False, "count_screen": count})
    paths = [Path(__file__), ROOT / "experiments/bfv_search_lab/structured_registration_oracle.py",
             ROOT / "experiments/bfv_search_lab/structured_operator_oracle.py",
             ROOT / "benchmarks/dictionary_layout_lab.py", args.operator_raw]
    result = metadata(paths)
    result.update(kind="structured_distinct_field_registration_algebra_and_object_counts",
                  cases=cases, toy_exact_public_identity_queries=sum(len(c["queries"]) for c in cases),
                  literal_object_count_screens=screens,
                  gadget_factorization_controls=[registration.digit_factorization_counterexample(b, 97) for b in (4, 16)],
                  scope="Implicit H=D A / Z=C D and projected identities against signed integer matrix reference. "
                        "No query encryption, output privacy, packing, extraction, soundness/protocol proof or security parameter choice. "
                        "Retained-profile counts include known norm-packed Hprime control; neither H nor Hprime is a universal storage lower bound. "
                        "Per-limb gadget nonlinearity rejects only the naive D-independent packing factorization.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "registration_cases": len(cases),
                      "exact_identity_queries": result["toy_exact_public_identity_queries"], "geometry_screens": len(screens)}))


if __name__ == "__main__":
    main()
