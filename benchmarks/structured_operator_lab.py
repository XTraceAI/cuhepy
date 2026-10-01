#!/usr/bin/env python3
"""E68 structured/digit correctness and optimistic recorded-geometry counts.

No outer protocol, private-query transport, timing win or security parameter
claim. Exact count screens precede expensive dense allocations/acceleration.
"""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import itertools
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import ciphertext_linear_oracle as literal
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import decryption_support as support
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import structured_operator_oracle as structured


def toys():
    cases = []
    descriptors = ((8, ("0", "1"), (1, 1), (7, 1), (0, 1), ()),
                   (16, ("00", "01", "10", "11"), (1,) * 4, (1, 2, 3, 1), (0, 0, 1, 1), ((0,), (1,))),
                   (32, ("0", "10", "11"), (2, 1, 2), (4, 2, 3), (0, 1, 2), ()))
    rng = random.Random(68001)
    for n, paths, features, counts, map_ids, coordinates in descriptors:
        layout = tree.layout(tree.context(n, paths, 17), features, counts)
        s = space.space(layout, map_ids, coordinate_ids=coordinates)
        groups = [[[(-1)**(i+j) for j in range(f)] for i in range(count)]
                  for count, f in zip(counts, features, strict=True)]
        pk, sk = masked.key_gen(s, q_bits=32, eta=1)
        with closing(owner.OwnerClient(pk, sk)) as client:
            index, _ = masked.enroll(s, groups, b"s" * 32, client)
        op, matrix = structured.from_index(index, pk), literal.matrix(index, pk)
        beta = tuple(rng.randrange(op.q) for _ in range(op.rows))
        transpose = structured.adjoint(op, beta)
        assert transpose == tuple(sum(b * row[j] for b, row in zip(beta, matrix.rows, strict=True)) % op.q
                                  for j in range(op.width))
        rows = structured.projected_rows(support.certify(layout))
        projected_beta = structured.project(beta, rows)
        projected_transpose = structured.adjoint(op, structured.projection_adjoint(projected_beta, rows, op.rows))
        query_count, recovered, digest = 0, 0, hashlib.sha256()
        for values in itertools.product((0, 1), repeat=s.dimension):
            forms = literal.alpha(s, values)
            result = structured.forward(op, forms)
            assert result == literal.evaluate(matrix, forms) == literal.independent(index, pk, values)
            assert sum(a*b for a, b in zip(beta, result, strict=True)) % op.q == sum(a*b for a, b in zip(transpose, forms, strict=True)) % op.q
            assert sum(a*b for a, b in zip(projected_beta, structured.project(result, rows), strict=True)) % op.q == sum(a*b for a, b in zip(projected_transpose, forms, strict=True)) % op.q
            for base in (4, 16, 256):
                products = structured.digit_products(op, forms, base)
                assert structured.reconstruct_digit_products(products, base, op.q) == result
            try:
                recovered += structured.recover_public_input(matrix, result) == tuple(x % op.q for x in forms)
            except ValueError:
                pass  # Rank deficiency is recorded, never called privacy.
            digest.update(repr((values, result)).encode())
            query_count += 1
        cases.append({"n": n, "paths": paths, "features": features, "counts": counts,
                      "degrees": op.degrees, "rows": op.rows, "width": op.width,
                      "all_binary_queries": query_count, "all_reference_and_adjoint_digit_equalities": True,
                      "public_full_rank_input_recoveries": recovered, "projected_rows": len(rows),
                      "outputs_sha256": digest.hexdigest(), "q": op.q,
                      "ideal_outer_only": True})
    return cases


def geometry_screens():
    cases, paths = [], []
    for fixture in ("mushroom", "semeion"):
        path = ROOT / f"benchmarks/results/publication-anchor-{fixture}-20260930.json"
        paths.append(path)
        data = json.loads(path.read_text())
        for profile in data["result"]["cases"]:
            cost = profile["cost_model"]
            cases.append((fixture, profile["layout"], int(profile["q"]), cost))
    path = ROOT / "benchmarks/results/publication-connect4-encrypted-controls-20260930.json"
    paths.append(path)
    for profile in json.loads(path.read_text())["cases"]:
        cases.append(("connect4", profile["kind"], int(profile["q"]), profile["geometry"]))
    results = []
    for fixture, label, q, c in cases:
        rows = 2 * c["n"] * c["replies"]
        scans = [structured.digit_screen(rows=rows, width=c["correction_coefficients"],
                                        columns=c["coordinate_columns"], q=q, query_bound=c["t"] // 2,
                                        base=base) for base in (4, 16, 256, 4096, 65536)]
        best = min(scans, key=lambda x: x["optimistic_digit_output_body_bytes"])
        results.append({"dataset": fixture, "profile": label, "inner_q": q, "inner_t": c["t"],
                        "rows": rows, "width": c["correction_coefficients"], "columns": c["coordinate_columns"],
                        "implicit_generator_entries": rows*c["coordinate_columns"],
                        "literal_entries": rows*c["correction_coefficients"],
                        "query_coordinate_count": c["query_coordinates"],
                        "phase_correctness_profile_from_retained_run_not_assurance": True,
                        "digit_scans": scans, "best_optimistic_integer_body": best,
                        "best_digit_to_inner_bitpacked_body_ratio": best["optimistic_digit_output_body_bytes"] / best["inner_output_body_bytes"],
                        "outer_body_compression_protocol_not_excluded_by_this_screen": True})
    return results, paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new output path; retained runs are immutable")
    screens, inputs = geometry_screens()
    paths = [Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "structured_operator_oracle", "ciphertext_linear_oracle", "crt_query_space", "crt_masked_bgv",
        "dyadic_crt", "reduction_oracles", "decryption_support", "owner_bgv", "seeded_bgv", "shallow_bgv")),
        ROOT / "src/cuhepy/bfv/scheme.py", ROOT / "benchmarks/dictionary_layout_lab.py", *inputs]
    result = metadata(paths)
    result.update(kind="structured_operator_exact_oracle_and_count_screen", toy_cases=toys(),
                  recorded_geometry_count_screens=screens,
                  scope="Implicit negacyclic operator and adjoint, signed digit reconstruction and projection are exact algebra controls. "
                        "Toy ciphertexts/keys are random and research-only. No outer vLHE/proof implementation, measured performance, "
                        "parameter approval or original construction. Integer digit bodies omit every outer encryption/proof/setup cost. "
                        "Poor integer-digit counts reject that elementary encoding, not every compressed outer protocol.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "toy_queries": sum(c["all_binary_queries"] for c in result["toy_cases"]),
                      "geometry_profiles": len(screens), "minimum_digit_ratio": min(c["best_digit_to_inner_bitpacked_body_ratio"] for c in screens)}))


if __name__ == "__main__":
    main()
