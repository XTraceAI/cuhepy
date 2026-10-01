#!/usr/bin/env python3
"""E70 exact quotient/NTT point controls and lifetime-matched state counts."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from dataclasses import replace
import itertools
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import convolution_certificate_oracle as certificate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new result path")
    vectors = tuple(tuple(x % 17 for x in p) for p in itertools.product((-1, 0, 1), repeat=2))
    point_checks = 0
    for a, b in itertools.product(vectors, repeat=2):
        pairs = ((a, b),)
        result = certificate.certify(pairs, 17)
        assert result == certificate.cyclic_quotient_control(pairs, 17)
        for point in range(17):
            assert certificate.verify_at_point(pairs, result, point, 17)
            point_checks += 1
    cases = []
    for n, q in ((8, 97), (16, 193), (32, 257)):
        rng = random.Random(70000+n)
        pairs = tuple((tuple(rng.randrange(q) for _ in range(n)), tuple(rng.randrange(q) for _ in range(n))) for _ in range(3))
        result = certificate.certify(pairs, q)
        assert result == certificate.cyclic_quotient_control(pairs, q)
        assert all(certificate.verify_at_point(pairs, result, point, q) for point in range(q))
        cases.append({"n": n, "q": q, "factor_pairs": 3, "all_field_points_honest": q,
                      "cyclic_negacyclic_quotient_exact": True})
    pairs = (((1, 2, 3, 4, 5, 6, 7, 8), (8, 7, 6, 5, 4, 3, 2, 1)),)
    honest = certificate.certify(pairs, 97)
    roots = certificate.negacyclic_roots(8, 97)
    error = certificate.vanishing_polynomial(roots[:-1], 97)
    forged = replace(honest, output=tuple((a+b) % 97 for a, b in zip(honest.output, error, strict=True)))
    root_accepts = sum(certificate.verify_at_point(pairs, forged, point, 97) for point in roots)
    field_accepts = sum(certificate.verify_at_point(pairs, forged, point, 97) for point in range(97))
    assert root_accepts == field_accepts == 7 and forged.output != honest.output
    inverse = pow(certificate.evaluate(error, roots[-1], 97), -1, 97)
    idempotent = tuple(x*inverse % 97 for x in error)
    assert certificate.certify(((idempotent, idempotent),), 97).output == idempotent
    assert any(idempotent[1:])
    original = ROOT / "benchmarks/results/publication-structured-operator-screen-20260930.json"
    screens = []
    for profile in json.loads(original.read_text())["recorded_geometry_count_screens"]:
        n = 2048 if profile["dataset"] == "connect4" else 16384
        replies = profile["rows"]//(2*n)
        screens.append({"dataset": profile["dataset"], "profile": profile["profile"],
                        "n": n, "inner_q": profile["inner_q"], "replies": replies,
                        "cost": certificate.cost(n=n, q=profile["inner_q"], replies=replies,
                                                 columns=profile["columns"], width=profile["width"])})
    paths = [Path(__file__), ROOT / "experiments/bfv_search_lab/convolution_certificate_oracle.py",
             ROOT / "experiments/bfv_search_lab/reduction_oracles.py",
             ROOT / "benchmarks/dictionary_layout_lab.py", original]
    result = metadata(paths)
    result.update(kind="negacyclic_polynomial_quotient_certificate_primitive_screen",
                  exhaustive_tiny_products=81, exhaustive_tiny_point_checks=point_checks, cases=cases,
                  NTT_frequency_error={"n": 8, "q": 97, "NTT_domain_accepts": root_accepts,
                                       "NTT_domain_size": 8, "whole_field_accepts": field_accepts, "whole_field_size": 97},
                  split_ring_bit_constraint_control={"n": 8, "q": 97, "nonconstant_idempotent": idempotent,
                                                     "x_squared_equals_x_but_not_a_constant_bit": True,
                                                     "not_an_attack_on_a_different_ring_instantiation": True},
                  geometry_count_screens=screens,
                  scope="Known quotient identity and cyclic-negacyclic decomposition, not a new proof or complete HE protocol. "
                        "No encrypted queries, privacy composition, hidden-state receiver, commitments, batching, native/GPU timings or parameter assurance. "
                        "Count panel is direct masked-polynomial control; it does NOT remove fresh owner answer generation. "
                        "Exact NTT-point and disclosed/reused-point forgeries are shortcut controls, not attacks on reviewed proof systems.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "tiny_point_checks": point_checks,
                      "additional_all_point_checks": sum(c["q"] for c in cases), "NTT_forgery_accepts": root_accepts}))


if __name__ == "__main__":
    main()
