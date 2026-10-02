#!/usr/bin/env python3
"""E84 complete integer oracle, collision controls and paid conversion inventory."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from itertools import product
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import exact_bucket_release_oracle as oracle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new immutable result path")
    files = [Path(__file__), ROOT / "experiments/bfv_search_lab/exact_bucket_release_oracle.py",
             ROOT / "experiments/bfv_search_lab/test_exact_bucket_release_oracle.py",
             ROOT / "docs/research/exact-bucket-release-preregistration-20261002.md"]
    result = metadata(files)
    ids, searches = (8, 3, 21, 1, 15), 0
    for scores in product(range(4), repeat=5):
        claim = oracle.certificate(scores, ids, 3)
        assert claim.winners == tuple(sorted(zip(scores, ids, strict=True))[:3])
        assert oracle.check_certificate(scores, ids, 3, claim)
        searches += 1
    collisions = []
    for q in (3, 5, 17, 193, 257, 1031):
        left, right = (q, 1), (1, q)
        equal = sum(oracle.histogram_product(left, point, q) == oracle.histogram_product(right, point, q)
                    for point in range(q))
        assert equal == q
        collisions.append({"field": q, "left_counts": left, "right_counts": right,
                           "rows": q + 1, "equal_at_all_challenge_points": equal,
                           "exact_top3_distances_differ": True})
    equal_extension_points = [point for point in product(range(5), repeat=2)
                             if oracle.f25_histogram_product((5, 1), point) == oracle.f25_histogram_product((1, 5), point)]
    prefix_cards, total_domain_cases = [], 0
    for d, q in ((3, 5), (4, 5), (7, 17)):
        degrees = []
        for threshold in range(d + 2):
            polynomial = oracle.prefix_polynomial(d, threshold, q)
            degrees.append(len(polynomial) - 1)
            for score in range(d + 1):
                assert oracle.polynomial_value(polynomial, score, q) == int(score < threshold)
                total_domain_cases += 1
        prefix_cards.append({"dimension": d, "field": q, "degrees_by_threshold": degrees})
    slots = [oracle.ring_slot_structure(n, q) for n, q in
             ((2048, 193), (2048, 257), (16384, 1031), (16384, 65537))]
    challenges = [oracle.challenge_degree(q, 8191, attempts=attempts)
                  for q in (193, 257, 1031, 65537) for attempts in (1, 1024)]
    result.update(kind="E84_exact_bucket_and_complete_conversion_boundary_screen",
                  exact_integer_score_ID_top3_searches=searches,
                  small_field_grand_product_counterexamples=collisions,
                  extension_repair_control={"field_order": 25, "base_subfield_order": 5,
                                            "equal_points": equal_extension_points,
                                            "binding_or_HE_protocol_implemented": False},
                  prefix_interpolation_cards=prefix_cards, exact_prefix_domain_cases=total_domain_cases,
                  plaintext_ring_slot_cards=slots, fixed_polynomial_challenge_cards=challenges,
                  missing_paid_interfaces=["original encrypted-score binding and complete coverage proof",
                                         "private threshold/counts and exact integer count lifts",
                                         "coefficient-to-scalar conversion or complete TFHE comparator",
                                         "noise/parameters, setup, ciphertext maintenance and malformed feedback"],
                  mandatory_primitive_controls=["RevoLUT key-value counting", "strong tournament/network",
                                                "full-score release/local top3", "SophOMR after paid predicate"],
                  decision="Stop small-base-field grand-product certificate; known interpolation alone gives no new complete winner. Revisit Q4/R6 with coefficient/slot conversion as the next precise missing interface.",
                  scope="Homemade public integer/field oracle and algebra/count inventories only. No encrypted selection, proof backend, performance benchmark or security/novelty assurance.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "exact_searches": searches,
                      "collision_field_points": sum(c["equal_at_all_challenge_points"] for c in collisions),
                      "prefix_domain_cases": total_domain_cases,
                      "slot_cards": [(c["prime"], c["n"], c["extension_field_slots"]) for c in slots]}))


if __name__ == "__main__":
    main()
