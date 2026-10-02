#!/usr/bin/env python3
"""E83 complete tiny coded-access control plus paid direct-query geometry."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from dataclasses import replace
from fractions import Fraction
from itertools import product
import json
from math import ceil, log2
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import coded_operator_oracle as oracle


def access_counts(profile, expansion):
    """Optimistic MDS distance; no distance assurance for our large code."""
    n, f, replies, q = profile["n"], profile["columns"], profile["replies"], profile["modeled_Q"]
    # E72 fresh encrypted query has two full-degree components per column.
    width, rows = 2 * n * f, 3 * n * replies
    length = expansion * rows
    best_distance = length - rows + 1
    miss = Fraction(rows - 1, length)
    samples = ceil(128 / -log2(float(miss)))
    bits = q.bit_length()
    values = (samples * width * bits + 7) // 8
    online = profile["public_online_body_upper_bound_bytes"]
    return {
        "dataset": profile["dataset"], "profile": profile["profile"],
        "mode": "E72 actual original fresh encrypted query, full three-component reply upper bound",
        "input_W": width, "output_L": rows, "modeled_Q": q, "code_expansion": expansion,
        "optimistic_MDS_distance": best_distance,
        "samples_for_128bit_fixed_error_target": samples,
        "minimum_row_values_bitpacked_bytes_per_query": values,
        "row_values_over_existing_query_plus_reply_upper_bound": values / online,
        "existing_private_dense_hint_bytes": profile["private_compiled_fingerprint_body_bytes"],
        "coded_dense_enrollment_bytes": (length * width * bits + 7) // 8,
        "row_dot_products_per_query": samples * width,
        "baseline_fingerprint_input_products": profile["dense_field_rounds_for_1024_attempt_128bit_algebraic_target"] * width,
        "best_possible_distance_not_claimed_for_QC_code": True,
        "factory_removal_counted_correctly": True,
        "excluded_costs": ["paths/openings", "code evaluation", "extra RTT", "setup and code-distance assurance"],
        "decision": "Stop literal authenticated row fetch; optimistic row values alone dominate the entire baseline public body.",
    }


def authenticated_control():
    matrix, q, points = ((1, 3), (2, 1)), 5, (0, 1, 2, 3)
    def encode(values):
        return oracle.rs_encode(values, points, q)
    coded = oracle.encode_matrix(matrix, q, encode)
    registration, layers = oracle.register(coded, q, "a" * 64)
    openings = tuple(oracle.open_row(coded, layers, i) for i in range(4))
    correct, wrong, largest_miss = 0, 0, Fraction()
    for query in product(range(q), repeat=2):
        answer = oracle.matvec(matrix, query, q)
        fixed = oracle.fix_answer(answer, query, registration)
        assert oracle.check_rows(fixed, tuple(range(4)), openings, encode)
        correct += 1
        for error in product(range(q), repeat=2):
            if not any(error):
                continue
            changed = replace(fixed, values=tuple((a + e) % q for a, e in zip(answer, error, strict=True)))
            misses = sum(oracle.check_rows(changed, (i,), (openings[i],), encode) for i in range(4))
            largest_miss = max(largest_miss, Fraction(misses, 4))
            assert not oracle.check_rows(changed, tuple(range(4)), openings, encode)
            wrong += 1
    return {"correct_public_queries": correct, "all_nonzero_error_answers": wrong,
            "largest_single_random_row_miss_probability": [largest_miss.numerator, largest_miss.denominator],
            "all_four_rows_reject_every_wrong_answer": True,
            "proof_and_field_relation_both_checked": True,
            "owner_generated_ED_and_original_input_are_premises": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new immutable result path")
    profiles_path = ROOT / "benchmarks/results/publication-encrypted-query-gate-control-20261001.json"
    files = [Path(__file__), profiles_path, ROOT / "benchmarks/dictionary_layout_lab.py",
             ROOT / "experiments/bfv_search_lab/coded_operator_oracle.py",
             ROOT / "experiments/bfv_search_lab/test_coded_operator_oracle.py"]
    result = metadata(files)
    distance = []
    for name, dimension, q, encoder in (
        ("RS_control", 3, 7, lambda e: oracle.rs_encode(e, tuple(range(6)), 7)),
        ("known_negacirculant", 2, 5, lambda e: oracle.quasi_encode(e, ((1, 0), (1, 1)), 5)),
        ("known_tensor", 4, 5, lambda e: oracle.tensor_encode(e, 2, ((1, 0), (1, 1)), (0, 1, 2, 3), 5)),
        ("bad_commuting_code", 2, 5, lambda e: oracle.quasi_encode(e, ((1, 0), (0, 0)), 5)),
        ("NTT_basis_only_counterexample", 4, 17, lambda e: oracle.rs_encode(e, (2, 8, 15, 9), 17)),
    ):
        card = oracle.exhaustive_distance(dimension, q, encoder)
        card["kind"] = name
        distance.append(card)
    counts = [access_counts(profile, expansion)
              for profile in json.loads(profiles_path.read_text())["retained_geometry_count_screens"]
              for expansion in (2, 4, 8)]
    assert all(c["row_values_over_existing_query_plus_reply_upper_bound"] > 1 for c in counts)
    result.update(kind="E83_known_structured_code_and_complete_authenticated_access_screen",
                  exhaustive_all_error_distance_cards=distance,
                  tiny_authenticated_operator_control=authenticated_control(),
                  direct_encrypted_query_count_cards=counts,
                  signed_shift_generator_commutation_tested=True,
                  scope="Homemade finite public arithmetic and Merkle control; counts use unapproved retained modeled Q. No private-key receiver, large-code distance proof, remote lifecycle, security/novelty acceptance or timing benchmark.",
                  decision="Structure survives known code multiplication; ordinary row access fails paid direct-query wire/work. A new succinct authenticated-evaluation step is still missing; do not port this control to CUDA.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    ratios = [c["row_values_over_existing_query_plus_reply_upper_bound"] for c in counts]
    print(json.dumps({"output": str(args.json_out), "all_error_vectors": sum(d["errors_checked"] for d in distance),
                      "direct_query_cards": len(counts), "row_bytes_to_baseline_total_range": [min(ratios), max(ratios)]}))


if __name__ == "__main__":
    main()
