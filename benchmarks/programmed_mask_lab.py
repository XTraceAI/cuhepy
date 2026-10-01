#!/usr/bin/env python3
"""E74 public-code programming versus actual block factory dimensions."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
import hashlib
from itertools import product
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import programmed_mask_oracle as oracle
from experiments.bfv_search_lab.test_supported_decoder import CASES, inputs


def algebra():
    code, matrix, q, checked = ((1,), (2,), (1,)), ((1, 0, 2), (2, 1, 1)), 3, 0
    compiled = tuple(sum(a*b[0] for a, b in zip(row, code, strict=True)) % q for row in matrix)
    for secret in range(q):
        for error in product(range(q), repeat=3):
            r = oracle.mask(code, (secret,), error, q)
            direct = tuple(sum(a*b for a, b in zip(row, r, strict=True)) % q for row in matrix)
            programmed = tuple((a*secret+sum(x*y for x, y in zip(row, error, strict=True))) % q
                               for a, row in zip(compiled, matrix, strict=True))
            assert direct == programmed
            checked += 1
    schedules = []
    for descriptor in CASES:
        original, _, groups, _, _ = inputs(*descriptor)
        for shared in (0, 1):
            s = crt.space(original.layout, original.map_ids, shared=shared)
            code = tuple(((i+1) % 17, (i*i+3) % 17) for i in range(s.dimension))
            compiled = oracle.compile_scores(s, groups, code)
            for secret in ((0, 0), (1, 7), (16, 16)):
                error = tuple(3 if i % 3 == 0 else 0 for i in range(s.dimension))
                r = oracle.mask(code, secret, error, 17)
                assert oracle.programmed_scores(s, groups, compiled, secret, error) == tuple(tuple(row) for row in crt.scores(s, groups, r))
            schedules.append({"paths": descriptor[1], "counts": descriptor[2], "shared_forms": shared,
                              "query_dimension": s.dimension, "latent_dimension": 2, "exact_recombinations": 3})
    return {"exhaustive_F3_integer_recombinations": checked, "CRT_schedules": schedules,
            "scope": "Plaintext programming algebra only; fresh encryption/verification remain paid existing stages."}


def privacy_controls():
    code, q, secret, error = tuple((1, i) for i in range(12)), 17, (3, 7), (5,)+(0,)*11
    r = oracle.mask(code, secret, error, q)
    recovered = oracle.recover_tiny_sample(code, r, q, 1)
    assert recovered["secret"] == secret and recovered["error"] == error
    wrong = (r[0], (r[1]+1) % q, *r[2:])
    assert oracle.recover_tiny_sample(code, wrong, q, 1) is None
    p = oracle.clean_set_probability(12, 2, 1)
    return {"noiseless_and_public_support_exact_syndrome_leak": True,
            "toy_field": q, "toy_sample_dimension": 12, "toy_latent_dimension": 2, "toy_noise_weight": 1,
            "tiny_known_query_pair_distinguished": True, "tiny_deterministic_sets_examined": recovered["sets_examined"],
            "uniform_random_clean_set_probability_exact": [p.numerator, p.denominator],
            "production_HE_secret_or_reviewed_scheme_attack": False,
            "scope": "Exact tiny public-code sample controls; not attack runtime or parameter assurance."}


def count_screen(profile):
    n, f, prime = profile["query_coordinate_count"], profile["columns"], profile["inner_t"]
    screen = oracle.saving_frontier(n, f, prime)
    screen.update(dataset=profile["dataset"], profile=profile["profile"],
                  row_width_is_optimistic_maximum_not_measured_average=True,
                  matrix_assumed_dense_only_inside_its_private_block=True,
                  naive_dense_comparator_is_not_the_deployed_factory=True,
                  fresh_HE_answer_encryption_removed=False, full_Q_verification_removed=False,
                  hypothesis_decision="Stop this one-level public-code recipe: >=20% row saving fails the conservative 128-bit clean-set trial filter. Not a general PCG impossibility/security proof.")
    assert not any(c["clean_set_trial_filter_passes"] for c in screen["maximal_noise_candidates"])
    best = screen["largest_trial_exponent_saving_candidate"]
    if best:
        k = best["k"]
        screen["public_code_coefficient_body_bytes_for_largest_trial_candidate"] = (n*k*prime.bit_length()+7)//8
        screen["per_private_row_preprocessed_field_coefficient_body_bytes_for_that_candidate"] = (k*prime.bit_length()+7)//8
        screen["extra_mask_generation_products_per_query_for_that_candidate"] = n*k
    screen["scope"] = "Exact expected-work/combinatorial screening. Max row width favors proposal; baseline may exploit zeros/batching. Rank loss/inversion/other attacks, setup, state, private support timing and fresh encryption are not included in trial exponents."
    return screen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new result path")
    original = ROOT/"benchmarks/results/publication-structured-operator-screen-20260930.json"
    references = [ROOT.parent/"research-data/literature-query-packing-20261001/trapdoored-matrices-2502.13065v2.pdf",
                  ROOT.parent/"research-data/literature-query-packing-20261001/trapdoored-matrices-2502.13065v2.txt"]
    paths = [Path(__file__), original, ROOT/"benchmarks/dictionary_layout_lab.py"]
    paths.extend(ROOT/"experiments/bfv_search_lab"/f"{name}.py" for name in
                 ("programmed_mask_oracle", "test_programmed_mask_oracle", "test_supported_decoder", "crt_query_space",
                  "coordinate_factory", "dyadic_crt", "score_layout"))
    result = metadata(paths)
    result["source_sha256"].update({"../research-data/literature-query-packing-20261001/"+p.name:
                                   hashlib.sha256(p.read_bytes()).hexdigest() for p in references})
    result.update(kind="one_level_public_code_programmed_mask_structure_aware_negative_screen",
                  algebra=algebra(), privacy_controls=privacy_controls(),
                  geometry_screens=[count_screen(p) for p in json.loads(original.read_text())["recorded_geometry_count_screens"]],
                  scope="Homemade exact algebra/count discriminator only. Fixed-weight public-code mask is unapproved and not enabled in any client. Existing uniform masks, fresh encrypted answers and full-Q gates unchanged. Known code/trapdoor/PCG ingredients attributed; negative applies only to specified one-level recipe. No large crypto benchmark, attack runtime, parameter/timing/durability/novelty assurance.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({"output": str(args.json_out),
                      "exhaustive_products": result["algebra"]["exhaustive_F3_integer_recombinations"],
                      "CRT_recombinations": sum(c["exact_recombinations"] for c in result["algebra"]["CRT_schedules"]),
                      "largest_trial_exponents_for_20percent_saving":
                          [p["largest_trial_exponent_saving_candidate"]["clean_set_trial_exponent_excluding_polynomial_work"]
                           for p in result["geometry_screens"]]}))


if __name__ == "__main__":
    main()
