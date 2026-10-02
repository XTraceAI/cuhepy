#!/usr/bin/env python3
"""E99 exact dependency/hidden-support and paid counts; not HE timings."""

# ruff: noqa: E402 -- standalone research runner.

from argparse import ArgumentParser
from datetime import UTC, datetime
from fractions import Fraction
import hashlib
import json
from math import isqrt, log2
from pathlib import Path
import platform
from random import SystemRandom
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.bfv_search_lab import gadget_dependency as lab
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.test_committed_precision_epoch import make_keys
from experiments.bfv_search_lab.test_gadget_dependency import (
    actual_key_contexts, formal_axes, geometry_laws, hidden_laws, phase_check, transcript,
)
from experiments.bfv_search_lab.test_partial_packed_switch import multiply

OLD = ROOT / "benchmarks/results/publication-owner-bound-rounding-screen-20261002.json"
SOURCE = ROOT / "benchmarks/results/publication-adaptive-query-phase-screen-20261002.json"


def metadata(extra=()):
    # Conservative inherited source pins plus every new diagnostic dependency.
    paths = {ROOT / p for p in json.loads(OLD.read_text())["source_sha256"]}
    paths.update([Path(__file__), OLD, SOURCE,
                  ROOT / "experiments/bfv_search_lab/gadget_dependency.py",
                  ROOT / "experiments/bfv_search_lab/test_gadget_dependency.py",
                  ROOT / "docs/research/gadget-dependency-preregistration-20261002.md", *extra])
    return {"utc": datetime.now(UTC).isoformat(), "command": sys.argv,
            "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "python": platform.python_version(), "platform": platform.platform(),
            "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in sorted(paths)}}


def contexts():
    values = {(c["policy"]["n"], c["modeled_original_depth_one_Q"])
              for c in json.loads(SOURCE.read_text())["cards"] if c["policy"]["max_fresh_queries"] == 4096}
    old = {(c["source_N"], c["Q"]) for c in json.loads(OLD.read_text())["cards"] if c["lifetime"] == 4096}
    assert values == old and len(values) == 6
    return tuple(sorted(values))


def fresh_bgv():
    pk, sk = bgv.key_gen(n=8, t=17, q_bits=32, eta=1)
    q, rng = int(pk.q), SystemRandom()
    source = tuple(int(x) if x <= q//2 else int(x-q) for x in sk.s)
    policy = lab.HiddenSupport(8, 2, 1)
    target = lab.sample_hidden(policy, rng)
    keys, errors = make_keys(q, 3, source, target, 8, 1, rng)
    equations = 0
    for f, actual in enumerate((source, multiply(source, source))):
        start = 1 if f else 0
        masks = tuple(a for a, _ in keys.values[f])
        tr = transcript(q, 3, ("S", "S-square")[f], actual, target, masks, errors[f], start)
        assert tuple((row.mask, row.body) for row in tr.rows) == keys.values[f]
        equations += phase_check(tr, target, errors[f], lab.modular_basis(q, 3, len(masks)))
    return {"source_N": pk.n, "Q": q, "t": pk.t, "source_key_generations": 1,
            "target_key_generations": 1, "hidden_public_policy": vars(policy),
            "whole_polynomial_private_phase_equations": equations,
            "source_target_errors_positions_not_returned": True, "SEAL_used": False,
            "attack_parameter_or_release_approval": False}


def paid_cards():
    sources = {(c["dataset"], c["profile"], c["policy"]["max_fresh_queries"]): c
               for c in json.loads(SOURCE.read_text())["cards"]}
    cards, checked, same = [], 0, 0
    for old in json.loads(OLD.read_text())["cards"]:
        s = sources[old["dataset"], old["profile"], old["lifetime"]]
        policy = s["policy"]
        n, q, h, lifetime = old["source_N"], old["Q"], old["target_prefix"], old["lifetime"]
        hidden = lab.HiddenSupport(n, h, h//2)
        count = lab.support_count(hidden)
        encoded = count.to_bytes((count.bit_length()+7)//8, "big")
        levels, capacity = 0, 1
        while capacity < q:
            capacity *= 257
            levels += 1
        rows = 2*levels-old["skipped_C2_levels"]
        events = 2*policy["replies"]*(n if old["dense"] else 1)
        confidence = 129+(lifetime-1).bit_length()+(2*events-1).bit_length()
        square = ((q*q*(h+1)+1)//2)*confidence
        threshold = isqrt(square)+(isqrt(square)**2 < square)
        key_error = policy["eta"]*rows*n*128
        residual = n*n*((257**old["skipped_C2_levels"]-1)//2)
        points = []
        for point in old["points"]:
            bound = min(threshold, (h+1)*(q-1))+2*point["degree"]*(key_error+residual)
            assert threshold == point["statistical_rounding_threshold"]
            assert bound == point["owner_stochastic_uniform_bound"] == point["known_shared_stochastic_bound"]
            passes = bound < Fraction(point["finite_odd_budget"])
            assert passes == point["owner_stochastic_pass"]
            points.append({"degree": point["degree"], "hidden_cap_bound": bound,
                           "full_source_key_error_and_skip_residual_paid": True,
                           "finite_odd_budget": point["finite_odd_budget"], "passes_correctness_only": passes})
            checked += 1
        first = next((p["degree"] for p in points if p["passes_correctness_only"]), None)
        assert first == old["first_owner_stochastic_degree"]
        same += 1
        poly_bytes = (n*q.bit_length()+7)//8
        assert old["reusable_switch_key_full_setup_bytes"] == 2*rows*poly_bytes
        assert old["unseeded_coin_packet_bytes_per_family"] == 2*poly_bytes
        assert old["switch_products_per_reply"] == old["full_verifier_repeats_switch_products_per_reply"] == 2*rows
        disjoint = levels//2+(levels-old["skipped_C2_levels"])//2
        cards.append({"dataset": old["dataset"], "profile": old["profile"], "source_N": n, "Q": q,
                      "lifetime": lifetime, "dense": old["dense"], "skipped_C2_levels": old["skipped_C2_levels"],
                      "public_hidden_policy": vars(hidden), "unknown_dimension": n,
                      "secret_count_exact_formula": "binomial(N,h)*binomial(h,positives)",
                      "secret_count_integer_bit_length": count.bit_length(),
                      "secret_count_big_endian_sha256": hashlib.sha256(encoded).hexdigest(),
                      "log2_secret_count_not_security_bits": log2(count),
                      "points": points, "first_correctness_degree": first,
                      "same_old_numerical_prefix_precision": True,
                      "historical_prefix_security_estimates_apply": False,
                      "hidden_full_N_disjoint_setup_sample_subset": disjoint,
                      "false_known_prefix_setup_sample_count": disjoint*(n//h),
                      "lifetime_does_not_multiply_setup_samples": True,
                      "full_N_ciphertext_body_and_mask_bytes": 2*poly_bytes,
                      "full_N_reusable_switch_key_setup_bytes": 2*rows*poly_bytes,
                      "seeded_key_setup_bytes_ROM_not_true_uniform": rows*(poly_bytes+32),
                      "owner_uniform_coin_draws_per_family": 2*n,
                      "cold_keygen_secret_products": rows,
                      "switch_products_per_reply": 2*rows, "verifier_switch_repeat_products_per_reply": 2*rows,
                      "seeded_query_body_bytes": old["seeded_query_body_bytes"],
                      "owner_allowed_plaintext_cache_bytes": old["owner_allowed_plaintext_cache_bytes"],
                      "standard_hidden_sparse_control_law_and_resources_identical": True,
                      "proof_PBS_RSS_CPU_GPU_private_seed_lifecycle_and_sparse_key_graph_assurance": "open_not_zero",
                      "security_approval_original_mechanism_or_measured_speedup": False})
    assert checked == 8640 and same == len(cards) == 720
    return cards


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    output = metadata()
    output.update(kind="E99_exact_dependency_and_hidden_support_paid_controls",
                  geometry=geometry_laws(), formal_factor_cover=formal_axes(),
                  actual_key_contexts=[actual_key_contexts(n) for n in (2, 4, 8)],
                  fresh_BGV=fresh_bgv(), hidden_law=hidden_laws(),
                  reconstructed_source_contexts=contexts(), cards=paid_cards(),
                  old_E97_points_independently_recomputed=8640,
                  decision="Keep exact assurance controls; stop generic gadget/compiler/sparse originality. Hidden positions change sample applicability,not paid correctness bounds; sparse/correlated/key-graph assurance and original complete mechanism remain open.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(output, indent=2)+"\n")
    print(json.dumps({"output": str(args.json_out), "formal": output["formal_factor_cover"],
                      "hidden_law": output["hidden_law"], "cards": len(output["cards"]),
                      "geometry": len(output["geometry"])}))


if __name__ == "__main__":
    main()
