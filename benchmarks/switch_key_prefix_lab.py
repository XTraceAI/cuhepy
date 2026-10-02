#!/usr/bin/env python3
"""E98 exact setup-row samples/distribution, not an attack or HE timing."""

# ruff: noqa: E402 -- standalone research runner.

from argparse import ArgumentParser
from collections import Counter
from fractions import Fraction
from itertools import product
import hashlib
import json
from pathlib import Path
from random import SystemRandom
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import switch_key_prefix_samples as lab
from experiments.bfv_search_lab.test_committed_precision_epoch import make_keys
from experiments.bfv_search_lab.test_partial_packed_switch import multiply
from experiments.bfv_search_lab.test_switch_key_prefix_samples import (
    exact_formal_pair, test_actual_full_key_contexts_cancel_source_and_derived_square,
)


def uniform_masks():
    cards = []
    for radix in (3, 5):
        counts = Counter()
        for first, second in product(product(range(3), repeat=4), repeat=2):
            mask, body = lab.row_pair(first, (0,)*4, second, (0,)*4, 3, radix)
            rows = tuple(a for a, _ in lab.extract(mask, body, 3, 2))
            counts[rows] += 1
        assert len(counts) == 81 and set(counts.values()) == {81}
        cards.append({"N": 4, "Q": 3, "radix": radix, "prefix": 2,
                      "mask_pair_outcomes": 6561, "joint_independent_row_values": 81,
                      "equal_coin_mass_per_joint_value": 81})
    return cards


def distribution():
    literal = Counter((bits[2]-bits[3])-3*(bits[0]-bits[1]) for bits in product((0, 1), repeat=4))
    assert lab.error_distribution(1, 3) == (literal, 16)
    counts, denominator = lab.error_distribution(21, 257)
    variance = Fraction(sum(x*x*c for x, c in counts.items()), denominator)
    encoded = json.dumps(sorted(counts.items()), separators=(",", ":")).encode()
    assert variance == 693525 and len(counts) == 1849 and 22 not in counts
    return {"eta": 21, "radix": 257, "error_law": "E2-257*E1, independent CBD21",
            "coin_mass_denominator": denominator, "support_values": len(counts),
            "mean": "0", "variance": str(variance), "bounds": [min(counts), max(counts)],
            "zero_mass": str(Fraction(counts[0], denominator)),
            "nonzero_density": str(1-Fraction(counts[0], denominator)),
            "support_has_gaps_22_absent": True, "ordered_integer_mass_sha256": hashlib.sha256(encoded).hexdigest(),
            "estimator_summary_not_claimed_identical_Gaussian": True,
            "CBD1_radix3_literal_Bernoulli_outcomes": 16}


def fresh_bgv():
    pk, sk = bgv.key_gen(n=8, t=17, q_bits=32, eta=1)
    q, rng = int(pk.q), SystemRandom()
    source = tuple(int(x) if x <= q//2 else int(x-q) for x in sk.s)
    target = tuple(rng.randrange(-1, 2) for _ in range(3))+(0,)*5
    keys, errors = make_keys(q, 3, source, target, 3, 1, rng)
    pairs = lab.from_keys(keys)
    equations = 0
    for pair in pairs:
        family, (first, second) = pair.family, pair.levels
        start = keys.skipped_c2_levels if family else 0
        e1, e2 = errors[family][first-start], errors[family][second-start]
        phase = multiply(pair.mask, target)
        assert all((b+p+3*a-e) % q == 0 for b, p, a, e in zip(pair.body, phase, e1, e2, strict=True))
        for (a, b), position in zip(pair.samples, lab.positions(8, 3), strict=True):
            assert (b-sum(x*t for x, t in zip(a, target[:3], strict=True))-3*e1[position]+e2[position]) % q == 0
            equations += 1
    assert equations == lab.sample_count(8, 3, q, 3, 1)
    return {"homemade_public_key_BGV_source_N": pk.n, "Q": q, "t": pk.t, "target_prefix": 3,
            "setup_source_generations": 1, "fresh_target_switch_key_generations": 1,
            "disjoint_pair_polynomials": len(pairs), "public_independent_sample_equations": equations,
            "private_source_derived_square_target_error_witness_not_returned": True,
            "SEAL_used": False, "actual_attack_or_parameter_approval": False}


def inventories(source_path):
    contexts = {}
    for card in json.loads(source_path.read_text())["cards"]:
        if card["policy"]["max_fresh_queries"] == 4096:
            contexts.setdefault((card["policy"]["n"], card["modeled_original_depth_one_Q"]), []).append(
                {"dataset": card["dataset"], "profile": card["profile"]})
    assert len(contexts) == 6
    cards, full_ring = [], []
    for (n, q), labels in contexts.items():
        for skip in (0, 1):
            pairs = lab.pairing_inventory(q, 257, skip)
            used = tuple((family, row) for family, first, second in pairs for row in (first, second))
            assert len(set(used)) == len(used)
            common = {"source_N": n, "exact_Q": q, "Q_bits": q.bit_length(), "labels": labels,
                      "radix": 257, "eta": 21, "skipped_C2_levels": skip,
                      "original_key_rows": 2*lab.context(q, 257)-skip,
                      "disjoint_paired_polynomials": len(pairs), "paired_original_level_inventory": pairs,
                      "queries_reusing_keys_not_new_samples": 4096}
            full_ring.append(common | {"target_prefix": n, "available_independent_samples": len(pairs),
                                       "full_ring_inventory_only_no_cost_approval": True})
            for prefix in (512, 1024, 2048, 4096):
                if prefix <= n:
                    cards.append(common | {"target_prefix": prefix, "rows_per_pair": n//prefix,
                                           "available_independent_samples": lab.sample_count(n, prefix, q, 257, skip),
                                           "setup_only_not_multiplied_by_lifetime": True})
    assert len(cards) == 44 and len(full_ring) == 12
    return cards, full_ring


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    source_path = ROOT / "benchmarks/results/publication-adaptive-query-phase-screen-20261002.json"
    paths = [Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", source_path,
             *[ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
                 "switch_key_prefix_samples", "test_switch_key_prefix_samples", "target_prefix_samples",
                 "test_committed_precision_epoch", "committed_precision_epoch", "test_partial_packed_switch",
                 "partial_packed_switch", "batched_score_bridge", "quadratic_drift", "shallow_bgv")],
             ROOT / "src/cuhepy/bfv/scheme.py",
             ROOT / "docs/research/switch-key-prefix-preregistration-20261002.md"]
    output = metadata(paths)
    actual_contexts = 0
    for n in (2, 4, 8):
        test_actual_full_key_contexts_cancel_source_and_derived_square(n)
        actual_contexts += sum(lab.context(q, 3)+1 for q in (97, 1009))
    cards, full_ring = inventories(source_path)
    output.update(kind="E98_exact_setup_switch_row_known_prefix_sample_control",
                  exact=exact_formal_pair(), uniform_mask_controls=uniform_masks(),
                  actual_full_key_contexts_checked=actual_contexts, error_distribution=distribution(),
                  fresh_BGV=fresh_bgv(), profiles=cards, full_ring_inventory=full_ring,
                  decision="Exact setup sample subset exists without fresh encrypted zeros. Cost screen required separately; no parameter or original contribution approved.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(output, indent=2)+"\n")
    print(json.dumps({"output": str(args.json_out), "exact": output["exact"],
                      "actual_contexts": actual_contexts, "profiles": len(cards), "distribution": output["error_distribution"]}))


if __name__ == "__main__":
    main()
