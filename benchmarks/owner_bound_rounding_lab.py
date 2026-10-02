#!/usr/bin/env python3
"""E97 known fixed-input rounding law, receiver and paid counts, not HE timings."""

# ruff: noqa: E402 -- standalone research runner.

from argparse import ArgumentParser
from collections import Counter
from dataclasses import replace
from fractions import Fraction
from itertools import product
import json
from pathlib import Path
from random import SystemRandom
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from benchmarks.target_prefix_frontier_lab import bounds as previous_bounds
from experiments.bfv_search_lab.batched_score_bridge import context
from experiments.bfv_search_lab import bgv_unit_bridge as unit
from experiments.bfv_search_lab import committed_precision_epoch as epoch
from experiments.bfv_search_lab import owner_bound_rounding as lab
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.test_committed_precision_epoch import make_keys
from experiments.bfv_search_lab.test_owner_bound_rounding import (
    corruption_cases, exact_post_coin_tail, exact_symmetric_tail, fixture, literal_round, private_phase_check,
)
from experiments.bfv_search_lab.test_partial_packed_switch import add, multiply


def exact_cards():
    scalar_contexts = scalar_coins = 0
    for q, b in product((2, 3, 4, 5, 7, 9, 15), (2, 4, 8, 16, 32)):
        for x in range(q):
            errors = []
            for u in range(q):
                rounded = literal_round(x, q, b, u)
                assert rounded == lab.round_integer(x, q, b, u)
                error = q*rounded-b*x
                errors.append(error)
                opposite = lab.round_integer(-x % q, q, b, q-1-u)
                assert (opposite+rounded) % b == 0 and q*opposite-b*(-x % q) == -error
                scalar_coins += 1
            r = b*x % q
            assert sum(errors) == 0 and sum(d*d for d in errors) == q*r*(q-r)
            scalar_contexts += 1
    q, n, branches, identities, means = 3, 2, 0, 0, 0
    views = tuple(product((0, 1), (-1, 1), (4, 8)))
    for target, flat in product(product((-1, 0, 1), repeat=n), product(range(q), repeat=2*n)):
        body, mask = flat[:n], flat[n:]
        sums = [[0]*n for _ in views]
        squares = [[0]*n for _ in views]
        variances = []
        for source, sign, b in views:
            xs = (tuple(sign*(x+source) % q for x in body),
                  tuple(sign*(x+source*(i+1)) % q for i, x in enumerate(mask)))
            rs = tuple(tuple(b*x % q for x in poly) for poly in xs)
            variances.append(tuple(rs[0][k]*(q-rs[0][k]) + sum(
                target[i]**2*rs[1][(k-i) % n]*(q-rs[1][(k-i) % n]) for i in range(n)) for k in range(n)))
        for coins in product(range(q), repeat=2*n):
            for vi, (source, sign, b) in enumerate(views):
                xs = (tuple(sign*(x+source) % q for x in body),
                      tuple(sign*(x+source*(i+1)) % q for i, x in enumerate(mask)))
                us = tuple(tuple(u if sign == 1 else q-1-u for u in poly) for poly in (coins[:n], coins[n:]))
                raw = tuple(tuple(literal_round(x, q, b, u) for x, u in zip(poly, coin, strict=True))
                            for poly, coin in zip(xs, us, strict=True))
                drift = tuple(tuple(q*r-b*x for r, x in zip(poly, old, strict=True))
                              for poly, old in zip(raw, xs, strict=True))
                numerator = add(drift[0], multiply(drift[1], target))
                original, rounded = add(xs[0], multiply(xs[1], target)), add(raw[0], multiply(raw[1], target))
                for k in range(n):
                    assert q*rounded[k]-b*original[k] == numerator[k]
                    sums[vi][k] += numerator[k]
                    squares[vi][k] += numerator[k]**2
                    identities += 1
            branches += 1
        for total, square, variance in zip(sums, squares, variances, strict=True):
            assert total == [0]*n
            assert square == [q**(2*n)*v for v in variance]
            means += n
    threshold, tail = exact_symmetric_tail()
    invalid_threshold, invalid_tail = exact_post_coin_tail()
    assert scalar_contexts == 225 and scalar_coins == 2045
    assert branches == 59049 and identities == 944784 and means == 11664
    return {"scalar_input_contexts": scalar_contexts, "scalar_coin_outcomes": scalar_coins,
            "fixed_secret_two_component_origin_families": 729, "whole_fresh_coin_support_branches": branches,
            "shared_views_per_family": 8, "integer_phase_equalities": identities,
            "exact_conditional_coefficient_mean_variance_checks": means,
            "no_posterior_secret_or_uniform_ciphertext_assumption": True,
            "toy_family_bound_vacuous_not_negligible_failure_measurement": True,
            "N128_Q4_B2_body_plus128_mask_terms_threshold": threshold,
            "exact_nonzero_fixed_input_tail": str(tail),
            "N64_Q5_B4_post_coin_input_invalid_threshold": invalid_threshold,
            "exact_post_coin_or_reused_coin_invalid_tail": str(invalid_tail),
            "same_coin_in_all_N128_mask_positions_failure": "1",
            "sign_complement_exact_unchanged_sign_coin_not_equivariant": True,
            "public_coin_shape_or_deterministic_seed_relation_does_not_prove_uniformity": True}


def receiver_cards():
    family, policy, coins, ledger, *_ = fixture()
    certificate, calls, rejected = lab.build(family, policy, coins), [], 0
    for bad in corruption_cases(certificate):
        try:
            lab.verify_and_consume(family, policy, coins, bad, (0,), ledger, calls.append)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError("False original/coin arithmetic certificate accepted")
    other = replace(coins, body=(family.q-1, 0))
    try:
        lab.verify_and_consume(family, policy, other, lab.build(family, policy, other), (0,), ledger, calls.append)
    except RuntimeError:
        pass
    else:
        raise AssertionError("Same-ID packet replacement accepted")
    assert rejected == 77 and not calls
    lab.verify_and_consume(family, policy, coins, certificate, (0,), ledger, calls.append)
    try:
        lab.verify_and_consume(family, policy, coins, certificate, (0,), ledger, calls.append)
    except RuntimeError:
        pass
    else:
        raise AssertionError("Replay accepted")
    return {"corruptions_rejected_before_callback": rejected, "same_ID_packet_replacement_rejected": True,
            "valid_callbacks": len(calls), "replay_rejected": True,
            "compact_original_score_verification_honest_sampling_PBS_durability": False}


def fresh_bgv_differential():
    pk, sk = bgv.key_gen(n=8, t=17, q_bits=32, eta=1)
    q, rng = int(pk.q), SystemRandom()
    source = tuple(int(x) if x <= pk.q//2 else int(x-pk.q) for x in sk.s)
    target = tuple(rng.randrange(-1, 2) for _ in range(3))+(0,)*5
    keys, errors = make_keys(q, 3, source, target, 3, 1, rng)
    policy, previous = lab.OwnerKeys("same-local-T", 1, keys), [0]*8
    ledger = lab.OwnerLedger(policy, 2)
    index = bgv.encrypt([0, 1, 1, 0, 0, 1, 0, 1], pk)
    for query in range(2):
        message = [(x+previous[i]) % 2 for i, x in enumerate([1, 0, 1, 1, 0, 1, 0, 0])]
        cipher = bgv.multiply(bgv.encrypt(message, pk), index, pk)
        parts = unit.convert(tuple(tuple(int(x) for x in p) for p in cipher.components), q, pk.t)
        family = epoch.Family(q, pk.t, pk.n, cipher.phase_bound, pk.key_id,
                              f"adaptive-original-{query}", "fixed-encrypted-index", f"family-{query}", 32,
                              (parts,), (epoch.View(0, 1, 1 << 64, tuple(range(pk.n)), "nearest"),
                                         epoch.View(0, -1, 1 << 14, tuple(range(pk.n)), "odd_lut")))
        coins = lab.generate_owner_coins(family, policy, ledger, query.to_bytes(16, "big"))
        cert = private_phase_check(family, policy, coins, source, target, errors)
        lab.verify_and_consume(family, policy, coins, cert, (0, 1), ledger, lambda _: None)
        phase = add(cert.views[0].rounded[0], multiply(cert.views[0].rounded[1], target))
        inverse = unit.unit_parameters(q, pk.t)["plaintext_permutation_inverse"]
        previous = [((2*pk.t*(x % (1 << 64))+(1 << 64)) // (2*(1 << 64))) % pk.t*inverse % pk.t for x in phase]
        assert previous == bgv.decrypt(cipher, pk, sk)
    return {"N": pk.n, "q": q, "t": pk.t, "adaptive_families": 2, "fresh_owner_coin_packets": 2,
            "target_switch_key_generations": 1, "owner_auxiliary_secret_products_or_CBD_draws": 0,
            "decoded_coefficients": 16, "mixed_rounded_phase_coefficients": 32,
            "OS_independent_uniform_coins_after_binding": True, "no_SEAL_or_private_witness_returned": True,
            "toy_not_PBS_parameter_privacy_or_private_implementation_assurance": True}


def paid_cards(old_frontier, source_cards):
    source = {(c["dataset"], c["profile"], c["policy"]["max_fresh_queries"]): c for c in source_cards}
    cards, reproduced = [], 0
    for old in old_frontier:
        c = source[old["dataset"], old["profile"], old["lifetime"]]
        p, n, q, prefix = c["policy"], old["source_N"], old["Q"], old["target_prefix"]
        events = 2*p["replies"]*(n if old["dense"] else 1)
        points = []
        for point in old["points"]:
            expected = previous_bounds(n, q, p["t"], p["eta"], c["bound"]["whole_lifetime_phase"],
                                       old["lifetime"], p["replies"], old["dense"], old["skipped_C2_levels"], prefix, point["degree"])
            assert point == expected
            reproduced += 1
            _, threshold = lab.uniform_precision(q, prefix, 129+(old["lifetime"]-1).bit_length(), events)
            # Fixed original remainders are unavailable in these model cards.
            b = 2*point["degree"]
            rows = 2*context(q, 257)-old["skipped_C2_levels"]
            key_error = p["eta"]*rows*n*128
            residual = n*n*((257**old["skipped_C2_levels"]-1)//2)
            bound = min(threshold, (prefix+1)*(q-1))+b*(key_error+residual)
            points.append({**point, "owner_stochastic_uniform_bound": bound,
                           "owner_stochastic_pass": bound < Fraction(point["finite_odd_budget"]),
                           "statistical_rounding_threshold": threshold,
                           "known_shared_stochastic_bound": bound})
        poly_bytes = (n*q.bit_length()+7)//8
        cards.append({k: v for k, v in old.items() if k not in ("points",)} | {
            "points": points, "first_owner_stochastic_degree": next((x["degree"] for x in points if x["owner_stochastic_pass"]), None),
            "strong_known_shared_stochastic_arithmetic_relation_and_resources_identical": True,
            "target_status_interpretation": "E96 owner-zero transcript historical control, not a new no-zero key-transcript security estimate",
            "new_no_zero_target_assurance": "open_actual_switch_key_rows_need_separate_screen",
            "unseeded_coin_packet_bytes_per_family": 2*poly_bytes, "unseeded_zero_packet_bytes_per_family": 2*poly_bytes,
            "uniform_coin_draws_per_family": 2*n, "zero_uniform_draws_per_family": n,
            "coin_owner_auxiliary_secret_products_per_family": 0, "zero_owner_auxiliary_secret_products_per_family": 1,
            "coin_owner_auxiliary_CBD_bits_per_family": 0, "zero_owner_auxiliary_CBD_bits_per_family": 2*p["eta"]*n,
            "reusable_switch_key_full_setup_bytes": 2*rows*poly_bytes,
            "reusable_switch_key_seeded_mask_setup_bytes": rows*(poly_bytes+32),
            "coin_route_cold_lifetime_auxiliary_products": rows, "zero_route_cold_lifetime_auxiliary_products": rows+old["lifetime"],
            "switch_products_per_reply": 2*rows, "full_verifier_repeats_switch_products_per_reply": 2*rows,
            "stochastic_integer_rounds_per_view": 2*n, "zero_additions_per_reply": 2*n,
            "owner_allowed_plaintext_cache_bytes": c["owner_allowed_plaintext_cache_bytes"],
            "seeded_query_body_bytes": p["columns"]*(poly_bytes+32),
            "extra_RTT_both_colocated_routes": 0, "real_public_remainder_precision_credited": False,
            "framing_proof_PBS_private_CPU_GPU_RSS_durability_and_security": "open_not_zero",
            "measured_speedup_or_original_main_selected": False})
    assert reproduced == 8640 and len(cards) == 720
    return cards


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    frontier_path = ROOT / "benchmarks/results/publication-target-prefix-frontier-screen-20261002.json"
    source_path = ROOT / "benchmarks/results/publication-adaptive-query-phase-screen-20261002.json"
    paths = [Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", frontier_path, source_path,
             ROOT / "benchmarks/target_prefix_frontier_lab.py",
             *[ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
                 "owner_bound_rounding", "test_owner_bound_rounding", "committed_precision_epoch", "test_committed_precision_epoch",
                 "partial_packed_switch", "test_partial_packed_switch", "quadratic_drift", "batched_score_bridge",
                 "bgv_unit_bridge", "shallow_bgv", "target_prefix_samples", "test_target_prefix_samples",
                 "source_phase_budget", "test_source_phase_budget")],
             ROOT / "src/cuhepy/bfv/scheme.py",
             ROOT / "docs/research/owner-bound-rounding-preregistration-20261002.md"]
    result = metadata(paths)
    result.update(kind="E97_known_owner_bound_fixed_input_stochastic_rounding_control",
                  exact=exact_cards(), receiver=receiver_cards(), fresh_BGV=fresh_bgv_differential(),
                  old_E96_points_independently_reproduced=8640,
                  cards=paid_cards(json.loads(frontier_path.read_text())["cards"], json.loads(source_path.read_text())["cards"]),
                  decision="Keep the homemade known stochastic control. Stop generic rounding as originality; no new no-zero parameter assurance. Return to actual key-transcript assurance before a novel score/proof/query construction.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({"output": str(args.json_out), "exact": result["exact"], "receiver": result["receiver"],
                      "contexts": len(result["cards"]), "old_points_reproduced": 8640}))


if __name__ == "__main__":
    main()
