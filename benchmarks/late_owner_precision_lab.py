#!/usr/bin/env python3
"""E95 exact fixed-target late-zero law and paid geometry counts, not timings."""

# ruff: noqa: E402 -- standalone research runner.

from argparse import ArgumentParser
from collections import Counter
from fractions import Fraction
from itertools import product
import json
from pathlib import Path
from random import SystemRandom
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import bgv_unit_bridge as unit
from experiments.bfv_search_lab import committed_precision_epoch as epoch
from experiments.bfv_search_lab import late_owner_precision as lab
from experiments.bfv_search_lab import partial_packed_switch as switch
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.test_committed_precision_epoch import make_keys
from experiments.bfv_search_lab.test_late_owner_precision import (
    corruption_cases, exact_uniform_error_tail, fixture, private_phase_check,
)
from experiments.bfv_search_lab.test_partial_packed_switch import add, multiply


def exact_cards():
    scalar_cases, residues, branches, weighted_mass, identities = 0, 0, 0, 0, 0
    for q, target in product((3, 5, 7, 9, 15, 31), (2, 4, 8, 16, 32)):
        for offset in range(q):
            counts = Counter(lab.rounding_error((offset + rho) % q, q, target) for rho in range(q))
            assert counts == Counter(range(-(q // 2), q // 2 + 1))
            scalar_cases += 1
            residues += q
    q, n, eta, kappa, events = 5, 2, 1, 1, 16
    max_failure = Fraction(0)
    for target, offset in product(product((-1, 0, 1), repeat=n), product(range(q), repeat=n)):
        # Arbitrary secret/body-dependent origins are fixed before fresh rho.
        body = tuple((a + 2*s + 1) % q for a, s in zip(offset, target, strict=True))
        fixed_failure, fixed_mass = 0, 0
        for rho, error in product(product(range(q), repeat=n), product((-1, 0, 1), repeat=n)):
            weight = 2**error.count(0)
            zbody = tuple((e - v) % q for e, v in zip(error, multiply(rho, target), strict=True))
            bad = False
            for source, sign, modulus in product((0, 1), (-1, 1), (4, 8)):
                a = tuple(sign * (x + source*(i+1)) % q for i, x in enumerate(offset))
                b = tuple(sign * (x + source) % q for x in body)
                original = add(b, multiply(a, target))
                added = tuple(tuple((x + y) % q for x, y in zip(p, z, strict=True))
                              for p, z in ((b, zbody), (a, rho)))
                rounded = tuple(tuple((2*modulus*x+q)//(2*q) for x in p) for p in added)
                drift = tuple(tuple(q*r-modulus*x for r, x in zip(p, xs, strict=True))
                              for p, xs in zip(rounded, added, strict=True))
                assert drift == tuple(tuple(((-modulus*x + q//2) % q) - q//2 for x in p) for p in added)
                fresh = add(multiply(drift[1], target), tuple(modulus*e for e in error))
                after = add(rounded[0], multiply(rounded[1], target))
                threshold = lab.precision(q, modulus, n, eta, kappa, events)[1]
                for i in range(n):
                    assert (q*after[i] - modulus*original[i] - drift[0][i] - fresh[i]) % (q*modulus) == 0
                    bad |= abs(fresh[i]) > threshold
                    identities += 1
            fixed_failure += weight * bad
            fixed_mass += weight
            weighted_mass += weight
            branches += 1
        max_failure = max(max_failure, Fraction(fixed_failure, fixed_mass))
        assert Fraction(fixed_failure, fixed_mass) <= Fraction(1, 2**kappa)
    threshold, nonzero = exact_uniform_error_tail()
    post_threshold = lab.precision(5, 4, 1024, 1, 8, 1)[1]
    assert post_threshold < 2048
    return {"all_offset_scalar_contexts": scalar_cases, "scalar_residues": residues,
            "fixed_secret_offset_families": 225, "whole_fresh_coin_support_branches": branches,
            "weighted_fresh_uniform_CBD_coin_mass": weighted_mass,
            "shared_views_per_family": 8, "mixed_rounded_phase_identities": identities,
            "maximum_conditional_whole_family_failure_tiny": str(max_failure),
            "tiny_bound_vacuous_not_a_negligible_tail_measurement": True,
            "N128_Q3_B2_uniform_CBD_threshold": threshold, "N128_exact_nonzero_tail": str(nonzero),
            "post_rho_or_reused_rho_N1024_forced_error": 2048,
            "incorrect_single_event_threshold": post_threshold, "missing_order_failure": "1",
            "shared_mask_difference_event": "1", "independent_fresh_mask_difference_event": "1/25",
            "shared_zero_does_not_give_joint_independent_fresh_ciphertexts": True,
            "no_IID_or_posterior_target_secret_assumption": True,
            "published_scheme_attack_or_parameter_assurance": False}


def receiver_cards():
    family, policy, zero, ledger, *_ = fixture()
    certificate, rejected, calls = lab.build(family, policy, zero), 0, []
    for bad in corruption_cases(certificate):
        try:
            lab.verify_and_consume(family, policy, zero, bad, (0,), ledger, calls.append)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError("False arithmetic certificate accepted")
    assert rejected == 65 and not calls
    lab.verify_and_consume(family, policy, zero, certificate, (0,), ledger, calls.append)
    try:
        lab.verify_and_consume(family, policy, zero, certificate, (0,), ledger, calls.append)
    except RuntimeError:
        pass
    else:
        raise AssertionError("Consumed zero accepted twice")
    return {"corruptions_rejected_before_callback": rejected, "valid_callbacks": len(calls),
            "replay_rejected": True, "compact_verification_original_sampling_PBS_or_durability": False}


def fresh_bgv_differential():
    pk, sk = bgv.key_gen(n=8, t=17, q_bits=32, eta=1)
    q, rng = int(pk.q), SystemRandom()
    source = tuple(int(x) if x <= pk.q//2 else int(x-pk.q) for x in sk.s)
    target = tuple(rng.randrange(-1, 2) for _ in range(3))+(0,)*5
    keys, errors = make_keys(q, 3, source, target, 3, 1, rng)
    policy = lab.OwnerKeys("same-local-T", 1, 1, keys)
    ledger = lab.OwnerLedger(policy, 2)
    index = bgv.encrypt([0, 1, 1, 0, 0, 1, 0, 1], pk)
    previous, decoded_count, phase_count = [0]*8, 0, 0
    root = lab.keys_anchor(policy)
    for query in range(2):
        message = [(x + previous[i]) % 2 for i, x in enumerate([1, 0, 1, 1, 0, 1, 0, 0])]
        cipher = bgv.multiply(bgv.encrypt(message, pk), index, pk)
        parts = unit.convert(tuple(tuple(int(x) for x in p) for p in cipher.components), q, pk.t)
        family = epoch.Family(q, pk.t, pk.n, cipher.phase_bound, pk.key_id,
                              f"adaptive-original-{query}", "fixed-encrypted-index", f"family-{query}", 32,
                              (parts,), (epoch.View(0, 1, 1 << 64, tuple(range(pk.n)), "nearest"),
                                         epoch.View(0, 1, 1 << 14, tuple(range(pk.n)), "odd_lut")))
        zero = lab.generate_owner_zero(family, policy, ledger, query.to_bytes(16, "big"), target)
        e0 = tuple((x + q//2) % q - q//2 for x in add(zero.body, multiply(zero.mask, target)))
        assert max(map(abs, e0)) <= policy.zero_error_eta and lab.keys_anchor(policy) == root
        cert = private_phase_check(family, policy, zero, source, target, errors, e0)
        lab.verify_and_consume(family, policy, zero, cert, (0, 1), ledger, lambda _: None)
        phase = add(cert.views[0].rounded[0], multiply(cert.views[0].rounded[1], target))
        inverse = unit.unit_parameters(q, pk.t)["plaintext_permutation_inverse"]
        previous = [((2*pk.t*(x % (1 << 64))+(1 << 64)) // (2*(1 << 64))) % pk.t*inverse % pk.t for x in phase]
        assert previous == bgv.decrypt(cipher, pk, sk)
        decoded_count += pk.n
        phase_count += 2*pk.n
    return {"N": pk.n, "q": q, "t": pk.t, "reused_target_and_switch_keys_across_adaptive_queries": True,
            "target_switch_key_generations": 1, "adaptive_families": 2, "fresh_owner_zeros": 2,
            "decoded_coefficients": decoded_count, "mixed_rounded_phase_coefficients": phase_count,
            "OS_uniform_zero_masks_and_CBD_eta1_after_original_binding": True,
            "no_private_error_or_key_witness_returned": True,
            "toy_not_PBS_parameter_privacy_or_private_implementation_assurance": True}


def paid_cards(source_cards):
    cards = []
    for c in source_cards:
        p, n, q, t, phase = c["policy"], c["policy"]["n"], c["modeled_original_depth_one_Q"], c["policy"]["t"], c["bound"]["whole_lifetime_phase"]
        life, eta, h = p["max_fresh_queries"], p["eta"], p["columns"]
        for dense, skip in product((False, True), (0, 1)):
            selected = n if dense else 1
            events = 2*p["replies"]*selected
            levels = switch.context(q, 257)
            prefix, rows = 512, 2*levels-skip
            key_error = eta*rows*n*128
            residual = n**2*((257**skip-1)//2)
            points = []
            for bits in range(11, 21):
                degree, target = 1 << bits, 2 << bits
                proxy, stat, det = lab.precision(q, target, prefix, eta, 129+(life-1).bit_length(), events)
                assert stat == lab.precision(q, target, prefix, eta, 129, events*life)[1]
                budget = q*Fraction(2*((degree//t-1)//2)-1, 2)-Fraction(target*phase, t)
                candidate = q//2+min(stat, det)+target*(key_error+residual)
                no_zero = q//2+prefix*(q//2)+target*(key_error+residual)
                fresh_proxy = 2*prefix*(q//2)**2+eta*target**2*rows*n*128**2
                fresh_stat = epoch.tail_threshold(fresh_proxy, 129, events*life)
                fresh_det = prefix*(q//2)+target*key_error
                fresh = q//2+min(fresh_stat, fresh_det)+target*residual
                points.append({"degree": degree, "twice_proxy": proxy, "late_zero_bound": candidate,
                               "known_shared_zero_bound": candidate, "deterministic_no_zero_bound": no_zero,
                               "fresh_target_bound": fresh, "finite_odd_budget": str(budget),
                               "late_zero_pass": candidate < budget, "deterministic_no_zero_pass": no_zero < budget,
                               "fresh_target_pass": fresh < budget})
            poly_bytes = (n*q.bit_length()+7)//8
            zero_bytes, query_bytes = 2*poly_bytes, h*(poly_bytes+32)
            key_full, key_seeded = 2*rows*poly_bytes, rows*(poly_bytes+32)
            cards.append({"dataset": c["dataset"], "profile": c["profile"], "policy": p,
                          "dense": dense, "skipped_C2_levels": skip, "points": points,
                          "first_late_zero_degree": next((x["degree"] for x in points if x["late_zero_pass"]), None),
                          "first_deterministic_no_zero_degree": next((x["degree"] for x in points if x["deterministic_no_zero_pass"]), None),
                          "first_fresh_target_degree": next((x["degree"] for x in points if x["fresh_target_pass"]), None),
                          "strong_known_shared_zero_arithmetic_proof_relation_and_resources_identical": True,
                          "seeded_query_bytes_excluding_framing": query_bytes, "unseeded_zero_upload_bytes_per_family": zero_bytes,
                          "extra_query_body_fraction": str(Fraction(zero_bytes, query_bytes)),
                          "zero_lifetime_upload_bytes": life*zero_bytes, "fresh_target_full_key_lifetime_bytes": life*key_full,
                          "fresh_target_seeded_mask_key_lifetime_bytes": life*key_seeded,
                          "reusable_target_key_full_setup_bytes": key_full, "reusable_target_key_seeded_mask_setup_bytes": key_seeded,
                          "owner_zero_products_per_family": 1, "zero_route_cold_lifetime_products": rows+life,
                          "fresh_target_lifetime_products": rows*life, "source_square_products_once_per_source_key": 1,
                          "fresh_target_ternary_draws_lifetime": life*prefix, "late_zero_new_target_secret_draws": 0,
                          "uniform_zero_mask_coefficients_per_family": n, "zero_CBD_Bernoulli_bits_per_family": 2*eta*n,
                          "server_additions_per_reply": 2*n, "switch_products_per_reply": 2*rows,
                          "full_verifier_repeats_switch_products_per_reply": 2*rows,
                          "colocated_owner_query_zero_extra_RTT": 0, "strong_colocated_owner_query_fresh_key_extra_RTT": 0,
                          "legacy_separate_provisioning_extra_RTT_assumption": 1,
                          "private_target_support_coefficients": prefix, "owner_allowed_plaintext_cache_bytes": c["owner_allowed_plaintext_cache_bytes"],
                          "other_source_phase_or_body_reduction_credited": False,
                          "PBS_proof_private_CPU_GPU_RSS_durability_and_security": "open_not_zero",
                          "original_main_or_measured_speedup": False})
    return cards


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    source_path = ROOT / "benchmarks/results/publication-adaptive-query-phase-screen-20261002.json"
    paths = [Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", source_path,
             *[ROOT / f"experiments/bfv_search_lab/{name}.py" for name in
               ("late_owner_precision", "test_late_owner_precision", "committed_precision_epoch", "test_committed_precision_epoch",
                "partial_packed_switch", "test_partial_packed_switch", "quadratic_drift", "batched_score_bridge",
                "bgv_unit_bridge", "shallow_bgv")], ROOT / "src/cuhepy/bfv/scheme.py",
             ROOT / "docs/research/late-owner-precision-preregistration-20261002.md"]
    result = metadata(paths)
    result.update(kind="E95_fixed_target_late_owner_zero_exact_law_and_paid_controls", exact=exact_cards(),
                  receiver=receiver_cards(), fresh_BGV=fresh_bgv_differential(),
                  cards=paid_cards(json.loads(source_path.read_text())["cards"]),
                  decision="Keep the conditional fixed-key adapter. Stop generic shared rerandomization as original: strongest known shared-zero control is identical. New complete binding/security or measured-cost claim remains open.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({"output": str(args.json_out), "exact": result["exact"], "receiver": result["receiver"],
                      "fresh_BGV": result["fresh_BGV"], "paid_cards": len(result["cards"])}))


if __name__ == "__main__":
    main()
