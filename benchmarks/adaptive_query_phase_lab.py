#!/usr/bin/env python3
"""E94 exact fixed-index/fresh-query controls and conditional original-Q counts."""

# ruff: noqa: E402 -- standalone research runner.

from argparse import ArgumentParser
from dataclasses import asdict, replace
from fractions import Fraction
from itertools import product
import json
from math import comb
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import adaptive_query_phase as lab
from experiments.bfv_search_lab import committed_precision_epoch as tails
from experiments.bfv_search_lab import partial_packed_switch as packed
from experiments.bfv_search_lab import seeded_bgv as seeded
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import source_phase_budget as source
from experiments.bfv_search_lab.test_source_phase_budget import cyclic_reference


def exact_cards():
    cases, weighted_mass, max_failure = 0, 0, Fraction(0)
    p = lab.Policy(2, 3, 1, 1, 1, 1, 1, "S", "index-1")
    b = lab.derive(p)
    for index, message in product(product(range(-4, 5), repeat=2), product((-1, 0, 1), repeat=2)):
        mean, failure = cyclic_reference(index, message), 0
        assert max(map(abs, mean)) <= b.deterministic_mean
        for error in product((-1, 0, 1), repeat=2):
            phi = cyclic_reference(index, tuple(m + 3 * e for m, e in zip(message, error, strict=True)))
            noise = tuple(3 * x for x in cyclic_reference(index, error))
            assert phi == tuple(m + e for m, e in zip(mean, noise, strict=True))
            assert max(map(abs, phi)) <= b.all_support_phase
            weight = product_mass(error)
            failure += weight * (max(map(abs, phi)) > b.whole_lifetime_phase)
            cases, weighted_mass = cases + 1, weighted_mass + weight
        max_failure = max(max_failure, Fraction(failure, 16))
    assert max_failure <= Fraction(1, 2)
    larger = lab.Policy(16, 3, 1, 1, 1, 1, 8, "S", "index-1")
    large_bound = lab.derive(larger)
    counts, denominator = tails.exact_distribution((12,) * 16, law="centered_binomial", eta=1)
    nonzero_tail = Fraction(sum(c for v, c in counts.items() if abs(v) > large_bound.fresh_query_tail), denominator)
    assert 0 < nonzero_tail <= Fraction(1, 2**larger.kappa * large_bound.events)
    invalid = lab.Policy(1024, 3, 1, 1, 1, 1, 8, "S", "index-1")
    cutoff = lab.derive(invalid).whole_lifetime_phase // 12
    adaptive_bad = Fraction(sum(comb(1024, k) for k in range(cutoff + 1, 1025)), 2**1024)
    assert adaptive_bad > Fraction(1, 256)
    return {"fixed_supported_index_message_error_cases": cases, "CBD_weighted_coin_mass": weighted_mass,
            "integer_ring_phase_coefficients": 2 * cases, "maximum_conditional_failure_small_support": str(max_failure),
            "N16_fixed_index_noise_tail_exact_nonzero": str(nonzero_tail),
            "N16_registered_tail": large_bound.fresh_query_tail,
            "post_error_index_choice_revealing_toy_tail": str(adaptive_bad),
            "post_error_index_choice_cutoff_nonzero_errors": cutoff,
            "source_index_or_message_independence_assumed": False,
            "fresh_query_error_independence_required": True,
            "published_scheme_attack_or_parameter_assurance": False}


def product_mass(errors):
    weight = 1
    for error in errors:
        weight *= 2 if error == 0 else 1
    return weight


def fresh_seeded_differential():
    pk, sk = bgv.key_gen(n=8, t=17, q_bits=32, eta=21)
    secret = tuple(int(x) if x <= pk.q // 2 else int(x - pk.q) for x in sk.s)
    columns = ([1, 0, 1, 1, 0, 1, 0, 0], [0, 1, 1, 0, 0, 1, 0, 1])
    index = tuple(seeded.expand(seeded.encrypt(list(m), pk, sk), pk) for m in columns)
    def phase(c):
        poly = cyclic_reference(tuple(int(x) for x in c.components[1]), secret)
        return tuple((int(a) + b + int(pk.q) // 2) % int(pk.q) - int(pk.q) // 2
                     for a, b in zip(c.components[0], poly, strict=True))
    phases = tuple(phase(c) for c in index)
    # Deliberately choose plaintext messages using the fixed index phases.
    # The independent owner CBD query coins are sampled only afterwards.
    messages = tuple(tuple((pk.t // 2) * (1 if phi[0] >= 0 else -1) if i == 0 else
                           -(pk.t // 2) * (1 if phi[-i] >= 0 else -1) for i in range(pk.n)) for phi in phases)
    p = lab.Policy(pk.n, pk.t, pk.eta, 2, 1, 1, 32, pk.key_id, "local-index")
    bound = lab.derive(p)
    ledger = lab.FreshQueryLedger(p)
    ledger.reserve(bytes(16), pk.key_id, p.index_epoch)
    query = tuple(seeded.expand(seeded.encrypt(list(m), pk, sk), pk) for m in messages)
    products = tuple(bgv.multiply(a, b, pk) for a, b in zip(index, query, strict=True))
    result = tuple(tuple(sum(int(c.components[j][i]) for c in products) % int(pk.q) for i in range(pk.n))
                   for j in range(3))
    source_phase = tuple(sum(x) for x in zip(*(cyclic_reference(a, phase(b)) for a, b in zip(phases, query, strict=True)), strict=True))
    cipher_phase = tuple((sum(x) + int(pk.q) // 2) % int(pk.q) - int(pk.q) // 2 for x in zip(
        result[0], cyclic_reference(result[1], secret), cyclic_reference(result[2], cyclic_reference(secret, secret)), strict=True))
    assert source_phase == cipher_phase and max(map(abs, source_phase)) <= bound.whole_lifetime_phase
    assert bound.whole_lifetime_phase < bound.all_support_phase
    return {"N": pk.n, "t": pk.t, "q": int(pk.q), "eta": pk.eta, "owner_seeded_columns": 2,
            "original_integer_cipher_and_conditional_phase_coefficients": pk.n,
            "message_selection_using_fixed_index_phases": True, "query_CBD_coins_sampled_afterwards": True,
            "same_context_source_bound": asdict(bound), "toy_not_secure_parameter_or_production_assurance": True}


def degree_control(c, phase_bound, life, dense, skip):
    n, q, t, eta = c["envelope"]["n"], c["Q"], c["envelope"]["t"], c["envelope"]["eta"]
    levels, prefix = packed.context(q, 257), 512
    rows = 2 * levels - skip
    events_batch = 2 * life * c["replies"] * (n if dense else 1)
    events_single = events_batch // life
    kappa_single = 129 + (life - 1).bit_length()
    # One committed target epoch and life independent target epochs get the
    # same total lifetime allocation; never give fresh-per-query a free budget.
    assert 129 + (2 * events_batch - 1).bit_length() == kappa_single + (2 * events_single - 1).bit_length()
    points = []
    for bits in range(11, 21):
        degree, target = 1 << bits, 2 << bits
        proxy = 2 * prefix * (q // 2)**2 + eta * target**2 * rows * n * 128**2
        statistical = tails.tail_threshold(proxy, 129, events_batch)
        assert statistical == tails.tail_threshold(proxy, kappa_single, events_single)
        deterministic = prefix * (q // 2) + target * eta * rows * n * 128
        residual = n**2 * ((257**skip - 1) // 2)
        total, all_key = q // 2 + min(statistical, deterministic) + target * residual, q // 2 + deterministic + target * residual
        allowed = (degree // t - 1) // 2
        budget = q * Fraction(2 * allowed - 1, 2) - Fraction(target * phase_bound, t)
        points.append({"degree": degree, "statistical_pass": total < budget, "deterministic_pass": all_key < budget})
    key_bytes = rows * 2 * n * 8
    return {"dense": dense, "skipped_C2_levels": skip, "points": points,
            "first_statistical_degree": next((p["degree"] for p in points if p["statistical_pass"]), None),
            "first_deterministic_degree": next((p["degree"] for p in points if p["deterministic_pass"]), None),
            "one_committed_epoch_target_kappa": 129, "adaptive_per_query_epoch_target_kappa": kappa_single,
            "same_total_lifetime_confidence_and_threshold": True,
            "committed_shared_epoch_key_body_bytes": key_bytes, "adaptive_fresh_per_query_key_lifetime_bytes": life * key_bytes,
            "per_query_fresh_target_keygen_ring_products": rows, "extra_fresh_key_RTT_per_adaptive_query": 1,
            "source_precommit_lifetime_does_not_make_target_key_reuse_independent": True,
            "PBS_keys_proof_private_work_RSS_and_parameter_assurance": "open_not_zero"}


def geometry_cards(contexts):
    cards = []
    for c in contexts:
        if c["Q_multiplier_of_phase_lower_bound"] != 2:
            continue
        s = c["envelope"]
        for life in (1, 8, 32, 256, 4096):
            p = lab.Policy(s["n"], s["t"], s["eta"], s["columns"], c["replies"], life, 129, "S", "fixed-index")
            b = lab.derive(p)
            for field in b.__dataclass_fields__:
                try:
                    lab.verify(p, replace(b, **{field: getattr(b, field) + 1}))
                except ValueError:
                    pass
                else:
                    raise AssertionError("False source policy accepted")
            minimum_q = source.ntt_prime_above(p.n, max(2 * s["owner_fresh"] + 1, 2 * b.whole_lifetime_phase + 1))
            cards.append({"dataset": c["dataset"], "profile": c["profile"], "modeled_original_depth_one_Q": c["Q"],
                          "original_linear_Q_different_circuit": c["original_linear_Q"], "policy": asdict(p), "bound": asdict(b),
                          "all_support_to_conditional_bound_ratio": str(Fraction(b.all_support_phase, b.whole_lifetime_phase)),
                          "original_depth_one_Q_has_nonempty_quarter_source_margin": c["Q"] > 4 * b.whole_lifetime_phase,
                          "same_original_depth_one_Q_requires_no_reenrollment": True,
                          "conditional_minimal_correctness_new_Q": minimum_q,
                          "new_Q_coefficient_bit_reduction": c["Q"].bit_length() - minimum_q.bit_length(),
                          "using_smaller_Q_requires_new_keys_index_and_security_review": True,
                          "source_bound_fields_recomputed_and_corruptions_rejected": len(b.__dataclass_fields__),
                          "source_failure_at_most": "1/" + str(2**129),
                          "one_target_epoch_plus_source_failure_at_most": "1/" + str(2**128),
                          "adaptive_fresh_epochs_use_kappa129_plus_ceil_log2_lifetime": True,
                          "proof_PBS_private_side_channel_and_RLWE_assurance_in_failure_sum": "uninstantiated_not_zero",
                          "owner_allowed_plaintext_cache_bytes": c["raw_owner_binary_cache_bytes"],
                          "target_degree_controls": [degree_control(c, b.whole_lifetime_phase, life, dense, skip)
                                                     for dense, skip in product((False, True), (0, 1))],
                          "original_complete_mechanism_or_measured_speedup": False})
    return cards


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    source_path = ROOT / "benchmarks/results/publication-source-phase-budget-screen-20261002.json"
    paths = [Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", source_path,
             *[ROOT / f"experiments/bfv_search_lab/{name}.py" for name in
               ("adaptive_query_phase", "test_adaptive_query_phase", "committed_precision_epoch", "source_phase_budget",
                "test_source_phase_budget", "seeded_bgv", "shallow_bgv", "partial_packed_switch", "batched_score_bridge")],
             ROOT / "src/cuhepy/bfv/scheme.py", ROOT / "docs/research/adaptive-query-phase-preregistration-20261002.md"]
    result = metadata(paths)
    result.update(kind="E94_conditional_frozen_index_fresh_query_lifetime_phase_controls",
                  exact=exact_cards(), fresh_seeded_BGV=fresh_seeded_differential(),
                  cards=geometry_cards(json.loads(source_path.read_text())["geometry_cards"]),
                  decision="Keep the valid conditional source-lifetime control; all original modeled-Q source quarter margins reopen. No Gaussian, full posterior secret law, reused-target-key precision or new complete main mechanism follows.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "exact_cases": result["exact"]["fixed_supported_index_message_error_cases"],
                      "lifetime_cards": len(result["cards"]), "nonempty_original_quarter_margins": sum(c["original_depth_one_Q_has_nonempty_quarter_source_margin"] for c in result["cards"]),
                      "fresh_seeded_BGV": result["fresh_seeded_BGV"]}))


if __name__ == "__main__":
    main()
