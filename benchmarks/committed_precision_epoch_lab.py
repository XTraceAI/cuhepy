#!/usr/bin/env python3
"""E93B/C exact fresh-key laws and conditional paid ledgers, not timings."""

# ruff: noqa: E402 -- standalone research runner.

from argparse import ArgumentParser
from collections import Counter
from dataclasses import replace
from fractions import Fraction
from itertools import product
import json
from math import comb
from pathlib import Path
from random import SystemRandom
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import bgv_unit_bridge as unit
from experiments.bfv_search_lab import committed_precision_epoch as lab
from experiments.bfv_search_lab import partial_packed_switch as packed
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import test_committed_precision_epoch as independent


def whole_scalar_coin_law():
    # All source/target/mask/CBD coins. q5/t3 is deliberately an algebra toy,
    # with no source correctness margin or RLWE claim. All four views share
    # T, masks and errors. The source commitment may depend on source S.
    q, multiplier, atoms = 5, 2, ((-1, 1), (0, 2), (1, 1))
    branches = mass = equalities = bad_mass = 0
    joint, posterior = Counter(), {}
    for s, a1, a2, (e1, m1), (e2, m2) in product((-1, 0, 1), range(q), range(q), atoms, atoms):
        b1, b2 = (1 + 3*e1 - a1*s) % q, (1 + 3*e2 - a2*s) % q
        original = tuple(multiplier*x % q for x in (b1*b2, b1*a2+b2*a1, a1*a2))
        phi = sum(original[i]*s**i for i in range(3))
        for mask1, mask2 in product(range(q), repeat=2):
            views = []
            for sign, target in product((1, -1), (4, 16)):
                c0, d1, d2 = (sign*x % q for x in original)
                d1, d2 = (x if x <= q//2 else x-q for x in (d1, d2))
                mask = (d1*mask1+d2*mask2) % q
                drift = q*packed.round_integer(mask, q, target)-target*mask
                proxy = 2*drift**2+target**2*(d1**2+d2**2)
                views.append((sign, target, c0, d1, d2, mask, drift, lab.tail_threshold(proxy, 1, 4)))
            for t in (-1, 0, 1):
                joint[(views[0][5], t)] += m1*m2*16
                for (ke1, km1), (ke2, km2) in product(atoms, repeat=2):
                    kb1, kb2 = (s+ke1-mask1*t) % q, (s**2+ke2-mask2*t) % q
                    weight, failed = m1*m2*km1*km2, False
                    branches, mass = branches+1, mass+weight
                    for sign, target, c0, d1, d2, mask, drift, threshold in views:
                        body, error = (c0+d1*kb1+d2*kb2) % q, d1*ke1+d2*ke2
                        assert (body+mask*t-sign*phi-error) % q == 0
                        body_drift = q*packed.round_integer(body, q, target)-target*body
                        after = packed.round_integer(body, q, target)+packed.round_integer(mask, q, target)*t
                        z = drift*t+target*error
                        assert (q*after-target*sign*phi-body_drift-z) % (q*target) == 0
                        failed |= abs(z) > threshold
                        equalities += 1
                    bad_mass += weight*failed
                    if s == 0 and a1 == a2 == 1 and e1 == e2 == 0:
                        posterior.setdefault((mask1, mask2, kb1, kb2), Counter())[t] += km1*km2
    assert mass == 3*q**2*16*q**2*3*16
    assert all(len({joint[(mask, t)] for t in (-1, 0, 1)}) == 1 for mask in range(q))
    failure = Fraction(bad_mass, mass)
    assert failure <= Fraction(1, 2)
    witness, counts = next((t, c) for t, c in sorted(posterior.items())
                           if len({c[k] for k in (-1, 0, 1)}) != 1)
    return {"N": 1, "q": q, "t": 3, "whole_coin_support_branches": branches,
            "weighted_sampler_coin_mass": mass, "shared_sign_stage_views_per_family": 4,
            "mixed_and_rounded_phase_equalities": equalities, "whole_family_failure_at_kappa1": str(failure),
            "unconditional_T_and_switched_mask_independent": True,
            "full_transcript_posterior_is_not_uniform": True,
            "posterior_witness": {"masks_and_bodies": witness, "T_masses": [counts[k] for k in (-1, 0, 1)]},
            "source_secret_input_dependence_allowed": True,
            "source_correctness_margin_or_RLWE_security_claimed": False,
            "subset_bad_event_contained_in_whole_family": True}


def adaptive_control():
    n, kappa = 32, 8
    threshold = lab.tail_threshold(2*n, kappa, 1)
    counts, denominator = lab.exact_distribution((1,)*n)
    fixed = Fraction(sum(c for v, c in counts.items() if abs(v) > threshold), denominator)
    adaptive = Fraction(sum(comb(n, k)*2**k for k in range(threshold+1, n+1)), 3**n)
    family_threshold = lab.tail_threshold(2*n, kappa, 2**n)
    assert fixed <= Fraction(1, 2**kappa) < adaptive and family_threshold >= n
    return {"coordinates": n, "kappa": kappa, "single_event_threshold": threshold,
            "fixed_weight_exact_tail": str(fixed), "post_key_sign_T_exact_tail": str(adaptive),
            "target_failure": str(Fraction(1, 2**kappa)),
            "whole_2pow32_sign_family_threshold": family_threshold, "whole_family_tail": "0",
            "revealing_toy_not_an_RLWE_or_published_scheme_attack": True}


def receiver_cards():
    family, epoch, _, _, _ = independent.fixture()
    cert, calls, rejected = lab.build(family, epoch), [], 0
    assert lab.verify_and_release(family, epoch, cert, (0,), lambda _: "control") == "control"
    bads = [replace(cert, family_anchor="wrong"), replace(cert, epoch_anchor="wrong"),
            replace(cert, whole_family_events=True), replace(cert, views=cert.views[:-1])]
    for vi, view in enumerate(cert.views):
        for field in ("output", "rounded"):
            for pi, poly in enumerate(getattr(view, field)):
                for ci, value in enumerate(poly):
                    changed = [list(p) for p in getattr(view, field)]
                    changed[pi][ci] = value+1
                    updated = replace(view, **{field: tuple(tuple(p) for p in changed)})
                    bads.append(replace(cert, views=(*cert.views[:vi], updated, *cert.views[vi+1:])))
        for ei, event in enumerate(view.events):
            for field in ("twice_proxy", "statistical_bound", "deterministic_bound", "body_bound",
                          "source_residual_bound", "total_bound", "coefficient", "sufficient"):
                value = not event.sufficient if field == "sufficient" else getattr(event, field)+1
                events = (*view.events[:ei], replace(event, **{field: value}), *view.events[ei+1:])
                updated = replace(view, events=events)
                bads.append(replace(cert, views=(*cert.views[:vi], updated, *cert.views[vi+1:])))
    for bad in bads:
        try:
            lab.verify_and_release(family, epoch, bad, (0,), lambda x: calls.append(x))
        except ValueError:
            rejected += 1
        else:
            raise AssertionError("False family certificate accepted")
    assert not calls
    return {"accepted_public_control": 1, "corruptions_rejected": rejected,
            "callback_calls_on_rejection": 0, "succinct_or_upstream_PBS_or_key_provenance_proof": False}


def fresh_bgv_differential():
    pk, sk = bgv.key_gen(n=8, t=17, q_bits=32, eta=1)
    vectors = ([1, 0, 1, 1, 0, 1, 0, 0], [0, 1, 1, 0, 0, 1, 0, 1])
    cipher = bgv.multiply(*(bgv.encrypt(x, pk) for x in vectors), pk)
    q, rng = int(pk.q), SystemRandom()
    components = unit.convert(tuple(tuple(int(x) for x in p) for p in cipher.components), q, pk.t)
    source = tuple(int(x) if x <= pk.q//2 else int(x-pk.q) for x in sk.s)
    family = lab.Family(q, pk.t, pk.n, cipher.phase_bound, pk.key_id, "local-original-query",
                        "local-original-index", "local-fresh-epoch", 32, (components,),
                        (lab.View(0, 1, 1 << 64, tuple(range(pk.n)), "nearest"),
                         lab.View(0, 1, 1 << 14, tuple(range(pk.n)), "odd_lut")))
    root = lab.family_anchor(family)  # Before all independent target/KS coins.
    target = tuple(rng.randrange(-1, 2) for _ in range(3))+(0,)*5
    keys, errors = independent.make_keys(q, 3, source, target, 3, 1, rng)
    epoch = lab.OwnerApprovedEpoch(root, "independent-local-T", 1, lab.TERNARY_CBD, keys)
    cert = independent.private_phase_check(family, epoch, source, target, errors)
    lab.verify_and_release(family, epoch, cert, (0, 1), lambda _: None)
    phase = independent.add(cert.views[0].rounded[0], independent.multiply(cert.views[0].rounded[1], target))
    inverse = unit.unit_parameters(q, pk.t)["plaintext_permutation_inverse"]
    decoded = [((2*pk.t*(x % (1 << 64))+(1 << 64)) // (2*(1 << 64))) % pk.t*inverse % pk.t for x in phase]
    assert decoded == bgv.decrypt(cipher, pk, sk)
    return {"N": pk.n, "q": q, "t": pk.t, "target_prefix": 3, "skipped_C2_levels": 1,
            "decoded_coefficients": pk.n, "certified_view_coefficients": 2*pk.n,
            "actual_key_noise_sampler": "centered_binomial_eta1",
            "fresh_target_and_KS_coins_after_commitment": True,
            "toy_not_parameter_PBS_privacy_or_side_channel_assurance": True}


def paid_cards(contexts):
    cards = []
    for c in contexts:
        s = c["envelope"]
        n, q, t, eta = s["n"], c["Q"], s["t"], s["eta"]
        levels, prefix, radix = packed.context(q, 257), 512, 257
        for batch, dense, degree, skip in product((1, 8, 32, 256, 4096), (False, True),
                                                  (2048, 8192, 131072, 524288), (0, 1)):
            target, selected = 2*degree, n if dense else 1
            events, retained = 2*batch*c["replies"]*selected, 2*levels-skip
            # Sound coefficient caps, NOT synthetic switched-mask samples.
            digit_l1, digit_squares = retained*n*(radix//2), retained*n*(radix//2)**2
            proxy = 2*prefix*(q//2)**2+eta*target**2*digit_squares
            stat = lab.tail_threshold(proxy, 128, events)
            det = prefix*(q//2)+target*eta*digit_l1
            residual = n**2*((radix**skip-1)//2)
            bound, det_bound = q//2+min(stat, det)+target*residual, q//2+det+target*residual
            allowed = (degree//t-1)//2
            finite = q*Fraction(2*allowed-1, 2)-Fraction(target*s["centered_phase"], t)
            half = Fraction(target*(q-2*s["centered_phase"]), 2*t)
            key_bytes = retained*2*n*8
            cards.append({"dataset": c["dataset"], "profile": c["profile"], "N": n, "Q": q, "t": t,
                          "eta": eta, "context_phase_multiplier": c["Q_multiplier_of_phase_lower_bound"],
                          "phase_bound": s["centered_phase"], "committed_batch": batch,
                          "selected_mode": "dense" if dense else "one_per_reply", "bootstrap_degree": degree,
                          "target_prefix": prefix, "skipped_C2_levels": skip, "whole_family_events": events,
                          "statistical_bound": bound, "deterministic_bound": det_bound,
                          "finite_odd_budget": str(finite), "nearest_budget_NOT_PBS": str(half),
                          "statistical_finite_margin": bound < finite, "deterministic_finite_margin": det_bound < finite,
                          "statistical_nearest_margin_NOT_PBS": bound < half, "original_S_residual_bound": residual,
                          "shared_epoch_key_u64_body_bytes": key_bytes,
                          "same_strong_standard_shared_epoch_key_bytes": key_bytes,
                          "fresh_per_query_key_lifetime_bytes": batch*key_bytes,
                          "shared_epoch_key_bytes_amortized_per_query": str(Fraction(key_bytes, batch)),
                          "fresh_epoch_keygen_ring_products": retained, "source_square_products_once_per_S": 1,
                          "server_switch_products_per_reply": 2*retained,
                          "public_verifier_repeats_switch_products_per_reply": 2*retained,
                          "source_server_products_per_query": 3*s["columns"]*c["replies"],
                          "fresh_uniform_mask_coefficients": retained*n,
                          "fresh_key_error_Bernoulli_bits": retained*n*2*eta,
                          "target_ternary_draws": prefix, "additional_key_provisioning_RTT": 1,
                          "future_input_after_feedback_requires_new_epoch_or_separate_theorem": True,
                          "query_body_bytes": c["seeded_query_body_bytes_excluding_framing"],
                          "unprojected_full_two_component_pre_PBS_reply_body_bytes": (2*c["replies"]*n*(target-1).bit_length()+7)//8,
                          "new_index_body_bytes": c["seeded_index_body_bytes_excluding_framing"],
                          "owner_allowed_plaintext_cache_bytes": c["raw_owner_binary_cache_bytes"],
                          "private_source_secret_u64_body_bytes": n*8,
                          "private_source_square_wide_body_bytes": n*16, "private_target_secret_u64_body_bytes": prefix*8,
                          "full_verifier_retains_original_inputs_and_public_keys": True,
                          "PBS_auxiliary_key_proof_private_CPU_GPU_RSS_refresh_and_transport_costs": "unmeasured_not_zero",
                          "security_parameters_or_complete_mechanism_or_runtime_winner": False,
                          "strong_known_precommitted_shared_epoch_has_identical_resources": True})
    return cards


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", required=True, type=Path)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    source = ROOT / "benchmarks/results/publication-source-phase-budget-screen-20261002.json"
    paths = [Path(__file__), ROOT/"benchmarks/dictionary_layout_lab.py", source,
             *[ROOT/f"experiments/bfv_search_lab/{name}.py" for name in
               ("committed_precision_epoch", "test_committed_precision_epoch", "partial_packed_switch",
                "batched_score_bridge", "quadratic_drift", "shallow_bgv", "test_partial_packed_switch", "bgv_unit_bridge")],
             ROOT/"src/cuhepy/bfv/scheme.py", ROOT/"docs/research/committed-precision-preregistration-20261002.md"]
    result = metadata(paths)
    result.update(kind="E93B_C_committed_fresh_key_dependency_and_paid_precision_controls",
                  exact=whole_scalar_coin_law(), adaptive=adaptive_control(), public_receiver=receiver_cards(),
                  fresh_BGV=fresh_bgv_differential(), cards=paid_cards(json.loads(source.read_text())["geometry_cards"]),
                  decision="Keep valid restricted fresh-family/MGF control; stop generic fresh-epoch composition as original. Strong standard shared epoch has identical arithmetic/resources. Complete PBS/proof/parameter/privacy and useful-cost gates remain open.",
                  scope="Whole finite toy laws, public full recomputation and conditional paid counts; no timing, published-scheme attack, posterior independence or production assurance.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({"output": str(args.json_out), "exact": result["exact"], "adaptive": result["adaptive"],
                      "cards": len(result["cards"]), "statistical_finite_passing": sum(c["statistical_finite_margin"] for c in result["cards"]),
                      "deterministic_finite_passing": sum(c["deterministic_finite_margin"] for c in result["cards"]),
                      "public_receiver": result["public_receiver"]}))


if __name__ == "__main__":
    main()
