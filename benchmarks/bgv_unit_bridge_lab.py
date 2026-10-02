#!/usr/bin/env python3
"""E86 exact known unit conversion and paid rounding/context ledger, no timings."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from itertools import product
import json
from pathlib import Path
import sys

from gmpy2 import is_prime

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import bgv_unit_bridge as bridge
from experiments.bfv_search_lab import score_phase_bridge_oracle as oracle
from experiments.bfv_search_lab import shallow_bgv as bgv


def scalar_control():
    cards = []
    for q, t in ((17, 3), (101, 5), (103, 5), (323, 5), (257, 17)):
        cases = 0
        for sign in (-1, 1):
            context = bridge.unit_parameters(q, t, sign=sign)
            for signed in range(-(q // 2), q // 2 + 1):
                changed = signed * context["multiplier"] % q
                assert bridge.scaled_decode_reference(changed, q, t, sign=sign) == signed % t
                cases += 1
        cards.append({"Q": q, "t": t, "signed_full_phase_and_both_sign_cases": cases,
                      "all_correct": True, "positive_unit_context": bridge.unit_parameters(q, t)})
    return cards


def ring_control():
    cards = []
    for count in (2, 3):
        checked = 0
        for values in product(range(3), repeat=2 * count):
            original = tuple(values[i:i + 2] for i in range(0, len(values), 2))
            changed = bridge.convert(original, 3, 2)
            for secret in product(range(3), repeat=2):
                before, after = oracle.ring_phase(original, secret, 3), oracle.ring_phase(changed, secret, 3)
                for a, b in zip(before, after, strict=True):
                    assert bridge.scaled_decode_reference(b, 3, 2) == oracle.decode_bgv(a, 3, 2)
                    checked += 1
        cards.append({"Q": 3, "t": 2, "n": 2, "components": count,
                      "all_coefficient_phase_conversion_cases": checked})
    return cards


def torus_control():
    q, t, target, checked = 101, 5, 256, 0
    context = bridge.unit_parameters(q, t)
    for a in product((0, 1, 50, 100), repeat=2):
        for secret in product((-1, 0, 1), repeat=2):
            for signed in range(-10, 11):
                b = (signed - sum(x * s for x, s in zip(a, secret, strict=True))) % q
                unit = oracle.Sample(tuple(x * context["multiplier"] % q for x in a),
                                     b * context["multiplier"] % q, q)
                torus = oracle.scale_sample(unit, target, q)
                permuted = oracle.decode_scaled(oracle.sample_phase(torus, secret), target, t)
                assert permuted * context["plaintext_permutation_inverse"] % t == signed % t
                checked += 1
    failures = 0
    for a, signed in product(range(q), range(-50, 51)):
        unit = oracle.Sample((a * context["multiplier"] % q,),
                             (signed - a) * context["multiplier"] % q, q)
        torus = oracle.scale_sample(unit, 8, q)
        decoded = oracle.decode_scaled(oracle.sample_phase(torus, (1,)), 8, t)
        failures += decoded * context["plaintext_permutation_inverse"] % t != signed % t
    assert failures > 0
    return {"Q": q, "t": t, "safe_B": target, "safe_centered_phase_bound": 10,
            "safe_mask_key_phase_cases": checked, "all_safe_cases_correct": True,
            "unsafe_B": 8, "unsafe_full_phase_mask_cases": q * q,
            "unsafe_roundtrip_failures": failures,
            "additional_KS_PBS_noise_and_padding_paid": False}


def real_bgv_control():
    pk, sk = bgv.key_gen(n=8, t=17, q_bits=32, eta=1)
    inputs = ([1, 0, 1, 1, 0, 1, 0, 0], [0, 1, 1, 0, 0, 1, 0, 1])
    cipher = bgv.multiply(*(bgv.encrypt(x, pk) for x in inputs), pk)
    expected = bgv.decrypt(cipher, pk, sk)
    converted = bridge.convert(tuple(tuple(int(x) for x in poly) for poly in cipher.components), int(pk.q), pk.t)
    q, n = int(pk.q), pk.n
    def multiply(left, right):
        result = [0] * n
        for i, a in enumerate(left):
            for j, b in enumerate(right):
                result[(i + j) % n] += a * b * (1 if i + j < n else -1)
        return tuple(x % q for x in result)
    secret = tuple(int(x) for x in sk.s)
    squared = multiply(secret, secret)
    phase = tuple((a + b + c) % q for a, b, c in zip(converted[0], multiply(converted[1], secret),
                  multiply(converted[2], squared), strict=True))
    actual = [bridge.scaled_decode_reference(value, q, pk.t) for value in phase]
    assert actual == expected
    return {"n": n, "t": pk.t, "Q": q, "eta": pk.eta, "input_messages": inputs,
            "original_circuit": "one ciphertext product, three components, no relinearization",
            "independent_schoolbook_vs_GMP_decode": True, "all_coefficients_checked": n,
            "fresh_random_OS_keys_not_replayed": True,
            "only_local_trusted_test_decryption": True, "production_parameters": False}


def rounding_card(profile, target_bits, relin):
    n, t, q, bound = (profile[k] for k in ("n", "t", "modeled_Q", "phase_bound"))
    target = 1 << target_bits
    # Ternary ||S||_1<=N and ||S²||_1<=||S||_1²<=N². Correlation/security
    # of the derived key and relinearization noise are not accounted for here.
    secret_l1 = n if relin else n + n * n
    condition = bridge.switched_bound(q, t, target, bound, secret_l1)
    denominator = target - t * (1 + secret_l1)
    minimum_q = 2 * target * bound // denominator + 1 if denominator > 0 else None
    # Existing Q remains adequate for exact unit conversion regardless of this
    # torus rounding condition. A changed Q is a NEW key/index context.
    candidate = None
    if minimum_q is not None:
        stride = 2 * n * t
        candidate = ((minimum_q - 1 + stride - 1) // stride) * stride + 1
        while not is_prime(candidate):
            candidate += stride
        assert candidate % (2 * n) == candidate % t == 1
        assert bridge.switched_bound(candidate, t, target, bound, secret_l1)["sufficient_strict_margin"]
    return {"dataset": profile["dataset"], "profile": profile["profile"], "n": n, "t": t,
            "existing_modeled_Q": q, "torus_B_bits": target_bits,
            "route": "once_relinearized_packed_reply" if relin else "direct_C2_derived_secret",
            "ternary_extracted_secret_L1_upper_bound": secret_l1,
            "conditional_post_unit_error_bound": str(condition["error_bound"]),
            "nearest_message_margin": str(condition["nearest_message_margin"]),
            "existing_Q_satisfies_sufficient_bound_excluding_KS_PBS_relin_noise": condition["sufficient_strict_margin"],
            "minimum_Q_for_same_phase_bound_before_prime_rounding": minimum_q,
            "optional_identity_permutation_NTT_prime_Q": candidate,
            "optional_changed_Q_bits": candidate.bit_length() if candidate is not None else None,
            "existing_Q_bits": q.bit_length(),
            "new_context_and_reencrypted_index_if_Q_changed": True,
            "post_KS_PBS_and_relin_noise_budget_known": False,
            "parameter_security_or_PBS_compatibility_approved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new immutable result path")
    profiles_path = ROOT / "benchmarks/results/publication-encrypted-query-gate-control-20261001.json"
    paths = [Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", profiles_path,
             ROOT / "experiments/bfv_search_lab/bgv_unit_bridge.py",
             ROOT / "experiments/bfv_search_lab/test_bgv_unit_bridge.py",
             ROOT / "experiments/bfv_search_lab/score_phase_bridge_oracle.py",
             ROOT / "experiments/bfv_search_lab/shallow_bgv.py",
             ROOT / "docs/research/bgv-unit-bridge-preregistration-20261002.md"]
    result = metadata(paths)
    profiles = json.loads(profiles_path.read_text())["retained_geometry_count_screens"]
    mask_cases = 0
    for a, secret, signed in product(range(17), (-1, 0, 1), range(-8, 9)):
        context = bridge.unit_parameters(17, 3)
        phase = (a * context["multiplier"] * secret +
                 (signed - a * secret) * context["multiplier"]) % 17
        assert bridge.scaled_decode_reference(phase, 17, 3) == signed % 3
        mask_cases += 1
    residue_cases = 0
    for value in range(323):
        converted = value * pow(5, -1, 323) % 323
        limbs = (value % 17 * pow(5, -1, 17) % 17, value % 19 * pow(5, -1, 19) % 19)
        assert oracle.crt_value(limbs, (17, 19)) == converted
        residue_cases += 1
    result.update(kind="E86_known_modular_unit_BGV_conversion_control",
                  full_centered_scalar_phase_cards=scalar_control(), all_mask_key_phase_decompositions=mask_cases,
                  all_ring_component_cards=ring_control(), unit_then_torus_switch=torus_control(),
                  real_homemade_BGV_differential=real_bgv_control(),
                  all_canonical_RNS_unit_mapping_cases=residue_cases,
                  paid_conversion_geometry_cards=[{
                      "dataset": p["dataset"], "profile": p["profile"], "n": p["n"],
                      "existing_unit_context": bridge.unit_parameters(p["modeled_Q"], p["t"]),
                      "full_three_component_modular_products": 3 * p["n"] * p["replies"],
                      "index_or_key_context_change_required_for_unit_only": False,
                      "extra_secret_key_material_or_online_bytes_for_unit_only": 0,
                      "linear_RNS_or_NTT_scalar_fusion_possible_not_benchmarked": True,
                      "execution_binding_must_include_unit_map_and_permutation": True} for p in profiles],
                  post_unit_torus_margin_cards=[rounding_card(p, bits, relin)
                                               for p in profiles for bits in (32, 64) for relin in (False, True)],
                  decision="Advance known modular-unit conversion as the strong baseline. E85 naive adapters remain stopped, but a cheap correct phase conversion exists; no novel full selection/verification mechanism follows automatically.",
                  scope="Homemade bounded public unit adapter, exhaustive toy arithmetic, one actual local BGV differential and deterministic counts only. No TFHE PBS/keyswitch, runtime benchmark, release authentication, parameter/private-side-channel or novelty assurance.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out),
                      "full_scalar_cases": sum(c["signed_full_phase_and_both_sign_cases"] for c in result["full_centered_scalar_phase_cards"]),
                      "ring_cases": sum(c["all_coefficient_phase_conversion_cases"] for c in result["all_ring_component_cards"]),
                      "safe_torus_cases": result["unit_then_torus_switch"]["safe_mask_key_phase_cases"],
                      "conditional_margin_cards": len(result["post_unit_torus_margin_cards"])}))


if __name__ == "__main__":
    main()
