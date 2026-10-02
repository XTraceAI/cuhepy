#!/usr/bin/env python3
"""E92 exact mixed-key controls and conditional approximate-switch counts."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from dataclasses import replace
from fractions import Fraction
import hashlib
from itertools import product
import json
from pathlib import Path
from random import Random, SystemRandom
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import bgv_unit_bridge as unit
from experiments.bfv_search_lab import partial_packed_switch as lab
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import test_partial_packed_switch as independent


def digest(poly):
    return hashlib.sha256(json.dumps(poly, separators=(",", ":")).encode()).hexdigest()


def exact_cards():
    residues = boundaries = phases = coefficients = containments = 0
    for q, radix in product((3, 5, 7, 9, 17, 97), (3, 5)):
        for skip in range(lab.context(q, radix) + 1):
            for x in range(q):
                residual = lab.residual_bound(x, q, radix, skip)
                residues += 1
                for target in (2, 4, 16, 64, 1 << 64):
                    zero = lab.round_integer(residual, q, target) == 0
                    assert zero == (2 * target * abs(residual) < q)
                    assert target != 1 << 64 or zero == (residual == 0)
                    boundaries += 1
    for n, q, source_prefix, target_prefix in ((2, 7, 2, 2), (4, 17, 4, 1)):
        source_space = tuple((*part, *((0,) * (n - source_prefix)))
                             for part in product((-1, 0, 1), repeat=source_prefix))
        target_space = tuple((*part, *((0,) * (n - target_prefix)))
                             for part in product((-1, 0, 1), repeat=target_prefix))
        for skip, target_modulus in product(range(lab.context(q, 3) + 1), (4, 64)):
            for source, destination in product(source_space, target_space):
                rng = Random(92002)
                components = tuple(tuple(rng.randrange(q) for _ in range(n)) for _ in range(3))
                keys, errors = independent.make_keys(q, 3, source, destination, target_prefix, skip, rng)
                approved = lab.Approved(components, keys, source_prefix, target_modulus, 1,
                                       1 << 200, False, "unit-toy", "S", "T", "epoch")
                cert = independent.check_phase(approved, source, destination, errors)
                stricter = lab.build(replace(approved, require_zero_residual_mask=True))
                assert stricter.output == cert.output and stricter.rounded == cert.rounded
                assert stricter.total_bound == cert.total_bound
                phases += 1
                coefficients += n
                containments += 1
    for test in (independent.test_source_and_target_prefixes_have_separate_all_key_bounds,
                 independent.test_candidate_outputs_are_strictly_contained_in_known_approximate_control,
                 independent.test_zero_rounded_residual_does_not_remove_original_secret_phase,
                 independent.test_unit_conversion_must_precede_low_digit_choice,
                 independent.test_small_target_prefix_cannot_bound_full_source_squared_secret):
        test()
    return {"whole_small_residue_carry_cases": residues, "exact_round_zero_boundaries": boundaries,
            "all_small_source_target_secret_class_mixed_phases": phases,
            "whole_phase_rounding_and_complete_bound_coefficients": coefficients,
            "candidate_and_known_approximate_outputs_and_bounds_identical": containments,
            "negative_controls": ["zero_mask_nonzero_hidden_phase", "wrong_T_squared_for_S_squared",
                                  "target_prefix_for_original_source_secret", "unit_after_low_digit_choice",
                                  "B64_q64_no_nonzero_zero_mask_residual"]}


def receiver_cards():
    approved, _, _, _ = independent.example()
    good, calls, rejected = lab.build(approved), [], 0
    assert lab.verify_and_release(approved, good, lambda _: "public-control") == "public-control"
    def reject(bad):
        nonlocal rejected
        try:
            lab.verify_and_release(approved, bad, lambda value: calls.append(value))
        except ValueError:
            rejected += 1
        else:
            raise AssertionError("False public subrelation certificate accepted")
    for field in ("output", "rounded", "drift"):
        arrays = getattr(good, field)
        for family, poly in enumerate(arrays):
            for i, value in enumerate(poly):
                updated = [list(p) for p in arrays]
                updated[family][i] = value + 1
                reject(replace(good, **{field: tuple(tuple(p) for p in updated)}))
    for i, value in enumerate(good.residual):
        reject(replace(good, residual=(*good.residual[:i], value + 1, *good.residual[i + 1:])))
    for index, moment in enumerate(good.moments):
        for i, value in enumerate(moment.polynomial):
            updated = replace(moment, polynomial=(*moment.polynomial[:i], value + 1, *moment.polynomial[i + 1:]))
            reject(replace(good, moments=(*good.moments[:index], updated, *good.moments[index + 1:])))
        for field in ("trace", "root_upper"):
            updated = replace(moment, **{field: getattr(moment, field) + 1})
            reject(replace(good, moments=(*good.moments[:index], updated, *good.moments[index + 1:])))
    for field in ("body_bound", "linear_bound", "residual_box_bound", "residual_moment_bound",
                  "key_error_bound", "total_bound"):
        reject(replace(good, **{field: getattr(good, field) + 1}))
    for bad in (replace(good, anchor="0" * 64), replace(good, moments=good.moments[:-1]),
                replace(good, rounded=good.rounded[:-1]), replace(good, residual_mask_zero=1)):
        reject(bad)
    assert not calls
    return {"accepted_full_public_subrelations": 1, "corruptions_rejected": rejected,
            "private_callback_calls_on_rejections": 0, "full_recomputation_not_succinct": True,
            "upstream_score_PBS_ID_key_distribution_or_decryption_authorization": False}


def fresh_bgv_differential():
    pk, sk = bgv.key_gen(n=8, t=17, q_bits=32, eta=1)
    inputs = ([1, 0, 1, 1, 0, 1, 0, 0], [0, 1, 1, 0, 0, 1, 0, 1])
    cipher = bgv.multiply(*(bgv.encrypt(x, pk) for x in inputs), pk)
    q, target, rng = int(pk.q), 1 << 64, SystemRandom()
    components = unit.convert(tuple(tuple(int(x) for x in poly) for poly in cipher.components), q, pk.t)
    source = tuple(int(x) if x <= pk.q // 2 else int(x - pk.q) for x in sk.s)
    destination = tuple(rng.randrange(-1, 2) for _ in range(3)) + (0,) * 5
    keys, errors = independent.make_keys(q, 3, source, destination, 3, 1, rng)
    budget = target * (q - 4 * cipher.phase_bound) // (4 * pk.t) - 1
    approved = lab.Approved(components, keys, pk.n, target, 1, budget, False,
                           "local-unit-BGV", pk.key_id, "fresh-independent-target", "local-test")
    cert = independent.check_phase(approved, source, destination, errors)
    lab.verify_and_release(approved, cert, lambda _: None)
    after = independent.add(cert.rounded[0], independent.multiply(cert.rounded[1], destination))
    inverse = unit.unit_parameters(q, pk.t)["plaintext_permutation_inverse"]
    decoded = [((2 * pk.t * (value % target) + target) // (2 * target)) % pk.t * inverse % pk.t
               for value in after]
    assert decoded == bgv.decrypt(cipher, pk, sk)
    return {"N": pk.n, "q": q, "t": pk.t, "target_bits": 64, "skipped_C2_levels": 1,
            "source_prefix": pk.n, "independent_target_prefix": 3,
            "whole_decoded_and_integer_drift_coefficients_checked": pk.n,
            "source_and_key_and_rounding_bound_sufficient_local_fixture": True,
            "fresh_OS_random_source_and_independent_target_keys": True,
            "toy_trusted_differential_not_production_PBS_parameters": True}


def geometry_cards(profiles):
    cards = []
    for index, p in enumerate(profiles):
        n, q, radix = p["n"], p["modeled_Q"], 257
        levels, rng = lab.context(q, radix), Random(920000 + index)
        c1, c2 = (tuple(rng.randrange(q) for _ in range(n)) for _ in range(2))
        row1, row2 = (tuple(lab.digits(x, q, radix) for x in poly) for poly in (c1, c2))
        c1_l1 = sum(abs(x) for row in row1 for x in row)
        # Synthetic switched body/mask: these arrays are not a real switch.
        output = tuple(tuple(rng.randrange(q) for _ in range(n)) for _ in range(2))
        for skip in range(levels + 1):
            residual = tuple(sum(row[i] * radix ** i for i in range(skip)) for row in row2)
            traces = lab.moments(residual)
            box = lab.quadratic_box(residual, n)
            spectral = n * min(m.root_upper for m in traces)
            error = c1_l1 + sum(abs(x) for row in row2 for x in row[skip:])
            retained = 2 * levels - skip
            for bits in (12, 14, 64):
                target = 1 << bits
                drift = tuple(tuple(q * lab.round_integer(x, q, target) - target * x for x in poly)
                              for poly in output)
                numerator = max(map(abs, drift[0])) + lab.linear_bound(drift[1], 512) + target * (min(box, spectral) + error)
                budget = Fraction(target * (q - 4 * p["phase_bound"]), 4 * p["t"])
                zero = all(lab.round_integer(x, q, target) == 0 for x in residual)
                enough = numerator < budget
                cards.append({"dataset": p["dataset"], "profile": p["profile"], "N": n, "Q": q,
                              "source_prefix": n, "target_prefix": 512, "radix": radix,
                              "target_bits": bits, "full_levels_per_family": levels, "skipped_C2_levels": skip,
                              "source_public_mask_sha256": [digest(c1), digest(c2)],
                              "synthetic_switched_body_and_mask_sha256": [digest(poly) for poly in output],
                              "residual_sha256": digest(residual), "residual_pair_box": box,
                              "residual_moment_bound": spectral, "honest_key_eta1_noise_bound": error,
                              "moment_trace_and_root": [{"p": m.power, "trace": m.trace, "root_upper": m.root_upper}
                                                        for m in traces],
                              "total_drift_numerator": numerator, "conditional_E72_source_budget_numerator": str(budget),
                              "sufficient_known_approximate_high_precision_margin": enough,
                              "candidate_extra_zero_mask_condition": zero,
                              "sufficient_candidate_margin_and_zero_mask": enough and zero,
                              "retained_keys_per_target_family_pair": retained,
                              "full_key_u64_body_bytes": 2 * levels * 2 * n * 8,
                              "retained_key_u64_body_bytes": retained * 2 * n * 8,
                              "retained_polynomial_products": 2 * retained,
                              "key_and_product_fraction_saved_NOT_runtime": str(Fraction(skip, 2 * levels)),
                              "exact_certificate_products_additional": 6,
                              "full_verifier_repeats_certificate_and_switch_products": True,
                              "input_and_output_NOT_real_encrypted_search_or_switched_samples": True,
                              "original_phase_bound_for_synthetic_arrays_is_an_external_model_assumption": True,
                              "final_small_ring_MS_PBS_and_complete_score_ID_proof_cost_paid": False,
                              "actual_key_codec_setup_residency_RSS_lifecycle_and_elapsed_measured": False,
                              "parameters_private_implementation_or_original_main_mechanism_approved": False})
    return cards


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", required=True, type=Path)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    profile_path = ROOT / "benchmarks/results/publication-encrypted-query-gate-control-20261001.json"
    dependencies = [Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", profile_path,
                    ROOT / "experiments/bfv_search_lab/partial_packed_switch.py",
                    ROOT / "experiments/bfv_search_lab/test_partial_packed_switch.py",
                    ROOT / "experiments/bfv_search_lab/batched_score_bridge.py",
                    ROOT / "experiments/bfv_search_lab/quadratic_drift.py",
                    ROOT / "experiments/bfv_search_lab/shallow_bgv.py",
                    ROOT / "experiments/bfv_search_lab/bgv_unit_bridge.py",
                    ROOT / "experiments/bfv_search_lab/score_phase_bridge_oracle.py",
                    ROOT / "src/cuhepy/bfv/scheme.py", ROOT / "src/cuhepy/types.py", ROOT / "src/cuhepy/base.py",
                    ROOT / "docs/research/partial-packed-switch-preregistration-20261002.md"]
    result = metadata(dependencies)
    profiles = json.loads(profile_path.read_text())["retained_geometry_count_screens"]
    result.update(kind="E92_known_approximate_switch_containment_and_mixed_key_control",
                  exact=exact_cards(), full_public_receiver=receiver_cards(),
                  fresh_homemade_BGV_differential=fresh_bgv_differential(),
                  conditional_synthetic_geometry_cards=geometry_cards(profiles),
                  decision="Stop the zero-mask mixed release as an original mechanism: ordinary approximate switching has identical outputs and at least its admissibility region. Keep sound homemade mixed-key/source-residual controls. No complete timing/parameter/PBS/winner or original protocol accepted; return to R6.",
                  scope="Bounded exact arithmetic/public full recomputation, local fresh real BGV differential and conditional synthetic counts. Not measured runtime, secure parameter, compact proof or complete protocol assurance.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    cards = result["conditional_synthetic_geometry_cards"]
    print(json.dumps({"output": str(args.json_out), "exact": result["exact"],
                      "rejected_corruptions": result["full_public_receiver"]["corruptions_rejected"],
                      "synthetic_cards": len(cards),
                      "known_approximate_margin_cards": sum(c["sufficient_known_approximate_high_precision_margin"] for c in cards),
                      "candidate_margin_cards": sum(c["sufficient_candidate_margin_and_zero_mask"] for c in cards)}))


if __name__ == "__main__":
    main()
