#!/usr/bin/env python3
"""E91 exact all-secret drift bounds and conditional precision/count cards."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from dataclasses import replace
from fractions import Fraction
import hashlib
from itertools import product
import json
from pathlib import Path
from random import Random
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import bgv_unit_bridge as unit
from experiments.bfv_search_lab import quadratic_drift as lab
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import test_quadratic_drift as independent


def exact_cards():
    products, matrices, traces, inequalities = 0, 0, 0, 0
    for n in (2, 4):
        space = tuple(product((-1, 0, 1), repeat=n))
        for a, b in product(space, repeat=2):
            assert lab.ring_product(a, b) == independent.multiply(a, b)
            products += 1
        for poly in space:
            c = independent.convolution_matrix(poly)
            gram, moments = independent.matmul(c, independent.transpose(c)), lab.moments(poly)
            for k in range(n):
                h = independent.quadratic_matrix(poly, k)
                assert h == independent.transpose(h) and independent.matmul(h, h) == gram
                matrices += 1
            current = gram
            for moment in moments:
                if moment.power > 1:
                    current = independent.matmul(current, current)
                assert independent.matrix_trace(current) == moment.trace
                assert moment.trace == n * moment.polynomial[0]
                traces += 1
            for prefix in range(1, n + 1):
                bound = min(lab.quadratic_box(poly, prefix), prefix * min(m.root_upper for m in moments))
                for part in product((-1, 0, 1), repeat=prefix):
                    secret = (*part, *((0,) * (n - prefix)))
                    values = independent.multiply(poly, independent.multiply(secret, secret))
                    for value in values:
                        assert abs(value) <= bound
                        assert all(abs(value) <= prefix * m.root_upper for m in moments)
                        inequalities += 1
    independent.test_complete_tiny_rounding_phase_law_and_total_bound()
    independent.test_complete_linear_prefix_box_and_all_pair_quadratic_box_controls()
    independent.test_cropped_orbit_invariance_is_false()
    independent.test_wrong_star_modular_trace_and_floor_roots_are_not_certificates()
    return {"entire_small_signed_polynomial_products": products,
            "entire_small_symmetric_orbit_Gram_equalities": matrices,
            "independent_dense_trace_and_polynomial_trace_equalities": traces,
            "full_ternary_prefix_all_coefficient_bound_inequalities": inequalities,
            "complete_tiny_rounding_phase_and_total_bound_coefficient_cases": 17496,
            "exact_negatives": {"cropped_H0_norm_zero_but_H1_norm_one_for_monomial_prefix1": True,
                                "wrong_star_and_modular_trace_invalid": True,
                                "N2_poly1_1_fourth_trace8_floor_root1_is_not_upper": True}}


def receiver_cards():
    approved, rejected, called = independent.example(), 0, []
    good = lab.build(approved)
    assert lab.verify_and_release(approved, good, lambda _: "accepted") == "accepted"
    def reject(bad):
        nonlocal rejected
        try:
            lab.verify_and_release(approved, bad, lambda value: called.append(value))
        except ValueError:
            rejected += 1
        else:
            raise AssertionError("Wrong public certificate accepted")
    for field in ("rounded", "drift"):
        arrays = getattr(good, field)
        for family, poly in enumerate(arrays):
            for i, value in enumerate(poly):
                updated = [list(p) for p in arrays]
                updated[family][i] = value + 1
                reject(replace(good, **{field: tuple(tuple(p) for p in updated)}))
    for index, moment in enumerate(good.moments):
        for i, value in enumerate(moment.polynomial):
            updated = replace(moment, polynomial=(*moment.polynomial[:i], value + 1, *moment.polynomial[i + 1:]))
            reject(replace(good, moments=(*good.moments[:index], updated, *good.moments[index + 1:])))
        for field in ("trace", "root_upper"):
            updated = replace(moment, **{field: getattr(moment, field) + 1})
            reject(replace(good, moments=(*good.moments[:index], updated, *good.moments[index + 1:])))
    for field in ("body_bound", "linear_bound", "quadratic_box_bound", "quadratic_moment_bound", "total_bound"):
        reject(replace(good, **{field: getattr(good, field) + 1}))
    for bad in (replace(good, anchor="0" * 64), replace(good, moments=good.moments[:-1]),
                replace(good, rounded=good.rounded[:-1])):
        reject(bad)
    assert not called
    return {"accepted_owner_approved_transcripts": 1, "single_cell_and_framing_corruptions_rejected": rejected,
            "private_callback_calls_on_rejections": 0,
            "mode": "Full public original-rounding/product/root recomputation; no succinct proof",
            "complete_score_PBS_ID_or_decryption_authorization": False}


def fresh_bgv_differential():
    pk, sk = bgv.key_gen(n=8, t=17, q_bits=32, eta=1)
    inputs = ([1, 0, 1, 1, 0, 1, 0, 0], [0, 1, 1, 0, 0, 1, 0, 1])
    cipher = bgv.multiply(*(bgv.encrypt(x, pk) for x in inputs), pk)
    q, target = int(pk.q), 1 << 64
    components = unit.convert(tuple(tuple(int(x) for x in poly) for poly in cipher.components), q, pk.t)
    budget = (target * (q - 4 * cipher.phase_bound)) // (4 * pk.t) - 1
    assert budget > 0
    approved = lab.Approved(q, target, pk.n, components, "local-trusted-BGV-unit", pk.key_id, "fresh-test", budget)
    cert = lab.build(approved)
    lab.verify_and_release(approved, cert, lambda _: None)
    secret = tuple(int(x) if x <= pk.q // 2 else int(x - pk.q) for x in sk.s)
    original, rounded, drift = (independent.phase(polys, secret) for polys in
                                (components, cert.rounded, cert.drift))
    assert all((q * out - target * old - error) % (q * target) == 0
               for old, out, error in zip(original, rounded, drift, strict=True))
    inverse = unit.unit_parameters(q, pk.t)["plaintext_permutation_inverse"]
    decoded = [((2 * pk.t * (value % target) + target) // (2 * target)) % pk.t * inverse % pk.t
               for value in rounded]
    assert decoded == bgv.decrypt(cipher, pk, sk)
    assert max(map(abs, drift)) <= cert.total_bound
    return {"n": pk.n, "Q": q, "t": pk.t, "eta": pk.eta, "target_bits": 64,
            "all_integer_drift_and_GMP_decoded_coefficients_checked": pk.n,
            "original_public_phase_bound_and_all_secret_rounding_bound_sufficient": True,
            "fresh_random_OS_keys_not_replayed": True, "local_trusted_fixture_only": True,
            "production_parameters_or_PBS": False}


def polynomial_hash(poly):
    return hashlib.sha256(json.dumps(poly, separators=(",", ":")).encode()).hexdigest()


def geometry_cards(profiles):
    cards = []
    for index, p in enumerate(profiles):
        n, q = p["n"], p["modeled_Q"]
        for degree, shape in product((2048, 8192), ("uniform_public", "coherent_public", "monomial_public")):
            target, rng = 2 * degree, Random(910000 + index)
            if shape == "uniform_public":
                components = tuple(tuple(rng.randrange(q) for _ in range(n)) for _ in range(3))
            else:
                value = q // (2 * target)
                last = (value,) * n if shape == "coherent_public" else (value,) + (0,) * (n - 1)
                components = ((0,) * n, (0,) * n, last)
            for prefix in (512, n):
                approved = lab.Approved(q, target, prefix, components, "synthetic-public-count", "unapproved-prefix", "epoch", 1 << 200)
                cert = lab.build(approved)
                denominator = cert.body_bound + cert.linear_bound + cert.quadratic_box_bound
                normalized = np.array(cert.drift[2], dtype=np.float64) / q
                values = np.fft.fft(normalized * np.exp(-1j * np.pi * np.arange(n) / n))
                canonical_diagnostic = float(np.abs(values).max())
                error = Fraction(cert.total_bound, q) + Fraction(target * p["phase_bound"], q * p["t"]) + Fraction(1, 2)
                radius = (degree // p["t"] - 1) // 2
                words = sum(n * ((max(abs(x).bit_length() for x in m.polynomial) + 8) // 8) for m in cert.moments)
                cards.append({"dataset": p["dataset"], "profile": p["profile"], "N": n, "Q": q,
                              "public_key_prefix": prefix, "PBS_degree": degree, "target_modulus": target,
                              "synthetic_public_input_shape": shape, "source_component_sha256": [polynomial_hash(poly) for poly in components],
                              "input_is_NOT_real_encrypted_search_workload": True,
                              "body_bound_numerator": cert.body_bound, "linear_prefix_bound_numerator": cert.linear_bound,
                              "quadratic_all_pair_box_numerator": cert.quadratic_box_bound,
                              "quadratic_moment_numerator": cert.quadratic_moment_bound,
                              "all_coefficient_drift_bound_numerator": cert.total_bound,
                              "box_to_chosen_full_bound_ratio_NOT_runtime": str(Fraction(denominator, cert.total_bound)),
                              "box_total_bound_numerator": denominator,
                              "moment_strictly_improves_quadratic_box": cert.quadratic_moment_bound < cert.quadratic_box_bound,
                              "exact_moments": [{"p": m.power, "trace": m.trace, "root_upper": m.root_upper,
                                                 "polynomial_sha256": polynomial_hash(m.polynomial),
                                                 "maximum_signed_coefficient_bits": max(abs(x).bit_length() for x in m.polynomial) + 1}
                                                for m in cert.moments],
                              "canonical_norm_over_Q_FLOAT_DIAGNOSTIC_NOT_CERTIFICATE": canonical_diagnostic,
                              "chosen_moment_norm_over_Q": str(Fraction(min(m.root_upper for m in cert.moments), q)),
                              "known_exact_canonical_norm_is_at_least_as_tight_as_moment_norm": True,
                              "certified_interval_FFT_and_complete_proof_cost_implemented": False,
                              "moment_integer_polynomial_products": 4, "additional_pair_box_products": 2,
                              "full_public_verifier_repeats_moment_and_box_products": True,
                              "modeled_signed_variable_width_moment_body_upper_bytes_NO_codec_or_RSS": words,
                              "source_cipher_body_u64_bytes": 3 * n * 8,
                              "whole_odd_domain_error_bound_with_E72_input_phase": str(error),
                              "odd_domain_allowed_integer_error": radius,
                              "sufficient_original_Q_odd_domain_margin": error <= radius,
                              "source_secret_S_squared_relation_required": True,
                              "relin_packed_switch_and_S_squared_PBS_key_costs_paid_complete": False,
                              "compact_original_input_PBS_stable_ID_authentication_cost": None,
                              "owner_new_client_lifecycle_caches_and_whole_elapsed_measured": False,
                              "parameters_and_private_implementation_approved": False})
    return cards


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", required=True, type=Path)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    profile_path = ROOT / "benchmarks/results/publication-encrypted-query-gate-control-20261001.json"
    result = metadata([Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", profile_path,
                       ROOT / "experiments/bfv_search_lab/quadratic_drift.py",
                       ROOT / "experiments/bfv_search_lab/test_quadratic_drift.py",
                       ROOT / "experiments/bfv_search_lab/shallow_bgv.py", ROOT / "experiments/bfv_search_lab/bgv_unit_bridge.py",
                       ROOT / "experiments/bfv_search_lab/score_phase_bridge_oracle.py",
                       ROOT / "src/cuhepy/bfv/scheme.py", ROOT / "src/cuhepy/types.py", ROOT / "src/cuhepy/base.py",
                       ROOT / "docs/research/quadratic-drift-plan-20261002.md"])
    profiles = json.loads(profile_path.read_text())["retained_geometry_count_screens"]
    result.update(kind="E91_all_secret_quadratic_drift_certificate_control", exact=exact_cards(),
                  full_recomputation_receivers=receiver_cards(), fresh_homemade_BGV_differential=fresh_bgv_differential(),
                  synthetic_geometry_cards=geometry_cards(profiles),
                  decision="Keep a sound all-secret dependent-source drift bound and GMP integer certificate control. Known canonical norm is tighter; no original complete authenticated or parameter/performance mechanism is established. Return to R6 for a proof-carrying certified Fourier/prefix envelope discriminator, with full binding and strongest controls.",
                  scope="Homemade exact finite, matrix and public full-recomputation controls, one local real BGV differential and synthetic counts. FFT is diagnostic only. No runtime, secure parameters, compact proof, PBS/winner protocol, private assurance or novelty acceptance.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    cards = result["synthetic_geometry_cards"]
    print(json.dumps({"output": str(args.json_out), "exact": result["exact"],
                      "corrupt_certificates": result["full_recomputation_receivers"]["single_cell_and_framing_corruptions_rejected"],
                      "synthetic_cards": len(cards), "moment_beats_box": sum(c["moment_strictly_improves_quadratic_box"] for c in cards),
                      "original_Q_margin_passes": sum(c["sufficient_original_Q_odd_domain_margin"] for c in cards)}))


if __name__ == "__main__":
    main()
