#!/usr/bin/env python3
"""E114 two exact ideal-law cards; no setup, timing, native or GPU execution."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from experiments.bfv_search_lab.one_prime_bounds import Profile, byte_card, complete_bound  # noqa: E402
from experiments.bfv_search_lab.query_quantizer_law import ideal_card  # noqa: E402

WORK = REPO.parent / "research-data/query-quantizer-law-20261003"
RAW = REPO / "benchmarks/results/publication-query-quantizer-law-20261003.json"
PREREG = "docs/research/query-quantizer-law-preregistration.md"
FROZEN_SHA = "a527f8688bcf203096367fe0716701bda353335d9a02635c98011b238fe4fb19"
OWNED_SOURCES = ["experiments/bfv_search_lab/query_quantizer_law.py",
                 "experiments/bfv_search_lab/test_query_quantizer_law.py",
                 "benchmarks/query_quantizer_law_lab.py"]
SOURCE_PATHS = [PREREG, *OWNED_SOURCES,
                "experiments/bfv_search_lab/one_prime_bounds.py",
                "experiments/bfv_search_lab/compressed_query_bgv.py",
                "experiments/bfv_search_lab/seeded_bgv.py",
                "experiments/bfv_search_lab/owner_bgv.py",
                "experiments/bfv_search_lab/support_bounds_bgv.py",
                "experiments/bfv_search_lab/butterfly_bgv.py",
                "experiments/bfv_search_lab/trace_bgv.py",
                "experiments/bfv_search_lab/compact_bgv.py",
                "src/cuhepy/bfv/scheme.py"]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exact_json(value):
    if type(value) is Fraction:
        return {"numerator": str(value.numerator), "denominator": str(value.denominator)}
    if type(value) is dict:
        return {key: exact_json(item) for key, item in value.items()}
    if type(value) in (tuple, list):
        return [exact_json(item) for item in value]
    return value


def write_json(path, value):
    path.write_text(json.dumps(exact_json(value), indent=2) + "\n")


def main():
    # Exact MGF numerator/denominator text is archived outside Git. The fixed
    # powers have around 10^5 bits; no N-fold rational product is materialized.
    sys.set_int_max_str_digits(0)
    WORK.mkdir(parents=True, exist_ok=True)
    receipt = json.loads((WORK / "preregistration-receipt.json").read_text())
    if sha(REPO / PREREG) != FROZEN_SHA or receipt["sha256"] != FROZEN_SHA:
        raise ValueError("Frozen preregistration changed")
    if RAW.exists():
        raise ValueError("Refuse to overwrite a completed scientific run")
    snapshot = WORK / "before-main-sources"
    snapshot.mkdir(exist_ok=False)
    for source in SOURCE_PATHS:
        target = snapshot / source
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / source, target)
    profile = Profile(16384, 512, 8192, t=1031, eta=21, digit_bits=15)
    cards = []
    for drop in (22, 23):
        deterministic = complete_bound(profile, drop=drop, relaxed=True)
        law, plus, minus, ideal = ideal_card(profile, deterministic)
        if sum(mass for _, mass in law.pmf()) != law.q:
            raise AssertionError("Incomplete exact scalar law")
        law_path = WORK / f"drop{drop}-exact-law.json"
        write_json(law_path, {"q": law.q, "t": law.t, "drop": drop,
                              "units": "delta/t", "denominator": law.q,
                              "pmf": law.pmf(), "mean_units": law.mean_units(),
                              "second_moment_units": law.second_moment_units()})
        mgf_path = WORK / f"drop{drop}-exact-mgf.json"
        write_json(mgf_path, {"base": Fraction(16385, 16384),
                              "joint_mgf_plus": plus, "joint_mgf_minus": minus})
        ordinary = ideal["certificate"]
        cards.append({"drop": drop, "deterministic_common_digit_control": deterministic,
                      "exact_law": {"radix": law.radix, "full_cycles": law.full_cycles,
                                    "tail": law.tail, "bin_count": len(law.pmf()),
                                    "support_units": [law.center_units - law.intervals,
                                                      law.center_units],
                                    "added_radius": law.added_bound,
                                    "mean_units": law.mean_units(),
                                    "mean_added_error": law.t * law.mean_units(),
                                    "second_moment_units": law.second_moment_units(),
                                    "mass_denominator": law.q,
                                    "law_path": str(law_path), "law_sha256": sha(law_path),
                                    "mgf_path": str(mgf_path), "mgf_sha256": sha(mgf_path),
                                    "plus_numerator_bits": plus.numerator.bit_length(),
                                    "plus_denominator_bits": plus.denominator.bit_length(),
                                    "minus_numerator_bits": minus.numerator.bit_length(),
                                    "minus_denominator_bits": minus.denominator.bit_length()},
                      "conditional_ideal_control": ideal,
                      "equally_informed_generic_certificate": ordinary,
                      "identical_generic_certificate": ordinary == ideal["certificate"],
                      "ordinary_control_ratio": 1,
                      "declared_schema_byte_model": byte_card(profile, deterministic)})
    summary = {"registered_card_count": 2, "drops": [22, 23],
               "pmf_bins_total": sum(card["exact_law"]["bin_count"] for card in cards),
               "deterministic_complete_common_digit_pass": [card["drop"] for card in cards
                   if card["deterministic_common_digit_control"]["owner_bound_feasible"]],
               "conditional_ideal_statistical_target_pass": [card["drop"] for card in cards
                   if card["conditional_ideal_control"]["certificate"]["conditional_target_2_pow_minus_128"]],
               "candidate_equals_generic_cards": sum(card["identical_generic_certificate"] for card in cards),
               "ordinary_control_ratio": 1,
               "outcome": "stop_literal_known_law_concentration_recipe; conditional_fact_only"}
    anchor = REPO / "benchmarks/results/publication-one-prime-20261003.json"
    output = {"kind": "E114_exact_uniform_ideal_mask_quantizer_law_two_card_conditional_certificate",
              "utc": datetime.now(UTC).isoformat(), "profile": asdict(profile),
              "current_repo_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
              "preregistration_sha256": FROZEN_SHA,
              "evidence_parent_E113_raw_sha256": sha(anchor),
              "source_sha256": {source: sha(REPO / source) for source in SOURCE_PATHS},
              "python": sys.version, "summary": summary, "cards": cards,
              "scope": {"exact_scalar_PMF_not_Q_enumeration": True,
                        "fixed_base_and_outward_rational_certificate": True,
                        "ideal_fresh_full_uniform_ring_mask_required": True,
                        "unit_secret_required": True, "query_chosen_before_own_mask_required": True,
                        "fresh_CBD_independent_of_mask_required": True,
                        "maintenance_and_reused_digits_bounded_pointwise": True,
                        "actual_public_SHAKE_seed_or_ROM_composition_proved": False,
                        "actual_secret_unit_probability_proved": False,
                        "actual_supported_security_parameters_approved": False,
                        "malicious_trace_admission_or_adaptive_protocol_proved": False,
                        "large_native_or_GPU_or_keygen_executed": False,
                        "timings_measured": False, "proof_backend_executed": False,
                        "schema_bytes_actual_large_packet_executed": False,
                        "complete_proof_authentication_enrollment_peak_memory_costs": "unknown",
                        "contribution_originality_pass": False},
              "development_failures": [],
              "development_corrections": ["peer review required P<Q for the compact-v1 helper; initial scientific raw/source/log preserved; same two cards must remain exact"]}
    RAW.parent.mkdir(parents=True, exist_ok=True)
    write_json(RAW, output)
    print(json.dumps(summary, indent=2))
    for card in cards:
        c = card["conditional_ideal_control"]["certificate"]
        print("drop", card["drop"], "floor_A", c["floor_log_exponent_lower"],
              "union", c["lifetime_union_factor"], "query_model_bytes",
              card["declared_schema_byte_model"]["query_complete_packet_bytes"])
    print("raw", RAW, "sha256", sha(RAW))


if __name__ == "__main__":
    main()
