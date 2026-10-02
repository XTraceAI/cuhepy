#!/usr/bin/env python3
"""E93A exact source-headroom audit; no timing/parameter/PBS assurance."""

# ruff: noqa: E402 -- standalone research runner.

from argparse import ArgumentParser
from dataclasses import asdict
from fractions import Fraction
from itertools import product
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import source_phase_budget as lab
from experiments.bfv_search_lab.test_source_phase_budget import cyclic_reference


def exact_support():
    vectors, cases, largest = tuple(product((-1, 0, 1), repeat=2)), 0, 0
    for ml, mr, el, er in product(vectors, repeat=4):
        got = lab.expanded_phase((ml,), (mr,), (el,), (er,), 3)
        direct = cyclic_reference(tuple(m + 3 * e for m, e in zip(ml, el, strict=True)),
                                  tuple(m + 3 * e for m, e in zip(mr, er, strict=True)))
        assert got["centered_phase_before_possible_Q_wrap"] == direct
        largest, cases = max(largest, *map(abs, direct)), cases + 1
    assert largest == lab.envelope(2, 3, 1, 1).centered_phase
    return {"whole_message_error_support_cases": cases, "integer_phase_coefficients": 2 * cases,
            "attained_centered_phase_bound": largest, "probability_of_attaining_bound_estimated": False}


def geometry_cards():
    old_path = ROOT / "benchmarks/results/publication-structured-operator-screen-20260930.json"
    inherited_path = ROOT / "benchmarks/results/publication-encrypted-query-gate-control-20261001.json"
    originals = json.loads(old_path.read_text())["recorded_geometry_count_screens"]
    inherited = json.loads(inherited_path.read_text())["retained_geometry_count_screens"]
    cards = []
    for profile, old in zip(originals, inherited, strict=True):
        n = 2048 if profile["dataset"] == "connect4" else 16384
        b = lab.envelope(n, profile["inner_t"], 21, profile["columns"])
        original = lab.ntt_prime_above(n, max(profile["inner_q"], 2 * b.centered_phase + 1))
        assert (n, b.centered_phase, original) == (old["n"], old["phase_bound"], old["modeled_Q"])
        replies = profile["rows"] // (2 * n)
        for multiplier in (2, 4, 6, 8):
            q = original if multiplier == 2 else lab.ntt_prime_above(n, multiplier * b.centered_phase + 1)
            bits = q.bit_length()
            cards.append({"dataset": profile["dataset"], "profile": profile["profile"],
                          "original_linear_Q": profile["inner_q"], "original_depth_one_Q": original,
                          "Q_multiplier_of_phase_lower_bound": multiplier, "Q": q,
                          "envelope": asdict(b), "replies": replies, "coefficient_bits": bits,
                          "bit_increase_from_depth_one_original": bits - original.bit_length(),
                          "original_Q_exactly_recovered": True,
                          "Q_minus_twice_phase": q - 2 * b.centered_phase,
                          "Q_minus_four_times_phase": q - 4 * b.centered_phase,
                          "unit_phase_error_in_torus": str(Fraction(b.centered_phase, b.t * q)),
                          "source_only_half_margin_B64": str(lab.source_margin(q, b.t, b.centered_phase, 1 << 64, domain="half")),
                          "source_only_quarter_margin_B64": str(lab.source_margin(q, b.t, b.centered_phase, 1 << 64, domain="quarter")),
                          "noise_product_fraction_of_bound": str(Fraction(b.error_products, b.centered_phase)),
                          "new_keys_index_required": q != profile["inner_q"],
                          "new_context_from_depth_one_original": q != original,
                          "seeded_query_body_bytes_excluding_framing": (n * b.columns * bits + 7) // 8 + 32 * b.columns,
                          "seeded_index_body_bytes_excluding_framing": replies * b.columns * ((n * bits + 7) // 8 + 32),
                          "full_three_component_source_reply_body_bytes": (3 * replies * n * bits + 7) // 8,
                          "raw_owner_binary_cache_bytes": (profile["rows"] * profile["width"] + 7) // 8,
                          "correctness_support_bound_recomputed": True,
                          "security_parameters_PBS_or_private_implementation_approved": False})
    return cards, (old_path, inherited_path)


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", required=True, type=Path)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    cards, inputs = geometry_cards()
    paths = [Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", *inputs,
             ROOT / "experiments/bfv_search_lab/source_phase_budget.py",
             ROOT / "experiments/bfv_search_lab/test_source_phase_budget.py",
             ROOT / "experiments/bfv_search_lab/seeded_bgv.py",
             ROOT / "experiments/bfv_search_lab/encrypted_query_certificate.py",
             ROOT / "src/cuhepy/bfv/scheme.py",
             ROOT / "docs/research/committed-precision-preregistration-20261002.md"]
    result = metadata(paths)
    result.update(kind="E93A_owner_source_phase_and_discriminating_context_audit",
                  exact=exact_support(), geometry_cards=cards,
                  decision="Original quarter budgets are empty; changed-Q contexts have recomputed support correctness, but no security approval. Proceed only with explicit nonempty changed-context or separately adapted high-precision premises.",
                  known_full_domain_control="FDFB-Compress 2023/645 Theorem1 uses half-message input margin, two PBS and beta<q/(4p); its published even-p domain is not instantiated for odd t by this count.",
                  scope="Exact integer supports and canonical body counts; no runtime or RLWE/PBS/whole protocol assurance.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "exact": result["exact"], "contexts": len(cards),
                      "original_quarter_positive": sum(c["Q_minus_four_times_phase"] > 0 for c in cards if c["Q_multiplier_of_phase_lower_bound"] == 2),
                      "changed_quarter_positive": sum(c["Q_minus_four_times_phase"] > 0 for c in cards if c["Q_multiplier_of_phase_lower_bound"] != 2)}))


if __name__ == "__main__":
    main()
