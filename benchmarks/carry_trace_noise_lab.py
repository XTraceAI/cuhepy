#!/usr/bin/env python3
"""E105 whole small-domain joint law and matched logical representation counts."""

# ruff: noqa: E402 -- standalone research entry point.

from argparse import ArgumentParser
from collections import Counter
from datetime import UTC, datetime
from fractions import Fraction
import gzip
import hashlib
from itertools import product
import json
from pathlib import Path
import platform
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.bfv_search_lab import carry_trace_noise as lab
from experiments.bfv_search_lab import finite_lifetime_noise as noise
from experiments.bfv_search_lab.test_carry_trace_noise import make_graph

PREREG = ROOT/"docs/research/carry-trace-noise-preregistration.md"
PREREG_SHA = "790889624fab7b87ec2f762dd3ee611b80c134db5dd8b6a07e828978f8a1ccbf"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def freeze(path):
    if path.exists():
        raise FileExistsError("Never redraw an existing fixed fixture")
    assert digest(PREREG.read_bytes()) == PREREG_SHA
    q = (1 << 61)-1
    fixture = {"kind": "E105_fixed_supported_setup_and_original_uniform_mask_realization",
               "utc_before_main_error_enumeration": datetime.now(UTC).isoformat(),
               "preregistration_sha256": PREREG_SHA, "N": 8, "dimension": 2, "t": 5, "Q": q,
               "index_mask": [secrets.randbelow(q) for _ in range(8)],
               "query_mask": [secrets.randbelow(q) for _ in range(8)],
               "draw_method": "Two independent full coefficient polynomials via OS-backed secrets.randbelow(Q), sampled once then conditioned/frozen",
               "not_production_SHAKE_seed_encoder_or_OS_entropy_assurance": True,
               "supported_deterministic_setup_helper": "test_finite_lifetime_noise.synthetic_context(8,2)",
               "same_mask_across_four_conditional_message_laws_not_deployed_mask_reuse": True}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(fixture, indent=2)+"\n")
    print(json.dumps({"fixture": str(path), "sha256": digest(path.read_bytes()), "error_enumeration_started": False}))


def literal_mass():
    return Counter(tuple(bits[2*j]-bits[2*j+1] for j in range(8)) for bits in product((0, 1), repeat=16))


def exact_quantile(counter, denominator, failure):
    absolute = Counter()
    for value, mass in counter.items():
        absolute[abs(value)] += mass
    remaining = denominator
    for radius in sorted(absolute):
        remaining -= absolute[radius]
        if Fraction(remaining, denominator) <= failure:
            return {"radius": radius, "exact_strict_tail": str(Fraction(remaining, denominator)),
                    "conditional_toy_target": str(failure)}
    raise AssertionError("Finite support mass mismatch")


def independence_diagnostic(joint, denominator):
    source, maintenance, total = Counter(), Counter(), Counter()
    for (p, r), mass in joint.items():
        source[p] += mass
        maintenance[r] += mass
        total[p+r] += mass
    mean_p = Fraction(sum(p*m for p, m in source.items()), denominator)
    mean_r = Fraction(sum(r*m for r, m in maintenance.items()), denominator)
    covariance = Fraction(sum(p*r*m for (p, r), m in joint.items()), denominator)-mean_p*mean_r
    witness = next(((p, r, mass) for (p, r), mass in sorted(joint.items())
                    if mass*denominator != source[p]*maintenance[r]), None)
    independent = Counter()
    for p, p_mass in source.items():
        for r, r_mass in maintenance.items():
            independent[p+r] += p_mass*r_mass
    true_abs, wrong_abs = Counter(), Counter()
    for x, mass in total.items():
        true_abs[abs(x)] += mass
    for x, mass in independent.items():
        wrong_abs[abs(x)] += mass
    true_remaining, wrong_remaining = denominator, denominator*denominator
    maximum_difference, tail_witness = Fraction(0), None
    for threshold in sorted(set(true_abs) | set(wrong_abs)):
        true_tail, wrong_tail = Fraction(true_remaining, denominator), Fraction(wrong_remaining, denominator*denominator)
        difference = abs(true_tail-wrong_tail)
        if difference > maximum_difference:
            maximum_difference = difference
            tail_witness = {"absolute_threshold_ge": threshold, "true_joint_tail": str(true_tail),
                            "false_independent_marginal_tail": str(wrong_tail)}
        true_remaining -= true_abs[threshold]
        wrong_remaining -= wrong_abs[threshold]
    return {"joint_mean_source": str(mean_p), "joint_mean_maintenance": str(mean_r),
            "exact_covariance": str(covariance), "joint_pair_count": len(joint),
            "joint_not_product_of_marginals": witness is not None,
            "one_pair_independence_falsifier": None if witness is None else {
                "source": witness[0], "maintenance": witness[1], "joint_mass": str(Fraction(witness[2], denominator)),
                "false_product_mass": str(Fraction(source[witness[0]]*maintenance[witness[1]], denominator*denominator))},
            "maximum_exact_total_tail_difference": str(maximum_difference), "tail_witness": tail_witness,
            "independent_marginal_model_is_only_a_falsifier_not_bound": True}


def integer_visits(snapshot):
    """Heterogeneous logical count, not calibrated hardware cycles or timing."""
    if isinstance(snapshot, dict):
        return sum(integer_visits(value) if isinstance(value, (dict, list, tuple)) else
                   value if type(value) is int and any(word in key for word in
                       ("integer_add", "integer_product", "coefficient_extract", "coefficient_visits",
                        "mod_radix", "div_radix", "wrap_comparisons")) else 0
                   for key, value in snapshot.items())
    if isinstance(snapshot, (list, tuple)):
        return 0  # Metadata basis arrays are not executed operation counters.
    return 0


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--freeze-only", action="store_true")
    parser.add_argument("--law-cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.freeze_only:
        freeze(args.fixture)
        return
    assert digest(PREREG.read_bytes()) == PREREG_SHA
    if args.output.exists():
        raise FileExistsError("Preserve raw outputs; choose another output path")
    frozen = json.loads(args.fixture.read_text())
    assert frozen["preregistration_sha256"] == PREREG_SHA and frozen["Q"] == (1 << 61)-1
    graph = make_graph(tuple(frozen["index_mask"]), tuple(frozen["query_mask"]))
    literal = literal_mass()
    assert literal == Counter({state.errors: state.mass for state in graph.states})
    matrix = tuple(tuple(column[i] % graph.q for column in graph.mask_columns) for i in range(8))
    inverse = lab.unit_inverse(matrix, graph.q)
    units = tuple(tuple(int(i == j) for i in range(8)) for j in range(8))
    source_columns = tuple(tuple(graph.t*x for x in noise.multiply(graph.index_phase, u)) for u in units)
    source_matrix = tuple(tuple(column[i] % graph.q for column in source_columns) for i in range(8))
    source_inverse = lab.unit_inverse(source_matrix, graph.q)
    direct, binary, carry = lab.Direct(graph.errors[1]), lab.Binary(graph.errors[1]), lab.Carry(graph.errors[1], graph.q)
    query_cards, whole_canonical, all_scores = [], set(), 0
    args.law_cache.mkdir(parents=True, exist_ok=True)
    for bits in product((0, 1), repeat=2):
        query = graph.query(bits)
        law, coefficient_laws, canonical_seen = Counter(), [Counter() for _ in range(8)], set()
        by_error = {}
        expected_distances = tuple(sum(a != b for a, b in zip(bits, row, strict=True)) for row in ((0, 0), (0, 1), (1, 0)))
        phase_max, source_max, maintenance_max = 0, 0, 0
        for state in graph.states:
            canonical, digits = graph.canonical(query, state)
            canonical_seen.add(canonical)
            whole_canonical.add(canonical)
            a, b, c = direct.functional(digits), binary.functional(digits), carry.functional(query, state, digits)
            assert a == b == c
            original = tuple(m+e for m, e in zip(query.original_mean, state.original_noise, strict=True))
            maintenance = tuple(r+graph.t*x for r, x in zip(graph.fixed_maintenance, a, strict=True))
            final = tuple(p+r for p, r in zip(original, maintenance, strict=True))
            actual_phase, decoded = graph.actual(query, state)
            assert actual_phase == tuple(x % graph.q for x in final) and decoded == expected_distances
            all_scores += len(decoded)
            law[original, maintenance] += state.mass
            by_error[state.errors] = original, maintenance
            for k in range(8):
                coefficient_laws[k][original[k], maintenance[k]] += state.mass
            phase_max = max(phase_max, *map(abs, final))
            source_max = max(source_max, *map(abs, original))
            maintenance_max = max(maintenance_max, *map(abs, maintenance))
        assert len(canonical_seen) == 6561 and sum(law.values()) == 65536
        literal_joint = Counter()
        # Repeat only integer state-to-law bookkeeping, not fake resampling or
        # repeated full crypto work in the generic operation-count comparator.
        for error, mass in literal.items():
            literal_joint[by_error[error]] += mass
        assert literal_joint == law
        joint_data = json.dumps({"bits": bits, "denominator": 65536,
                                "joint_vector_law": [{"original": p, "maintenance": r, "mass": mass}
                                                     for (p, r), mass in sorted(law.items())]}, separators=(",", ":")).encode()
        law_path = args.law_cache/f"joint-vector-law-{bits[0]}{bits[1]}.json.gz"
        if law_path.exists():
            raise FileExistsError("Preserve archived full joint laws")
        law_path.write_bytes(gzip.compress(joint_data, mtime=0))
        source_support = [abs(query.original_mean[k])+sum(abs(column[k]) for column in graph.source_columns) for k in range(8)]
        rotation_cap = noise.uniform_switch_cap(graph.errors[1], 16, graph.t)
        complete_support = max(source_support[k]+abs(graph.fixed_maintenance[k])+rotation_cap for k in range(8))
        diagnostics = []
        for k, coefficient_law in enumerate(coefficient_laws):
            total = Counter()
            for (p, r), mass in coefficient_law.items():
                total[p+r] += mass
            diagnostics.append({"coefficient": k, **independence_diagnostic(coefficient_law, 65536),
                                "exact_conditional_total_phase_quantiles": [exact_quantile(total, 65536, target)
                                                                            for target in (Fraction(1, 16), Fraction(1, 256))]})
        query_cards.append({"query": bits, "weighted_error_states": 6561, "literal_coin_outcomes": 65536,
                            "distinct_canonical_full_digit_sources": len(canonical_seen), "distinct_joint_vector_law_values": len(law),
                            "exact_original_phase_max": source_max, "exact_maintenance_phase_max": maintenance_max,
                            "exact_final_phase_max": phase_max, "matched_fixed_setup_all_support_phase_bound": complete_support,
                            "all_support_to_exact_finite_max_ratio": str(Fraction(complete_support, phase_max)),
                            "joint_law_archive": {"path": str(law_path.resolve()), "compressed_sha256": digest(law_path.read_bytes()),
                                                  "uncompressed_sha256": digest(joint_data)},
                            "coefficient_joint_diagnostics": diagnostics})
        print(f"E105 query {bits}: full joint law, actual API and literal mass checks complete", file=sys.stderr, flush=True)
    snapshots = {"generic_grouped_direct": direct.snapshot(), "generic_grouped_signed_binary": binary.snapshot(),
                 "carry_grouped_signed_binary_factor": carry.snapshot()}
    visits = {name: integer_visits(value) for name, value in snapshots.items()}
    preparation = dict(graph.counts)
    carry_preparation = {k: preparation.pop(k) for k in tuple(preparation) if k.startswith("carry_only_")}
    assert all_scores == 78732
    source_paths = [Path(__file__), PREREG, ROOT/"experiments/bfv_search_lab/carry_trace_noise.py",
                    ROOT/"experiments/bfv_search_lab/test_carry_trace_noise.py",
                    ROOT/"experiments/bfv_search_lab/test_finite_lifetime_noise.py",
                    ROOT/"experiments/bfv_search_lab/finite_lifetime_noise.py",
                    ROOT/"experiments/bfv_search_lab/shallow_bgv.py", ROOT/"experiments/bfv_search_lab/trace_bgv.py",
                    ROOT/"src/cuhepy/bfv/scheme.py"]
    result = {"kind": "E105_full_support_conditioned_trace_joint_law_and_matched_counts",
              "metadata": {"utc": datetime.now(UTC).isoformat(), "command": sys.argv,
                           "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                           "python": platform.python_version(), "platform": platform.platform(),
                           "source_sha256": {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in source_paths}},
              "frozen_fixture": {"path": str(args.fixture.resolve()), "sha256": digest(args.fixture.read_bytes()), "contents": frozen},
              "graph": {"N": 8, "D": 2, "t": 5, "Q": graph.q, "gadget_levels": 16,
                        "one_product_one_relin_one_rotation": True, "full_N_support": True,
                        "fixed_deterministic_setup_not_honest_setup_sampling": True,
                        "original_index_integer_phase": graph.index_phase,
                        "rotated_mask_affine_inverse_verified": inverse is not None,
                        "rotated_mask_affine_inverse": inverse,
                        "unprojected_source_affine_inverse_verified": source_inverse is not None,
                        "unprojected_source_affine_inverse": source_inverse,
                        "complete_source_digit_state_injectivity_is_known_algebra_not_novelty": True,
                        "projected_source_field_rank_upper_bound": 4,
                        "projected_source_distinct_bounded_ternary_vectors": len({s.original_noise for s in graph.states}),
                        "setup_rotation_error_distinct_rows": len(set(graph.errors[1])),
                        "setup_rotation_error_signed_primitive_orbits": direct.memo.snapshot()["compiled_distinct_primitive_orbits"],
                        "Q_wrap_kernel_exactly_last_periodic_error_row": carry.q_kernel == graph.errors[1][-1],
                        "Q_wrap_diagnostic_cancellation_not_generic_IID": True},
              "common_preparation_and_canonical_operation_counts": preparation,
              "carry_specific_prepared_digit_counts_also_paid_in_carry_snapshot": carry_preparation,
              "query_cards": query_cards, "representation_count_snapshots": snapshots,
              "heterogeneous_logical_integer_visit_counts": visits,
              "summary": {"queries": 4, "weighted_states": 26244, "equivalent_literal_coin_outcomes": 262144,
                          "actual_API_exact_record_distances": all_scores, "actual_API_full_phase_coefficients": 26244*8,
                          "full_canonical_sources_across_all_contexts": len(whole_canonical),
                          "canonical_state_compression_found": False,
                          "coefficient_laws_not_independent_marginals": sum(d["joint_not_product_of_marginals"] for card in query_cards for d in card["coefficient_joint_diagnostics"]),
                          "nonzero_covariance_coefficient_laws": sum(Fraction(d["exact_covariance"]) != 0 for card in query_cards for d in card["coefficient_joint_diagnostics"]),
                          "carry_fewer_registered_arithmetic_visits_than_both_controls": visits["carry_grouped_signed_binary_factor"] < min(visits["generic_grouped_direct"], visits["generic_grouped_signed_binary"]),
                          "known_carry_identity_finite_law_reuse_not_online_HE_optimization": True,
                          "candidate_status": "STOP_literal_full_state_compression_known_injectivity_and_finite_domain_control",
                          "new_original_mechanisms_accepted": 0, "parameters_approved": 0,
                          "timing_panels": 0, "general_adaptive_setup_theorem": False},
              "scope": "Exact conditional small synthetic setup/fixed ideal-uniform mask law only. Logical counts exclude Python object memory/hardware calibration and separately list common prep. All error-dependent carries and joint noise preserved; no new security/parameter/privacy/release/performance claim."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({"summary": result["summary"], "logical_visits": visits}, indent=2))


if __name__ == "__main__":
    main()
