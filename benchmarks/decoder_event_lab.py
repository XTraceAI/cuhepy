#!/usr/bin/env python3
"""E111 one fixed-context exact decoder event and matched cell-cover counts."""

# ruff: noqa: E402 -- standalone research entry point.

from argparse import ArgumentParser
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime
from fractions import Fraction
import gzip
import hashlib
from itertools import product
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cuhepy.bfv.scheme import _ring_product
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import decoder_event as lab
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab.test_carry_trace_noise import make_graph

PREREG = ROOT/"docs/research/decoder-event-preregistration.md"
PREREG_SHA = "6a927610a2ec2cc2d943e56ed84ca74a7a27facbaae9f01069f6914c0d578df0"
FIXTURE_SHA = "67865c3a405f9fde1257685cd4d384c107e1fde557ac7781bb5daac3be1f4c78"


def pin(path):
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}


def exact_covariance(joint):
    source, maintenance, denominator = Counter(), Counter(), sum(joint.values())
    for (p, r), mass in joint.items():
        source[p] += mass
        maintenance[r] += mass
    mean_p = Fraction(sum(p*m for p, m in source.items()), denominator)
    mean_r = Fraction(sum(r*m for r, m in maintenance.items()), denominator)
    covariance = Fraction(sum(p*r*m for (p, r), m in joint.items()), denominator)-mean_p*mean_r
    witness = next(((p, r, m) for (p, r), m in sorted(joint.items())
                    if m*denominator != source[p]*maintenance[r]), None)
    return {"coefficient_joint_pair_count": len(joint), "covariance": str(covariance),
            "not_product_of_marginals": witness is not None,
            "one_pair_falsifier": None if witness is None else {
                "original": witness[0], "maintenance": witness[1],
                "joint_mass": str(Fraction(witness[2], denominator)),
                "false_independent_mass": str(Fraction(source[witness[0]]*maintenance[witness[1]], denominator*denominator))},
            "no_covariance_or_independence_bound_used_for_native_certificate": True}


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.flags.optimize or args.output.exists():
        raise ValueError("Assertions must be active; preserve every existing raw output")
    if pin(PREREG)["sha256"] != PREREG_SHA or pin(args.fixture)["sha256"] != FIXTURE_SHA:
        raise ValueError("Frozen preregistration and original E105 fixture required")
    args.cache_dir.mkdir(parents=True, exist_ok=True)
    if any(args.cache_dir.glob("query-*-reference.jsonl.gz")):
        raise FileExistsError("Never replace a previous reference law")
    fixture = json.loads(args.fixture.read_text())
    graph = make_graph(tuple(fixture["index_mask"]), tuple(fixture["query_mask"]))
    literal = Counter(tuple(bits[2*i]-bits[2*i+1] for i in range(8)) for bits in product((0, 1), repeat=16))
    assert literal == dict(lab.weighted_states(8)) and sum(literal.values()) == 65536
    source_paths = (
        "experiments/bfv_search_lab/decoder_event.py", "experiments/bfv_search_lab/test_decoder_event.py",
        "benchmarks/decoder_event_lab.py", "experiments/bfv_search_lab/carry_trace_noise.py",
        "experiments/bfv_search_lab/test_carry_trace_noise.py", "experiments/bfv_search_lab/finite_lifetime_noise.py",
        "experiments/bfv_search_lab/test_finite_lifetime_noise.py", "experiments/bfv_search_lab/shallow_bgv.py",
        "experiments/bfv_search_lab/trace_bgv.py", "experiments/bfv_search_lab/compact_bgv.py", "src/cuhepy/bfv/scheme.py",
    )
    sources = [pin(ROOT/p) for p in source_paths]
    rows, totals = [], Counter()
    for bits in product((0, 1), repeat=2):
        event = lab.NativeEvent(graph, bits)
        certificates = {rule: lab.certify(event, rule=rule) for rule in ("generic", "candidate-residue")}
        cover = {rule: lab.check_certificate(event, cert) for rule, cert in certificates.items()}
        assert cover["generic"] == cover["candidate-residue"]
        assert cover["generic"]["failure_lower"] == cover["generic"]["failure_upper"] == "0"
        bound = event.bound(lab.Cell.root(8))
        name = "".join(map(str, bits))
        certificate_files = []
        for rule, cert in certificates.items():
            path = args.cache_dir/f"query-{name}-{rule}-certificate.json"
            if path.exists():
                raise FileExistsError("Never replace a previous certificate")
            path.write_bytes(lab.certificate_bytes(cert))
            certificate_files.append(pin(path))
        path = args.cache_dir/f"query-{name}-reference.jsonl.gz"
        law = [Counter() for _ in range(8)]
        actual_failures, failure_mass, max_phase, max_terminal = 0, 0, 0, 0
        with path.open("wb") as raw_file, gzip.GzipFile(fileobj=raw_file, mode="wb", mtime=0) as archive:
            for errors, mass in lab.weighted_states(8):
                values = event.evaluate(errors)
                query = graph.cipher(event.message, errors, graph.query_mask)
                result = trace.search(query, [graph.index], 3, graph.pk, graph.keys)[0]
                actual_components = tuple(tuple(map(int, p)) for p in result.components)
                assert actual_components == values.components
                q_product = _ring_product(result.components[1], graph.sk.s, graph.pk.q)
                actual_phase = tuple(int((a+b) % graph.pk.q) for a, b in zip(result.components[0], q_product, strict=True))
                assert actual_phase == tuple(x % event.q for x in values.final_phase)
                assert tuple(bgv.decrypt(result, graph.pk, graph.sk)) == event.expected_plaintext
                reduced = compact.compact(result, graph.pk, 16)
                assert int(reduced.modulus) == event.p
                assert tuple(tuple(map(int, p)) for p in reduced.components) == values.terminal
                secret_p = tuple(event.p-1 if s == -1 else s for s in event.secret)
                p_product = _ring_product(reduced.components[1], secret_p, reduced.modulus)
                terminal_phase = tuple(((int(a+b)+event.p//2) % event.p)-event.p//2
                                       for a, b in zip(reduced.components[0], p_product, strict=True))
                assert terminal_phase == values.terminal_phase
                plaintext = compact.decrypt(reduced, graph.pk, graph.sk)
                assert tuple(plaintext) == values.plaintext
                distances = tuple(trace.decode([plaintext], 3, 2, graph.pk))
                ranked = tuple(record_id for _, record_id in sorted(zip(distances, event.ids, strict=True)))
                failed = tuple(plaintext) != event.expected_plaintext or distances != event.expected_distances or ranked != event.expected_rank
                assert failed == values.failed and not failed
                assert all(i.lower <= x <= i.upper for x, i in zip(values.final_phase, bound.phase, strict=True))
                for j, digit in enumerate(values.digits):
                    assert all(i.lower <= x <= i.upper for x, i in zip(digit, bound.digit_ranges[j], strict=True))
                actual_failures += failed
                failure_mass += mass*failed
                max_phase = max(max_phase, *map(abs, values.final_phase))
                max_terminal = max(max_terminal, *map(abs, values.terminal_phase))
                for k, joint in enumerate(law):
                    joint[values.original[k], values.maintenance[k]] += mass
                record = {"errors": errors, "literal_coin_weight": mass, "original": values.original,
                          "maintenance": values.maintenance, "final_phase": values.final_phase,
                          "canonical_rotation_source": values.canonical, "terminal_phase": values.terminal_phase,
                          "plaintext": values.plaintext, "distances": distances, "ranked_ids": ranked, "failed": failed,
                          "preterminal_components_sha256": lab.digest(actual_components),
                          "terminal_components_sha256": lab.digest(values.terminal)}
                archive.write((json.dumps(record, separators=(",", ":"))+"\n").encode())
                totals.update({"query_error_states": 1, "literal_coin_equivalents": mass,
                               "Q_component_equalities": 16, "terminal_component_equalities": 16,
                               "Q_phase_equalities": 8, "terminal_phase_equalities": 8,
                               "preterminal_plaintext_equalities": 8, "terminal_plaintext_equalities": 8,
                               "distance_equalities": 3, "local_stable_ID_equalities": 1})
        assert actual_failures == failure_mass == 0
        rows.append({"query_bits": bits, "event_digest": event.event_digest, "expected_distances": event.expected_distances,
                     "local_stable_ids": event.ids, "expected_rank": event.expected_rank, "P": event.p,
                     "uniform_control": event.uniform_control(), "root_phase_intervals": [asdict(i) for i in bound.phase],
                     "root_phase_cap": bound.phase_cap, "root_terminal_cap": bound.terminal_cap,
                     "generic": cover["generic"], "candidate_residue": cover["candidate-residue"],
                     "candidate_generic_node_ratio": "1", "actual_failure_states": actual_failures,
                     "actual_failure_coin_mass": failure_mass, "exact_failure_probability": "0",
                     "maximum_exact_abs_Q_phase": max_phase, "maximum_exact_abs_terminal_phase": max_terminal,
                     "same_E_coefficient_joint_diagnostics": [exact_covariance(joint) for joint in law],
                     "certificate_files": certificate_files, "whole_joint_reference_cache": pin(path)})
        print(json.dumps({"query": name, "states": 6561, "coins": 65536,
                          "failures": actual_failures, "generic_and_candidate_nodes": 1}), flush=True)
    assert totals["query_error_states"] == 26244 and totals["literal_coin_equivalents"] == 262144
    assert sources == [pin(ROOT/p) for p in source_paths]
    output = {"schema": "publication-decoder-event-exact-control-v1", "utc": datetime.now(UTC).isoformat(),
              "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "git_branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip(),
              "python": sys.version, "platform": platform.platform(), "assertions_active": not sys.flags.optimize,
              "command": sys.argv, "preregistration": pin(PREREG), "original_E105_fixture": pin(args.fixture),
              "sources": sources, "contexts": 1, "queries": rows, "totals": dict(totals),
              "literal_coin_distribution_unique_errors": len(literal), "literal_coin_distribution_total": sum(literal.values()),
              "status": "completed bounded negative/control; stop literal native event compression and return to plan",
              "interpretation": {"native_failure_event_already_empty_by_strong_uniform_control": True,
                  "generic_receives_every_residue_enclosure_normalization_and_branch_rule": True,
                  "new_uncontained_algorithm_demonstrated": False, "timing_or_GPU_run": False,
                  "abstract_tests_not_new_native_parameters_or_surviving_candidate": True,
                  "conditioned_structured_setup_not_honest_IID_or_adaptive_lifetime_assurance": True,
                  "actual_private_decoder_is_disclosed_toy_GMP_API_not_production_side_channel_assurance": True,
                  "no_security_parameter_approval_tail_forecast_proof_bytes_or_novelty_claim": True}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2)+"\n")
    print(json.dumps({"raw": pin(args.output), "status": output["status"]}))


if __name__ == "__main__":
    main()
