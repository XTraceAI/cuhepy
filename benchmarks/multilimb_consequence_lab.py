#!/usr/bin/env python3
"""One frozen E120 public selector/schema/suffix cohort; no HE or probability."""

from __future__ import annotations

import ast
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from experiments.bfv_search_lab import multilimb_consequence as lab  # noqa: E402

WORK = REPO.parent / "research-data/multilimb-consequence-20261003"
RAW = REPO / "benchmarks/results/publication-multilimb-consequence-20261003.json"
PREREG = "docs/research/multilimb-consequence-preregistration-20261003.md"
PREREG_SHA = "25a23fa7841c144a0f2143f26b64faa60c7f78ff2c9d163a6333f8e088e69c40"
OWNED = ("experiments/bfv_search_lab/multilimb_consequence.py",
         "experiments/bfv_search_lab/test_multilimb_consequence.py",
         "benchmarks/multilimb_consequence_lab.py")
HISTORICAL = "benchmarks/results/bgv_owner_pipeline_8192.json"
OLD_Q_HEX = "ffffffffffc00020000003bffc0001"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encode(value):
    if is_dataclass(value):
        return encode(asdict(value))
    if type(value) is dict:
        return {str(k): encode(v) for k, v in value.items()}
    if type(value) in (tuple, list):
        return [encode(v) for v in value]
    return value


def write_json(path, value):
    path.write_text(json.dumps(encode(value), indent=2)+"\n")


def require(condition, check, evidence):
    if not condition:
        write_json(WORK / "main-failure.json", {"check": check, "evidence": evidence})
        raise AssertionError(check)


def constant_tag(path):
    tree = ast.parse(path.read_text())
    values = [node.value.value for node in tree.body
              if isinstance(node, ast.Assign) and len(node.targets) == 1
              and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "_TAG"
              and isinstance(node.value, ast.Constant)]
    if len(values) != 1:
        raise ValueError("Source tag is not a unique literal")
    return values[0]


def bounded_source_call(function, args, *, terminal=False):
    """Capped source identity check AFTER the matching bounded reproduction.

    The original company selectors alone are public. Their actual probable-
    prime calls are capped and recorded here; no private constructors run.
    """
    original = lab.gmpy2.is_prime
    counts, current, values = [], 0, []

    def checked(*actual):
        nonlocal current
        if len(actual) != (2 if terminal else 1) or (terminal and actual[1] != 32):
            raise ValueError("Source primality call contract drift")
        current += 1
        if current > lab.SELECTOR_CAP:
            raise RuntimeError("Actual source selector exceeded the frozen per-family cap")
        result = original(*actual)
        if result:
            values.append(int(actual[0]))
            counts.append(current)
            current = 0
        return result

    lab.gmpy2.is_prime = checked
    try:
        result = function(*args)
    finally:
        lab.gmpy2.is_prime = original
    return result, tuple(counts), tuple(values)


def main():
    #These clocks/limits are resource guards, not benchmark phases.
    resource.setrlimit(resource.RLIMIT_AS, (256*1024*1024, 256*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    signal.alarm(60)
    WORK.mkdir(parents=True, exist_ok=True)
    root_receipt = json.loads((WORK / "root-freeze-receipt.json").read_text())
    require(sha(REPO / PREREG) == PREREG_SHA == root_receipt["frozen_sha256"], "prereg_pin", {})
    freeze = json.loads((WORK / "source-argv-freeze.json").read_text())
    require(freeze["argv"] == [sys.executable, *sys.argv], "argv_pin", {})
    for name, digest in freeze["source_sha256"].items():
        require(sha(Path(name)) == digest, "source_pin", name)
    anchors = dict(re.findall(r"^([0-9a-f]{64}) (.+)$", (REPO / PREREG).read_text(), re.MULTILINE))
    require(len(anchors) == 23, "prereg_anchor_count", len(anchors))
    for digest, name in anchors.items():
        require(sha(REPO / name) == digest, "original_anchor_pin", name)
    require(not RAW.exists() and not (WORK / "candidate-selection-freeze.json").exists(), "one_cohort_only", {})
    snapshot = WORK / "before-main-sources"
    snapshot.mkdir(exist_ok=False)
    for name in (*OWNED, PREREG):
        destination = snapshot / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, destination)
    require(constant_tag(REPO / "experiments/bfv_search_lab/seeded_bgv.py") == lab.SEEDED_TAG
            and constant_tag(REPO / "experiments/bfv_search_lab/compressed_query_bgv.py") == lab.ROUNDED_TAG,
            "source_query_tags", {})
    graph = lab.Graph(16384, 512, 8192, 1031, 21, 30)
    historical = json.loads((REPO / HISTORICAL).read_text())
    require((historical["n"], historical["dimension"], historical["num_vectors"], historical["t"],
             historical["eta"], historical["digit_bits"], historical["terminal_bits"], historical["q_hex"])
            == (16384, 512, 8192, 1031, 21, 30, 25, OLD_Q_HEX), "historical_profile_identity", {})
    primes, checks = lab.reproduce_rns_primes(graph.n, 120)
    q = 1
    for p in primes:
        q *= p
    require(format(q, "x") == OLD_Q_HEX and q.bit_length() == 120, "current_selector_old_q_identity", primes)
    p, pchecks = lab.reproduce_terminal_modulus(q, graph.t, 25)
    #Public selectors only; actual loops are independently capped by the wrapper.
    from cuhepy.bfv.scheme import _rns_coefficient_primes
    from experiments.bfv_search_lab.compact_bgv import terminal_modulus
    actual_primes, actual_checks, actual_values = bounded_source_call(_rns_coefficient_primes, (graph.n, 120))
    actual_p, actual_pchecks, actual_pvalues = bounded_source_call(terminal_modulus, (lab.gmpy2.mpz(q), graph.t, 25), terminal=True)
    require(actual_primes == primes == actual_values and actual_checks == checks,
            "capped_actual_RNS_selector_matches", actual_checks)
    require(int(actual_p) == p and actual_pchecks == (pchecks,) and actual_pvalues == (p,),
            "capped_actual_terminal_selector_matches", actual_pchecks)
    ctx = lab.Context(graph, q, p).validate()
    broad, canonical = (lab.deterministic_baseline(ctx, law) for law in ("broad", "canonical"))
    response = lab.response_schema(ctx)
    historical_responses = {entry["response_bytes"] for entry in historical["warmup"].values()}
    require(historical_responses == {response["response_packet_bytes"]}, "response_schema_historical_format_control", response)
    require(response["terminal_bits"] == 25, "fixed_terminal25", response)
    selection = None
    if broad["drop"] is not None and canonical["drop"] is not None:
        selection = lab.select_candidate(ctx, canonical)
        require(lab.query_schema(ctx, canonical["drop"])["query_packet_bytes"]
                <= lab.query_schema(ctx, broad["drop"])["query_packet_bytes"], "stronger_denominator", {})
    phase = {"kind": "E120_selection_only_before_norm_suffix", "context": ctx,
             "source_order_primes": primes, "source_RNS_candidate_checks": checks,
             "source_terminal_candidate_checks": pchecks,
             "capped_actual_source_calls_match": True,
             "broad_registered_envelope": broad, "canonical_registered_envelope": canonical,
             "response_schema": response, "selection": selection,
             "norm_or_suffix_calculated": False, "probability_calculated": False,
             "owner_index_hypothetical_reenrollment_not_historical_public_index": True}
    phase_path = WORK / "candidate-selection-freeze.json"
    write_json(phase_path, phase)
    phase_hash = sha(phase_path)
    require(json.loads(phase_path.read_text()) == encode(phase), "candidate_phase_readback", {})
    #Exactly this persisted, immutable schema-selected scalar enters the next phase.
    certificate = suffix = candidate_bound = None
    stop = "registered_unrounded_baseline_rejects" if selection is None else selection["stop"]
    if selection is not None and selection["candidate"] is not None:
        frozen_drop = json.loads(phase_path.read_text())["selection"]["candidate"]["drop"]
        certificate = lab.norm_prefix(graph.n, primes)
        norm_bound = graph.n**(graph.n//2)
        require(all(prime**k <= norm_bound and (k == graph.n or norm_bound < prime**(k+1))
                    for prime, k in zip(primes, certificate["limb_nullity_caps"], strict=True)),
                "independent_adjacent_prime_power_control", certificate)
        suffix = lab.suffix_screen(ctx, frozen_drop, certificate)
        candidate_bound = lab.complete_bound(ctx, frozen_drop, "broad")
        stop = suffix["stop"]
    require(sha(phase_path) == phase_hash, "frozen_candidate_unchanged_after_suffix", {})
    for name, digest in freeze["source_sha256"].items():
        require(sha(Path(name)) == digest, "final_source_unchanged", name)
    summary = {"one_source_selected_profile": True, "source_q_hex_matches_historical": True,
               "b_det_broad": broad["drop"], "b_det_canonical": canonical["drop"],
               "candidate_drop": selection["candidate"]["drop"] if selection and selection["candidate"] else None,
               "response_packet_bytes": response["response_packet_bytes"],
               "canonical_baseline_exchange_bytes": selection["baseline_exchange_bytes"] if selection else None,
               "candidate_exchange_bytes": selection["candidate"]["exchange_bytes"] if selection and selection["candidate"] else None,
               "source_order_limb_nullity_caps": certificate["limb_nullity_caps"] if certificate else None,
               "prefix_length": certificate["prefix_length"] if certificate else None,
               "retained_threshold": suffix["retained_threshold"] if suffix else None,
               "equally_informed_generic_control_ratio": 1, "probability_calculated": False,
               "outcome": stop}
    output = {"kind": "E120_one_multilimb_owner_selection_and_suffix_screen", "utc": datetime.now(UTC).isoformat(),
              "repo_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
              "preregistration_sha256": PREREG_SHA, "source_argv_freeze_sha256": sha(WORK / "source-argv-freeze.json"),
              "owned_source_sha256": {name: sha(REPO / name) for name in OWNED},
              "candidate_selection_freeze_path": str(phase_path), "candidate_selection_freeze_sha256": phase_hash,
              "selection_phase": phase, "nonzero_ternary_norm_certificate": certificate,
              "candidate_broad_fullsupport_bound": candidate_bound, "candidate_broad_suffix_screen": suffix,
              "summary": summary, "resource_caps": {"wall_and_CPU_seconds": 60, "address_space_bytes": 256*1024*1024,
                                                       "selector_checks_per_family": lab.SELECTOR_CAP},
              "scope": {"hypothetical_owner_reenrollment": True, "canonical_and_broad_contracts_differ": True,
                        "exact_emitted_HE_schema_only": True, "candidate_disk_freeze_precedes_norm_suffix": True,
                        "suffix_certificate_recomputed_for_validation_not_new_profile": True,
                        "no_probability_MGF_lifetime_zero_mass_XOF_ROM_calculation": True,
                        "no_secret_key_ciphertext_sampler_native_GPU_proof_estimator_timing_service": True,
                        "existing_guards_unchanged_arithmetic_only": True,
                        "parameter_security_originality_complete_system_approved": False},
              "development_failures": json.loads((WORK / "development-fix.json").read_text())}
    RAW.parent.mkdir(parents=True, exist_ok=True)
    write_json(RAW, output)
    shutil.copyfile(RAW, WORK / "selected-raw.json")
    print(json.dumps(encode(summary), indent=2))
    print("raw_sha256", sha(RAW))


if __name__ == "__main__":
    main()
