#!/usr/bin/env python3
"""E72 one-registration projected gate, measured toy stages and separate counts."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from contextlib import closing
from itertools import product
import json
from pathlib import Path
import secrets
import statistics
import sys
from time import perf_counter
import tracemalloc

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from benchmarks.encrypted_query_certificate_lab import geometry_count
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import encrypted_query_certificate as encrypted
from experiments.bfv_search_lab import encrypted_query_gate as protocol
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import verification_lifetime as lifetime
from experiments.bfv_search_lab.test_supported_decoder import CASES, inputs


def measure(call, *args, **kwargs):
    start = perf_counter()
    result = call(*args, **kwargs)
    return result, (perf_counter()-start)*1000


def count_screen(profile):
    old = geometry_count(profile)
    n, h, r, q = old["n"], old["columns"], old["replies"], old["modeled_NTT_prime_q"]
    rounds = protocol.rounds_for(q, 1024, 128)
    bits = q.bit_length()
    query, reply = old["seeded_query_coefficient_and_seed_body_bytes"], old["three_component_response_body_bytes"]
    return {"dataset": profile["dataset"], "profile": profile["profile"], "n": n,
            "columns": h, "replies": r, "t": old["t"], "eta": old["eta"],
            "modeled_Q": q, "phase_bound": old["depth_one_sum_phase_bound"],
            "requires_new_key_and_reencrypted_index": old["requires_new_key_and_reencrypted_index"],
            "dense_field_rounds_for_1024_attempt_128bit_algebraic_target": rounds,
            "seeded_query_coefficient_and_seed_body_bytes": query,
            "full_three_component_response_body_upper_bound_bytes": reply,
            "public_online_body_upper_bound_bytes": query+reply,
            "private_compiled_fingerprint_body_bytes": (rounds*2*h*n*bits+7)//8,
            "private_full_output_challenge_body_upper_bound_bytes": (rounds*3*r*n*bits+7)//8,
            "registration_negacyclic_products": rounds*4*h*r,
            "client_check_field_products_upper_bound_per_query": rounds*(2*h*n+3*r*n),
            "server_ring_products_per_query": 3*h*r,
            "per_query_owner_answer_or_point_hint_preparation": False,
            "old_linear_reply_and_delta_body_bytes_excluding_factory": old["old_linear_reply_plus_public_delta_body_bytes"],
            "public_upper_bound_ratio_to_old_excluding_factory": (query+reply)/old["old_linear_reply_plus_public_delta_body_bytes"],
            "scope": "Correctness/body model only. Full C0 upper bounds; real support not measured here. New Q is not approved, private bodies are not RSS, old factory/framing costs excluded. No deployment or novelty claim."}


def feedback_count():
    accepted = 0
    for entries in product(range(3), repeat=4):
        rows = (entries[:2], entries[2:])
        first = all(row[0] == 0 for row in rows)
        second = all(row[1] == 0 for row in rows) if not first else False
        accepted += first or second
    return {"field": 3, "independent_rows": 2, "error_dimension": 2,
            "private_matrices_exhausted": 81, "two_attempt_first_wrong_accept_count": accepted,
            "ideal_union_bound_numerator_denominator": [2, 9],
            "scope": "Exact finite aggregate-feedback control, not a cryptographic security proof."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new result path")
    cases = []
    for descriptor in CASES:
        s, words, groups, ids, binding = inputs(*descriptor)
        (pk, sk), key_ms = measure(masked.key_gen, s, q_bits=32, eta=1)
        epoch, attempts = secrets.token_bytes(32), lifetime.AttemptBudget(16)
        with closing(owner.OwnerClient(pk, sk)) as client:
            (index, upload_bytes), enrollment_ms = measure(masked.enroll, s, groups, epoch, client)
            receiver, registration_ms = measure(protocol.Gate, index, pk, ids, binding, attempts)
            # Separate allocation diagnostic; never merge its slowed timing into
            # the registration or per-query observations above/below.
            tracemalloc.start()
            diagnostic_gate = protocol.Gate(index, pk, ids, binding, lifetime.AttemptBudget(1))
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            del diagnostic_gate
            observations = []
            for word in range(16):
                values = tuple((1-2*(word >> j & 1)) % 17 for _ in s.dimensions for j in range(4))
                rid = word.to_bytes(16, "little")
                (request, query_bytes), query_ms = measure(encrypted.make_query, s, epoch, rid, values, client)
                _, pin_ms = measure(receiver.pin_query, request)
                output, server_ms = measure(encrypted.evaluate, index, request, pk)
                reply, projection_ms = measure(protocol.project, output, index, pk)
                body, pack_ms = measure(protocol.pack, reply, pk)
                dots, release_ms = measure(receiver.open_body_once, rid, body, sk)
                assert dots == tuple(tuple(row) for row in crt.scores(s, groups, values))
                # Independent full decryption is diagnostic, not receiver work.
                full, diagnostic_ms = measure(lambda s=s, pk=pk, sk=sk, output=output:
                                              tree.unpack(s.layout, [bgv.decrypt(c, pk, sk) for c in output]))
                assert dots == tuple(tuple(row) for row in full)
                scores = tuple((x+word.bit_count()) % 17 for row in dots for x in row)
                expected = tuple((word ^ old).bit_count() for row in words for old in row)
                flat_ids = tuple(i for row in ids for i in row)
                assert scores == expected
                assert sorted(zip(scores, flat_ids, strict=True))[:3] == sorted(zip(expected, flat_ids, strict=True))[:3]
                observations.append({"query_word": word, "client_query_encryption_ms": query_ms,
                                     "client_pin_original_query_ms": pin_ms, "GMP_server_evaluation_ms": server_ms,
                                     "server_projection_validation_ms": projection_ms, "server_response_pack_ms": pack_ms,
                                     "client_verify_selected_decrypt_decode_ms": release_ms,
                                     "full_decrypt_diagnostic_ms_excluded": diagnostic_ms,
                                     "actual_seeded_query_packet_bytes": query_bytes,
                                     "projected_three_component_response_body_bytes": len(body),
                                     "per_query_owner_answer_or_point_hint_preparation_ms": 0,
                                     "all_scores_and_stable_top3_exact": True})
        cases.append({"n": pk.n, "q": int(pk.q), "t": pk.t, "eta": pk.eta,
                      "paths": descriptor[1], "counts": descriptor[2], "layout": descriptor[3].__module__,
                      "owner_key_generation_ms": key_ms, "owner_index_enrollment_ms": enrollment_ms,
                      "actual_seeded_index_upload_packet_bytes": upload_bytes,
                      "once_per_index_private_registration_ms": registration_ms,
                      "separate_python_registration_traced_retained_bytes": current,
                      "separate_python_registration_traced_peak_bytes": peak,
                      "body_counts": protocol.body_cost(index, pk, 4), "observations": observations,
                      "small_fixture_stage_median_ms_not_service_estimates":
                          {k: statistics.median(row[k] for row in observations) for k in observations[0] if k.endswith("_ms")},
                      "attempts_consumed": attempts.used})
    original = ROOT/"benchmarks/results/publication-structured-operator-screen-20260930.json"
    paths = [Path(__file__), original, ROOT/"benchmarks/dictionary_layout_lab.py",
             ROOT/"benchmarks/encrypted_query_certificate_lab.py", ROOT/"src/cuhepy/bfv/scheme.py", ROOT/"src/cuhepy/types.py"]
    paths.extend(ROOT/"experiments/bfv_search_lab"/f"{p}.py" for p in
                 ("encrypted_query_gate", "test_encrypted_query_gate", "encrypted_query_certificate", "test_supported_decoder",
                  "coefficient_body", "decryption_support", "owner_bgv", "seeded_bgv", "shallow_bgv", "crt_masked_bgv",
                  "crt_query_space", "dyadic_crt", "score_layout", "verification_lifetime"))
    result = metadata(paths)
    result.update(kind="one_registration_dense_projected_encrypted_query_gate_known_control", exact_queries=16*len(cases),
                  cases=cases, feedback_exhaustion=feedback_count(),
                  retained_geometry_count_screens=[count_screen(p) for p in json.loads(original.read_text())["recorded_geometry_count_screens"]],
                  scope="Homemade known control; no per-query owner answers/private point hints. Large uniform-field private registration. "
                        "Toy stages and separate Python traced allocations are not large/native/GPU/service/RSS results. "
                        "One aggregate relation gate, no separate proof input, volatile request and lifetime state. "
                        "Real geometries are count/correctness screens; no parameter/private timing/durability/security/novelty approval.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({"output": str(args.json_out), "exact_queries": result["exact_queries"],
                      "registration_required_per_query": False, "large_profiles_measured": False}))


if __name__ == "__main__":
    main()
