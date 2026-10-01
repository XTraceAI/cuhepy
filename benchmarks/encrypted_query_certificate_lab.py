#!/usr/bin/env python3
"""E71 actual encrypted-query release pilot and separate real-geometry counts."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from contextlib import closing
import json
from pathlib import Path
import secrets
import statistics
import sys
from time import perf_counter

from gmpy2 import is_prime

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import convolution_certificate_oracle as polynomial
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import encrypted_query_certificate as protocol
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import verification_lifetime as lifetime
from experiments.bfv_search_lab.test_supported_decoder import CASES, inputs


def measure(call, *args, **kwargs):
    started = perf_counter()
    result = call(*args, **kwargs)
    return result, (perf_counter()-started)*1000


def independent_product_reference(index, request, pk):
    return tuple(polynomial.certify(g, int(pk.q)) for g in protocol.factor_groups(index, request, pk))


def geometry_count(profile, *, eta=21, budget=1024, target_bits=128):
    n = 2048 if profile["dataset"] == "connect4" else 16384
    h, t, replies = profile["columns"], profile["inner_t"], profile["rows"]//(2*n)
    fresh = t//2+t*eta
    bound = n*h*fresh**2
    minimum = max(profile["inner_q"], 2*bound+1)
    q = ((minimum-1+2*n-1)//(2*n))*(2*n)+1
    while not is_prime(q):
        q += 2*n
    if q >= 1 << 64:
        raise ValueError("Count screen exceeds word-size field")
    rounds = polynomial.rounds_for(q, 2*n-1, budget, target_bits)
    bits = q.bit_length()
    query = (h*n*bits+7)//8+32*h
    response = (3*replies*n*bits+7)//8
    quotient = (rounds*(n-1)*bits+7)//8
    weights = (rounds*3*replies*bits+7)//8
    hints = (rounds*(2*h*replies+1)*bits+7)//8
    old_reply = (profile["rows"]*profile["inner_q"].bit_length()+7)//8
    old_delta = profile["query_coordinate_count"]*((t.bit_length()+7)//8)
    return {"dataset": profile["dataset"], "profile": profile["profile"],
            "n": n, "columns": h, "replies": replies, "t": t, "eta": eta,
            "fresh_phase_bound": fresh, "depth_one_sum_phase_bound": bound,
            "original_linear_q": profile["inner_q"], "modeled_NTT_prime_q": q,
            "requires_new_key_and_reencrypted_index": q != profile["inner_q"],
            "inner_RLWE_parameters_approved": False,
            "ideal_one_use_certificate_attempt_budget": budget,
            "algebraic_target_bits_not_parameter_assurance": target_bits,
            "point_and_public_weight_rounds": rounds,
            "seeded_query_coefficient_and_seed_body_bytes": query,
            "three_component_response_body_bytes": response,
            "batched_quotient_body_bytes": quotient,
            "public_weight_body_bytes": weights,
            "public_online_body_bytes": query+response+quotient+weights,
            "private_one_use_hint_body_bytes_per_request": hints,
            "ticket_preparation_coefficient_evaluation_steps": rounds*2*h*replies*n,
            "GMP_Karatsuba_ring_products_per_request": 3*h*replies,
            "full_index_coefficient_body_bytes": (2*h*replies*n*bits+7)//8,
            "old_linear_reply_plus_public_delta_body_bytes": old_reply+old_delta,
            "new_public_body_to_old_public_body_ratio_not_total_cost": (query+response+quotient+weights)/(old_reply+old_delta),
            "extra_public_challenge_RTT": 1,
            "scope": "Correctness/count model, not measured large HE circuit, security parameters or total cost comparison. Old fresh-answer/check preparation and both framing/provisioning transports excluded; new private hints listed separately. Each new ticket's hidden points are independent and one-use."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new result path")
    cases = []
    for descriptor in CASES:
        s, words, groups, ids, _ = inputs(*descriptor)
        (pk, sk), key_ms = measure(masked.key_gen, s, q_bits=32, eta=1)
        epoch, attempts = secrets.token_bytes(32), lifetime.AttemptBudget(16)
        with closing(owner.OwnerClient(pk, sk)) as client:
            (index, upload_packet_bytes), enrollment_ms = measure(masked.enroll, s, groups, epoch, client)
            observations = []
            for word in range(16):
                rid = word.to_bytes(16, "little")
                receiver, prep_ms = measure(protocol.Receiver, index, pk, rid, attempts)
                values = tuple((1-2*(word >> j & 1)) % 17 for _ in s.dimensions for j in range(4))
                (request, query_packet_bytes), query_ms = measure(protocol.make_query, s, epoch, rid, values, client)
                output, server_ms = measure(protocol.evaluate, index, request, pk)
                body, pack_ms = measure(protocol.pack_output, output, index, pk)
                # This all-factor reference is diagnostic work, NOT the
                # receiver algorithm or included in the server evaluation time.
                independent, diagnostic_ms = measure(independent_product_reference, index, request, pk)
                assert tuple(tuple(int(x) for x in p) for c in output for p in c.components) == tuple(c.output for c in independent)
                challenge, freeze_ms = measure(receiver.freeze_once, request, body)
                proof, proof_ms = measure(protocol.prove, index, request, pk, challenge)
                dots, finish_ms = measure(receiver.open_once, proof, sk)
                assert dots == tuple(tuple(row) for row in crt.scores(s, groups, values))
                scores = tuple((x+word.bit_count()) % 17 for row in dots for x in row)
                expected = tuple((word ^ old).bit_count() for row in words for old in row)
                flat_ids = tuple(i for row in ids for i in row)
                assert scores == expected
                assert sorted(zip(scores, flat_ids, strict=True))[:3] == sorted(zip(expected, flat_ids, strict=True))[:3]
                observations.append({"query_word": word, "private_ticket_preparation_ms": prep_ms,
                                     "fresh_owner_query_ms": query_ms, "GMP_server_evaluation_ms": server_ms,
                                     "server_response_pack_ms": pack_ms,
                                     "independent_ordinary_product_diagnostic_ms_excluded": diagnostic_ms,
                                     "client_freeze_and_challenge_ms": freeze_ms,
                                     "server_reference_quotient_generation_pack_ms": proof_ms,
                                     "client_verification_decryption_score_decode_ms": finish_ms,
                                     "actual_query_packet_bytes": query_packet_bytes,
                                     "response_coefficient_body_bytes": len(body), "quotient_coefficient_body_bytes": len(proof),
                                     "all_scores_and_stable_top3_exact": True})
        medians = {name: statistics.median(row[name] for row in observations) for name in observations[0] if name.endswith("_ms")}
        cases.append({"n": pk.n, "q": int(pk.q), "t": pk.t, "eta": pk.eta,
                      "paths": descriptor[1], "counts": descriptor[2], "layout": descriptor[3].__module__,
                      "owner_key_generation_ms": key_ms, "owner_index_enrollment_ms": enrollment_ms,
                      "actual_seeded_index_upload_packet_bytes": upload_packet_bytes,
                      "body_counts": protocol.body_cost(index, pk, 4), "observations": observations,
                      "small_fixture_stage_median_ms_not_service_estimates": medians,
                      "one_use_receivers_consumed": attempts.used})
    original = ROOT/"benchmarks/results/publication-structured-operator-screen-20260930.json"
    screens = [geometry_count(p) for p in json.loads(original.read_text())["recorded_geometry_count_screens"]]
    paths = [Path(__file__), original, ROOT/"benchmarks/dictionary_layout_lab.py",
             ROOT/"src/cuhepy/bfv/scheme.py", ROOT/"src/cuhepy/types.py"]
    paths.extend(ROOT/"experiments/bfv_search_lab"/f"{name}.py" for name in
                 ("encrypted_query_certificate", "test_encrypted_query_certificate", "test_supported_decoder",
                  "convolution_certificate_oracle", "convolution_batch_certificate", "coefficient_body",
                  "owner_bgv", "seeded_bgv", "shallow_bgv", "crt_masked_bgv", "crt_query_space", "dyadic_crt",
                  "score_layout", "verification_lifetime"))
    result = metadata(paths)
    result.update(kind="one_use_encrypted_CRT_query_quotient_release_known_control",
                  exact_encrypted_queries=16*len(cases), cases=cases, retained_geometry_count_screens=screens,
                  scope="Homemade known-control depth-one composition; no owner encrypted mask answers, but one-use private index hints per request. "
                        "Toy N32/t17/eta1/4-round arithmetic and stage timings are NOT production security or large/native/GPU measurements. "
                        "Local immutable two-stage receiver is not a transport commitment, durable service or proof of privacy under rejection. "
                        "Body models exclude envelopes/framing/TLS/RTT and resident memory. Retained geometries are correctness/count screens, not deployed ciphertext runs. "
                        "No novelty, useful-effect gate, private timing or parameter assurance claimed.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({"output": str(args.json_out), "exact_encrypted_queries": result["exact_encrypted_queries"],
                      "retained_geometry_count_screens": len(screens),
                      "public_body_ratio_range_not_total_cost": [min(x["new_public_body_to_old_public_body_ratio_not_total_cost"] for x in screens),
                                                                 max(x["new_public_body_to_old_public_body_ratio_not_total_cost"] for x in screens)]}))


if __name__ == "__main__":
    main()
