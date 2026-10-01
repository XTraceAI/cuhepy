#!/usr/bin/env python3
"""E73 matched toy encrypted-query packing, trusted expansion and full costs."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from contextlib import closing
import json
from pathlib import Path
import secrets
import statistics
import sys

from gmpy2 import is_prime

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from benchmarks.encrypted_query_certificate_lab import geometry_count
from benchmarks.encrypted_query_gate_lab import measure
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import encrypted_query_certificate as encrypted
from experiments.bfv_search_lab import encrypted_query_gate as gate
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import packed_query_expansion as protocol
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import verification_lifetime as lifetime
from experiments.bfv_search_lab.test_packed_query_expansion import independent_products
from experiments.bfv_search_lab.test_supported_decoder import CASES, inputs


def count_screen(profile, *, digit_bits=4):
    old = geometry_count(profile)
    n, h, r, t, eta = old["n"], old["columns"], old["replies"], old["t"], old["eta"]
    if profile["width"] % h:
        raise ValueError("Uniform column geometry not established")
    degree, factor = profile["width"]//h, 1 << (h-1).bit_length()
    if degree & (degree-1) or (n//degree) % factor:
        raise ValueError("Retained uniform geometry does not fit expansion")
    fresh, bits = t//2+t*eta, old["modeled_NTT_prime_q"].bit_length()
    for _ in range(16):
        digits = (bits+digit_bits-1)//digit_bits
        switch = t*eta*n*((1 << digit_bits)-1)*digits
        expanded = factor*fresh+(factor-1)*switch
        bound = n*h*fresh*expanded
        minimum = max(old["modeled_NTT_prime_q"], 2*bound+1)
        q = ((minimum-1+2*n-1)//(2*n))*(2*n)+1
        while not is_prime(q):
            q += 2*n
        if q.bit_length() == bits:
            break
        bits = q.bit_length()
    else:
        raise AssertionError("Correctness/gadget count did not stabilize")
    levels = factor.bit_length()-1
    key_bytes = (levels*2*digits*n*bits+7)//8
    query = (n*bits+7)//8+32
    same_q_unpacked = (h*n*bits+7)//8+32*h
    reply = (3*r*n*bits+7)//8
    private_rounds = gate.rounds_for(q, 1024, 128)
    return {"dataset": profile["dataset"], "profile": profile["profile"], "n": n, "columns": h,
            "uniform_column_degree": degree, "replies": r, "t": t, "eta": eta,
            "expansion_factor": factor, "expansion_levels": levels,
            "unpacked_depth_one_Q": old["modeled_NTT_prime_q"], "packed_correctness_model_Q": int(q),
            "packed_Q_bits": bits, "fresh_query_bound": fresh, "switch_error_bound": switch,
            "expanded_query_bound": expanded, "summed_depth_one_output_bound": bound,
            "digit_bits": digit_bits, "gadget_digits": digits,
            "packed_query_coefficient_and_seed_body_bytes": query,
            "unpacked_query_at_same_Q_coefficient_and_seed_body_bytes": same_q_unpacked,
            "unpacked_query_at_own_smaller_Q_body_bytes": old["seeded_query_coefficient_and_seed_body_bytes"],
            "full_three_component_response_body_upper_bound_bytes": reply,
            "full_public_online_body_upper_bound_bytes": query+reply,
            "unseeded_public_evaluation_key_body_bytes": key_bytes,
            "setup_key_payload_amortization_queries_at_same_Q": (key_bytes+same_q_unpacked-query-1)//(same_q_unpacked-query),
            "one_expansion_ring_products": 2*digits*(factor-1),
            "server_index_query_ring_products": 3*h*r,
            "client_expansion_ring_products_for_trusted_E72_boundary": 2*digits*(factor-1),
            "dense_gate_compiled_private_fingerprint_body_bytes": (private_rounds*2*h*n*bits+7)//8,
            "native_word_only_Q_would_be_exceeded": bits > 64,
            "requires_new_key_and_reencrypted_index": q != profile["inner_q"],
            "scope": "Conservative correctness/body count, no large circuit measured or parameter approval. Uniform degrees inferred from retained unshared geometry. Full C0 upper bounds. RNS/key/preparation/transport work is not free; client expansion is required for this control, not a succinct certificate."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new result path")
    cases = []
    for descriptor in CASES:
        s, words, groups, ids, binding = inputs(*descriptor)
        pk, sk = masked.key_gen(s, q_bits=32, eta=1)
        keys, key_ms = measure(protocol.key_gen, s, pk, sk)
        epoch = secrets.token_bytes(32)
        with closing(owner.OwnerClient(pk, sk)) as client:
            index, index_bytes = masked.enroll(s, groups, epoch, client)
            baseline, baseline_registration_ms = measure(gate.Gate, index, pk, ids, binding, lifetime.AttemptBudget(16))
            receiver, registration_ms = measure(gate.Gate, index, pk, ids, binding, lifetime.AttemptBudget(16),
                                                query_phase_bound=protocol.expanded_bound(s, pk, keys))
            observations = []
            for word in range(16):
                values = tuple((1-2*(word >> j & 1)) % 17 for _ in s.dimensions for j in range(4))
                rid = word.to_bytes(16, "little")
                (original, packet_bytes), query_ms = measure(protocol.make_query, s, epoch, rid, values, client)
                canonical, client_expand_ms = measure(protocol.expand, original, s, pk, keys)
                _, pin_ms = measure(receiver.pin_query, canonical)
                expanded, server_expand_ms = measure(protocol.expand, original, s, pk, keys)
                assert expanded == canonical
                output, server_ms = measure(protocol.evaluate, index, expanded, pk, keys)
                # Independent full ordinary products and query decrypt are
                # diagnostics, not a cost hidden inside the service boundary.
                independent, diagnostic_ms = measure(independent_products, index, expanded, pk)
                assert tuple(tuple(tuple(map(int, p)) for p in c.components) for c in output) == independent
                assert tuple(tuple(bgv.decrypt(c, pk, sk)) for c in canonical.ciphertexts) == protocol.plaintext_oracle(s, protocol.plaintext(s, values))
                reply = gate.project(output, index, pk, expected_bound=protocol.output_bound(index, pk, keys))
                body, pack_ms = measure(gate.pack, reply, pk)
                dots, release_ms = measure(receiver.open_body_once, rid, body, sk)
                (unpacked, baseline_query_bytes), base_query_ms = measure(encrypted.make_query, s, epoch, rid, values, client)
                baseline.pin_query(unpacked)
                base_output, base_server_ms = measure(encrypted.evaluate, index, unpacked, pk)
                base_body = gate.pack(gate.project(base_output, index, pk), pk)
                base_dots, base_release_ms = measure(baseline.open_body_once, rid, base_body, sk)
                assert dots == base_dots == tuple(tuple(row) for row in crt.scores(s, groups, values))
                scores = tuple((x+word.bit_count()) % 17 for row in dots for x in row)
                expected = tuple((word ^ old).bit_count() for row in words for old in row)
                flat_ids = tuple(i for row in ids for i in row)
                assert scores == expected and sorted(zip(scores, flat_ids, strict=True))[:3] == sorted(zip(expected, flat_ids, strict=True))[:3]
                observations.append({"query_word": word, "client_packed_query_encryption_ms": query_ms,
                                     "trusted_client_expansion_ms": client_expand_ms, "client_pin_canonical_query_ms": pin_ms,
                                     "server_query_expansion_ms": server_expand_ms, "server_index_query_product_ms": server_ms,
                                     "server_response_pack_ms": pack_ms, "client_verify_selected_decrypt_decode_ms": release_ms,
                                     "ordinary_product_diagnostic_ms_excluded": diagnostic_ms,
                                     "baseline_client_unpacked_query_ms": base_query_ms,
                                     "baseline_server_index_query_product_ms": base_server_ms,
                                     "baseline_client_verify_selected_decrypt_decode_ms": base_release_ms,
                                     "actual_packed_query_packet_bytes": packet_bytes, "actual_unpacked_query_packet_bytes": baseline_query_bytes,
                                     "projected_three_component_response_body_bytes": len(body),
                                     "baseline_projected_response_body_bytes": len(base_body), "all_scores_and_stable_top3_exact": True})
        cases.append({"n": pk.n, "q": int(pk.q), "t": pk.t, "eta": pk.eta, "paths": descriptor[1], "counts": descriptor[2],
                      "layout": descriptor[3].__module__, "actual_index_upload_packet_bytes": index_bytes,
                      "owner_public_expansion_key_generation_ms": key_ms,
                      "once_per_index_gate_registration_ms": registration_ms,
                      "baseline_once_per_index_gate_registration_ms": baseline_registration_ms,
                      "body_and_operation_counts": protocol.cost(s, pk, keys), "observations": observations,
                      "stage_median_ms_not_service_estimates": {k: statistics.median(x[k] for x in observations) for k in observations[0] if k.endswith("_ms")}})
    original = ROOT/"benchmarks/results/publication-structured-operator-screen-20260930.json"
    paths = [Path(__file__), original, ROOT/"benchmarks/dictionary_layout_lab.py", ROOT/"benchmarks/encrypted_query_gate_lab.py",
             ROOT/"benchmarks/encrypted_query_certificate_lab.py", ROOT/"src/cuhepy/bfv/scheme.py", ROOT/"src/cuhepy/types.py"]
    paths.extend(ROOT/"experiments/bfv_search_lab"/f"{name}.py" for name in
                 ("packed_query_expansion", "test_packed_query_expansion", "encrypted_query_gate", "encrypted_query_certificate",
                  "test_supported_decoder", "trace_bgv", "convolution_certificate_oracle", "coefficient_body", "decryption_support",
                  "owner_bgv", "seeded_bgv", "shallow_bgv", "crt_masked_bgv", "crt_query_space", "dyadic_crt", "score_layout", "verification_lifetime"))
    result = metadata(paths)
    result.update(kind="partial_coefficient_expansion_of_encrypted_CRT_queries_known_control", exact_packed_queries=16*len(cases),
                  exact_unpacked_query_controls=16*len(cases), cases=cases,
                  retained_geometry_correctness_count_screens=[count_screen(p) for p in json.loads(original.read_text())["recorded_geometry_count_screens"]],
                  scope="Homemade known SealPIR/MulPIR-style partial expansion, same full-ring toy key/index/Q as unpacked control. "
                        "Valid release uses trusted client expansion; server expansion alone has no certificate. "
                        "Related-secret key security, timing, durability and parameters are unapproved. "
                        "Large profiles are separate correctness/count models, not performance measurements; full reply upper bounds and unseeded switch-key bodies. "
                        "No novel protocol or production change.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({"output": str(args.json_out), "exact_packed_queries": result["exact_packed_queries"],
                      "extra_trusted_client_expansion_charged": True,
                      "modeled_Q_bits": [p["packed_Q_bits"] for p in result["retained_geometry_correctness_count_screens"]]}))


if __name__ == "__main__":
    main()
