#!/usr/bin/env python3
"""E77 seed-conditioned online state control, with all trusted factory costs."""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from contextlib import closing
import json
from pathlib import Path
import secrets
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from benchmarks.encrypted_query_gate_lab import measure
from benchmarks.packed_query_expansion_lab import count_screen as packed_count
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import encrypted_query_gate as dense
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import packed_query_expansion as packed
from experiments.bfv_search_lab import seed_affine_gate as protocol
from experiments.bfv_search_lab.test_packed_query_expansion import independent_products
from experiments.bfv_search_lab.test_supported_decoder import CASES, inputs
from experiments.bfv_search_lab import verification_lifetime as lifetime


def count_screen(profile):
    old = packed_count(profile)
    n, h, factor, bits = old["n"], old["columns"], old["expansion_factor"], old["packed_Q_bits"]
    rounds = dense.rounds_for(old["packed_correctness_model_Q"], 1024, 128)
    receiver = (rounds * n * bits + 7) // 8
    return {"dataset": old["dataset"], "profile": old["profile"], "n": n, "columns": h,
            "packed_Q_bits": bits, "rounds": rounds,
            "online_receiver_full_vector_body_bytes": receiver,
            "possible_active_vector_packing_body_bytes_model": (rounds * n * h // factor * bits + 7) // 8,
            "baseline_expanded_fingerprint_body_bytes": old["dense_gate_compiled_private_fingerprint_body_bytes"],
            "trusted_factory_expanded_fingerprint_body_bytes": old["dense_gate_compiled_private_fingerprint_body_bytes"],
            "whole_factory_plus_receiver_extra_vector_body_bytes": receiver,
            "per_fresh_seed_private_scalar_hint_body_bytes": (rounds * bits + 7) // 8,
            "per_fresh_seed_trusted_expansion_ring_products": old["one_expansion_ring_products"],
            "per_fresh_seed_trusted_hint_field_products": rounds * 2 * h * n,
            "online_input_fingerprint_field_products": rounds * n,
            "public_query_and_response_upper_bound_bytes": old["full_public_online_body_upper_bound_bytes"],
            "public_evaluation_key_body_bytes": old["unseeded_public_evaluation_key_body_bytes"],
            "separate_trusted_factory_required_by_literal_recipe": True,
            "scope": "Count only. Online vectors shrink but old expanded hints remain at the trusted factory, with full fresh expansion. Challenges/pending originals, IDs/hash sets/private provisioning/metadata also paid. No large latency, parameter or originality claim."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Fresh result path required")
    cases = []
    for descriptor in CASES:
        s, words, groups, ids, binding = inputs(*descriptor)
        pk, sk = masked.key_gen(s, q_bits=32, eta=1)
        keys = packed.key_gen(s, pk, sk)
        epoch, attempts = secrets.token_bytes(32), lifetime.AttemptBudget(16)
        with closing(owner.OwnerClient(pk, sk)) as client:
            index, index_bytes = masked.enroll(s, groups, epoch, client)
            factory, factory_setup_ms = measure(protocol.Factory, index, pk, keys, ids, binding, attempts)
            receiver, receiver_setup_ms = measure(protocol.Receiver, factory, attempts)
            baseline, baseline_setup_ms = measure(dense.Gate, index, pk, ids, binding, lifetime.AttemptBudget(16),
                                                 query_phase_bound=packed.expanded_bound(s, pk, keys))
            samples = []
            for word in range(16):
                values = tuple((1 - 2 * (word >> j & 1)) % 17 for _ in s.dimensions for j in range(4))
                (request, query_bytes), query_ms = measure(packed.make_query, s, epoch, word.to_bytes(16, "little"), values, client)
                hint, seed_prepare_ms = measure(factory.prepare_seed, request)
                _, hint_register_ms = measure(receiver.register_seed, hint)
                _, original_pin_ms = measure(receiver.pin_query, request)
                canonical, baseline_expand_ms = measure(packed.expand, request, s, pk, keys)
                _, baseline_pin_ms = measure(baseline.pin_query, canonical)
                server_expanded, server_expand_ms = measure(packed.expand, request, s, pk, keys)
                assert canonical == server_expanded
                output, product_ms = measure(packed.evaluate, index, server_expanded, pk, keys)
                reply, project_ms = measure(dense.project, output, index, pk, expected_bound=packed.output_bound(index, pk, keys))
                body, pack_ms = measure(dense.pack, reply, pk)
                dots, open_ms = measure(receiver.open_body_once, request.token_id, body, sk)
                baseline_dots, baseline_open_ms = measure(baseline.open_body_once, request.token_id, body, sk)
                expected_dots = tuple(tuple(row) for row in crt.scores(s, groups, values))
                assert dots == baseline_dots == expected_dots
                independent = independent_products(index, server_expanded, pk)
                assert tuple(tuple(tuple(map(int, p)) for p in c.components) for c in output) == independent
                # The exact compiled identity is checked against the original
                # expanded-input fingerprint, not just decoded plaintexts.
                for raw_hints, vector, constant in zip(factory._dense._hints, receiver._vectors, hint.constants, strict=True):
                    expanded_hash = sum(dense._dot(z, c, pk.q) for pair, cipher in
                                        zip(raw_hints, canonical.ciphertexts, strict=True)
                                        for z, c in zip(pair, cipher.components, strict=True)) % pk.q
                    assert expanded_hash == (dense._dot(vector, request.ciphertext.components[0], pk.q) + constant) % pk.q
                scores = tuple((x + word.bit_count()) % 17 for row in dots for x in row)
                expected = tuple((word ^ old).bit_count() for row in words for old in row)
                flat_ids = tuple(i for group in ids for i in group)
                assert scores == expected and sorted(zip(scores, flat_ids, strict=True))[:3] == sorted(zip(expected, flat_ids, strict=True))[:3]
                samples.append({"query_word": word, "actual_query_packet_bytes": query_bytes, "projected_response_body_bytes": len(body),
                                "query_encrypt_ms": query_ms, "trusted_seed_full_expansion_and_hint_ms": seed_prepare_ms,
                                "client_private_hint_registration_ms": hint_register_ms, "client_original_pin_ms": original_pin_ms,
                                "server_expansion_ms": server_expand_ms, "server_product_ms": product_ms,
                                "server_projection_validation_ms": project_ms, "server_response_pack_ms": pack_ms,
                                "client_affine_gate_decrypt_decode_ms": open_ms,
                                "baseline_client_full_expansion_ms": baseline_expand_ms,
                                "baseline_expanded_input_pin_ms": baseline_pin_ms,
                                "baseline_dense_gate_decrypt_decode_ms": baseline_open_ms,
                                "affine_client_plus_trusted_factory_stage_sum_ms": seed_prepare_ms + hint_register_ms + original_pin_ms + open_ms,
                                "baseline_client_stage_sum_ms": baseline_expand_ms + baseline_pin_ms + baseline_open_ms,
                                "all_ciphertext_products_fingerprint_identities_scores_ids_top3_exact": True})
        cases.append({"n": pk.n, "q": int(pk.q), "t": pk.t, "eta": pk.eta, "paths": descriptor[1], "counts": descriptor[2],
                      "actual_seeded_index_packets_bytes": index_bytes, "private_factory_register_ms": factory_setup_ms,
                      "online_receiver_register_ms": receiver_setup_ms, "baseline_complete_gate_register_ms": baseline_setup_ms,
                      "body_cost": protocol.cost(factory, receiver), "samples": samples,
                      "toy_stage_medians_ms_not_service_estimates": {k: statistics.median(p[k] for p in samples)
                                                                     for k in samples[0] if k.endswith("_ms")},
                      "verification_attempts_consumed": attempts.used})
    prior = ROOT / "benchmarks/results/publication-structured-operator-screen-20260930.json"
    paths = [Path(__file__), prior, ROOT / "benchmarks/dictionary_layout_lab.py", ROOT / "benchmarks/encrypted_query_gate_lab.py",
             ROOT / "benchmarks/encrypted_query_certificate_lab.py", ROOT / "benchmarks/packed_query_expansion_lab.py",
             ROOT / "src/cuhepy/bfv/scheme.py", ROOT / "src/cuhepy/types.py"]
    paths.extend(ROOT / "experiments/bfv_search_lab" / f"{name}.py" for name in (
        "seed_affine_gate", "test_seed_affine_gate", "packed_query_expansion", "test_packed_query_expansion", "test_supported_decoder",
        "encrypted_query_gate", "encrypted_query_certificate", "trace_bgv", "convolution_certificate_oracle", "coefficient_body",
        "decryption_support", "owner_bgv", "seeded_bgv", "shallow_bgv", "crt_masked_bgv", "crt_query_space", "dyadic_crt", "score_layout",
        "verification_lifetime"))
    result = metadata(paths)
    result.update(kind="public_seed_conditioned_affine_query_gate_known_control", exact_queries=16 * len(cases), cases=cases,
                  retained_geometry_count_screens=[count_screen(p) for p in json.loads(prior.read_text())["recorded_geometry_count_screens"]],
                  scope="Homemade affine selection/hoisting plus known private linear fingerprint control. Online receiver state shrinks, "
                        "but a trusted factory retains large expanded fingerprints and does a full fresh canonical zero-C0 expansion per seed. "
                        "Synthetic offsets are public algebra and never decrypted. All input/seed/epoch/lifetime binding is trusted local volatile state. "
                        "Toy stages/counts are not large/GPU/native/RSS/transport/cold-bootstrap or production/parameter/KDM/private-timing assurance. "
                        "No whole-system saving or original paper contribution claimed; factory role and private seed hints are not free.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "exact_queries": result["exact_queries"], "fresh_trusted_seed_preparation_charged": True}))


if __name__ == "__main__":
    main()
