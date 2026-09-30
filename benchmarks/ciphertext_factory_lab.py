#!/usr/bin/env python3
"""E49 plaintext-factory versus encrypted-index-factory CPU/work/state pilot.

Both produce one-use correlations and use the same complete online check.
The alternative pays an extra trusted native index, full unseeded packets and
larger deterministic noise. The reduction premise is explicitly provisional.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from contextlib import closing
import heapq
import json
from pathlib import Path
import random
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata, summary
from benchmarks.field_frontier_lab import public_space
from benchmarks.verification_frontier_lab import parse_bits
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import ciphertext_factory as alternative
from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import coordinate_factory
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import native_linear_check as checks
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=("mushroom", "semeion", "synthetic128"), required=True)
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--repeats", type=int, default=4)
    parser.add_argument("--vectorized-control", action="store_true")
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 16 or (args.dataset != "synthetic128" and args.cache_dir is None):
        parser.error("Expected bounded repeats and public fixture cache")
    setup, observations = {}, []
    start = time.perf_counter()
    if args.dataset == "synthetic128":
        dimension, t, q_bits = 512, 1153, 40
        rng = random.Random(4901)
        def lift(x):
            return sum(x << j for j in range(0, dimension, 128))
        rows = [lift(rng.randrange(1 << 128)) for _ in range(16384)]
        ids = tuple(range(len(rows)))
        workload = Workload(tuple(rows), ids, dimension)
        # Use the exact generator's known schema, not an uncharged expensive
        # empirical rank fit. Certification/coordinate generation still costs.
        mapping = affine.Plan(dimension, t, rows[0], tuple(range(128)),
                              tuple(tuple(int(j % 128 == i) for j in range(dimension)) for i in range(128)))
        choice = oracle.Choice((oracle.Piece("", tuple(range(len(rows))), mapping, "affine"),))
        plan = oracle.compile_choice(workload, choice, Profile(16384, t, q_bits=q_bits), (1,))
        candidate, s, maps = plan.candidate, plan.query_space, plan.maps
        groups = [[list(row) for row in group] for group in plan.groups]
        words = [random.Random(49010 + i).randrange(1 << dimension) for i in range(args.repeats + 1)]
        fixture_digest = workload.digest
        basis_source = "Exact public synthetic generator schema; full row certification is charged"
    else:
        data = fixtures.load(args.dataset, args.cache_dir / fixtures.SOURCES[args.dataset]["member"])
        ids, heldout = fixtures.split(data, 3001)
        rows, dimension = [data.rows[i] for i in ids], data.dimension
        order = dictionary.metric_order(rows, dimension, 32)
        t, slots = (193, 32) if data.name == "mushroom" else (257, 64)
        candidate = fields.allocate(fields.fit(rows, dimension, order, prime=t, target=32), rows, slots)
        maps, s = public_space(candidate)
        groups = [affine.index_features(b.mapping, [rows[i] for i in b.positions]) for b in candidate.blocks]
        words = [data.rows[heldout[64 + i]] for i in range(args.repeats + 1)]
        q_bits, fixture_digest, basis_source = 32, data.sha256, "Existing E37 empirical public-fixture private affine plan"
    setup["fixture_load_plan_and_full_certification_s"] = time.perf_counter() - start
    bitmaps = [affine.compile_bits(p) for p in maps]
    setup["key_gen_s"], (pk, sk) = timed(masked.key_gen, s, q_bits=q_bits)
    epoch = secrets.token_bytes(32)
    with closing(owner.OwnerClient(pk, sk)) as client:
        setup["enroll_s"], (index, index_upload) = timed(masked.enroll, s, groups, epoch, client)
        setup["server_native_prepare_s"], server = timed(native.NativeIndex, index, pk)
        setup["extra_trusted_encrypted_factory_prepare_s"], producer = timed(alternative.Factory, index, client)
        variants = ("plaintext", "numpy_plaintext", "encrypted_index") if args.vectorized_control else ("plaintext", "encrypted_index")
        if args.vectorized_control:
            setup["extra_vectorized_plaintext_factory_prepare_s"], plaintext_producer = timed(
                coordinate_factory.Factory, s, groups, epoch, client)
        gates = {name: checks.NativeVectorCheck(index, pk, rounds=fields.rounds(int(pk.q)), budget=1024) for name in variants}
        phase = audit.Audit(index, pk, sk, maximum_answer_bound=max(producer.answer_bounds))
        for ordinal, word in enumerate(words):
            # Matched public query/workload, fresh independent pads/encryption.
            names = variants if ordinal % 2 == 0 else tuple(reversed(variants))
            for name in names:
                token_id = (len(variants) * ordinal + variants.index(name)).to_bytes(16, "little")
                if name == "plaintext":
                    prepare_s, (ticket, answer, packet_bytes) = timed(lambda token_id=token_id: masked.prepare(
                        s, groups, epoch, token_id, secrets.token_bytes(32), client))
                elif name == "numpy_plaintext":
                    prepare_s, (ticket, answer, packet_bytes) = timed(plaintext_producer.prepare, token_id)
                else:
                    prepare_s, (ticket, answer, body) = timed(producer.prepare, token_id)
                    packet_bytes = len(body)
                check_prepare_s, _ = timed(gates[name].prepare_answer, answer)
                start = time.perf_counter()
                transformed = [affine.bit_query_features(p, word) for p in bitmaps]
                values = tuple(x for weights, _ in transformed for x in weights)
                offsets = tuple(off for _, off in transformed)
                request = ticket.consume(values, epoch)
                result = server.evaluate(answer, request)
                online_body = codec.pack(tuple(int(x) for c in result for poly in c.components for x in poly), int(pk.q))
                # Reconstruct from the actual canonical response body.
                received = parse_bits(online_body, pk, tuple(c.phase_bound for c in result))
                if not gates[name].verify_once(request, received):
                    raise AssertionError("Honest factory response failed the complete pre-decryption gate")
                dots = tree.unpack(candidate.layout, [bgv.decrypt(c, pk, sk) for c in received])
                scores = [None] * len(rows)
                for block, block_scores, map_id in zip(candidate.blocks, dots, s.map_ids, strict=True):
                    for position, score in zip(block.positions, affine.bit_decode(bitmaps[map_id], block_scores, offsets[map_id]), strict=True):
                        scores[position] = score
                top = heapq.nsmallest(3, zip(scores, ids, strict=True))
                online_s = time.perf_counter() - start
                assert tuple(scores) == tuple((word ^ row).bit_count() for row in rows)
                assert received == masked.evaluate(index, answer, request, pk)
                phase_report = phase.measure(request, answer, received)
                observations.append({"variant": name, "ordinal": ordinal, "warmup": ordinal == 0,
                    "offline_correlation_production_and_serialization_s": prepare_s,
                    "complete_answer_check_prepare_s": check_prepare_s,
                    "offline_production_and_check_s": prepare_s + check_prepare_s,
                    "correlation_packet_body_bytes": packet_bytes, "response_body_bytes": len(online_body),
                    "complete_local_online_elapsed_s": online_s,
                    "private_pad_norm_not_published": name != "encrypted_index" or tuple(c.phase_bound for c in answer.ciphertexts) == producer.answer_bounds,
                    "all_scores_stable_top3_and_full_gmp_native_coefficients_exact": True,
                    "gate_pass_before_secret_decryption": True, "top3": top, "phase": phase_report})
    paths = [Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "ciphertext_factory", "crt_masked_bgv", "crt_query_space", "crt_native_bgv", "owner_bgv", "seeded_bgv",
        "shallow_bgv", "integer_phase_audit", "native_linear_check", "crt_linear_check", "coefficient_body", "coordinate_factory")),
        ROOT / "src/cuhepy/bfv/scheme.py"]
    paths.extend(p for folder in ("_subring", "_fingerprint")
                 for p in (ROOT / "experiments/bfv_search_lab" / folder).glob("*.so"))
    result = metadata(paths)
    result.update(kind="encrypted_index_trusted_factory", dataset=args.dataset, count=len(rows), dimension=dimension,
                  n=pk.n, t=t, q=int(pk.q), fixture_sha256=fixture_digest, basis_source=basis_source,
                  setup=setup, seeded_index_upload_bytes=index_upload, observations=observations,
                  checker_rounds=fields.rounds(int(pk.q)),
                  summary={name: summary([{axis: r[axis] for axis in (
                      "offline_correlation_production_and_serialization_s", "offline_production_and_check_s",
                      "correlation_packet_body_bytes", "complete_local_online_elapsed_s")}
                      for r in observations if r["variant"] == name and not r["warmup"]])
                           for name in variants},
                  vectorized_plaintext_control=args.vectorized_control,
                  vectorized_plaintext_private_coordinate_array_bytes=(plaintext_producer.coordinate_array_bytes if args.vectorized_control else None),
                  original_owner_coordinate_ternary_body_bytes_model=(2 * sum(len(group) * f for group, f in zip(groups, s.layout.features, strict=True)) + 7) // 8,
                  encrypted_factory_expanded_index_body_bytes_model=s.columns * s.layout.cost.response_ciphertexts * 2 * pk.n * ((pk.q.bit_length() + 7) // 8),
                  encrypted_factory_native_word_bytes_model=s.columns * s.layout.cost.response_ciphertexts * 2 * pk.n * 8,
                  fresh_plaintext_factory_answer_bound=pk.t // 2 + pk.t * pk.eta,
                  encrypted_factory_answer_bounds=producer.answer_bounds,
                  encrypted_factory_worst_response_bounds=producer.worst_response_bounds,
                  scope="Trusted LOCAL CPU factory, no new GPU/TEE/service deployment. Same complete check and exact full-score output. "
                        "Only encrypted-index factory avoids the plaintext coordinate scan; it retains much larger encrypted/native state. "
                        "Original correlations use seeded packets; alternative releases FULL coefficients, never the zero seed. "
                        "Measured stages exclude the independent GMP/integer-phase diagnostics. Initial setup is recorded separately, "
                        "not amortized away. Conditional extra RLWE pseudorandomness assumption has no independent review. "
                        "Known rerandomization ingredients; no new cryptographic primitive, complete lifetime, production or Gate C claim.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "observations": len(observations)}))


if __name__ == "__main__":
    main()
