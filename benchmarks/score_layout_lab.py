#!/usr/bin/env python3
"""E51: measured full-ring/context and output-geometry frontier.

Fixed E37 owner maps/public fixtures. New score-only allocation has no legacy
input feature-width bound. Every complete response is checked before secret
decryption and independently audited, using homemade encryption/native/GMP.
Profiles are local research candidates; heuristic estimates do not approve them.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from contextlib import closing
from dataclasses import replace
import heapq
import json
from pathlib import Path
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
from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import coordinate_factory
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import native_linear_check as checks
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab.representation_contract import Profile, Workload
from experiments.bfv_search_lab import score_layout
from experiments.bfv_search_lab import shallow_bgv as bgv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=("mushroom", "semeion"), required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--n", type=int, nargs="+", default=[16384, 2048])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--representations", nargs="+", choices=("legacy", "score_only", "global_raw", "global_affine"),
                        default=["legacy", "score_only"])
    parser.add_argument("--vectorized-owner", action="store_true")
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 16 or any(n < 2048 or n > 32768 or n & (n - 1) for n in args.n):
        parser.error("Require 1..16 repeats and bounded full-ring research candidates N>=2048")
    start = time.perf_counter()
    data = fixtures.load(args.dataset, args.cache_dir / fixtures.SOURCES[args.dataset]["member"])
    ids, heldout = fixtures.split(data, 3001)
    rows = [data.rows[i] for i in ids]
    order = dictionary.metric_order(rows, data.dimension, 32)
    t, slots = (193, 32) if data.name == "mushroom" else (257, 64)
    fixture_s = time.perf_counter() - start
    discovery_s, discovery = (timed(fields.fit, rows, data.dimension, order, prime=t, target=32)
                              if set(args.representations) & {"legacy", "score_only"} else (0, None))
    mappings, map_discovery = {}, {}
    if "global_raw" in args.representations:
        map_discovery["global_raw"], mappings["global_raw"] = timed(oracle.raw_map, data.dimension, t)
    if "global_affine" in args.representations:
        map_discovery["global_affine"], mappings["global_affine"] = timed(affine.prepare, rows, data.dimension, t)
    workload = Workload(tuple(rows), tuple(ids), data.dimension)
    words = [data.rows[heldout[64 + i]] for i in range(args.repeats + 1)]
    cases = []
    for n in args.n:
        for kind in args.representations:
            start = time.perf_counter()
            try:
                if kind in mappings:
                    choice = oracle.Choice((oracle.Piece("", tuple(range(len(rows))), mappings[kind],
                                                        "raw" if kind == "global_raw" else "affine"),))
                    p = oracle.compile_choice(workload, choice, Profile(n, t, q_bits=32), (1,))
                    candidate = p.candidate
                else:
                    candidate = (fields.allocate(replace(discovery, n=n), rows, slots) if kind == "legacy"
                                 else score_layout.allocate(discovery, rows, slots, n=n))
                maps, s = public_space(candidate)
                groups = [affine.index_features(b.mapping, [rows[i] for i in b.positions]) for b in candidate.blocks]
                bitmaps = [affine.compile_bits(p) for p in maps]
                compilation_s = time.perf_counter() - start
                key_s, (pk, sk) = timed(masked.key_gen, s, q_bits=32)
                cases.append(measure(candidate, s, groups, bitmaps, pk, sk, ids, rows, words, kind, compilation_s, key_s,
                                     args.vectorized_owner))
            except ValueError as error:
                cases.append({"kind": kind, "n": n, "status": "rejected", "reason": str(error)})
    paths = [Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "score_layout", "dyadic_crt", "crt_query_space", "crt_masked_bgv", "crt_native_bgv", "owner_bgv", "seeded_bgv",
        "shallow_bgv", "native_linear_check", "crt_linear_check", "integer_phase_audit", "coefficient_body",
        "coordinate_factory", "representation_oracle", "representation_contract")),
        ROOT / "src/cuhepy/bfv/scheme.py"]
    paths.extend(p for folder in ("_subring", "_fingerprint")
                 for p in (ROOT / "experiments/bfv_search_lab" / folder).glob("*.so"))
    result = metadata(paths)
    result.update(kind="score_only_full_ring_frontier", dataset=data.name, fixture_sha256=data.sha256,
                  count=len(rows), dimension=data.dimension, t=t, common_fixture_load_order_s=fixture_s,
                  local_private_map_discovery_s=discovery_s, global_private_map_discovery_s=map_discovery,
                  vectorized_owner=args.vectorized_owner,
                  cases=cases, scope="Same public fixture, IDs and held-out queries, exact complete scores/stable top3; "
                  "local-layout cases share approved maps, global raw/affine controls use their own certified whole-index maps. "
                  "Full-ring N changes, unlike a public correction subring change; estimates and seeded/protocol assumptions remain unreviewed. "
                  "Complete check, serialization, parse, native server, secret decrypt and selection all timed. "
                  "Setup and diagnostics reported separately; this is not a full lifetime, network, new GPU or production-parameter claim.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cases": len(cases)}))


def measure(candidate, s, groups, bitmaps, pk, sk, ids, rows, words, kind, compile_s, key_s, vectorized_owner):
    setup = {"map_allocation_and_coordinate_certification_s": compile_s, "key_gen_s": key_s}
    epoch = secrets.token_bytes(32)
    samples = []
    setup["private_owner_backend_prepare_s"], client = timed(owner.OwnerClient, pk, sk)
    with closing(client):
        if vectorized_owner:
            setup["private_vectorized_coordinate_factory_prepare_s"], producer = timed(coordinate_factory.Factory, s, groups, epoch, client)
        setup["enroll_s"], (index, upload) = timed(masked.enroll, s, groups, epoch, client)
        setup["native_index_prepare_s"], server = timed(native.NativeIndex, index, pk)
        setup["full_checker_prepare_s"], gate = timed(checks.NativeVectorCheck, index, pk,
                                                       rounds=fields.rounds(int(pk.q)), budget=1024)
        phase = audit.Audit(index, pk, sk)
        for ordinal, word in enumerate(words):
            if vectorized_owner:
                offline_s, (ticket, answer, packet_bytes) = timed(producer.prepare, ordinal.to_bytes(16, "little"))
            else:
                offline_s, (ticket, answer, packet_bytes) = timed(masked.prepare, s, groups, epoch,
                    ordinal.to_bytes(16, "little"), secrets.token_bytes(32), client)
            answer_check_s, _ = timed(gate.prepare_answer, answer)
            start = time.perf_counter()
            features = [affine.bit_query_features(p, word) for p in bitmaps]
            values = tuple(x for weights, _ in features for x in weights)
            offsets = tuple(off for _, off in features)
            request = ticket.consume(values, epoch)
            transform_s = time.perf_counter() - start
            server_s, result = timed(server.evaluate, answer, request)
            def serialize(values):
                masked.validate_ciphertexts(values, len(values), pk)
                return codec.pack(tuple(int(x) for c in values for p in c.components for x in p), int(pk.q))
            pack_s, body = timed(serialize, result)
            parse_s, received = timed(parse_bits, body, pk, tuple(c.phase_bound for c in result))
            gate_s, accepted = timed(gate.verify_once, request, received)
            assert accepted
            decrypt_s, plaintexts = timed(lambda values: [bgv.decrypt(c, pk, sk) for c in values], received)
            def decode(plaintexts, offsets):
                actual = [None] * len(rows)
                for block, dots, map_id in zip(candidate.blocks, tree.unpack(candidate.layout, plaintexts), s.map_ids, strict=True):
                    for position, score in zip(block.positions, affine.bit_decode(bitmaps[map_id], dots, offsets[map_id]), strict=True):
                        actual[position] = score
                return tuple(actual), tuple(heapq.nsmallest(3, zip(actual, ids, strict=True)))
            decode_s, (scores, top3) = timed(decode, plaintexts, offsets)
            assert scores == tuple((word ^ row).bit_count() for row in rows)
            assert top3 == tuple(sorted(zip(scores, ids, strict=True))[:3])
            assert received == masked.evaluate(index, answer, request, pk)
            phase_report = phase.measure(request, answer, received)
            stages = {"transform_and_one_use_s": transform_s, "native_server_s": server_s,
                      "serialize_s": pack_s, "parse_s": parse_s, "full_gate_s": gate_s,
                      "secret_decrypt_s": decrypt_s, "decode_and_stable_top3_s": decode_s}
            samples.append({"ordinal": ordinal, "warmup": ordinal == 0, "stages": stages,
                            "online_stage_sum_s": sum(stages.values()),
                            "offline_produce_and_check_s": offline_s + answer_check_s,
                            "prepared_answer_packet_bytes": packet_bytes, "response_body_bytes": len(body),
                            "all_scores_top3_full_native_gmp_coefficients_exact": True,
                            "complete_gate_before_secret_decrypt": True, "phase": phase_report, "top3": top3})
    return {"kind": kind, "n": pk.n, "q": int(pk.q), "status": "measured_research_only",
            "setup": setup, "upload_bytes": upload, "geometry": space.cost(s, q_bits=32, rounds=fields.rounds(int(pk.q))),
            "private_map_body_bytes": candidate.map_bytes, "samples": samples,
            "summary": summary([{k: row[k] for k in ("online_stage_sum_s", "offline_produce_and_check_s", "response_body_bytes")}
                                for row in samples if not row["warmup"]])}


if __name__ == "__main__":
    main()
