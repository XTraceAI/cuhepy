#!/usr/bin/env python3
"""E75 same-harness enrolled TCP HE/cache control, not a cold deployment."""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
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
from experiments.bfv_search_lab import cache_snapshot as snapshot
from experiments.bfv_search_lab import coordinate_cache as caches
from experiments.bfv_search_lab import coordinate_factory
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import enrolled_rpc as rpc
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import loopback_exchange as transport
from experiments.bfv_search_lab import native_linear_check as checks
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import verification_lifetime as lifetime


def open_response(body, request, pk, sk, gate):
    """Owner-local ordering control: no rejected public body reaches the key."""
    parse_start = time.perf_counter()
    try:
        parsed = parse_bits(body, pk, rpc.owner_bounds(request, pk))
    except (ValueError, TypeError):
        gate.verify_once(request, ())  # Burn malformed attempts as well.
        raise
    start = time.perf_counter()
    if not gate.verify_once(request, parsed):
        raise ValueError("Complete response check failed before decryption")
    checked = time.perf_counter()
    plaintexts = [bgv.decrypt(c, pk, sk) for c in parsed]
    return plaintexts, {"client_public_parse_bound_s": start - parse_start,
                        "client_complete_check_s": checked - start,
                        "client_secret_decrypt_s": time.perf_counter() - checked}


def finish(candidate, s, compiled, offsets, ids, plaintexts):
    scores = [None] * len(ids)
    for block, dots, group in zip(candidate.blocks, tree.unpack(candidate.layout, plaintexts), s.map_ids, strict=True):
        for position, value in zip(block.positions, affine.bit_decode(compiled[group], dots, offsets[group]), strict=True):
            scores[position] = value
    if any(value is None for value in scores):
        raise ValueError("Incomplete enrolled score coverage")
    return caches.Result(tuple(scores), tuple(heapq.nsmallest(3, zip(scores, ids, strict=True))))


def checked_result(result, rows, ids, word):
    expected = tuple((row ^ word).bit_count() for row in rows)
    assert result.scores == expected
    assert result.top3 == tuple(sorted(zip(expected, ids, strict=True))[:3])
    return {"scores_sha256": hashlib.sha256(b"".join(x.to_bytes(2, "little") for x in expected)).hexdigest(),
            "every_score_id_and_stable_top3_exact": True}


def he_control(rows, ids, words, dimension, query_budget):
    setup = {}
    setup["metric_order_s"], order = timed(dictionary.metric_order, rows, dimension, 32)
    t, slots = (193, 32) if dimension == 126 else (257, 64)
    setup["field_fit_s"], discovery = timed(fields.fit, rows, dimension, order, prime=t, target=32)
    setup["layout_allocate_s"], candidate = timed(fields.allocate, discovery, rows, slots)
    def compile_owner():
        maps, s = public_space(candidate)
        groups = [affine.index_features(b.mapping, [rows[i] for i in b.positions]) for b in candidate.blocks]
        return s, groups, [affine.compile_bits(p) for p in maps]

    setup["public_context_and_private_coordinates_s"], (s, groups, compiled) = timed(compile_owner)
    setup["key_gen_s"], (pk, sk) = timed(masked.key_gen, s, q_bits=32)
    epoch = secrets.token_bytes(32)  # Never disclose a plaintext-index digest as an epoch.
    with closing(owner.OwnerClient(pk, sk)) as client:
        captured = rpc.CaptureClient(client)
        setup["owner_encrypt_expand_index_s"], (index, uploaded_bytes) = timed(masked.enroll, s, groups, epoch, captured)
        packets = captured.take()
        assert len(packets) == s.columns * s.layout.cost.response_ciphertexts
        assert sum(map(len, packets)) == uploaded_bytes
        rounds = fields.rounds(int(pk.q), budget=query_budget)
        setup["private_complete_checker_prepare_s"], checker = timed(checks.NativeVectorCheck, index, pk,
                                                                    rounds=rounds, budget=query_budget)
        attempt_budget = lifetime.AttemptBudget(query_budget)
        gate = attempt_budget.bind(checker)
        setup["private_vectorized_factory_prepare_s"], factory = timed(coordinate_factory.Factory, s, groups, epoch,
                                                                     captured, budget=query_budget)
        server, samples = rpc.LinearServer(s, pk, epoch, budget=query_budget), []
        with transport.Exchange(server) as exchange:
            setup["tcp_connect_s"] = exchange.connection_establish_s
            setup["index_frame_pack_s"], index_body = timed(lambda: b"I" + rpc.bundle(packets))
            acknowledgement, enrollment = exchange.call(index_body)
            assert acknowledgement == b"\x01" and server._index == index
            setup.update(server.enrollment)
            for ordinal, word in enumerate(words):
                start = time.perf_counter()
                token_id = ordinal.to_bytes(16, "little")
                owner_prepare_s, (ticket, answer, answer_bytes) = timed(factory.prepare, token_id)
                answer_packets = captured.take()
                assert len(answer_packets) == s.layout.cost.response_ciphertexts
                assert sum(map(len, answer_packets)) == answer_bytes
                owner_register_s, _ = timed(gate.prepare_answer, answer)
                answer_pack_s, answer_body = timed(lambda token_id=token_id, answer_packets=answer_packets:
                                                   b"A" + token_id + rpc.bundle(answer_packets))
                acknowledgement, answer_upload = exchange.call(answer_body)
                assert acknowledgement == b"\x01" and server._answers[token_id] == answer
                server_answer = dict(server.last)

                def make_request(word=word, ticket=ticket):
                    transformed = [affine.bit_query_features(p, word) for p in compiled]
                    values = tuple(x for weights, _ in transformed for x in weights)
                    return ticket.consume(values, epoch), tuple(offset for _, offset in transformed)

                request_s, (request, offsets) = timed(make_request)
                request_pack_s, request_body = timed(lambda request=request: b"Q" + request.token_id + request.body())
                body, request_reply = exchange.call(request_body)
                server_query = dict(server.last)
                # open_response includes parse/bound computation, full check, then the private key.
                client_open_s, (plaintexts, client_stages) = timed(open_response, body, request, pk, sk, gate)
                finish_s, result = timed(finish, candidate, s, compiled, offsets, ids, plaintexts)
                wall_s = time.perf_counter() - start
                sample = {"ordinal": ordinal, "warmup": ordinal == 0, "complete_query_wall_s": wall_s,
                          "owner_fresh_prepare_s": owner_prepare_s, "owner_answer_register_s": owner_register_s,
                          "owner_answer_frame_pack_s": answer_pack_s, "client_transform_request_s": request_s,
                          "client_request_frame_pack_s": request_pack_s, "client_open_including_parse_s": client_open_s,
                          "client_decode_select_s": finish_s, "answer_upload": answer_upload, "query_reply": request_reply,
                          "application_bytes": answer_upload["application_bytes"] + request_reply["application_bytes"],
                          "seeded_answer_ciphertext_packet_bytes": answer_bytes, "correction_body_bytes": len(request.body()),
                          "full_bitpacked_response_body_bytes": len(body), "gate_accepts_before_secret_key_use": True,
                          **server_answer, **server_query, **client_stages}
                sample.update(checked_result(result, rows, ids, word))
                samples.append(sample)
                print("HE", dimension, ordinal, round(1000 * wall_s, 2), "ms", file=sys.stderr, flush=True)
        assert attempt_budget.used == len(words) and not server._answers
    return {"mode": "masked_bgv_native_fullq_check", "n": pk.n, "t": pk.t, "q": str(pk.q),
            "q_bits": pk.q.bit_length(), "eta": pk.eta, "rounds": rounds, "query_budget": query_budget,
            "setup": setup, "enrollment": enrollment, "seeded_index_ciphertext_packet_bytes": uploaded_bytes,
            "server_context_bootstrap": "already pinned; not transferred",
            "private_state_body_models": {"private_maps": candidate.map_bytes, "stable_ids_and_permutation": 12 * len(ids),
                                          "secret_key": pk.n * ((pk.q.bit_length() + 7) // 8),
                                          "checker_seed_key": 32 * rounds,
                                          "checker_fingerprints": (rounds * sum(s.column_degrees) * pk.q.bit_length() + 7) // 8,
                                          "owner_coordinate_arrays_actual_nbytes": factory.coordinate_array_bytes},
            "cost_model": space.cost(s, q_bits=32, rounds=rounds), "samples": samples,
            "summary": summary([{k: v for k, v in p.items() if k.endswith("_s") or k == "application_bytes"}
                                for p in samples[1:]]),
            "enrollment_plus_query_application_bytes": enrollment["application_bytes"] + sum(p["application_bytes"] for p in samples),
            "reported_query_wall_contains_nested_server_and_rpc_stages": True,
            "private_bootstrap_transferred": False}


def cache_control(rows, ids, words, dimension, level, retained):
    key_s, key = timed(secrets.token_bytes, 32)
    seal_s, (manifest, sealed) = timed(snapshot.seal, tuple(rows), tuple(ids), dimension, key,
                                     compressed=level is not None, compression_level=level or 9)
    server, samples = rpc.CacheServer(), []
    with transport.Exchange(server) as exchange:
        index_pack_s, body = timed(lambda: b"I" + sealed)
        acknowledgement, upload = exchange.call(body)
        assert acknowledgement == b"\x01"
        start = time.perf_counter()
        received, download = exchange.call(b"Q")
        assert received == sealed
        parse_s, cache = timed(snapshot.open_snapshot, received, key, manifest, retained=retained)
        acquisition_s = time.perf_counter() - start
        for ordinal, word in enumerate(words):
            query_s, result = timed(cache.query, word)
            sample = {"ordinal": ordinal, "warmup": ordinal == 0, "local_query_wall_s": query_s}
            sample.update(checked_result(result, rows, ids, word))
            samples.append(sample)
        connect_s = exchange.connection_establish_s
    return {"mode": "authorized_snapshot", "compression_level": level, "retained": retained,
            "key_generate_s": key_s, "owner_seal_s": seal_s, "tcp_connect_s": connect_s,
            "owner_index_frame_pack_s": index_pack_s, "enrollment": upload, "download": download,
            "snapshot_packet_bytes": len(sealed), "already_pinned_private_key_manifest_body_bytes": len(key + manifest.header()),
            "client_authenticate_parse_s": parse_s, "enrolled_client_acquire_wall_s": acquisition_s,
            "private_bootstrap_transferred": False, "retained_body_bytes_model": cache.retained_body_bytes_model,
            "owner_prep_enrollment_acquisition_stage_sum_s": key_s + seal_s + connect_s + index_pack_s + upload["rpc_wall_s"] + acquisition_s,
            "enrollment_download_query_application_bytes": upload["application_bytes"] + download["application_bytes"],
            "samples": samples, "summary": summary([{"local_query_wall_s": p["local_query_wall_s"]} for p in samples[1:]])}


def run(args):
    cases = []
    for name in args.datasets:
        load_s, data = timed(fixtures.load, name, args.cache_dir / fixtures.SOURCES[name]["member"])
        ids, heldout = fixtures.split(data, 3001)
        ids = tuple(ids)
        rows = tuple(data.rows[i] for i in ids)
        query_ids = heldout[64:64 + args.repeats + 1]
        words = tuple(data.rows[i] for i in query_ids)
        assert len(words) == args.repeats + 1
        raw_prepare_s, raw_cache = timed(caches.RawRows, rows, ids, data.dimension)
        raw_samples = []
        for word in words:
            seconds, result = timed(raw_cache.query, word)
            raw_samples.append({"local_query_wall_s": seconds, **checked_result(result, rows, ids, word)})
        he = he_control(rows, ids, words, data.dimension, args.query_budget)
        snapshots = [cache_control(rows, ids, words, data.dimension, level, retained)
                     for level, retained in ((None, "raw"), (1, "raw"), (9, "raw"), (1, "compressed"), (9, "compressed"))]
        expected = [p["scores_sha256"] for p in he["samples"]]
        assert expected == [p["scores_sha256"] for p in raw_samples]
        assert all(expected == [p["scores_sha256"] for p in control["samples"]] for control in snapshots)
        cases.append({"dataset": name, "fixture_sha256": data.sha256, "count": len(rows), "dimension": data.dimension,
                      "distinct_rows": len(set(rows)), "load_parse_s": load_s, "query_source_ids": query_ids,
                      "homemade_he": he, "snapshot_controls": snapshots,
                      "retained_authorized_owner_raw": {"prepare_s": raw_prepare_s, "acquisition_application_bytes": 0,
                                                        "scores_ids_body_bytes_model": len(ids) * (8 + (data.dimension + 7) // 8),
                                                        "samples": raw_samples,
                                                        "summary": summary([{"local_query_wall_s": p["local_query_wall_s"]}
                                                                            for p in raw_samples[1:]])},
                      "all_modes_same_exact_scores_ids_top3": True})
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--datasets", nargs="+", choices=tuple(fixtures.SOURCES), default=list(fixtures.SOURCES))
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--query-budget", type=int, default=1024)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 15 or not args.repeats + 1 <= args.query_budget <= 65536 or args.json_out.exists():
        parser.error("Bounded repeat/budget and new raw path required")
    paths = [Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", ROOT / "benchmarks/certified_filter_lab.py",
             ROOT / "benchmarks/verification_frontier_lab.py", ROOT / "benchmarks/field_frontier_lab.py",
             ROOT / "src/cuhepy/bfv/scheme.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "enrolled_rpc", "loopback_exchange", "loopback_transfer", "coefficient_body", "cache_snapshot", "coordinate_cache",
        "coordinate_factory", "verification_lifetime", "native_linear_check", "crt_linear_check", "crt_native_bgv",
        "crt_masked_bgv", "crt_query_space", "dyadic_crt", "field_frontier", "affine_dictionary", "folded_dictionary",
        "binary_fixtures", "owner_bgv", "seeded_bgv", "shallow_bgv"))
    for folder in ("_subring", "_fingerprint"):
        paths.extend((ROOT / "experiments/bfv_search_lab" / folder).glob("*.so"))
        paths.extend(ROOT / "experiments/bfv_search_lab" / folder / name for name in ("bindings.cpp", "Makefile"))
    report = metadata(paths)
    report.update(kind="matched_enrolled_endpoint_tcp_control", split_seed=3001, cases=run(args),
                  scope="Actual persistent same-process loopback TCP and application frames for native homemade masked BGV "
                        "and AES-GCM authorized caches on identical rows/IDs/queries. Full-Q verification precedes secret decryption. "
                        "Query wall includes fresh trusted owner prepare/register, answer upload, request/reply, public parsing, "
                        "check, secret decrypt, decode/select. Nested stages are not added again. Index upload populates actual server index. "
                        "Context/keys/maps/IDs/checker/cache manifests already pinned; private bootstrap and independent endpoint RSS/CPU "
                        "are not measured. No cold-deployment, WAN/TLS/GPU, p95/confidence, durability, private-timing, parameter assurance, "
                        "full reaction privacy proof, production or novel-mechanism claim. Fixed four-query pilot; cache lengths declared leakage.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "datasets": len(report["cases"]),
                      "exact_mode_queries": sum(len(c["homemade_he"]["samples"]) * 7 for c in report["cases"])}))


if __name__ == "__main__":
    main()
