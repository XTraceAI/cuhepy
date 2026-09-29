#!/usr/bin/env python3
"""E29 full-ring homemade BGV pilot, with every offline/online stage charged.

Same index-only E27 rank repair; no query chooses the maps or CRT geometry.
New seeded linear-circuit keys/index, exact full-q responses, no SEAL/CUDA.
Paired independent GMP and new public C++ short-subring NTT evaluator.
The existing native server timings are historical context, not a paired speedup.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import importlib
import json
from pathlib import Path
import random
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata, summary
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import rank_partition as partition
from experiments.bfv_search_lab import shallow_bgv as bgv


def run(args):
    data = fixtures.load("mushroom", args.cache_dir / fixtures.SOURCES["mushroom"]["member"])
    ids, holdout = fixtures.split(data, args.seed)
    rows = [data.rows[i] for i in ids]
    setup = {"n": 16384, "t": 1153, "q_bits_requested": args.q_bits, "eta": 21}
    if args.layout == "raw":
        d = data.dimension
        mapping = affine.Plan(d, 1153, 0, tuple(range(d)), tuple(tuple(int(i == j) for j in range(d)) for i in range(d)))
        layout = tree.layout(tree.context(16384, ("",)), (d,), (len(rows),))
        blocks = (partition.Block("", tuple(range(len(rows))), mapping),)
        candidate = partition.Candidate(layout, blocks, (), partition.epoch_digest(rows, d), d,
                                        partition.map_body_bytes(blocks), None)
        # This identity map is PUBLIC and reconstructed from d, not private owner state.
        setup["order_s"], setup["fit_s"] = 0.0, 0.0
    else:
        setup["order_s"], order = timed(dictionary.metric_order, rows, data.dimension, 32)
        setup["fit_s"], candidate = timed(partition.prepare, rows, data.dimension, order, target=32, policy="hybrid")
    # The new arithmetic no longer pays E27's tile products. At fixed maps,
    # prefer fewer output ciphertexts, then the smallest correction subring.
    allocation_source, alternatives = candidate, []
    setup["allocation_s"] = 0.0
    for slots in ((1,) if args.layout == "raw" else (1, 2, 4, 8, 16, 32, 64)):
        if slots < len(set(b.mapping for b in candidate.blocks)):
            continue
        seconds, choice = timed(partition.reallocate, allocation_source, rows, slots)
        setup["allocation_s"] += seconds
        alternatives.append((slots, choice))
    slots, candidate = min(alternatives, key=lambda item: (item[1].layout.cost.response_ciphertexts, item[0]))
    setup["allocation_candidates"] = [{"slots": s, "old_input_tiles": c.layout.cost.input_tiles,
                                       "response_ciphertexts": c.layout.cost.response_ciphertexts,
                                       "selected": s == slots} for s, c in alternatives]
    maps = list(dict.fromkeys(b.mapping for b in candidate.blocks))
    map_ids = tuple(maps.index(b.mapping) for b in candidate.blocks)
    s = space.space(candidate.layout, map_ids)
    setup["coordinate_enroll_s"], groups = timed(lambda: [affine.index_features(b.mapping, [rows[i] for i in b.positions])
                                                        for b in candidate.blocks])
    map_body = b"".join(affine.canonical_map(p) for p in maps)
    return run_prepared(args, data, ids, holdout, rows, candidate, setup, s, groups, map_body,
                        private_map_bytes=0 if args.layout == "raw" else len(map_body))


def run_prepared(args, data, ids, holdout, rows, candidate, setup, s, groups, map_body, *,
                 private_map_bytes, query_transform=None):
    """Shared E29/E30 measurement harness; preparation remains explicitly charged.

    The supplied candidate pins row ordering and original affine anchors. E30
    can provide a different exact coordinate space and owner query transform.
    Full private maps/coordinates are benchmark inputs, not server inputs.
    """
    maps = list(dict.fromkeys(b.mapping for b in candidate.blocks))
    map_ids = s.map_ids
    compiled = [affine.compile_bits(p) for p in maps]
    rounds = 5 if args.q_bits == 32 else 4
    model = space.cost(s, q_bits=args.q_bits, rounds=rounds)
    setup["key_gen_s"], (pk, sk) = timed(masked.key_gen, s, q_bits=args.q_bits)
    setup["q"], setup["q_bits_actual"] = str(pk.q), pk.q.bit_length()
    raw = b"".join(row.to_bytes((data.dimension + 7) // 8, "little") for row in rows)
    epoch = hashlib.sha256(bytes.fromhex(candidate.source_digest) + s.binding + bytes.fromhex(pk.key_id)
                           + map_body + json.dumps(ids).encode()).digest()
    setup.update({"map_body_bytes": len(map_body), "map_zlib9_bytes": len(zlib.compress(map_body, 9)),
                  "full_plaintext_cache_bytes": len(raw), "full_plaintext_cache_zlib9_bytes": len(zlib.compress(raw, 9)),
                  "common_stable_id_bytes": len(ids) * max(1, (max(ids).bit_length() + 7) // 8),
                  # This is the ORIGINAL pivot-bit cache control. Mixed-space
                  # coordinates need field residues, priced separately in E30;
                  # combining their map body with old pivot bits is invalid.
                  "baseline_original_affine_cache_modeled_bytes": sum(len(affine.canonical_map(p)) for p in maps)
                  + sum((len(b.positions) * b.mapping.rank + 7) // 8 for b in candidate.blocks),
                  "unique_maps": len(maps), "map_ranks": [p.rank for p in maps], "leaf_paths": [b.path for b in candidate.blocks],
                  "private_map_body_bytes": private_map_bytes,
                  "map_ids": map_ids, "counts": s.layout.counts, "previous_input_ciphertexts": s.layout.cost.input_tiles,
                  "previous_key_switches": s.layout.cost.switches, "private_coordinate_entries": sum(len(g) * f for g, f in zip(groups, s.layout.features, strict=True))})
    rng = random.Random(7300 + args.seed)
    with closing(owner.OwnerClient(pk, sk)) as client:
        setup["transposed_index_s"], (index, index_upload) = timed(masked.enroll, s, groups, epoch, client)
        setup["index_seeded_packet_bytes"] = index_upload
        setup["native_prepare_s"], prepared = timed(native.NativeIndex, index, pk)
        print("index ready", args.seed, "columns", s.columns, "mask dimensions", s.dimension, file=sys.stderr, flush=True)
        setup["conditional_checker_prepare_s"], gate = timed(check.EpochCheck, index, pk, budget=args.repeats + 1, rounds=rounds)
        pool, offline_samples = [], []
        # No future query is needed for this pool or its verification material.
        for i in range(args.repeats + 1):
            token_id, seed = i.to_bytes(16, "little"), rng.randbytes(32)  # Reproducible mask fixture only.
            prepare_s, (ticket, answer, upload) = timed(masked.prepare, s, groups, epoch, token_id, seed, client)
            checker_s, _ = timed(gate.prepare_answer, answer)
            offline_samples.append({"owner_answer_prepare_s": prepare_s, "trusted_answer_fingerprint_s": checker_s,
                                    "answer_seeded_packet_bytes": upload, "server_expanded_answer_bytes": model["stored_expanded_answer_bytes_per_token"]})
            pool.append((ticket, answer))
        query_ids = holdout[112:112 + args.repeats + 1]
        samples, warmup = [], None
        for query_number, (query_id, (ticket, answer)) in enumerate(zip(query_ids, pool, strict=True)):
            q = data.rows[query_id]
            plain_s, expected = timed(lambda q=q: sorted(((q ^ row).bit_count(), i) for row, i in zip(rows, ids, strict=True)))

            def request_for_query(q=q, ticket=ticket):
                if query_transform is not None:
                    weights, offsets = query_transform(q)
                    return ticket.consume(weights, epoch), offsets
                transforms = [affine.bit_query_features(p, q) for p in compiled]
                weights = tuple(w for ws, _ in transforms for w in ws)
                return ticket.consume(weights, epoch), [offset for _, offset in transforms]

            request_s, (request, offsets) = timed(request_for_query)
            native_first = bool(getattr(args, "alternate_order", False) and (query_number + args.seed) % 2)
            if native_first:
                native_s, native_result = timed(prepared.evaluate, answer, request)
                evaluate_s, result = timed(masked.evaluate, index, answer, request, pk)
            else:
                evaluate_s, result = timed(masked.evaluate, index, answer, request, pk)
                native_s, native_result = timed(prepared.evaluate, answer, request)
            assert native_result == result  # Every coefficient, context and bound.
            check_s, accepted = timed(gate.verify_once, request, native_result)
            assert accepted
            pack_s, body = timed(lambda result=result: b"".join(int(x).to_bytes((pk.q.bit_length() + 7) // 8, "little")
                                                                for c in result for p in c.components for x in p))
            assert len(body) == model["online_response_body_bytes"]
            decrypt_s, plaintexts = timed(lambda result=result: [bgv.decrypt(c, pk, sk) for c in result])

            def finish(plaintexts=plaintexts, offsets=offsets):
                dots = tree.unpack(s.layout, plaintexts)
                actual = []
                for block, values, group in zip(candidate.blocks, dots, map_ids, strict=True):
                    actual.extend(zip(affine.bit_decode(compiled[group], values, offsets[group]),
                                      (ids[i] for i in block.positions), strict=True))
                return sorted(actual)

            finish_s, actual = timed(finish)
            assert actual == expected and actual[:3] == expected[:3]
            sample = {"query_id": query_id, "native_evaluated_first": native_first,
                      "owner_request_s": request_s, "public_evaluate_s": evaluate_s,
                      "public_native_evaluate_s": native_s, "response_pack_s": pack_s,
                      "conditional_verify_s": check_s, "decrypt_s": decrypt_s, "decode_select_s": finish_s,
                      "online_local_s": request_s + evaluate_s + pack_s + check_s + decrypt_s + finish_s,
                      "online_native_local_s": request_s + native_s + pack_s + check_s + decrypt_s + finish_s,
                      "online_query_body_bytes": len(request.body()), "online_response_body_bytes": model["online_response_body_bytes"],
                      "plaintext_cache_s": plain_s, "maximum_phase_bound": max(c.phase_bound for c in result),
                      "all_distances_and_stable_top3_exact": True,
                      "score_digest": hashlib.sha256(json.dumps(actual).encode()).hexdigest()}
            if warmup is None:
                warmup = sample
            else:
                samples.append(sample)
            print("query", query_id, "GMP_s", round(sample["online_local_s"], 4),
                  "native_s", round(sample["online_native_local_s"], 4), file=sys.stderr, flush=True)
    # Discarded/expired masks still consume their offline upload/storage and owner work.
    offline_bytes = offline_samples[0]["answer_seeded_packet_bytes"]
    online_bytes = model["online_query_body_bytes"] + model["online_response_body_bytes"]
    utilization = [{"tokens_prepared": prepared, "tokens_used": used,
                    "offline_plus_online_bytes_per_completed_query": (prepared * offline_bytes + used * online_bytes) / used}
                   for prepared, used in ((1, 1), (100, 100), (100, 50), (100, 10))]
    return {"dataset": "mushroom", "layout": args.layout, "fixture_sha256": data.sha256, "split_seed": args.seed, "count": len(rows),
            "dimension": data.dimension, "unique_rows": len(set(rows)), "setup": setup, "cost_model": model,
            "query_ids_with_warmup": query_ids, "offline_samples": offline_samples, "warmup": warmup, "samples": samples,
            "summary": summary([{k: v for k, v in sample.items() if k.endswith("_s") or k.endswith("_bytes")} for sample in samples]),
            "token_utilization_model": utilization,
            "baseline_120bit_index_bytes": s.layout.cost.input_tiles * 2 * pk.n * 15,
            "baseline_best_allocated_120bit_index_bytes": min(c["old_input_tiles"] for c in setup["allocation_candidates"]) * 2 * pk.n * 15,
            "checker_ideal_error_bits_lower_bound": rounds * (pk.q.bit_length() - 1) - (args.repeats + 1 - 1).bit_length(),
            "baseline_previous_online_query_and_reply_bytes": 245866 + 131162,
            "all_distances_and_stable_top3_exact": True, "conditional_check_before_decryption": True,
            "all_gmp_native_ciphertext_coefficients_equal": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=3001)
    parser.add_argument("--layout", choices=("affine", "raw"), default="affine")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--q-bits", type=int, default=40)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 8:
        parser.error("Expected 1..8 measured queries")
    paths = [Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", ROOT / "benchmarks/certified_filter_lab.py",
             ROOT / "src/cuhepy/bfv/scheme.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "crt_query_space", "crt_masked_bgv", "crt_linear_check", "crt_native_bgv", "dyadic_crt", "rank_partition", "affine_dictionary",
        "binary_fixtures", "folded_dictionary", "owner_bgv", "seeded_bgv", "shallow_bgv", "test_crt_masked_bgv", "test_crt_linear_check", "test_crt_native_bgv"))
    paths.extend([ROOT / "experiments/bfv_search_lab/_subring/bindings.cpp", ROOT / "experiments/bfv_search_lab/_subring/Makefile",
                  ROOT / "experiments/bfv_search_lab/_subring/_crt_subring.pyi",
                  Path(importlib.import_module("experiments.bfv_search_lab._subring._crt_subring").__file__)])
    report = metadata(paths)
    report.update({"kind": "crt_response_transposition_masked_seeded_bgv",
                   "scope": "Research only. New key/index and conditional trusted preprocessing; no complete security or parameter approval. "
                            "Paired GMP and new single-thread C++ public arithmetic; historical BGV is not a paired speedup. "
                            "Full-q output checked without terminal rounding. Offline owner holds plaintext coordinates. "
                            "Counts omit envelopes, authenticated transport, durable one-use state and network latency.",
                   "result": run(args)})
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "queries": args.repeats + 1, "exact": True}))


if __name__ == "__main__":
    main()
