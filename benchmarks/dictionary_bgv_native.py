#!/usr/bin/env python3
"""Paired homemade CPU/CUDA full search, owner hints and packed witnesses.

Uses a reserved public-data query slice, complete original tiles and the
existing native API. Per-query subset preparation is deliberately CHARGED:
there is no resident-index gather API. Excludes network/authenticated routing.
"""

# ruff: noqa: E402 -- standalone benchmark.

from __future__ import annotations

import argparse
from contextlib import closing
from dataclasses import asdict
import gc
import importlib
import json
import os
from pathlib import Path
import random
import sys
import time

import msgpack

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata, summary
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import folded_filter as folded
from experiments.bfv_search_lab import interval_filter as interval
from experiments.bfv_search_lab import linear_packing as packing
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import owner_residuals as residuals
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import witness_packing as witness
from experiments.bfv_search_lab.native_bgv import NativeServer


def run(args):
    data = fixtures.load(args.dataset, args.cache_dir / fixtures.SOURCES[args.dataset]["member"])
    indices, holdout = fixtures.split(data, args.seed)
    rows = [data.rows[i] for i in indices]
    dimension, n = data.dimension, args.ring_degree
    setup = {}
    setup["dictionary_s"], model = timed(dictionary.prepare, rows, dimension, args.groups, tail_passes=2)
    plan = model.plan
    full_plan = folded.FoldPlan(dimension, tuple(range(dimension)), tuple((j, 0) for j in range(dimension)), 0)
    capacity = n // packing.packing_cost(dimension, len(rows), n).padded
    setup["metric_layout_s"], order = timed(dictionary.metric_order, rows, dimension, capacity)
    rows, ids = [rows[i] for i in order], [indices[i] for i in order]
    original_positions = list(range(len(rows)))
    random.Random(args.seed + 19000).shuffle(original_positions)
    reverse = {i: j for j, i in enumerate(order)}
    positions = [reverse[i] for i in original_positions[:args.witnesses]]
    witness_rows = [rows[i] for i in positions]
    setup["keygen_s"], (pk, sk) = timed(bgv.key_gen, n, q_bits=120, rns_modulus=True)
    setup["n"], setup["t"], setup["q_bits"], setup["eta"] = n, pk.t, pk.q.bit_length(), pk.eta
    setup["digit_bits"], setup["terminal_bits"] = 30, 32
    width = (pk.q.bit_length() + 7) // 8
    servers, prepared, encrypted = {}, {}, {}
    with closing(owner.OwnerClient(pk, sk, native=True, rns=True)) as client:
        setup["terminal_prepare_s"] = timed(client.prepare_terminal, 32)[0]
        setup["coarse_encode_s"], (_, coarse_tiles, cp, radii) = timed(interval.inputs, plan, 0, rows, n)
        setup["full_encode_s"], (_, full_tiles, fp) = timed(folded.inputs, full_plan, 0, rows, n)
        _, witness_tiles, _ = folded.inputs(full_plan, 0, witness_rows, n)
        placement = witness.place(n, cp, len(rows), fp, len(positions))
        setup["placement"] = asdict(placement)
        setup["groups"], setup["max_radius"] = len(plan.representatives), plan.max_error
        setup["owner_arrays"] = interval.owner_state_bytes(len(rows), dimension, max(ids), reordered=True)
        setup["residual_enroll_s"], hint = timed(residuals.prepare, plan, rows)
        setup["residual_compile_s"], residual_state = timed(residuals.compile_hint, hint)
        setup["residual_hint_body_bytes"] = hint.body_bytes
        setup["residual_python_mask_bytes"] = residual_state.python_mask_bytes
        setup["raw_plaintext_row_bytes"] = len(rows) * ((dimension + 7) // 8)
        for label, pad in (("coarse", cp), ("full", fp)):
            key_s, keys = timed(trace.evaluation_keys, pk, sk, pad)
            setup[label] = {"keygen_s": key_s,
                            "key_coefficient_bytes": (1 + len(keys.rotations)) * len(keys.relin) * 2 * n * width}
            for device in args.devices:
                prep_s, server = timed(NativeServer, pk, keys, residue=True, device=device,
                                      cuda_level=4 if device == "cuda" else 0,
                                      ntt_variant="indexed" if device == "cuda" else "baseline")
                servers[label, device] = server
                setup[label][device] = {"server_prepare_s": prep_s}
        for label, tiles, count in (("full", full_tiles, len(rows)), ("coarse", coarse_tiles, len(rows)),
                                    ("witness", witness_tiles, len(positions))):
            enc_s, encrypted[label] = timed(lambda tiles=tiles: [owner.expand(client.encrypt(p), pk) for p in tiles])
            setup[label + "_index"] = {"ciphertexts": len(tiles), "encrypt_expand_s": enc_s,
                                        "coefficient_bytes": len(tiles) * 2 * n * width}
            for device in args.devices:
                server = servers["coarse" if label == "coarse" else "full", device]
                prep_s, prepared[label, device] = timed(server.prepare_index, encrypted[label], count)
                setup[label + "_index"][device + "_prepare_s"] = prep_s
        del coarse_tiles, full_tiles, witness_tiles, keys
        gc.collect()
        cases = [(mode, device) for mode in ("full", "interval", "witness", "residual") for device in args.devices]
        samples = {f"{m}/{d}": [] for m, d in cases}
        plaintext_samples = []
        warmup = {}
        rng = random.Random(2905)
        query_ids = holdout[95:96 + args.repeats]  # Warmup, then unused holdout 96:104.
        for repeat, query_id in enumerate(query_ids):
            query = data.rows[query_id]
            exact = [(query ^ row).bit_count() for row in rows]
            expected_top = tuple(sorted(zip(exact, ids, strict=True))[:3])
            local_s, local_top = timed(lambda query=query: tuple(sorted(((query ^ row).bit_count(), i)
                                                            for row, i in zip(rows, ids, strict=True))[:3]))
            assert local_top == expected_top
            if repeat:
                plaintext_samples.append({"local_total_s": local_s})
            expected_templates = [(query ^ folded._template(plan, row)).bit_count() for row in rows]
            queries = {}
            for label, representation in (("full", full_plan), ("coarse", plan)):
                start = time.perf_counter()
                qp = (interval.inputs(representation, query, [], n)[0] if label == "coarse"
                      else folded.inputs(representation, query, [], n)[0])
                encode_s = time.perf_counter() - start
                encrypt_s, packet = timed(client.encrypt, qp)
                expand_s, cipher = timed(owner.expand, packet, pk)
                queries[label] = (cipher, encode_s + encrypt_s, expand_s, len(packet))
            rng.shuffle(cases)
            wires = {}
            for mode, device in cases:
                metrics = {"filter_evaluate_s": 0.0, "witness_evaluate_s": 0.0, "fusion_s": 0.0,
                           "compact_s": 0.0, "subset_prepare_s": 0.0, "refine_evaluate_s": 0.0,
                           "response_pack_s": 0.0, "response_bytes": 0, "response_ciphertexts": 0,
                           "refinement_tiles": 0, "routing_bytes": 0}
                metrics["residual_correct_s"] = 0.0
                response_wires = []
                full_server, coarse_server = servers["full", device], servers["coarse", device]

                def response(output, count, metrics=metrics, response_wires=response_wires):
                    pack_s, wire = timed(compact.pack, output, count, dimension, pk)
                    metrics["response_pack_s"] += pack_s
                    metrics["response_bytes"] += len(wire)
                    metrics["response_ciphertexts"] += len(output)
                    response_wires.append(wire)
                    return [client.decrypt_compact(c) for c in output]

                started = time.perf_counter()
                if mode == "full":
                    metrics["filter_evaluate_s"], out = timed(full_server.search_compact, queries["full"][0], prepared["full", device])
                    plain = response(out, len(rows))
                    distances = folded.decode(full_plan, packing.unpack(plain, len(rows), fp, n, pk.t), pk.t)
                    top = tuple(sorted(zip(distances, ids, strict=True))[:3])
                    template_scores, exact_witnesses = None, None
                    used_queries = ["full"]
                else:
                    known = None
                    if mode == "witness":
                        metrics["filter_evaluate_s"], left = timed(coarse_server.search, queries["coarse"][0], prepared["coarse", device])
                        metrics["witness_evaluate_s"], right = timed(full_server.search, queries["full"][0], prepared["witness", device])
                        metrics["fusion_s"], combined = timed(witness.combine, left[0], right[0], placement, pk)
                        metrics["compact_s"], combined = timed(coarse_server.compact_result, combined)
                        dots, wd = witness.decode(response([combined], len(rows) + len(positions))[0], placement, pk.t)
                        exact_witnesses = interval.decode_templates(wd, dimension, pk.t)
                        known = dict(zip(positions, exact_witnesses, strict=True))
                    else:
                        metrics["filter_evaluate_s"], out = timed(coarse_server.search_compact, queries["coarse"][0], prepared["coarse", device])
                        dots = packing.unpack(response(out, len(rows)), len(rows), cp, n, pk.t)
                        exact_witnesses = None
                    template_scores = interval.decode_templates(dots, dimension, pk.t)
                    if mode != "residual":
                        lo, hi = interval.intervals(template_scores, radii, dimension)

                    def fetch(selected, metrics=metrics, full_server=full_server, queries=queries, response=response):
                        positions = [i for t in selected for i in range(t * capacity, min((t + 1) * capacity, len(rows)))]
                        metrics["refinement_tiles"] = len(selected)
                        metrics["routing_bytes"] = len(msgpack.packb(list(selected)))
                        # No free repacking/gather: immutable ciphertexts, original full tiles.
                        metrics["subset_prepare_s"], subset = timed(full_server.prepare_index,
                                                                  [encrypted["full"][i] for i in selected], len(positions))
                        metrics["refine_evaluate_s"], result = timed(full_server.search_compact, queries["full"][0], subset)
                        dots = packing.unpack(response(result, len(positions)), len(positions), fp, n, pk.t)
                        return list(zip(positions, folded.decode(full_plan, dots, pk.t), strict=True))

                    if mode == "residual":
                        metrics["residual_correct_s"], distances = timed(residuals.correct, residual_state, query, template_scores)
                        top = tuple(sorted(zip(distances, ids, strict=True))[:3])
                        used_queries = ["coarse"]
                    else:
                        top, selection, _ = interval.refine_once(lo, hi, ids, capacity, fetch, known_scores=known)
                        used_queries = ["coarse"] + (["full"] if mode == "witness" or selection.tiles else [])
                pipeline_s = time.perf_counter() - started
                metrics["query_bytes"] = sum(queries[q][3] for q in used_queries)
                metrics["query_expand_s"] = sum(queries[q][2] for q in used_queries)
                metrics["local_total_s"] = pipeline_s + sum(queries[q][1] + queries[q][2] for q in used_queries)
                metrics["server_s"] = sum(metrics[k] for k in (
                    "filter_evaluate_s", "witness_evaluate_s", "fusion_s", "compact_s", "subset_prepare_s",
                    "refine_evaluate_s", "response_pack_s", "query_expand_s"))
                metrics["client_s"] = metrics["local_total_s"] - metrics["server_s"]
                assert top == expected_top
                if mode in ("full", "residual"):
                    assert distances == exact
                if mode != "full":
                    assert template_scores == expected_templates
                    if mode == "witness":
                        assert exact_witnesses == [exact[i] for i in positions]
                if mode in wires:
                    assert response_wires == wires[mode], "CPU/CUDA complete response mismatch"
                wires[mode] = response_wires
                label = f"{mode}/{device}"
                if repeat:
                    samples[label].append(metrics)
                else:
                    warmup[label] = metrics
            print(f"Encrypted paired round {repeat}/{args.repeats}", file=sys.stderr, flush=True)
    return {"dataset": args.dataset, "dataset_sha256": data.sha256, "count": len(rows), "dimension": dimension,
            "split_seed": args.seed, "query_ids": query_ids[1:], "warmup_query_id": query_ids[0], "setup": setup,
            "warmup": warmup, "samples": samples, "summary": {k: summary(v) for k, v in samples.items()},
            "plaintext_full_index_control": {"samples": plaintext_samples, "summary": summary(plaintext_samples),
                                             "python_rows_bytes": sys.getsizeof(rows) + sum(sys.getsizeof(x) for x in rows),
                                             "note": "Retains EVERY plaintext row on owner; no HE/server/network needed. Different storage contract."},
            "all_stable_top3_and_intermediate_scores_exact": True,
            "complete_cpu_cuda_response_bytes_equal": True if len(args.devices) == 2 else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--dataset", choices=tuple(fixtures.SOURCES), default="mushroom")
    parser.add_argument("--seed", type=int, default=2901)
    parser.add_argument("--groups", type=int, default=32)
    parser.add_argument("--witnesses", type=int, default=128)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--repeats", type=int, default=8)
    parser.add_argument("--devices", nargs="+", choices=("cpu", "cuda"), default=["cpu", "cuda"])
    args = parser.parse_args()
    if not 1 <= args.repeats <= 8 or not 3 <= args.witnesses <= 256 or len(set(args.devices)) != len(args.devices):
        parser.error("Invalid reserved holdout/paired workload")
    paths = [Path(__file__), ROOT / "benchmarks/dictionary_layout_lab.py", ROOT / "benchmarks/certified_filter_lab.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "binary_fixtures", "folded_dictionary", "folded_filter", "interval_filter", "witness_packing", "linear_packing",
        "native_bgv", "owner_bgv", "owner_residuals", "native_owner_bgv", "seeded_bgv", "private_bgv", "compact_bgv", "shallow_bgv", "trace_bgv", "butterfly_bgv"))
    modules = ["experiments.bfv_search_lab._native._bgv_trace", "experiments.bfv_search_lab._owner._bgv_owner"]
    if "cuda" in args.devices:
        modules.append("experiments.bfv_search_lab._native._bgv_trace_cuda")
    paths.extend(Path(importlib.import_module(m).__file__) for m in modules)
    result = metadata(paths)
    result.update({"kind": "public_fixture_two_round_native_bgv", "omp_num_threads": os.environ.get("OMP_NUM_THREADS"),
                   "notes": "Own CPU/CUDA/owner BGV, generic bounds, same key/ring/terminal precision. "
                            "Subset preparation and Python fusion charged. Complete output equality checked outside timing. "
                            "No resident subset gather, production protocol, network latency, authentication or private routing. "
                            "Bytes use existing local coefficient envelopes plus MessagePack tile IDs; exclude context/attestation framing. "
                            "This measures the ordinary native API, not all optimized workspace/codec paths. "
                            "Dataset labels unused; Mushroom describes hypothetical samples, not field observations.",
                   "result": run(args)})
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
