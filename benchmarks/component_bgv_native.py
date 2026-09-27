#!/usr/bin/env python3
"""E26 paired full-size homemade BGV: full scan, separate local queries, CRT.

Equal N, t, Q, secret, conservative bounds and terminal precision. Static
enrollment is separate; online query transforms, CRT, encryption, expansion,
evaluation, wire packing, decryption, decoding and top-k are all charged.
"""

# ruff: noqa: E402 -- standalone research benchmark.

from __future__ import annotations

import argparse
from contextlib import closing
import gc
import importlib
import json
import os
from pathlib import Path
import random
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.component_dictionary_lab import groups_for, piecewise_rows, representation
from benchmarks.dictionary_layout_lab import metadata, summary
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import crt_multiplex as crt
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import folded_filter as folded
from experiments.bfv_search_lab import linear_packing as packing
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab.native_bgv import NativeServer


def map_memory(plans):
    """Python object sum with shared references counted once; not process RSS."""
    seen = set()

    def size(value):
        if id(value) in seen:
            return 0
        seen.add(id(value))
        result = sys.getsizeof(value)
        if isinstance(value, (list, tuple)):
            result += sum(size(x) for x in value)
        elif isinstance(value, dict):
            result += sum(size(k) + size(v) for k, v in value.items())
        elif hasattr(value, "__dict__"):
            result += size(value.__dict__)
        return result

    return size(plans)


def run(args):
    fixture_sha256 = None
    if args.dataset == "piecewise":
        rows, dimension = piecewise_rows(), 512
        ids = list(range(len(rows)))
        order = tuple(ids)  # Public contiguous generative blocks, not a learned clustering claim.
        rng = random.Random(3005)
        queries = [rng.getrandbits(dimension) if i % 2 else rows[rng.randrange(len(rows))] ^ 31
                   for i in range(args.repeats + 1)]
        query_ids = []
    else:
        data = fixtures.load(args.dataset, args.cache_dir / fixtures.SOURCES[args.dataset]["member"])
        fixture_sha256 = data.sha256
        ids, holdout = fixtures.split(data, args.seed)
        rows, dimension = [data.rows[i] for i in ids], data.dimension
        order = dictionary.metric_order(rows, dimension, 32)
        query_ids = holdout[103:104 + args.repeats]  # Warmup + reserved queries 104:112.
        queries = [data.rows[i] for i in query_ids]
    groups, stable = groups_for(rows, ids, args.parts, order)
    plans, layout, state = representation(groups, dimension, args.ring_degree, 1153)
    ordered = [x for group in groups for x in group]
    flat_ids = [x for group in stable for x in group]
    state["python_map_object_bytes"] = map_memory(plans)
    compiled_s, bit_plans = timed(lambda: [affine.compile_bits(p) for p in plans])
    state["compile_bit_masks_s"] = compiled_s
    state["python_bit_map_object_bytes"] = map_memory(bit_plans)
    state["bit_mask_terms"] = sum(len(row) for p in bit_plans for row in p.terms)
    raw = b"".join(x.to_bytes((dimension + 7) // 8, "little") for x in ordered)
    state.update({"raw_rows_bytes": len(raw), "raw_rows_zlib9_bytes": len(zlib.compress(raw, 9)),
                  "common_id_array_bytes": len(ids) * max(1, (max(ids).bit_length() + 7) // 8)})
    setup = {"private_representation": state, "padded": layout.padded, "parts": args.parts, "counts": layout.counts}
    setup["keygen_s"], (pk, sk) = timed(bgv.key_gen, args.ring_degree, t=1153, q_bits=120, rns_modulus=True)
    setup.update({"n": pk.n, "t": pk.t, "q_bits": pk.q.bit_length(), "eta": pk.eta, "digit_bits": 30, "terminal_bits": 32})
    width = (pk.q.bit_length() + 7) // 8
    full_plan = folded.FoldPlan(dimension, tuple(range(dimension)), tuple((j, 0) for j in range(dimension)), 0)
    encode_full_s, (_, full_tiles, fp) = timed(folded.inputs, full_plan, 0, ordered, pk.n)
    local_features = [affine.index_features(p, g) for p, g in zip(plans, groups, strict=True)]
    encode_crt_s, crt_tiles = timed(crt.index, layout, local_features)
    separate_tiles = [packing.pack([0] * layout.padded,
                                  [v + [0] * (layout.padded - len(v)) for v in group], pk.n)[1]
                      for group in local_features]
    definitions = {"full": (fp, [(full_tiles, len(rows))]),
                   "separate": (layout.padded, list(zip(separate_tiles, layout.counts, strict=True))),
                   "crt": (layout.padded, [(crt_tiles, layout.virtual_count)])}
    setup["full_encode_s"], setup["crt_index_encode_s"] = encode_full_s, encode_crt_s
    servers, prepared = {}, {}
    with closing(owner.OwnerClient(pk, sk, native=True, rns=True)) as client:
        client.prepare_terminal(32)
        for padded in sorted({fp, layout.padded}):
            keys_s, keys = timed(trace.evaluation_keys, pk, sk, padded)
            setup[f"keys_{padded}"] = {"create_s": keys_s,
                                      "coefficient_bytes": (1 + len(keys.rotations)) * len(keys.relin) * 2 * pk.n * width}
            for device in args.devices:
                server_s, servers[padded, device] = timed(NativeServer, pk, keys, residue=True, device=device,
                                                         cuda_level=4 if device == "cuda" else 0,
                                                         ntt_variant="indexed" if device == "cuda" else "baseline")
                setup[f"keys_{padded}"][device + "_prepare_s"] = server_s
        for name, (padded, chunks) in definitions.items():
            entry = {"ciphertexts": sum(len(tiles) for tiles, _ in chunks)}
            entry["coefficient_bytes"] = entry["ciphertexts"] * 2 * pk.n * width
            encryption_s, encrypted = timed(lambda chunks=chunks: [
                [owner.expand(client.encrypt(p), pk) for p in tiles] for tiles, _ in chunks])
            entry["encrypt_expand_s"] = encryption_s
            for device in args.devices:
                server = servers[padded, device]
                prepare_s, handles = timed(lambda encrypted=encrypted, chunks=chunks, server=server: [
                    server.prepare_index(cs, count) for cs, (_, count) in zip(encrypted, chunks, strict=True)])
                prepared[name, device] = handles
                entry[device + "_prepare_s"] = prepare_s
            setup[name + "_index"] = entry
        del encrypted, keys, full_tiles, crt_tiles, separate_tiles, local_features, raw
        gc.collect()
        # Reuse the exact CRT index: only the owner-side map representation changes.
        definitions["crt_masks"] = definitions["crt"]
        for device in args.devices:
            prepared["crt_masks", device] = prepared["crt", device]
        cases = [(name, device) for name in definitions for device in args.devices]
        samples = {f"{name}/{device}": [] for name, device in cases}
        warmup = {}
        rng = random.Random(3006)
        local_plaintext = []
        for repeat, q in enumerate(queries):
            exact = [(q ^ row).bit_count() for row in ordered]
            expected = tuple(sorted(zip(exact, flat_ids, strict=True))[:3])
            plain_s, plain_top = timed(lambda q=q: tuple(sorted(((q ^ row).bit_count(), i)
                                                               for row, i in zip(ordered, flat_ids, strict=True))[:3]))
            assert plain_top == expected
            if repeat:
                local_plaintext.append({"local_total_s": plain_s})
            query_cache = {}
            for name in definitions:
                def encode_query(name=name, q=q):
                    if name == "full":
                        return [folded.inputs(full_plan, q, [], pk.n)[0]], []
                    transforms = ([affine.bit_query_features(p, q) for p in bit_plans] if name == "crt_masks"
                                  else [affine.query_features(p, q) for p in plans])
                    offsets = [offset for _, offset in transforms]
                    weights = [w for w, _ in transforms]
                    if name in ("crt", "crt_masks"):
                        return [crt.query(layout, weights)], offsets
                    return [packing.pack(w + [0] * (layout.padded - len(w)), [], pk.n)[0] for w in weights], offsets

                encode_s, (polys, offsets) = timed(encode_query)
                encrypt_s, packets = timed(lambda polys=polys: [client.encrypt(p) for p in polys])
                expand_s, ciphers = timed(lambda packets=packets: [owner.expand(p, pk) for p in packets])
                query_cache[name] = (ciphers, offsets, encode_s, encrypt_s, expand_s, sum(map(len, packets)))
            rng.shuffle(cases)
            wires = {}
            for name, device in cases:
                ciphers, offsets, encode_s, encrypt_s, expand_s, query_bytes = query_cache[name]
                padded, chunks = definitions[name]
                server = servers[padded, device]
                evaluation_s, output = timed(lambda ciphers=ciphers, name=name, device=device, server=server: [
                    server.search_compact(qc, handle) for qc, handle in zip(ciphers, prepared[name, device], strict=True)])
                pack_s, wire = timed(lambda output=output, chunks=chunks: [
                    compact.pack(out, count, dimension, pk) for out, (_, count) in zip(output, chunks, strict=True)])
                decrypt_s, plaintexts = timed(lambda output=output: [[client.decrypt_compact(c) for c in out] for out in output])

                def finish(name=name, plaintexts=plaintexts, padded=padded, offsets=offsets):
                    if name == "full":
                        scores = folded.decode(full_plan, packing.unpack(plaintexts[0], len(rows), padded, pk.n, pk.t), pk.t)
                    else:
                        dots = (crt.unpack(layout, plaintexts[0]) if name in ("crt", "crt_masks") else
                                [packing.unpack(p, len(g), padded, pk.n, pk.t) for p, g in zip(plaintexts, groups, strict=True)])
                        scores = ([d for bp, ds, offset in zip(bit_plans, dots, offsets, strict=True)
                                   for d in affine.bit_decode(bp, ds, offset)] if name == "crt_masks" else
                                  [d for p, ds, offset in zip(plans, dots, offsets, strict=True) for d in affine.decode(p, ds, offset)])
                    return scores, tuple(sorted(zip(scores, flat_ids, strict=True))[:3])

                finish_s, (scores, top) = timed(finish)
                assert scores == exact and top == expected
                if name in wires:
                    assert wire == wires[name], "Complete CPU/CUDA output differs"
                wires[name] = wire
                sample = {"query_transform_s": encode_s, "encrypt_s": encrypt_s, "query_expand_s": expand_s,
                          "evaluate_s": evaluation_s, "response_pack_s": pack_s, "decrypt_s": decrypt_s,
                          "decode_select_s": finish_s, "server_s": expand_s + evaluation_s + pack_s,
                          "client_s": encode_s + encrypt_s + decrypt_s + finish_s,
                          "local_total_s": sum((encode_s, encrypt_s, expand_s, evaluation_s, pack_s, decrypt_s, finish_s)),
                          "query_bytes": query_bytes, "response_bytes": sum(map(len, wire)),
                          "query_ciphertexts": len(ciphers), "response_ciphertexts": sum(map(len, output))}
                label = f"{name}/{device}"
                if repeat:
                    samples[label].append(sample)
                else:
                    warmup[label] = sample
            print(f"{args.dataset} paired query {repeat}/{args.repeats}", file=sys.stderr, flush=True)
    return {"dataset": args.dataset, "dimension": dimension, "count": len(rows), "unique_rows": len(set(rows)),
            "split_seed": args.seed if args.dataset != "piecewise" else None, "fixture_sha256": fixture_sha256,
            "query_ids_with_warmup": query_ids, "setup": setup, "warmup": warmup, "samples": samples,
            "summary": {k: summary(v) for k, v in samples.items()}, "plaintext_full_index_control": summary(local_plaintext),
            "all_distances_and_stable_top3_exact": True,
            "complete_cpu_cuda_output_equal": True if len(args.devices) == 2 else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--dataset", choices=("mushroom", "semeion", "piecewise"), default="mushroom")
    parser.add_argument("--parts", type=int, default=8)
    parser.add_argument("--seed", type=int, default=3001)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--repeats", type=int, default=8)
    parser.add_argument("--devices", nargs="+", choices=("cpu", "cuda"), default=["cpu", "cuda"])
    args = parser.parse_args()
    if not 1 <= args.repeats <= 8 or len(set(args.devices)) != len(args.devices):
        parser.error("Invalid paired query workload")
    paths = [Path(__file__), ROOT / "benchmarks/component_dictionary_lab.py", ROOT / "benchmarks/certified_filter_lab.py",
             ROOT / "benchmarks/dictionary_layout_lab.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "affine_dictionary", "crt_multiplex", "folded_dictionary", "folded_filter", "binary_fixtures", "linear_packing",
        "native_bgv", "owner_bgv", "native_owner_bgv", "seeded_bgv", "private_bgv", "compact_bgv", "shallow_bgv", "trace_bgv", "butterfly_bgv"))
    modules = ["experiments.bfv_search_lab._native._bgv_trace", "experiments.bfv_search_lab._owner._bgv_owner"]
    if "cuda" in args.devices:
        modules.append("experiments.bfv_search_lab._native._bgv_trace_cuda")
    paths.extend(Path(importlib.import_module(m).__file__) for m in modules)
    result = metadata(paths)
    result.update({"kind": "affine_crt_paired_homemade_bgv", "omp_num_threads": os.environ.get("OMP_NUM_THREADS"),
                   "notes": "Same full encryption ring and t=1153 for ALL methods; 1031 does not support this CRT split. "
                            "No private row corrections, adaptive routing, secret-key GPU arithmetic or imported HE library. "
                            "Public-data metric partition or deliberately given piecewise synthetic blocks. "
                            "All online stages charged; setup, network and authentication excluded. Native API, not packed-workspace service. "
                            "Index-derived maps/anchors are private owner state; additional map size is independent of row count at fixed T,d. "
                            "Common stable-ID/permutation state is still O(M); no total constant-state claim. "
                            "No new parameter/side-channel assurance or production authorization.", "result": run(args)})
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
