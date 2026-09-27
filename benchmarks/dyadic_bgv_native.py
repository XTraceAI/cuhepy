#!/usr/bin/env python3
"""E27 paired native homemade BGV, full ring, exact rank/capacity ablations.

Includes the old flat CRT codec, equal-tree codec with identical index, targeted
rank repair, minimax allocation and a flat-64-slot control. No kernels changed.
All online stages are charged; enrollment, network and authentication separate.
"""

# ruff: noqa: E402 -- standalone benchmark.

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
from benchmarks.component_bgv_native import map_memory
from benchmarks.dictionary_layout_lab import metadata, summary
from benchmarks.dyadic_layout_lab import given_candidate, uneven_rows
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import crt_multiplex as flat
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import folded_filter as folded
from experiments.bfv_search_lab import linear_packing as packing
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import rank_partition as partition
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab.native_bgv import NativeServer


class View:
    def __init__(self, candidate, codec="tree", align_flat=False):
        self.candidate = candidate
        self.codec = flat if codec == "flat" else tree
        self.blocks = candidate.blocks
        if codec == "flat" or align_flat:
            assert len({len(b.path) for b in self.blocks}) == 1
            ctx = flat.context(candidate.layout.context.n, len(self.blocks), candidate.layout.context.prime)
            if align_flat:
                order = [ctx.roots.index(leaf.root) for leaf in candidate.layout.context.leaves]
                self.blocks = tuple(candidate.blocks[i] for i in order)
            else:
                self.layout = flat.layout(ctx, candidate.layout.features, candidate.layout.counts)
        if codec == "tree":
            self.layout = tree.layout(candidate.layout.context, tuple(b.mapping.features for b in self.blocks),
                                      tuple(len(b.positions) for b in self.blocks))
        maps = list(dict.fromkeys(b.mapping for b in self.blocks))
        numbers = {p: i for i, p in enumerate(maps)}
        self.map_ids = [numbers[b.mapping] for b in self.blocks]
        self.compile_s, self.compiled = timed(lambda: [affine.compile_bits(p) for p in maps])
        bodies = b"".join(affine.canonical_map(p) for p in maps)
        self.state = {"unique_maps": len(maps), "components": len(self.blocks),
                      "map_body_bytes": len(bodies), "map_zlib9_bytes": len(zlib.compress(bodies, 9)),
                      "python_dense_maps_bytes": map_memory(maps), "python_compiled_maps_bytes": map_memory(self.compiled),
                      "compile_masks_s": self.compile_s, "ranks": [p.rank for p in maps],
                      "counts": self.layout.counts, "map_ids": self.map_ids, "padded": self.layout.padded,
                      "virtual_count": self.layout.virtual_count,
                      "full_affine_cache_modeled_bytes": len(bodies) + sum((len(b.positions) * b.mapping.rank + 7) // 8
                                                                          for b in self.blocks)}

    def index(self, rows):
        return self.codec.index(self.layout, [affine.index_features(b.mapping, [rows[i] for i in b.positions]) for b in self.blocks])

    def query(self, q):
        transforms = [affine.bit_query_features(p, q) for p in self.compiled]
        return self.codec.query(self.layout, [transforms[i][0] for i in self.map_ids]), [o for _, o in transforms]

    def finish(self, plaintexts, offsets, ids):
        dots = self.codec.unpack(self.layout, plaintexts)
        pairs = []
        for block, ds, group in zip(self.blocks, dots, self.map_ids, strict=True):
            scores = affine.bit_decode(self.compiled[group], ds, offsets[group])
            pairs.extend(zip(scores, (ids[i] for i in block.positions), strict=True))
        return pairs


def run(args):
    setup, views, aliases, query_ids = {}, {}, {}, []
    if args.dataset == "mushroom":
        data = fixtures.load("mushroom", args.cache_dir / fixtures.SOURCES["mushroom"]["member"])
        ids, holdout = fixtures.split(data, args.seed)
        rows, dimension = [data.rows[i] for i in ids], data.dimension
        query_ids = holdout[119:120 + args.repeats]
        queries = [data.rows[i] for i in query_ids]
        setup["fixture_sha256"] = data.sha256
        setup["metric_order_s"], order = timed(dictionary.metric_order, rows, dimension, 32)
        candidates = {}
        for name, kwargs in (("equal8", {}), ("equal16", {"initial_parts": 16}),
                             ("repair64", {"target": 64, "policy": "hybrid"}),
                             ("repair32", {"target": 32, "policy": "hybrid"})):
            setup[name + "_fit_s"], candidates[name] = timed(partition.prepare, rows, dimension, order, **kwargs)
        views.update({"flat8": View(candidates["equal8"], "flat"), "flat16": View(candidates["equal16"], "flat"),
                      "tree16": View(candidates["equal16"], align_flat=True),
                      "repair64": View(candidates["repair64"]), "repair32": View(candidates["repair32"])})
        aliases["tree16"] = "flat16"
        allocation_source = candidates["repair32"]
    else:
        rows, counts = uneven_rows()
        dimension, ids = 512, list(range(len(rows)))
        rng = random.Random(3111)
        queries = [rng.getrandbits(dimension) if i % 2 else rows[rng.randrange(len(rows))] ^ 31
                   for i in range(args.repeats + 1)]
        setup["given_fit_s"], candidate = timed(given_candidate, rows, dimension, counts)
        views.update({"flat_given": View(candidate, "flat"), "tree_given": View(candidate, align_flat=True)})
        aliases["tree_given"] = "flat_given"
        allocation_source = candidate
    setup["allocation_s"], allocated = timed(partition.reallocate, allocation_source, rows)
    setup["flat_slot_allocation_s"], slots = timed(partition.reallocate, allocation_source, rows, coalesce=False)
    views["allocated"], views["flat_slots"] = View(allocated), View(slots, "flat")
    raw = b"".join(x.to_bytes((dimension + 7) // 8, "little") for x in rows)
    setup.update({"raw_rows_bytes": len(raw), "raw_rows_input_order_zlib9_bytes": len(zlib.compress(raw, 9)),
                  "common_stable_id_bytes": len(ids) * max(1, (max(ids).bit_length() + 7) // 8)})
    full_plan = folded.FoldPlan(dimension, tuple(range(dimension)), tuple((j, 0) for j in range(dimension)), 0)
    setup["full_encode_s"], (_, full_tiles, fp) = timed(folded.inputs, full_plan, 0, rows, 16384)
    definitions = {"full": (fp, len(rows), full_tiles)}
    for name, view in views.items():
        encode_s, tiles = timed(view.index, rows)
        definitions[name] = view.layout.padded, view.layout.virtual_count, tiles
        setup[name] = {"state": view.state, "index_encode_s": encode_s}
        if name in aliases:
            assert tiles == definitions[aliases[name]][2], "Equal-tree codec changed the exact index polynomial"
    setup["keygen_s"], (pk, sk) = timed(bgv.key_gen, 16384, t=1153, q_bits=120, rns_modulus=True)
    setup.update({"n": pk.n, "t": pk.t, "q_bits": pk.q.bit_length(), "eta": pk.eta, "digit_bits": 30, "terminal_bits": 32})
    width = (pk.q.bit_length() + 7) // 8
    servers, prepared = {}, {}
    with closing(owner.OwnerClient(pk, sk, native=True, rns=True)) as client:
        client.prepare_terminal(32)
        for padded in sorted({d[0] for d in definitions.values()}):
            keys_s, keys = timed(trace.evaluation_keys, pk, sk, padded)
            entry = {"create_s": keys_s, "coefficient_bytes": (1 + len(keys.rotations)) * len(keys.relin) * 2 * pk.n * width}
            for device in args.devices:
                entry[device + "_prepare_s"], servers[padded, device] = timed(
                    NativeServer, pk, keys, residue=True, device=device, cuda_level=4 if device == "cuda" else 0,
                    ntt_variant="indexed" if device == "cuda" else "baseline")
            setup[f"keys_{padded}"] = entry
        for name, (padded, count, tiles) in definitions.items():
            entry = {"ciphertexts": len(tiles), "coefficient_bytes": len(tiles) * 2 * pk.n * width}
            if name in aliases:
                entry["shared_index_with"] = aliases[name]
                for device in args.devices:
                    prepared[name, device] = prepared[aliases[name], device]
            else:
                entry["encrypt_expand_s"], encrypted = timed(lambda tiles=tiles: [owner.expand(client.encrypt(p), pk) for p in tiles])
                for device in args.devices:
                    entry[device + "_prepare_s"], prepared[name, device] = timed(servers[padded, device].prepare_index, encrypted, count)
            setup[name + "_index"] = entry
        definitions = {name: (padded, count) for name, (padded, count, _) in definitions.items()}
        del full_tiles, tiles, encrypted, keys, raw
        gc.collect()
        cases = [(name, device) for name in definitions for device in args.devices]
        samples, warmup, local_plaintext = {f"{name}/{device}": [] for name, device in cases}, {}, []
        rng = random.Random(3112)
        for repeat, q in enumerate(queries):
            expected = {i: (q ^ row).bit_count() for row, i in zip(rows, ids, strict=True)}
            expected_top = tuple(sorted((d, i) for i, d in expected.items())[:3])
            plain_s, top = timed(lambda q=q: tuple(sorted(((q ^ row).bit_count(), i) for row, i in zip(rows, ids, strict=True))[:3]))
            assert top == expected_top
            if repeat:
                local_plaintext.append({"local_total_s": plain_s})
            cache, polys = {}, {}
            for name in definitions:
                encode_s, (poly, offsets) = timed(views[name].query, q) if name != "full" else timed(
                    lambda q=q: (folded.inputs(full_plan, q, [], pk.n)[0], []))
                polys[name] = poly
                if name in aliases:
                    assert poly == polys[aliases[name]], "Equal-tree codec changed the query polynomial"
                encrypt_s, packet = timed(client.encrypt, poly)
                expand_s, cipher = timed(owner.expand, packet, pk)
                cache[name] = cipher, offsets, encode_s, encrypt_s, expand_s, len(packet)
            rng.shuffle(cases)
            wires = {}
            for name, device in cases:
                padded, count = definitions[name]
                cipher, offsets, encode_s, encrypt_s, expand_s, query_bytes = cache[name]
                evaluate_s, output = timed(servers[padded, device].search_compact, cipher, prepared[name, device])
                pack_s, wire = timed(compact.pack, output, count, dimension, pk)
                decrypt_s, plains = timed(lambda output=output: [client.decrypt_compact(c) for c in output])

                def finish(name=name, plains=plains, offsets=offsets):
                    if name == "full":
                        pairs = list(zip(folded.decode(full_plan, packing.unpack(plains, len(rows), fp, pk.n, pk.t), pk.t), ids, strict=True))
                    else:
                        pairs = views[name].finish(plains, offsets, ids)
                    return pairs, tuple(sorted(pairs)[:3])

                finish_s, (pairs, top) = timed(finish)
                assert len(pairs) == len(rows) and {i: d for d, i in pairs} == expected and top == expected_top
                if name in wires:
                    assert wire == wires[name], "Complete CPU/CUDA output differs"
                wires[name] = wire
                sample = {"query_transform_s": encode_s, "encrypt_s": encrypt_s, "query_expand_s": expand_s,
                          "evaluate_s": evaluate_s, "response_pack_s": pack_s, "decrypt_s": decrypt_s,
                          "decode_select_s": finish_s, "server_s": expand_s + evaluate_s + pack_s,
                          "client_s": encode_s + encrypt_s + decrypt_s + finish_s,
                          "local_total_s": sum((encode_s, encrypt_s, expand_s, evaluate_s, pack_s, decrypt_s, finish_s)),
                          "query_bytes": query_bytes, "response_bytes": len(wire), "response_ciphertexts": len(output)}
                label = f"{name}/{device}"
                if repeat:
                    samples[label].append(sample)
                else:
                    warmup[label] = sample
            print(args.dataset, args.seed, "paired query", repeat, "/", args.repeats, file=sys.stderr, flush=True)
    return {"dataset": args.dataset, "split_seed": args.seed if args.dataset == "mushroom" else None,
            "count": len(rows), "dimension": dimension, "unique_rows": len(set(rows)), "query_ids_with_warmup": query_ids,
            "setup": setup, "warmup": warmup, "samples": samples, "summary": {k: summary(s) for k, s in samples.items()},
            "plaintext_full_index_control": summary(local_plaintext), "all_distances_and_stable_top3_exact": True,
            "complete_cpu_cuda_output_equal": True if len(args.devices) == 2 else None,
            "equal_tree_index_and_query_plaintexts_equal_to_flat_control": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--dataset", choices=("mushroom", "uneven"), default="mushroom")
    parser.add_argument("--seed", type=int, default=3002)
    parser.add_argument("--repeats", type=int, default=8)
    parser.add_argument("--devices", nargs="+", choices=("cpu", "cuda"), default=["cpu", "cuda"])
    args = parser.parse_args()
    if not 1 <= args.repeats <= 8 or len(set(args.devices)) != len(args.devices):
        parser.error("Invalid paired workload")
    paths = [Path(__file__), *(ROOT / f"benchmarks/{name}.py" for name in (
        "dyadic_layout_lab", "component_bgv_native", "component_dictionary_lab", "certified_filter_lab", "dictionary_layout_lab"))]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "dyadic_crt", "rank_partition", "affine_dictionary", "crt_multiplex", "folded_dictionary", "folded_filter", "binary_fixtures",
        "linear_packing", "native_bgv", "owner_bgv", "native_owner_bgv", "seeded_bgv", "private_bgv", "compact_bgv", "shallow_bgv",
        "trace_bgv", "butterfly_bgv"))
    modules = ["experiments.bfv_search_lab._native._bgv_trace", "experiments.bfv_search_lab._owner._bgv_owner"]
    if "cuda" in args.devices:
        modules.append("experiments.bfv_search_lab._native._bgv_trace_cuda")
    paths.extend(Path(importlib.import_module(m).__file__) for m in modules)
    result = metadata(paths)
    result.update({"kind": "dyadic_rank_capacity_paired_homemade_bgv", "omp_num_threads": os.environ.get("OMP_NUM_THREADS"),
                   "notes": "Same full ring/key/t/Q/terminal precision. Native conservative path; all online stages, including transforms, charged. "
                            "Setup, network and authentication excluded; no production or private timing assurance. "
                            "Private map state deduplicated across replicas; common IDs, public tree/count metadata and setup separate. "
                            "Native API, not packed workspace. No external HE library or new CUDA kernels.", "result": run(args)})
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
