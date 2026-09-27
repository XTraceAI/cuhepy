#!/usr/bin/env python3
"""E27 changed-state controls: complete affine cache and one-row epoch changes.

Local owner-only plaintext cache, NOT an encrypted protocol. Every row is
reconstructed and every query score checked. Enrollment timings are models of
full rebuilding, not incremental encrypted-index updates. No raw cache is saved.
"""

# ruff: noqa: E402 -- standalone benchmark.

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import random
import sys
import zlib

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import structured_fixture, timed
from benchmarks.component_bgv_native import map_memory
from benchmarks.dictionary_layout_lab import metadata, summary
from benchmarks.dyadic_layout_lab import audit, given_candidate, uneven_rows
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import rank_partition as partition


def cache_control(candidate, rows, ids, queries):
    """Benchmark a local prepared cache whose extra state is ALL pivot bits.

    Maps stay privately compiled as in HE. Query timings include unpacking or
    per-block decompression, query transforms, field scores and stable top-k.
    Byte counts are bodies; public layout/IDs/framing are separate. This local
    fixture helper is not a parser for untrusted compressed cache messages.
    """
    maps = list(dict.fromkeys(b.mapping for b in candidate.blocks))
    map_ids = {p: i for i, p in enumerate(maps)}
    compiled = [affine.compile_bits(p) for p in maps]
    anchors = [np.asarray([(p.anchor >> j) & 1 for j in p.pivots], dtype=np.int64) for p in maps]
    payloads, compressed, entries = [], [], []
    width = (candidate.dimension + 7) // 8
    ordered_raw = b""
    for block in candidate.blocks:
        count, rank = len(block.positions), block.mapping.rank
        values = np.asarray([[(rows[i] >> j) & 1 for j in block.mapping.pivots] for i in block.positions],
                            dtype=np.uint8).reshape(count, rank)
        packed = np.packbits(values.ravel(), bitorder="little").tobytes()
        payloads.append(packed)
        compressed.append(zlib.compress(packed, 9))
        group = map_ids[block.mapping]
        entries.append((group, count, rank, tuple(ids[i] for i in block.positions)))
        bits = np.unpackbits(np.frombuffer(packed, dtype=np.uint8), bitorder="little")[:count * rank].reshape(count, rank)
        # Independent full-row reconstruction from packed pivot bits and maps.
        basis = np.asarray(block.mapping.basis, dtype=np.int64).reshape(rank, candidate.dimension)
        anchor = np.asarray([(block.mapping.anchor >> j) & 1 for j in range(candidate.dimension)], dtype=np.int64)
        decoded = ((bits.astype(np.int64) - anchors[group]) @ basis + anchor) % block.mapping.prime
        assert np.all((decoded == 0) | (decoded == 1))
        raw = b"".join(rows[i].to_bytes(width, "little") for i in block.positions)
        assert np.packbits(decoded.astype(np.uint8), axis=1, bitorder="little").tobytes() == raw
        ordered_raw += raw

    def search(q, use_zlib):
        transforms = [affine.bit_query_features(p, q) for p in compiled]
        arrays = [np.asarray(w[:len(a)], dtype=np.int64) for (w, _), a in zip(transforms, anchors, strict=True)]
        corrections = [offset - int(a @ w) for (_, offset), a, w in zip(transforms, anchors, arrays, strict=True)]
        pairs = []
        for position, (group, count, rank, names) in enumerate(entries):
            packed = zlib.decompress(compressed[position]) if use_zlib else payloads[position]
            bits = np.unpackbits(np.frombuffer(packed, dtype=np.uint8), bitorder="little")[:count * rank].reshape(count, rank)
            scores = ((bits @ arrays[group] + corrections[group]) % candidate.layout.context.prime).tolist()
            pairs.extend(zip(scores, names, strict=True))
        return pairs, tuple(sorted(pairs)[:3])

    samples = {"packed_pivots": [], "zlib_pivots": []}
    rng = random.Random(3120)
    for repeat, q in enumerate(queries):
        expected = {i: (row ^ q).bit_count() for row, i in zip(rows, ids, strict=True)}
        top = tuple(sorted((d, i) for i, d in expected.items())[:3])
        cases = [("packed_pivots", False), ("zlib_pivots", True)]
        rng.shuffle(cases)
        for name, compressed_query in cases:
            elapsed, (pairs, got) = timed(search, q, compressed_query)
            assert len(pairs) == len(rows) and {i: d for d, i in pairs} == expected and got == top
            if repeat:
                samples[name].append({"local_total_s": elapsed})
    bodies = b"".join(affine.canonical_map(p) for p in maps)
    return {"canonical_map_bytes": len(bodies), "map_zlib9_bytes": len(zlib.compress(bodies, 9)),
            "packed_coordinate_bytes": sum(map(len, payloads)), "blockwise_coordinate_zlib9_bytes": sum(map(len, compressed)),
            "complete_maps_plus_pivots_body_bytes": len(bodies) + sum(map(len, payloads)),
            "complete_maps_plus_pivots_zlib9_bytes": len(zlib.compress(bodies + b"".join(payloads), 9)),
            "full_rows_same_layout_bytes": len(ordered_raw), "full_rows_same_layout_zlib9_bytes": len(zlib.compress(ordered_raw, 9)),
            "python_compiled_maps_bytes": map_memory(compiled),
            "python_prepared_cache_query_state_bytes_including_ids": map_memory((compiled, anchors, entries, tuple(compressed))),
            "common_stable_id_body_bytes": len(ids) * max(1, (max(ids).bit_length() + 7) // 8),
            "samples": samples, "summary": {k: summary(s) for k, s in samples.items()},
            "all_rows_reconstructed_and_all_query_scores_exact": True}


def update_case():
    # Eight independent 64-dimensional affine groups plus one previously fixed
    # zero coordinate; replacing one row adds the 65th direction to one group.
    before = [row for i in range(8) for row in structured_fixture(1024, 511, 64, 0, 3130 + i)[1]]
    after = before.copy()
    after[-1] |= 1 << 511
    order = tuple(range(len(before)))
    old_s, old = timed(partition.prepare, before, 512, order)
    try:
        partition.validate_epoch(old, after)
    except ValueError as error:
        assert "epoch" in str(error)
    else:
        raise AssertionError("Stale epoch accepted")
    try:
        affine.index_features(old.blocks[-1].mapping, [after[-1]])
    except ValueError:
        pass
    else:
        raise AssertionError("New independent direction fits old map")
    fixed_s, fixed = timed(partition.prepare, after, 512, order)
    repaired_s, repaired = timed(partition.prepare, after, 512, order, target=64, policy="hybrid")
    allocation_s, allocated = timed(partition.reallocate, repaired, after)
    rng = random.Random(3140)
    queries = [after[-1], before[-1], *(rng.getrandbits(512) for _ in range(14))]
    return {"changed_rows": 1, "count": len(before), "dimension": 512, "stale_epoch_and_old_map_rejected": True,
            "old": {"fit_s": old_s, "result": audit(old, before, list(range(len(before))), queries)},
            "rebuilt_fixed_partition": {"fit_s": fixed_s, "result": audit(fixed, after, list(range(len(after))), queries)},
            "rebuilt_repaired_partition": {"fit_s": repaired_s, "result": audit(repaired, after, list(range(len(after))), queries)},
            "reallocated": {"allocation_s": allocation_s, "result": audit(allocated, after, list(range(len(after))), queries)},
            "cost_change": {"before": asdict(old.layout.cost), "after_fixed": asdict(fixed.layout.cost),
                            "after_repair": asdict(repaired.layout.cost), "after_allocation": asdict(allocated.layout.cost)},
            "notes": "Full owner rebuilds, not incremental HE updates. Re-encryption, native index preparation, key changes and epoch authorization excluded."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    paths = [Path(__file__), *(ROOT / f"benchmarks/{name}.py" for name in (
        "dyadic_layout_lab", "component_bgv_native", "component_dictionary_lab", "dictionary_layout_lab", "certified_filter_lab"))]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "dyadic_crt", "rank_partition", "affine_dictionary", "binary_fixtures", "folded_dictionary", "linear_packing"))
    result = metadata(paths)
    result.update({"kind": "dyadic_plaintext_cache_and_epoch_controls", "cache_results": [],
                   "notes": "Owner-only complete plaintext coordinate cache, changed state contract. "
                            "Body compression excludes layout/ID/framing. Python object sums are not RSS. "
                            "All cache queries include unpack/decompression, transforms, scores and stable top3; no server/HE/network. "
                            "Owner maps compiled exactly as in HE; private arithmetic variable-time. "
                            "Eight fresh queries plus warmup, separate from native timing. Full rebuilds are not an incremental update protocol."})
    data = fixtures.load("mushroom", args.cache_dir / fixtures.SOURCES["mushroom"]["member"])
    for seed in (3001, 3002):
        ids, holdout = fixtures.split(data, seed)
        rows = [data.rows[i] for i in ids]
        candidate = partition.prepare(rows, data.dimension, dictionary.metric_order(rows, data.dimension, 32), target=32, policy="hybrid")
        candidate = partition.reallocate(candidate, rows)
        result["cache_results"].append({"name": f"mushroom/{seed}", "fixture_sha256": data.sha256,
                                         "query_ids_with_warmup": holdout[119:128],
                                         "result": cache_control(candidate, rows, ids, [data.rows[i] for i in holdout[119:128]])})
    rows, counts = uneven_rows()
    candidate = partition.reallocate(given_candidate(rows, 512, counts), rows)
    rng = random.Random(3111)
    queries = [rng.getrandbits(512) if i % 2 else rows[rng.randrange(len(rows))] ^ 31 for i in range(9)]
    result["cache_results"].append({"name": "uneven_given", "result": cache_control(candidate, rows, list(range(len(rows))), queries)})
    result["single_row_update"] = update_case()
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
