#!/usr/bin/env python3
"""E50: exact private-coordinate/raw/compressed local-cache controls.

Same E37 fixture split, private affine representation, all scores/stable IDs.
Bodies are encoded sizes, not resident memory; peak NumPy/Python scratch is
not free and the benchmark does not impose a budget to exclude a winner.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata, summary
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import coordinate_cache as cache
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=("mushroom", "semeion", "synthetic128"), required=True)
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--repeats", type=int, default=8)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 32 or (args.dataset != "synthetic128" and args.cache_dir is None):
        parser.error("Expected bounded repeats and public fixture cache")
    start = time.perf_counter()
    if args.dataset == "synthetic128":
        rng = random.Random(4901)
        dimension, t = 512, 1153
        rows = [rng.randrange(1 << 128) for _ in range(16384)]
        rows = [sum(word << j for j in range(0, dimension, 128)) for word in rows]
        ids = tuple(range(len(rows)))
        workload = Workload(tuple(rows), ids, dimension)
        mapping = affine.Plan(dimension, t, rows[0], tuple(range(128)),
                              tuple(tuple(int(j % 128 == i) for j in range(dimension)) for i in range(128)))
        choice = oracle.Choice((oracle.Piece("", tuple(range(len(rows))), mapping, "affine"),))
        p = oracle.compile_choice(workload, choice, Profile(16384, t, q_bits=40), (1,))
        candidate, groups = p.candidate, p.groups
        words = [random.Random(49010 + i).randrange(1 << dimension) for i in range(args.repeats + 1)]
        digest = workload.digest
        policy = "Same E49 exact public generator schema/seed; independent held-out binary queries"
    else:
        data = fixtures.load(args.dataset, args.cache_dir / fixtures.SOURCES[args.dataset]["member"])
        ids, heldout = fixtures.split(data, 3001)
        ids = tuple(ids)
        rows, dimension = [data.rows[i] for i in ids], data.dimension
        order = dictionary.metric_order(rows, dimension, 32)
        t, slots = (193, 32) if data.name == "mushroom" else (257, 64)
        candidate = fields.allocate(fields.fit(rows, dimension, order, prime=t, target=32), rows, slots)
        groups = [affine.index_features(b.mapping, [rows[i] for i in b.positions]) for b in candidate.blocks]
        words = [data.rows[heldout[64 + i]] for i in range(args.repeats + 1)]
        digest, policy = data.sha256, "Same E49 held-out query prefix and E37 split/private maps"
    setup = {"load_fit_coordinate_certification_s": time.perf_counter() - start}
    variants = {}
    for mode in ("packed", "expanded"):
        setup[mode + "_cache_compile_s"], variants[mode] = timed(cache.Coordinates, candidate, groups, ids, mode=mode)
    setup["raw_cache_compile_s"], variants["raw"] = timed(cache.RawRows, rows, ids, dimension)
    setup["zlib_cache_compile_s"], variants["zlib"] = timed(cache.CompressedRows, rows, ids, dimension)
    observations = []
    for ordinal, word in enumerate(words):
        # Rotate order; separately timed query includes map contraction, decoding
        # or decompression, all-score materialization and stable top3 selection.
        names = tuple(variants)
        names = names[ordinal % 4:] + names[:ordinal % 4]
        reference = None
        for name in names:
            elapsed, actual = timed(variants[name].query, word)
            expected = tuple((word ^ row).bit_count() for row in rows)
            assert actual.scores == expected
            assert actual.top3 == tuple(sorted(zip(expected, ids, strict=True))[:3])
            if reference is not None:
                assert actual == reference
            reference = actual
            observations.append({"variant": name, "ordinal": ordinal, "warmup": ordinal == 0,
                                 "complete_local_query_s": elapsed, "all_scores_and_stable_top3_exact": True,
                                 "top3": actual.top3})
    state = {}
    for name in ("packed", "expanded"):
        c = variants[name]
        state[name] = {"coordinate_body_bytes": c.coordinate_body_bytes,
                       "private_map_body_bytes": c.private_map_body_bytes,
                       "stable_ids_and_permutation_bytes_model": c.stable_ids_and_permutation_bytes_model,
                       "complete_retained_body_bytes_model": c.coordinate_body_bytes + c.private_map_body_bytes + 12 * len(ids),
                       "largest_block_int64_dot_conversion_scratch_bytes_upper_model":
                           max(len(b.positions) * b.mapping.rank * 8 for b in candidate.blocks)}
    raw_bytes = len(rows) * ((dimension + 7) // 8)
    state["raw"] = {"packed_rows_body_bytes_model": raw_bytes, "stable_ids_body_bytes_model": 8 * len(ids),
                    "complete_retained_body_bytes_model": raw_bytes + 8 * len(ids)}
    state["zlib"] = {"compressed_rows_body_bytes": len(variants["zlib"].body), "stable_ids_body_bytes_model": 8 * len(ids),
                     "complete_retained_body_bytes_model": len(variants["zlib"].body) + 8 * len(ids),
                     "raw_decompression_scratch_body_bytes_model": raw_bytes}
    result = metadata([Path(__file__), ROOT / "experiments/bfv_search_lab/coordinate_cache.py",
                       ROOT / "experiments/bfv_search_lab/affine_dictionary.py",
                       ROOT / "experiments/bfv_search_lab/field_frontier.py"])
    result.update(kind="exact_private_coordinate_cache_control", dataset=args.dataset, fixture_sha256=digest,
                  query_policy=policy, count=len(rows), dimension=dimension, prime=t, setup=setup, state=state,
                  observations=observations,
                  summary={name: summary([{"complete_local_query_s": row["complete_local_query_s"]}
                                          for row in observations if row["variant"] == name and not row["warmup"]])
                           for name in variants},
                  scope="Owner-local exact all-score cache controls, no HE or changed privacy claim. "
                        "Retains private pivot bits, maps and IDs. One bit per pivot and zero coordinates for constant blocks. "
                        "Encoded-body counts do not measure Python/NumPy RSS and transient conversions must be charged. "
                        "Initial geometry discovery is recorded, not hidden; raw/zlib avoid it. "
                        "No arbitrary memory budget excludes these controls.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "observations": len(observations)}))


if __name__ == "__main__":
    main()
