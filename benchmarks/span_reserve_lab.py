#!/usr/bin/env python3
"""P05 held-out replacement-span screen; exact algebra, not HE runtime.

Published source rows are hypothetical schema-valid replacements, not recorded
customer updates. Candidate maps see only enrollment and the training slice.
Compare learned reservations with a public schema and a full raw basis. All
fitting/search is charged separately; real trace frequencies remain unknown.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import representation_oracle as oracle


def schema(name, dimension, prime):
    if name != "mushroom":
        return oracle.raw_map(dimension, prime)
    pivots, basis, anchor, start = [], [], 0, 0
    for categories in fixtures.MUSHROOM_CATEGORIES:
        anchor |= 1 << start
        for j in range(start + 1, start + len(categories)):
            row = [0] * dimension
            row[start], row[j] = prime - 1, 1
            pivots.append(j)
            basis.append(tuple(row))
        start += len(categories)
    mapping = affine.Plan(dimension, prime, anchor, tuple(pivots), tuple(basis))
    affine.validate(mapping)
    return mapping


def fits(mapping, words):
    """Independent batch reconstruction, plus individual API spot checks."""
    affine.validate(mapping)
    bits = np.asarray([[(row >> j) & 1 for j in range(mapping.dimension)] for row in words], dtype=np.int64)
    anchor = np.asarray([(mapping.anchor >> j) & 1 for j in range(mapping.dimension)], dtype=np.int64)
    delta = bits - anchor
    basis = np.asarray(mapping.basis, dtype=np.int64).reshape(mapping.rank, mapping.dimension)
    decoded = delta[:, mapping.pivots] @ basis % mapping.prime
    result = np.all(decoded == delta % mapping.prime, axis=1).tolist()
    for approved in (False, True):
        example = next((word for word, ok in zip(words, result, strict=True) if ok == approved), None)
        if example is None:
            continue
        try:
            affine.index_features(mapping, [example])
        except ValueError:
            assert not approved
        else:
            assert approved
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--prime", type=int, default=1153)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    cases = []
    for name in fixtures.SOURCES:
        data = fixtures.load(name, args.cache / fixtures.SOURCES[name]["member"])
        ids, heldout = fixtures.split(data, 3001)
        rows = tuple(data.rows[i] for i in ids)
        training = tuple(data.rows[i] for i in heldout[:32])
        evaluation = tuple(data.rows[i] for i in heldout[64:96])
        # These slices are disjoint for this reserve experiment. The public
        # fixtures were explored earlier; this is not a blinded paper test set.
        for block_size in (128, 512, len(rows)):
            blocks = [rows[i:i + block_size] for i in range(0, len(rows), block_size)]
            results = {name: [] for name in ("fit", "reserve4", "reserve16", "public_schema", "raw")}
            public, raw = schema(name, data.dimension, args.prime), oracle.raw_map(data.dimension, args.prime)
            exploration_start = time.perf_counter()
            for ordinal, block in enumerate(blocks):
                for mode, count in (("fit", 0), ("reserve4", 4), ("reserve16", 16), ("public_schema", None), ("raw", None)):
                    start = time.perf_counter()
                    mapping = (public if mode == "public_schema" else raw if mode == "raw"
                               else affine.prepare(list(block) + list(training[:count]), data.dimension, args.prime))
                    # Certify every enrolled row even for the public schema.
                    affine.index_features(mapping, list(block))
                    fitting_s = time.perf_counter() - start
                    start = time.perf_counter()
                    accepted = fits(mapping, evaluation)
                    evaluation_s = time.perf_counter() - start
                    results[mode].append({"block": ordinal, "rows": len(block), "rank": mapping.rank,
                                          "map_body_bytes": len(affine.canonical_map(mapping)),
                                          "fit_and_complete_certification_s": fitting_s,
                                          "heldout_span_check_s": evaluation_s, "accepted": sum(accepted), "tested": len(evaluation)})
            cases.append({"dataset": name, "dataset_sha256": data.sha256, "dimension": data.dimension,
                          "block_size": block_size, "blocks": len(blocks), "index_count": len(rows),
                          "training_source_ids": heldout[:32], "evaluation_source_ids": heldout[64:96],
                          "charged_catalog_exploration_s": time.perf_counter() - exploration_start,
                          "modes": {mode: {"blocks": values, "maximum_rank": max(x["rank"] for x in values),
                                            "sum_separate_query_ranks_model": sum(x["rank"] for x in values),
                                            "map_body_bytes_sum": sum(x["map_body_bytes"] for x in values),
                                            "fit_and_certification_s_sum": sum(x["fit_and_complete_certification_s"] for x in values),
                                            "uniform_source_ID_replacement_acceptance_fraction": sum(x["rows"] * x["accepted"] for x in values) / (len(rows) * len(evaluation))}
                                    for mode, values in results.items()}})
            print(name, block_size, {mode: round(result["uniform_source_ID_replacement_acceptance_fraction"], 4)
                                     for mode, result in cases[-1]["modes"].items()}, file=sys.stderr, flush=True)
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.with_suffix(".partial.json").write_text(json.dumps({"kind": "incomplete_span_reserve_screen", "cases": cases}, indent=2) + "\n")
    result = metadata([Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "affine_dictionary", "binary_fixtures", "representation_oracle"))])
    result.update(kind="heldout_source_row_reserve_span_screen", prime=args.prime, split_seed=3001, cases=cases,
                  scope="Exact finite-field certification and independent reconstruction. Hypothetical source-row replacements, "
                        "disjoint training/evaluation slices but previously explored public datasets. "
                        "No actual edit-frequency, HE latency/noise, layout optimization, online policy or novelty claim. "
                        "A public schema may reserve more dimensions while avoiding data-derived basis discovery; its columns/state still cost work.")
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cases": len(cases)}))


if __name__ == "__main__":
    main()
