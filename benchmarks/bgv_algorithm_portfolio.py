#!/usr/bin/env python3
"""E07 encrypted reference and E10 PLAINTEXT bound-quality experiments.

Neither experiment is a GPU or end-to-end performance claim. E07 compares two
switch schedules with the same encrypted features. E10 declares all access
leakage and reports exact-score counts; encrypted filtering is not implemented.
"""

import argparse
import hashlib
import json
from pathlib import Path
import random
import sys

from coefficient_search_lab import REPO_ROOT, timed

sys.path.insert(0, str(REPO_ROOT))
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, feature_major_bgv as feature
from experiments.bfv_search_lab.filter_oracle import select


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    rng = random.Random(20260925)
    encrypted = []
    for dimension in (8, 32):
        n, count = 256, 513
        pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
        keys = trace.evaluation_keys(pk, sk, 1)
        query = [rng.randrange(2) for _ in range(dimension)]
        rows = [[rng.randrange(2) for _ in query] for _ in range(count)]
        query_plain, index_plain = feature.encode(query, rows, n)
        setup_s, index = timed(lambda pk=pk, index_plain=index_plain: [[bgv.encrypt(p, pk) for p in group] for group in index_plain])
        query_s, queries = timed(lambda pk=pk, query_plain=query_plain: [bgv.encrypt(p, pk) for p in query_plain])
        expected = [sum(a != b for a, b in zip(row, query, strict=True)) for row in rows]
        samples, warmup = {"eager": [], "delayed": []}, {}
        for repeat in range(6):
            order = list(samples)
            rng.shuffle(order)
            for name in order:
                elapsed, response = timed(feature.search, queries, index, pk, keys, delayed=name == "delayed")
                assert feature.decode([bgv.decrypt(c, pk, sk) for c in response], count, dimension, pk) == expected
                reduced = [compact.compact(c, pk, 25) for c in response]
                assert feature.decode([compact.decrypt(c, pk, sk) for c in reduced], count, dimension, pk) == expected
                if repeat:
                    samples[name].append(elapsed)
                else:
                    warmup[name] = elapsed
        encrypted.append({"n": n, "dimension": dimension, "num_vectors": count, "q_hex": format(pk.q, "x"),
                          "costs": feature.costs(count, dimension, n), "index_encrypt_s": setup_s, "query_encrypt_s": query_s,
                          "server_seconds": samples, "warmup_seconds": warmup, "all_distances_correct": True})
    filters = []
    for kind in ("uniform", "clustered_3pct_flips"):
        count, dimension = 8192, 512
        query = rng.getrandbits(dimension)
        centers = [query] + [rng.getrandbits(dimension) for _ in range(15)]
        rows = []
        for i in range(count):
            if kind == "uniform":
                rows.append(rng.getrandbits(dimension))
            else:
                flips = sum((rng.random() < 0.03) << bit for bit in range(dimension))
                rows.append(centers[i % len(centers)] ^ flips)
        expected = tuple(sorted(((i, (row ^ query).bit_count()) for i, row in enumerate(rows)), key=lambda p: (p[1], p[0]))[:3])
        for block in (16, 32, 64, 128):
            result = select(rows, query, dimension, block_bits=block)
            assert result.top == expected
            filters.append({"dataset": kind, "num_vectors": count, "dimension": dimension, "block_bits": block,
                            "exact_evaluations": result.exact_evaluations, "weight_comparisons": result.weight_comparisons,
                            "exact_top3": True})
    files = [Path(__file__).resolve(), REPO_ROOT / "experiments/bfv_search_lab/feature_major_bgv.py",
             REPO_ROOT / "experiments/bfv_search_lab/filter_oracle.py", REPO_ROOT / "experiments/bfv_search_lab/shallow_bgv.py",
             REPO_ROOT / "experiments/bfv_search_lab/trace_bgv.py"]
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps({"kind": "bgv_algorithm_reference_portfolio", "scope": __doc__,
                                       "encrypted_feature_major": encrypted, "plaintext_filter": filters,
                                       "large_feature_major_cost_model": feature.costs(8192, 512, 16384),
                                       "sha256": {str(p.relative_to(REPO_ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}}, indent=2) + "\n")
    print(args.json_out)


if __name__ == "__main__":
    main()
