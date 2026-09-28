#!/usr/bin/env python3
"""E28/E17 noisy homemade pilots and structural count models.

Small Python timings diagnose the oracle only. They are not native/GPU
benchmarks, secure parameter measurements or a speedup over existing BGV.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import itertools
import json
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.bfv_search_lab import matrix_bgv_oracle as matrix
from experiments.bfv_search_lab import matrix_search_cost as counts

MODES = ("right", "right_symmetric", "left_independent", "left_transpose", "gadget_query")


def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def timed(fn, *args, **kwargs):
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    return time.perf_counter() - start, result


def gadget_digest(packet):
    return digest(packet.rows)


def pilot(n, rank, *, seed, folded=False):
    ctx, rng = matrix.Context(n=n, rank=rank), random.Random(seed)
    if folded and rank != 2:
        raise ValueError("The declared private-map fixture has rank two")
    dimension = 4 if folded else rank
    coordinates = list(range(1 << rank))
    if folded:
        words = [((u & 1) * 5) | (((u >> 1) & 1) << 1) | ((1 - ((u >> 1) & 1)) << 3) for u in coordinates]
    else:
        words = coordinates.copy()
    # Duplicate, non-monotone stable IDs, and a partial final plaintext tile.
    words += words[:3]
    coordinates += coordinates[:3]
    ids = list(range(100, 100 + len(words)))
    rng.shuffle(ids)
    queries = list(range(1 << dimension))
    secret = matrix.sample_matrix(ctx, rank, rank, rng, small=True)
    other = matrix.sample_matrix(ctx, rank, rank, rng, small=True)
    out_secret = matrix.sample_matrix(ctx, 1, rank, rng, small=True)[0]
    plaintext = tuple(tuple(matrix.simd_encode(ctx, tuple((coordinates[i] >> j) & 1 if i < len(words) else 0
                                                         for i in range(start, start + n)))
                            for j in range(rank)) for start in range(0, len(words), n))
    index_s, index = timed(matrix.encrypt, ctx, secret, plaintext, rng)
    zero_right = matrix.MatrixCipher(tuple((ctx.zero,) * rank for _ in range(rank)),
                                     tuple((ctx.zero,) * rank for _ in range(rank)), "right", 0)
    zero_left = matrix.MatrixCipher(tuple((ctx.zero,) for _ in range(rank)),
                                    tuple((ctx.zero,) for _ in range(rank)), "left", 0)
    keys, setup = {}, {}
    for mode in MODES[:-1]:
        forms = matrix.product_forms(ctx, index, zero_right if mode.startswith("right") else zero_left,
                                     mode=mode, columns=(0,))
        sources = {s for row in forms for form in row for s, _ in form.terms}
        values = matrix.source_values(ctx, secret, sources, other)
        setup_s, keys[mode] = timed(matrix.mask_sources, ctx, values, out_secret, rng)
        model = counts.cost(mode, rank, effective_dimension=rank * n, rows=len(plaintext),
                            q_bits=61, digit_bits=8, t=ctx.t, eta=ctx.eta)
        assert keys[mode].coefficient_bytes == model.offline_gadget_bytes
        setup[mode] = {"owner_switch_key_s": setup_s, "offline_gadget_bytes": keys[mode].coefficient_bytes,
                       "distinct_sources": len(sources), "gadget_sha256": gadget_digest(keys[mode])}
    samples = {mode: [] for mode in MODES}
    output_digests = {mode: [] for mode in MODES}
    for query in queries:
        expected = [(w ^ query).bit_count() for w in words]
        expected_top = sorted(zip(expected, ids, strict=True))[:3]
        raw = [1 - 2 * ((query >> j) & 1) for j in range(dimension)]
        weights, offset = ((raw[0] + raw[2], raw[1] - raw[3]), query.bit_count() + raw[3]) if folded else (tuple(raw), query.bit_count())
        polys = tuple(ctx.constant(w) for w in weights)
        order = list(MODES)
        rng.shuffle(order)
        for mode in order:
            if mode == "gadget_query":
                owner_s, key = timed(matrix.gadget_query, ctx, secret, polys, out_secret, rng)
                prepare_s, forms = timed(matrix.gadget_forms, ctx, index, max(map(abs, weights)))
                query_bytes = key.coefficient_bytes
            else:
                width = rank if mode.startswith("right") else 1
                message = tuple((p,) + (ctx.zero,) * (width - 1) for p in polys)
                query_secret = secret if mode.startswith("right") else (other if mode == "left_independent" else matrix.transpose(secret))
                owner_s, encrypted_query = timed(matrix.encrypt, ctx, query_secret, message, rng,
                                                  side="right" if mode.startswith("right") else "left")
                prepare_s, nested = timed(matrix.product_forms, ctx, index, encrypted_query, mode=mode, columns=(0,))
                forms, key = tuple(row[0] for row in nested), keys[mode]
                query_bytes = counts.cost(mode, rank, effective_dimension=rank * n,
                                          q_bits=61, digit_bits=8).query_coefficient_bytes
            evaluate_s, results = timed(lambda forms=forms, key=key: [matrix.switch(ctx, form, key) for form in forms])
            decrypt_s, decoded = timed(lambda results=results: [matrix.simd_decode(ctx, matrix.decrypt(ctx, c, out_secret)) for c in results])
            actual = [(x + offset) % ctx.t for row in decoded for x in row][:len(words)]
            assert actual == expected and sorted(zip(actual, ids, strict=True))[:3] == expected_top
            output_digests[mode].append((query, digest(actual)))
            samples[mode].append({"query_id": query, "owner_query_s": owner_s, "form_s": prepare_s,
                                  "switch_s": evaluate_s, "decrypt_decode_s": decrypt_s,
                                  "query_coefficient_bytes": query_bytes,
                                  "response_coefficient_bytes": len(results) * (rank + 1) * n * 8,
                                  "max_output_phase_bound": max(c.phase_bound for c in results),
                                  "all_distances_and_stable_top3_exact": True})
    for mode in MODES:
        output_digests[mode].sort()
        assert output_digests[mode] == output_digests["right"]
    return {"parameters": asdict(ctx), "seed": seed, "dimension": dimension, "count": len(words),
            "distinct_rows": len(set(words)), "queries": len(queries), "private_map_fixture": folded,
            "input_sha256": digest((words, ids)), "index_encrypt_s": index_s, "setup": setup,
            "results_sha256": digest(output_digests["right"]), "samples": samples,
            "median_oracle_ms": {mode: {field: 1000 * statistics.median(x[field] for x in values)
                                       for field in ("owner_query_s", "form_s", "switch_s", "decrypt_decode_s")}
                                 for mode, values in samples.items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    pilots = []
    for n, rank, folded in ((2, 1, False), (4, 2, False), (4, 4, False), (8, 2, True)):
        print(f"toy pilot n={n} rank={rank} private_map={folded}", file=sys.stderr, flush=True)
        pilots.append(pilot(n, rank, seed=5100 + n + rank, folded=folded))
    models = []
    for rank in (1, 2, 4, 8, 16, 32, 64, 128):
        for columns in sorted({1, min(4, rank), rank}):
            for mode in MODES:
                # Larger plaintext field supports full SIMD in every modeled
                # ring; this differs from the earlier t=1153 native benchmark.
                entry = asdict(counts.cost(mode, rank, columns=columns, rows=1, t=65537, eta=21))
                entry["published_naive_full_matrix_relin_body_bytes"] = counts.published_naive_relinearization_body(rank, 16384 // rank)
                models.append(entry)
    paths = ["experiments/bfv_search_lab/matrix_bgv_oracle.py", "experiments/bfv_search_lab/matrix_search_cost.py",
             "experiments/bfv_search_lab/test_matrix_bgv_oracle.py", "benchmarks/matrix_arithmetic_lab.py"]
    report = {"experiment": "E28 matrix orientation and E17 owner-prepared gadget queries",
              "scope": "tiny noisy encryption and exact count models; no secure native latency or production scheme",
              "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "python": sys.version, "platform": platform.platform(),
              "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths},
              "sources": ["https://eprint.iacr.org/2025/972", "https://eprint.iacr.org/2025/448",
                          "https://arxiv.org/html/2503.16080v1"],
              "pilots": pilots, "models": models,
              "model_profile": {"effective_dimension": 16384, "q_bits": 120, "digit_bits": 30,
                                "t": 65537, "eta": 21, "security_equivalence_established": False,
                                "terminal_compaction_or_cross_row_packing": False},
              "support_class_control": counts.lookup_rank_bound(128, tuple(tuple(range(i, i + 8)) for i in range(0, 128, 8)))}
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "encrypted_searches": sum(p["queries"] * len(MODES) for p in pilots),
                      "models": len(models), "all_distances_and_stable_top3_exact": True}))


if __name__ == "__main__":
    main()
