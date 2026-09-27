#!/usr/bin/env python3
"""E19/E22 exact-bound models and a paired homemade encrypted refinement pilot.

Synthetic fixtures only. Full-size results count circuit operations, not time;
timings below are separately labeled tiny CPU reference runs. Adaptive accesses
and round counts are visible, with no remote authentication or private routing.
"""

# ruff: noqa: E402 -- standalone benchmark imports the repository sandbox.

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.syndrome_search_model import fixtures
from experiments.bfv_search_lab import adaptive_refinement as adaptive
from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import certified_lookup as certified
from experiments.bfv_search_lab import folded_filter as folded
from experiments.bfv_search_lab import linear_packing as packing
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import syndrome_oracle as syndrome


def timed(function, *args, **kwargs):
    begin = time.perf_counter()
    result = function(*args, **kwargs)
    return time.perf_counter() - begin, result


def structured_fixture(count, dimension, groups, flips, seed):
    """Deliberately compressible columns, with distinct latent words when possible."""
    rng = random.Random(seed)
    mapping = [(j % groups, rng.randrange(2)) for j in range(dimension)]
    rng.shuffle(mapping)
    if count <= 1 << groups:
        latent = set()
        while len(latent) < count:
            latent.add(rng.getrandbits(groups))
        words = sorted(latent)
        rng.shuffle(words)
    else:
        words = [rng.getrandbits(groups) for _ in range(count)]
    rows = [sum((((word >> g) & 1) ^ c) << j for j, (g, c) in enumerate(mapping)) for word in words]
    if flips:
        rows = [row ^ sum(1 << j for j in rng.sample(range(dimension), flips)) for row in rows]
    query = rows[min(17, count - 1)] ^ sum(1 << j for j in rng.sample(range(dimension), min(12, dimension // 8)))
    return query, rows


def refinement_model(lower, distances, features, dimension, n=16384):
    baseline = packing.packing_cost(dimension, len(lower), n)
    first = packing.packing_cost(features, len(lower), n)
    capacity = n // baseline.padded
    expected = tuple(sorted((d, i) for i, d in enumerate(distances))[:3])
    records = []
    for batch in (1, 8, 32):
        def fetch(tiles):
            return [(i, distances[i]) for tile in tiles
                    for i in range(tile * capacity, min((tile + 1) * capacity, len(lower)))]
        result = adaptive.refine(lower, dimension, capacity, fetch, batch_tiles=batch)
        assert result.top == expected
        second = [packing.packing_cost(dimension, len(r.tiles) * capacity, n) for r in result.rounds]
        records.append({
            "batch_tiles": batch, "fetched_tiles": result.fetched_tiles, "exact_rows": result.exact_rows,
            "dependent_rounds_including_filter": 1 + len(result.rounds),
            "total_ciphertext_products": first.input_tiles + result.fetched_tiles,
            "total_switches": first.switches + sum(c.switches for c in second),
            "response_ciphertexts": first.response_ciphertexts + sum(c.response_ciphertexts for c in second),
            "initial_threshold_unknown": result.rounds[0].upper_before is None,
            "stable_top3_exact": True,
        })
    return {"filter_cost": asdict(first), "original_scan_cost": asdict(baseline), "adaptive": records,
            "oracle_radius_for_selectivity_only": expected[-1][0],
            "oracle_survivors": sum(x <= expected[-1][0] for x in lower),
            "mean_bound": sum(lower) / len(lower)}


def lookup_models(args):
    codes = [syndrome.make_code(8, 4, 20260927 + i) for i in range(args.dimension // 8)]
    proposals = {}
    setup = {}
    for rank in (1, 3, 7):
        elapsed, models = timed(lambda rank=rank: [certified.svd_proposal(code, rank) for code in codes])
        assert all(certified.verify(model) for model in models)
        digest = hashlib.sha256(repr(models).encode()).hexdigest()
        proposals[rank] = models
        setup[str(rank)] = {"public_preprocessing_s": elapsed, "model_sha256": digest,
                            "all_query_bucket_pairs_certified": True,
                            "minimum_plaintext_modulus_exclusive": 2 * sum(m.numerator_bound for m in models),
                            "features_including_bias": sum(m.rank for m in models) + 1}
        print(f"Certified all public rank-{rank} lookup tables", file=sys.stderr, flush=True)
    records = []
    for seed in args.seeds:
        for name, query, rows in fixtures(args.count, args.dimension, seed):
            distances = [(query ^ row).bit_count() for row in rows]
            bounds = syndrome.vector_bounds(query, rows, codes)
            current = {"fixture": name, "seed": seed, "variants": {}}
            for rank, models in proposals.items():
                values = certified.lower_bounds(models, query, rows)
                assert all(a <= b for a, b in zip(values, bounds["conditioned"], strict=True))
                current["variants"][f"certified-rank-{rank}"] = refinement_model(
                    values, distances, sum(m.rank for m in models) + 1, args.dimension)
                mask = sum(((1 << rank) - 1) << start for start in range(0, args.dimension, 8))
                sampled = [((query ^ row) & mask).bit_count() for row in rows]
                current["variants"][f"partial-{rank}-of-8"] = refinement_model(
                    sampled, distances, rank * len(codes), args.dimension)
            radius = sorted(distances)[2]
            current["conditioned_oracle_survivors"] = sum(x <= radius for x in bounds["conditioned"])
            records.append(current)
            print(f"Lookup models: {name}, seed {seed}", file=sys.stderr, flush=True)
    return {"public_setup": setup, "records": records}


def fold_models(args):
    records = []
    groups = min(48, args.dimension // 4)
    for seed in args.seeds:
        rng = random.Random(seed)
        cases = [("uniform", rng.getrandbits(args.dimension),
                  [rng.getrandbits(args.dimension) for _ in range(args.count)], 0)]
        for flips in (0, 2, 8, 16):
            query, rows = structured_fixture(args.count, args.dimension, groups, flips, seed)
            cases.append((f"foldable-{flips}-flips", query, rows,
                          min(args.count // 2, 4 * flips * args.count // args.dimension)))
        for name, query, rows, threshold in cases:
            setup_s, plan = timed(folded.prepare, rows, args.dimension, threshold)
            distances = [(query ^ row).bit_count() for row in rows]
            bounds = folded.lower_bounds(plan, query, rows)
            assert all(a <= b for a, b in zip(bounds, distances, strict=True))
            measured = refinement_model(bounds, distances, plan.features, args.dimension)
            if not plan.max_error:
                assert bounds == distances
            measured.update({"fixture": name, "seed": seed, "unique_rows": len(set(rows)),
                             "groups": len(plan.representatives), "max_error": plan.max_error,
                             "column_threshold": threshold, "owner_preprocessing_s": setup_s,
                             "exact_without_refinement": plan.max_error == 0,
                             "no_refinement_cost_if_exact": asdict(packing.packing_cost(plan.features, len(rows)))
                             if plan.max_error == 0 else None})
            # Equal padded-budget coordinate sampling is a necessary cheap control.
            sample_width = min(args.dimension, measured["filter_cost"]["padded"])
            mask = (1 << sample_width) - 1
            measured["partial_coordinate_control"] = refinement_model(
                [((query ^ row) & mask).bit_count() for row in rows], distances, sample_width, args.dimension)
            records.append(measured)
            print(f"Fold model: {name}, seed {seed}, groups={len(plan.representatives)}, "
                  f"error<={plan.max_error}, survivors={measured['oracle_survivors']}", file=sys.stderr, flush=True)
    return records


def encrypted_pilot(repeats):
    n, dimension, count = 128, 32, 257
    query, rows = structured_fixture(count, dimension, 5, 1, 2804)
    setup_s, plan = timed(folded.prepare, rows, dimension, 4 * count // dimension)
    full = folded.FoldPlan(dimension, tuple(range(dimension)), tuple((j, 0) for j in range(dimension)), 0)
    pk, sk = bgv.key_gen(n, t=257, q_bits=180, eta=1)
    keys, indices, setups = {}, {}, {}
    for name, current in (("full", full), ("fold", plan)):
        qp, tiles, padded = folded.inputs(current, query, rows, n)
        key_s, keys[name] = timed(trace.evaluation_keys, pk, sk, padded, 12)
        index_s, indices[name] = timed(lambda tiles=tiles: [bgv.encrypt(p, pk) for p in tiles])
        setups[name] = {"key_s": key_s, "index_s": index_s, "ciphertexts": len(tiles), "padded": padded}
    capacity = n // keys["full"].padded
    samples = {"full-scan": [], "fold-then-tiles": []}
    warmup = {}
    rng = random.Random(2805)
    for repeat in range(repeats + 1):
        query = rows[rng.randrange(count)] ^ (1 << rng.randrange(dimension))
        expected = tuple(sorted(((query ^ row).bit_count(), i) for i, row in enumerate(rows))[:3])
        variants = list(samples)
        rng.shuffle(variants)
        for name in variants:
            start = time.perf_counter()
            encode_s, qp = timed(lambda query=query: folded.inputs(full, query, [], n)[0])
            query_s, full_query = timed(bgv.encrypt, qp, pk)
            server_s = decrypt_s = 0.0
            response_count = products = 0

            def evaluate(cipher, index, size, key):
                nonlocal server_s, decrypt_s, response_count, products
                elapsed, output = timed(butterfly.search, cipher, index, size, pk, key)
                server_s += elapsed
                elapsed, plain = timed(lambda: [bgv.decrypt(c, pk, sk) for c in output])
                decrypt_s += elapsed
                response_count += len(output)
                products += len(index)
                return packing.unpack(plain, size, key.padded, n, pk.t)

            if name == "full-scan":
                distances = folded.decode(full, evaluate(full_query, indices["full"], count, keys["full"]), pk.t)
                top = tuple(sorted((d, i) for i, d in enumerate(distances))[:3])
                rounds, exact_rows = 1, count
            else:
                elapsed, qp = timed(lambda query=query: folded.inputs(plan, query, [], n)[0])
                encode_s += elapsed
                elapsed, fold_query = timed(bgv.encrypt, qp, pk)
                query_s += elapsed
                lower = folded.decode(plan, evaluate(fold_query, indices["fold"], count, keys["fold"]), pk.t)

                def fetch(tile_ids, current_query=full_query):
                    dots = evaluate(current_query, [indices["full"][t] for t in tile_ids],
                                    len(tile_ids) * capacity, keys["full"])
                    result = []
                    for position, t in enumerate(tile_ids):
                        size = min(capacity, count - t * capacity)
                        values = folded.decode(full, dots[position * capacity:position * capacity + size], pk.t)
                        result.extend((t * capacity + j, d) for j, d in enumerate(values))
                    return result

                result = adaptive.refine(lower, dimension, capacity, fetch, batch_tiles=4)
                top, rounds, exact_rows = result.top, 1 + len(result.rounds), result.exact_rows
            total_s = time.perf_counter() - start
            assert top == expected
            sample = {"local_total_s": total_s, "server_s": server_s, "decrypt_s": decrypt_s,
                      "query_encrypt_s": query_s, "encode_s": encode_s, "dependent_rounds": rounds,
                      "response_ciphertexts": response_count, "ciphertext_products": products, "exact_rows": exact_rows}
            if repeat:
                samples[name].append(sample)
            else:
                warmup[name] = sample
        print(f"Encrypted local refinement round {repeat}/{repeats}", file=sys.stderr, flush=True)
    return {"n": n, "dimension": dimension, "count": count, "t": pk.t, "q_bits": pk.q.bit_length(),
            "eta": pk.eta, "digit_bits": 12, "groups": len(plan.representatives), "max_error": plan.max_error,
            "fold_setup_s": setup_s, "setup": setups, "warmup": warmup, "samples": samples,
            "medians": {name: {key: statistics.median(r[key] for r in values) for key in values[0]}
                        for name, values in samples.items()}, "all_stable_top3_exact": True,
            "security_parameters_reviewed": False, "private_routing_implemented": False}


def provenance():
    paths = [Path(__file__), ROOT / "benchmarks/syndrome_search_model.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "adaptive_refinement", "linear_packing", "certified_lookup", "folded_filter", "syndrome_oracle",
        "shallow_bgv", "trace_bgv", "butterfly_bgv"))
    return {"git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
            "python": platform.python_version(), "numpy": np.__version__}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=8192)
    parser.add_argument("--dimension", type=int, default=512)
    parser.add_argument("--seeds", type=int, nargs="+", default=[2701, 2702, 2703])
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if not 3 <= args.count <= 32768 or not 64 <= args.dimension <= 512 or args.dimension % 8 or args.repeats < 1:
        parser.error("Require count 3..32768, dimension 64..512 divisible by 8, repeats >= 1")
    result = {"kind": "certified_filter_models_and_toy_encrypted_refinement", "utc": datetime.now(UTC).isoformat(),
              "command": sys.argv, **provenance(),
              "notes": "Full-size results are circuit COUNTS, not timings. SVD proposes; exact integers certify. "
                       "Synthetic favorable/adverse fixtures. Threshold discovery and whole-tile reranking are charged. "
                       "Traffic padding, authentication, private routing, encrypted-index updates and real data remain open. "
                       "Encrypted timings are a tiny local CPU reference, not optimized CUDA or production results.",
              "lookup": lookup_models(args), "fold": fold_models(args), "encrypted_pilot": encrypted_pilot(args.repeats)}
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
