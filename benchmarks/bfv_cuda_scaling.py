#!/usr/bin/env python3
"""Paired CUDA ablations, index scaling, and concurrent-query throughput.

Generate one fresh encrypted corpus. Compare the retained original CUDA path,
each optimization, and a prepared GPU index on identical inputs. CPU evaluation
and owner decryption provide correctness oracles outside GPU timings. No network
or attestation is included; one warmup precedes every set of measured samples.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import gc
from functools import partial
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
from datetime import UTC, datetime
from typing import Any

import gmpy2
import numpy as np

from bfv_client_matrix import REPO_ROOT, make_data
from cuhepy.bfv.cuda import BFVCudaServer
from cuhepy.bfv.rns import BFVRNSArithmetic
from cuhepy.hamming.bfv import BFVClient


def timed(fn):
    start = time.perf_counter()
    result = fn()
    return time.perf_counter() - start, result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", default="1024,8192,32768")
    parser.add_argument("--poly-modulus-degree", type=int, default=16384)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--batch-tiles", type=int, default=32)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seed", type=int, default=913)
    parser.add_argument("--concurrency-vectors", type=int, default=8192)
    parser.add_argument("--workers", default="1,2,4")
    parser.add_argument("--queries-per-wave", type=int, default=8)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    sizes = sorted(set(int(s) for s in args.sizes.split(",")))
    workers = sorted(set(int(s) for s in args.workers.split(",")))
    if (
        not sizes
        or sizes[0] < 1
        or args.repeats < 1
        or not workers
        or workers[0] < 1
        or workers[-1] > 8
        or args.queries_per_wave < workers[-1]
        or not 1 <= args.batch_tiles <= 256
        or (args.concurrency_vectors and args.concurrency_vectors not in sizes)
    ):
        parser.error("Invalid sizes, repeats, batch limit, concurrency size or workers")

    def progress(message):
        print(message, file=sys.stderr, flush=True)

    def command(parts):
        return subprocess.run(
            parts, cwd=REPO_ROOT, text=True, capture_output=True, check=True
        ).stdout.strip()

    progress("Generating one fresh public-key context and plaintext corpus")
    vectors, query, expected = make_data(sizes[-1], args.embed_len, args.seed)
    setup: dict[str, float] = {}
    setup["key_generation_s"], owner = timed(
        lambda: BFVClient(
            args.embed_len,
            args.poly_modulus_degree,
            65537,
            180,
            30,
            rns_modulus=True,
            server_backend="residue",
        )
    )
    capacity = owner.vectors_per_ciphertext
    index = []
    started = time.perf_counter()
    for at in range(0, len(vectors), capacity * 32):
        index.extend(owner.encrypt_vec_packed(vectors[at : at + capacity * 32]))
        progress(f"Encrypted {min(at + capacity * 32, len(vectors))}/{len(vectors)} vectors")
    setup["index_encrypt_s"] = time.perf_counter() - started
    setup["query_encrypt_s"], encrypted_query = timed(lambda: owner.encrypt_vec_one(query))
    setup["cpu_plan_s"], _ = timed(owner._native)
    arithmetic = BFVRNSArithmetic(owner._pk(), fast=True, residue=True)
    plans = {}
    for label, level in (
        ("original_cuda", 0),
        ("fused_ntt", 1),
        ("gpu_decode", 2),
        ("shared_keys", 3),
    ):
        setup[f"{label}_plan_s"], plans[label] = timed(
            partial(
                BFVCudaServer,
                arithmetic,
                owner.padded_embed_len,
                owner.response_modulus_bits,
                kernel_level=level,
                batch_tiles=32 if level == 0 else args.batch_tiles,
            )
        )

    output: dict[str, Any] = {
        "environment": {
            "utc": datetime.now(UTC).isoformat(),
            "revision": command(["git", "rev-parse", "HEAD"]),
            "working_tree_dirty": bool(command(["git", "status", "--porcelain"])),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "gmp": gmpy2.mp_version(),
            "gmpy2": gmpy2.version(),
            "gpu": command(
                [
                    "nvidia-smi",
                    "--query-gpu=name,memory.total,driver_version",
                    "--format=csv,noheader",
                ]
            ),
            "nvcc": command(["nvcc", "--version"]),
        },
        "command": sys.argv,
        "config": json.loads(owner.stringify_config()),
        "seed": args.seed,
        "batch_tiles": args.batch_tiles,
        "setup": setup,
        "notes": (
            "One fresh corpus, identical keys/query/index prefix per comparison; fresh encryption for every packed tile; larger indexes do not repeat ciphertexts. "
            "All plans prepared before timing; one warmup then measured repeats in alternating order. "
            "Raw searches include index upload, validation, allocations, query/response conversion and compaction. "
            "Prepared searches exclude the separately measured one-time index preparation. Neither includes network or owner crypto. "
            "CPU reference times are one warm-plan sample per size, not medians. Correctness checks and synchronized diagnostic profiles are untimed. "
            "Concurrency rows measure a wave of distinct encrypted queries, including task scheduling, not per-query latency."
        ),
        "sizes": [],
        "concurrency": [],
        "profiles": {},
    }
    references = {}
    gpu = plans["shared_keys"]
    for count in sizes:
        tiles = index[: (count + capacity - 1) // capacity]
        progress(f"CPU reference: {count} vectors")
        cpu_s, reference = timed(
            partial(owner.encode_hamming_server_packed, encrypted_query, tiles, count)
        )
        assert owner.decode_hamming_client_packed(reference, count) == expected[:count]
        references[count] = reference
        prepare_s, prepared = timed(partial(gpu.prepare_index, tiles, count))
        calls = {
            label: partial(plan.search, encrypted_query, tiles, count)
            for label, plan in plans.items()
        }
        calls["prepared_index"] = partial(gpu.search_prepared, encrypted_query, prepared)
        timings = {label: [] for label in calls}
        for repeat in range(args.repeats + 1):
            for label in calls if repeat % 2 == 0 else reversed(calls):
                elapsed, result = timed(calls[label])
                assert result == reference, f"Ciphertexts differ: {count}, {label}"
                assert owner.decode_hamming_client_packed(result, count) == expected[:count]
                if repeat:
                    timings[label].append(elapsed)
                progress(f"{count}: {label} {'warmup' if repeat == 0 else repeat}: {elapsed:.6f} s")
        medians = {label: statistics.median(values) for label, values in timings.items()}
        output["sizes"].append(
            {
                "vectors": count,
                "cpu_reference_s": cpu_s,
                "index_prepare_s": prepare_s,
                "resident_index_bytes": prepared.device_bytes,
                "samples_s": timings,
                "warm_medians_s": medians,
                "speedup_over_original_cuda": {
                    k: medians["original_cuda"] / v for k, v in medians.items()
                },
                "vectors_per_second": {k: count / v for k, v in medians.items()},
                "response_ciphertexts": len(reference),
                "identical_ciphertexts": True,
                "all_distances_correct": True,
            }
        )
        if count == args.concurrency_vectors:
            for label in ("original_cuda", "shared_keys", "prepared_index"):
                profile = {}
                result = (
                    gpu.search_prepared(encrypted_query, prepared, profile=profile)
                    if label == "prepared_index"
                    else plans[label].search(encrypted_query, tiles, count, profile=profile)
                )
                assert result == reference
                output["profiles"][label] = profile
        del prepared, calls
        gc.collect()
        args.json_out.write_text(json.dumps(output, indent=2) + "\n")

    if args.concurrency_vectors:
        count = args.concurrency_vectors
        tiles = index[: (count + capacity - 1) // capacity]
        plain = np.asarray(vectors[:count], dtype=np.uint8)
        queries = [owner.encrypt_vec_one(vectors[i % count]) for i in range(args.queries_per_wave)]
        distances = [
            np.count_nonzero(plain != plain[i % count], axis=1).tolist()
            for i in range(len(queries))
        ]
        shared = gpu.prepare_index(tiles, count)
        for kind in ("shared_plan", "independent_plans"):
            for concurrency in workers:
                instances = (
                    [gpu] * concurrency
                    if kind == "shared_plan"
                    else [
                        BFVCudaServer(
                            arithmetic,
                            owner.padded_embed_len,
                            owner.response_modulus_bits,
                            batch_tiles=args.batch_tiles,
                        )
                        for _ in range(concurrency)
                    ]
                )
                snapshots = (
                    [shared] * concurrency
                    if kind == "shared_plan"
                    else [s.prepare_index(tiles, count) for s in instances]
                )
                chunks = [
                    list(range(worker, len(queries), concurrency)) for worker in range(concurrency)
                ]

                def run_worker(worker, instances=instances, snapshots=snapshots, chunks=chunks):
                    return [
                        (i, instances[worker].search_prepared(queries[i], snapshots[worker]))
                        for i in chunks[worker]
                    ]

                samples = []
                with ThreadPoolExecutor(max_workers=concurrency) as pool:
                    for repeat in range(args.repeats + 1):
                        elapsed, outputs = timed(
                            lambda pool=pool, run_worker=run_worker, concurrency=concurrency: list(
                                pool.map(run_worker, range(concurrency))
                            )
                        )
                        for group in outputs:
                            for i, response in group:
                                assert (
                                    owner.decode_hamming_client_packed(response, count)
                                    == distances[i]
                                )
                        if repeat:
                            samples.append(elapsed)
                        progress(
                            f"{kind}, {concurrency} workers: {elapsed:.6f} s/{len(queries)} queries"
                        )
                median = statistics.median(samples)
                output["concurrency"].append(
                    {
                        "mode": kind,
                        "workers": concurrency,
                        "queries_per_wave": len(queries),
                        "vectors_per_query": count,
                        "samples_s": samples,
                        "median_wave_s": median,
                        "queries_per_second": len(queries) / median,
                        "vectors_per_second": len(queries) * count / median,
                        "all_distances_correct": True,
                    }
                )
                del run_worker, snapshots, instances
                gc.collect()
                args.json_out.write_text(json.dumps(output, indent=2) + "\n")

    paths = [Path(__file__).resolve(), REPO_ROOT / "benchmarks/bfv_client_matrix.py"]
    for part in ("src/cuhepy/bfv", "src/cuhepy/hamming"):
        paths.extend(
            p
            for p in (REPO_ROOT / part).rglob("*")
            if p.is_file() and p.suffix in (".py", ".cpp", ".h", ".cuh", ".cu", ".so")
        )
    output["source_sha256"] = {
        str(p.relative_to(REPO_ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths
    }
    args.json_out.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
