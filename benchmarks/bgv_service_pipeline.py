#!/usr/bin/env python3
"""Paired BGV service experiments. Synthetic trusted fixtures, no remote service.

Fresh query randomness; common index, keys and ciphertexts across variants.
Workspace construction is setup. Per-request evaluation includes Python/native
conversion and exact CPU compaction. Profile runs are NOT performance results.
No keys, ciphertexts, seeds or plaintext embeddings are written to artifacts.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import ctypes
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import platform
import queue
import random
import statistics
import subprocess
import sys
import time

from bfv_client_matrix import REPO_ROOT, make_data
from coefficient_search_lab import Case, timed

sys.path.insert(0, str(REPO_ROOT))
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, owner_bgv
from experiments.bfv_search_lab.native_bgv import NativeServer


def provenance():
    lab = REPO_ROOT / "experiments/bfv_search_lab"
    paths = [Path(__file__), REPO_ROOT / "benchmarks/bfv_client_matrix.py", REPO_ROOT / "benchmarks/coefficient_search_lab.py"]
    for directory in (lab, lab / "_native", lab / "_owner", REPO_ROOT / "src/cuhepy/bfv/_cpu_ext", REPO_ROOT / "src/cuhepy/bfv/_gpu_ext"):
        for pattern in ("*.py", "*.h", "*.cuh", "*.cpp", "*.cu", "*.pyi", "Makefile", "*.so"):
            paths.extend(sorted(directory.glob(pattern)))
    return {str(p.resolve().relative_to(REPO_ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def summary(samples):
    return {name: {"median": statistics.median(values), "minimum": min(values), "maximum": max(values),
                   "p95_nearest_rank": sorted(values)[max(0, (95 * len(values) + 99) // 100 - 1)], "samples": values}
            for name, values in samples.items()}


def prepare(args):
    setup = {}
    print("Preparing common keys and encrypted index", file=sys.stderr, flush=True)
    setup["keygen_s"], case = timed(Case, "bgv", args.ring_degree, 1031, 120, rns_modulus=True)
    rows, query, _ = make_data(args.num_vectors, args.embed_len, 1701)
    padded = 1 << (len(query) - 1).bit_length()
    setup["evaluation_keys_s"], keys = timed(trace.evaluation_keys, case.pk, case.sk, padded)
    _, tiles = bgv.coefficient_inputs(query, rows, case.n)
    setup["index_encrypt_s"], index = timed(lambda: [case.encrypt(p) for p in tiles])
    setup["server_create_s"], server = timed(NativeServer, case.pk, keys, residue=True, device="cuda", cuda_level=4)
    setup["index_prepare_s"], prepared = timed(server.prepare_index, index, len(rows))
    setup["owner_create_s"], client = timed(owner_bgv.OwnerClient, case.pk, case.sk, native=True, rns=args.owner_rns)
    setup["owner_terminal_prepare_s"] = timed(client.prepare_terminal, args.terminal_bits)[0]
    return case, rows, server, prepared, client, setup


def workspace_experiment(args, case, rows, server, index, client, setup):
    variants, skipped = {}, {}
    pools = {}
    samples, completions, first, warmup = {}, {}, {}, {}
    for workers in (1, 2, 4):
        memory = server.batch_workspace_bytes(index, workers)
        if memory > (4 << 30):
            skipped[str(workers)] = {"reason": "4 GiB coefficient workspace budget", "bytes": memory}
            continue
        pools[workers] = ThreadPoolExecutor(max_workers=workers)
        for persistent in (False, True):
            name = f"{'persistent' if persistent else 'transient'}-{workers}"
            variants[name] = (workers, persistent)
            samples[name], completions[name], first[name] = [], [], []
        start = time.perf_counter()
        leases = [server.prepare_workspace(index) for _ in range(workers)]
        setup[f"workspace_{workers}_create_s"] = time.perf_counter() - start
        setup[f"workspace_{workers}_bytes"] = memory
        # Retaining 1+2+4 leases would defeat the global coefficient budget.
        for lease in leases:
            lease.close()
    rng = random.Random(20260925)
    ciphertext_checks = distance_checks = 0
    try:
        for repeat in range(args.repeats + 1):
            queries, expected = [], []
            for _ in range(args.requests):
                plain = [rng.randrange(2) for _ in range(args.embed_len)]
                packet = client.encrypt(bgv.coefficient_inputs(plain, [], case.n)[0])
                queries.append(owner_bgv.expand(packet, case.pk))
                expected.append(tuple(sum(a != b for a, b in zip(row, plain, strict=True)) for row in rows))
            baseline = None
            order = list(variants)
            rng.shuffle(order)
            for name in order:
                workers, persistent = variants[name]
                available = queue.SimpleQueue()
                group = [server.prepare_workspace(index) for _ in range(workers)] if persistent else []
                for lease in group:
                    available.put(lease)
                begin = time.perf_counter()

                def one(i, persistent=persistent, available=available, queries=queries, begin=begin):
                    if persistent:
                        lease = available.get()
                        try:
                            value = lease.search_compact(queries[i], bits=args.terminal_bits)
                        finally:
                            available.put(lease)
                    else:
                        value = server.search_compact(queries[i], index, bits=args.terminal_bits)
                    return i, value, time.perf_counter() - begin

                outputs, offsets = [None] * len(queries), []
                try:
                    jobs = [pools[workers].submit(one, i) for i in range(len(queries))]
                    for future in as_completed(jobs):
                        i, value, ended = future.result()
                        outputs[i] = value
                        offsets.append(ended)
                    elapsed = time.perf_counter() - begin
                finally:
                    for lease in group:
                        lease.close()
                if baseline is None:
                    baseline = outputs
                else:
                    assert outputs == baseline
                    ciphertext_checks += sum(len(r) for r in outputs)
                if repeat:
                    samples[name].append(elapsed)
                    completions[name].extend(offsets)
                    first[name].append(min(offsets))
                else:
                    warmup[name] = elapsed
                print(f"{name} round {repeat}: {elapsed:.5f}s; first {min(offsets):.5f}s", file=sys.stderr, flush=True)
            for response, distances in zip(baseline, expected, strict=True):
                result = client.finish(response, len(rows), args.embed_len)
                assert result.distances == distances
                assert result.top == tuple(sorted(enumerate(distances), key=lambda x: (x[1], x[0]))[:3])
                distance_checks += len(rows)
    finally:
        for pool in pools.values():
            pool.shutdown(wait=True)
    return {"batch_seconds": summary(samples), "completion_seconds": summary(completions),
            "first_response_seconds": summary(first), "warmup_batch_seconds": warmup,
            "skipped": skipped, "exact_ciphertext_checks": ciphertext_checks, "distance_checks": distance_checks,
            "scope": "Ready expanded queries; conversions, GPU, CPU compaction included. No network, arrival queue, framing or owner work."}


def profile_experiment(args, case, server, index, client):
    plain = [i % 2 for i in range(args.embed_len)]
    query = owner_bgv.expand(client.encrypt(bgv.coefficient_inputs(plain, [], case.n)[0]), case.pk)
    runtime = ctypes.CDLL("libcudart.so.12")
    nvtx = ctypes.CDLL("libnvToolsExt.so.1")
    with server.prepare_workspace(index) as workspace:
        reference = server.search_compact(query, index, bits=args.terminal_bits)
        assert workspace.search_compact(query, bits=args.terminal_bits) == reference
        if runtime.cudaProfilerStart() != 0:
            raise RuntimeError("Could not start CUDA profiling capture")
        try:
            for _ in range(args.repeats):
                for name, function in ((b"transient", lambda: server.search_compact(query, index, bits=args.terminal_bits)),
                                       (b"persistent", lambda: workspace.search_compact(query, bits=args.terminal_bits))):
                    nvtx.nvtxRangePushA(name)
                    try:
                        result = function()
                    finally:
                        nvtx.nvtxRangePop()
                    assert result == reference
        finally:
            if runtime.cudaProfilerStop() != 0:
                raise RuntimeError("Could not stop CUDA profiling capture")
    return {"profile_only": True, "scope": "NVTX ranges include full Python/public evaluator boundary; no private operations in capture."}


def owner_experiment(args, case, rows, server, index, client, setup):
    setup["rns_owner_create_s"], rns = timed(owner_bgv.OwnerClient, case.pk, case.sk, native=True, rns=True)
    setup["rns_owner_terminal_prepare_s"] = timed(rns.prepare_terminal, args.terminal_bits)[0]
    clients = {"gmp": client, "rns": rns}
    encrypt, finish, warmup = {name: [] for name in clients}, {name: [] for name in clients}, {}
    rng = random.Random(20260925)
    try:
        with server.prepare_workspace(index) as workspace:
            for repeat in range(args.repeats + 1):
                plain = [rng.randrange(2) for _ in range(args.embed_len)]
                encoded = bgv.coefficient_inputs(plain, [], case.n)[0]
                response = workspace.search_compact(owner_bgv.expand(client.encrypt(encoded), case.pk), bits=args.terminal_bits)
                expected = tuple(sum(a != b for a, b in zip(row, plain, strict=True)) for row in rows)
                order = list(clients)
                rng.shuffle(order)
                for name in order:
                    encrypt_s, packet = timed(clients[name].encrypt, encoded)
                    finish_s, result = timed(clients[name].finish, response, len(rows), args.embed_len)
                    assert result.distances == expected
                    assert result.top == tuple(sorted(enumerate(expected), key=lambda x: (x[1], x[0]))[:3])
                    expanded = owner_bgv.expand(packet, case.pk)
                    assert client.decrypt_compact(compact.compact(expanded, case.pk, args.terminal_bits)) == [v % case.t for v in encoded]
                    if repeat:
                        encrypt[name].append(encrypt_s)
                        finish[name].append(finish_s)
                    else:
                        warmup[name] = {"encrypt_s": encrypt_s, "finish_s": finish_s}
    finally:
        rns.close()
    return {"encrypt_seconds": summary(encrypt), "finish_seconds": summary(finish), "warmup": warmup,
            "all_encryption_distances_and_top3_correct": True,
            "scope": "Fresh OS randomness included. Same parameters/index/response; variant order shuffled. Both CRT/export paths remain variable-time."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("workspace", "profile", "transport", "owner"), default="workspace")
    parser.add_argument("--num-vectors", type=int, default=8192)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--terminal-bits", type=int, default=25)
    parser.add_argument("--owner-rns", action="store_true", help="Opt in to the new private RNS experiment")
    parser.add_argument("--requests", type=int, default=4)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if (args.ring_degree not in (2048, 4096, 8192, 16384, 32768) or not 1 <= args.embed_len <= 512
        or not 1 <= args.num_vectors <= min(131072, 64 * args.ring_degree)
        or not 1 <= args.requests <= 32 or not 1 <= args.repeats <= 1000):
        parser.error("Invalid bounded workload")
    if args.mode == "owner" and args.owner_rns:
        parser.error("Owner comparison creates its own RNS variant; omit --owner-rns")
    case, rows, server, index, client, setup = prepare(args)
    try:
        if args.mode == "profile":
            result = profile_experiment(args, case, server, index, client)
        elif args.mode == "workspace":
            result = workspace_experiment(args, case, rows, server, index, client, setup)
        elif args.mode == "owner":
            result = owner_experiment(args, case, rows, server, index, client, setup)
        else:
            from bgv_transport import experiment
            result = experiment(args, case, rows, server, index, client)
    finally:
        client.close()
    report = {"kind": "homemade_bgv_service_" + args.mode, "utc": datetime.now(UTC).isoformat(),
              "command": sys.argv, "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip(),
              "platform": platform.platform(), "python": sys.version,
              "gpu": subprocess.check_output(["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"], text=True).strip(),
              "num_vectors": len(rows), "dimension": args.embed_len, "n": case.n, "t": case.t,
              "q_hex": format(case.q, "x"), "eta": case.pk.eta, "terminal_bits": args.terminal_bits,
              "requests": args.requests, "repeats": args.repeats, "owner_rns": args.owner_rns, "setup": setup, "result": result,
              "source_and_binary_sha256": provenance()}
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(args.json_out)


if __name__ == "__main__":
    main()
