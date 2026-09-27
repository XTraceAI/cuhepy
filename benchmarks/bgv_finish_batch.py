#!/usr/bin/env python3
"""Paired local result handling and distinct-query GPU batching experiments.

One common encrypted index and key set; fresh independent native owner queries
each round. All server variants receive the SAME ciphertexts in shuffled order.
One excluded warmup; all distances/top-k, exact CPU/GPU compact ciphertexts and
cross-variant ciphertext equality checked outside timers. Setup is separate.

Batch timings start with expanded queries ready: no batch-formation wait, query
creation, seed expansion, transport, response framing or authentication included.
Client local-phase sums add the measured FIRST serial query and its framing to
each finish variant. Top-only changes the local return contract, not wire bytes.
Only public parameters, counts, timings and source/binary hashes are saved.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
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

from bfv_client_matrix import REPO_ROOT, make_data
from coefficient_search_lab import Case, timed

sys.path.insert(0, str(REPO_ROOT))
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, owner_bgv, results_bgv
from experiments.bfv_search_lab.native_bgv import NativeServer

FINISH = ("sort", "heap", "lookup", "native", "native-top-only")
# Mode, concurrent queries per native wave / host worker count, index broadcast.
BATCH = {"serial": ("serial", 1, False), "threads-2": ("threads", 2, False),
         "threads-4": ("threads", 4, False), "batch-1": ("batch", 1, False),
         "batch-2": ("batch", 2, False), "batch-2-shared": ("batch", 2, True),
         "batch-4": ("batch", 4, False), "batch-4-shared": ("batch", 4, True)}


def summaries(samples):
    return [{"variant": name, "samples": entries,
             "medians": {k: statistics.median(row[k] for row in entries)
                         for k, v in entries[0].items() if isinstance(v, (int, float))}}
            for name, entries in samples.items()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=8192)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--terminal-bits", type=int, default=25)
    parser.add_argument("--requests", type=int, default=4)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if (not 1 <= args.num_vectors <= 64 * args.ring_degree or not 1 <= args.requests <= 8
        or args.repeats < 1 or not 1 <= args.embed_len <= 512
        or args.ring_degree not in (2048, 4096, 8192, 16384, 32768)):
        parser.error("Invalid bounded workload, ring, query count or repetition count")
    setup = {}
    print("Preparing common keys/index", file=sys.stderr, flush=True)
    setup["owner_keygen_s"], case = timed(Case, "bgv", args.ring_degree, 1031, 120, rns_modulus=True)
    rows, query, _ = make_data(args.num_vectors, args.embed_len, 1701)
    padded = 1 << (args.embed_len - 1).bit_length()
    setup["evaluation_keys_s"], keys = timed(trace.evaluation_keys, case.pk, case.sk, padded)
    _, tiles = bgv.coefficient_inputs(query, rows, case.n)
    setup["index_encrypt_s"], index = timed(lambda: [case.encrypt(tile) for tile in tiles])
    setup["index_bytes"] = len(case.pack(index, len(rows)))
    setup["server_create_s"], server = timed(NativeServer, case.pk, keys, residue=True, device="cuda", cuda_level=4)
    setup["index_prepare_s"], prepared = timed(server.prepare_index, index, len(rows))
    setup["owner_create_s"], client = timed(owner_bgv.OwnerClient, case.pk, case.sk, native=True)
    setup["owner_terminal_prepare_s"] = timed(client.prepare_terminal, args.terminal_bits)[0]
    setup["python_lut_prepare_s"] = timed(results_bgv._table, case.t, args.embed_len)[0]
    cpu = NativeServer(case.pk, keys, residue=True)
    cpu_index = cpu.prepare_index(index, len(rows))
    allowed, skipped = {}, {}
    for name, spec in BATCH.items():
        mode, count, shared = spec
        memory = server.batch_workspace_bytes(prepared, min(count, args.requests))
        if memory > (4 << 30):
            skipped[name] = {"reason": "exceeds the experiment's 4 GiB coefficient workspace budget", "bytes": memory}
        else:
            allowed[name] = {"mode": mode, "concurrency": count, "shared_index": shared, "coefficient_workspace_bytes": memory}
    batch_samples, finish_samples = {name: [] for name in allowed}, {name: [] for name in FINISH}
    batch_warmup, finish_warmup, preparation = {}, {}, []
    checks = {"exact_compact_ciphertexts": 0, "cpu_compact_ciphertexts": 0, "distance_values": 0, "top_results": 0}
    rng = random.Random(20260929)
    native_budget_checked = False
    with ThreadPoolExecutor(max_workers=2) as two, ThreadPoolExecutor(max_workers=4) as four:
        pools = {2: two, 4: four}
        for repeat in range(args.repeats + 1):
            queries, expected, prep, packets = [], [], [], []
            for request in range(args.requests):
                plain = [rng.randrange(2) for _ in query]
                encode_s, encoded = timed(lambda plain=plain: bgv.coefficient_inputs(plain, [], case.n)[0])
                encrypt_s, packet = timed(client.encrypt, encoded)
                expand_s, encrypted = timed(owner_bgv.expand, packet, case.pk)
                queries.append(encrypted)
                packets.append(packet)
                prep.append({"encode_s": encode_s, "encrypt_s": encrypt_s, "expand_s": expand_s})
                expected.append([sum(a != b for a, b in zip(plain, row, strict=True)) for row in rows])
            preparation.append({"warmup": not repeat, "requests": prep, "query_bytes": sum(map(len, packets))})
            if not repeat and server.batch_workspace_bytes(prepared, 8) > (4 << 30):
                # Also verify the raw native allocation gate on the REAL index.
                pair = tuple(server._pack(p) for p in queries[0].components)
                try:
                    server._native.search_many(server._server, (pair,) * 8, prepared.handle, 8, True)
                except ValueError as error:
                    assert "4 GiB" in str(error)
                    native_budget_checked = True
                else:
                    raise AssertionError("Native workspace budget was bypassed")
            order, baseline, serial_first = list(allowed), None, None
            rng.shuffle(order)
            for name in order:
                mode, count, shared = BATCH[name]
                begin = time.perf_counter()

                def one(q, begin=begin):
                    started = time.perf_counter()
                    value = server.search_compact(q, prepared, bits=args.terminal_bits)
                    ended = time.perf_counter()
                    return value, ended - started, ended - begin

                if mode == "batch":
                    outputs = server.search_many_compact(queries, prepared, batch_size=count,
                                                          shared_index=shared, bits=args.terminal_bits)
                    elapsed = time.perf_counter() - begin
                    completions = [elapsed] * args.requests  # one return after the entire call
                else:
                    records = list(pools[count].map(one, queries)) if mode == "threads" else [one(q) for q in queries]
                    elapsed = time.perf_counter() - begin
                    outputs = [r[0] for r in records]
                    completions = [r[2] for r in records]
                    if mode == "serial":
                        serial_first = records[0][1]
                if baseline is None:
                    baseline = outputs
                else:
                    assert outputs == baseline
                    checks["exact_compact_ciphertexts"] += sum(map(len, outputs))
                entry = {"evaluation_batch_s": elapsed, "requests_per_second": args.requests / elapsed,
                         "first_completion_s": min(completions), "last_completion_s": max(completions),
                         "mean_completion_s": statistics.mean(completions), "completion_offsets_s": completions}
                if repeat:
                    batch_samples[name].append(entry)
                else:
                    batch_warmup[name] = entry
                print(f"{name}, round {repeat}: {elapsed:.4f}s, {args.requests / elapsed:.2f} requests/s", file=sys.stderr, flush=True)
            assert baseline is not None and serial_first is not None
            if not repeat:
                for encrypted, response in zip(queries, baseline, strict=True):
                    full = cpu.search(encrypted, cpu_index)
                    assert response == [compact.compact(c, case.pk, args.terminal_bits) for c in full]
                    checks["cpu_compact_ciphertexts"] += len(response)
            # Every distinct request checked, not just the query used for finish timing.
            for response, distances in zip(baseline, expected, strict=True):
                result = client.finish(response, len(rows), len(query))
                assert result.distances == tuple(distances)
                assert result.top == tuple((i, distances[i]) for i in sorted(range(len(rows)), key=lambda i: (distances[i], i))[:3])
                checks["distance_values"] += len(rows)
            pack_s, wire = timed(compact.pack, baseline[0], len(rows), len(query), case.pk)
            common = sum(prep[0].values()) + serial_first + pack_s
            result_reference = client.finish(baseline[0], len(rows), len(query))
            finish_order = list(FINISH)
            rng.shuffle(finish_order)
            for name in finish_order:
                def finish(name=name, response=baseline[0]):
                    if name.startswith("native"):
                        return client.finish(response, len(rows), len(query), all_distances=name == "native")
                    # Original decoder/sort stays exactly outside the new native finisher.
                    plain = [client.decrypt_compact(c) for c in response]
                    return results_bgv.finish(plain, len(rows), len(query), case.pk, method=name)
                finish_s, result = timed(finish)
                assert result.top == result_reference.top
                checks["top_results"] += len(result.top)
                if name != "native-top-only":
                    assert result.distances == result_reference.distances == tuple(expected[0])
                    checks["distance_values"] += len(rows)
                else:
                    assert result.distances is None
                entry = {"decrypt_decode_select_s": finish_s, "local_phases_s": common + finish_s,
                         "common_phases_s": common, "query_encode_s": prep[0]["encode_s"],
                         "query_encrypt_s": prep[0]["encrypt_s"], "server_expand_s": prep[0]["expand_s"],
                         "server_single_evaluate_s": serial_first, "response_pack_s": pack_s,
                         "query_bytes": len(packets[0]), "response_bytes": len(wire),
                         "query_plus_response_bytes": len(packets[0]) + len(wire)}
                if repeat:
                    finish_samples[name].append(entry)
                else:
                    finish_warmup[name] = entry
                print(f"finish {name}, round {repeat}: {finish_s:.4f}s, local={entry['local_phases_s']:.4f}s", file=sys.stderr, flush=True)
    lab = REPO_ROOT / "experiments/bfv_search_lab"
    sources = [Path(__file__).resolve(), REPO_ROOT / "benchmarks/coefficient_search_lab.py", REPO_ROOT / "benchmarks/bfv_client_matrix.py",
               REPO_ROOT / "src/cuhepy/bfv/scheme.py", REPO_ROOT / "src/cuhepy/types.py"] + sorted(lab.glob("*.py"))
    for directory in (lab / "_native", lab / "_owner", REPO_ROOT / "src/cuhepy/bfv/_cpu_ext", REPO_ROOT / "src/cuhepy/bfv/_gpu_ext"):
        for pattern in ("*.h", "*.cuh", "*.cpp", "*.cu", "*.pyi", "Makefile"):
            sources += sorted(directory.glob(pattern))
    binaries = {"cpu": Path(cpu._native.__file__), "cuda": Path(server._native.__file__), "owner": Path(client._product._native.__file__)}
    report = {
        "kind": "paired_homemade_bgv_finish_and_batch", "utc": datetime.now(UTC).isoformat(), "command": sys.argv,
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip(),
        "platform": platform.platform(), "python": sys.version,
        "cpu": next((x.split(":", 1)[1].strip() for x in Path("/proc/cpuinfo").read_text().splitlines() if x.startswith("model name")), platform.machine()),
        "gpu": subprocess.check_output(["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"], text=True).strip(),
        "n": case.n, "t": case.t, "q_hex": format(case.q, "x"), "eta": case.pk.eta, "digit_bits": keys.digit_bits,
        "num_vectors": len(rows), "dimension": len(query), "terminal_bits": args.terminal_bits,
        "requests_per_batch": args.requests, "setup": setup, "preparation": preparation, "notes": __doc__,
        "batch_variants": allowed, "skipped_batch_variants": skipped,
        "batch_results": summaries(batch_samples), "finish_results": summaries(finish_samples),
        "batch_warmup": batch_warmup, "finish_warmup": finish_warmup, "checks": checks,
        "all_distances_and_top_results_correct": True, "native_workspace_refusal_checked": native_budget_checked,
        "sha256": {str(p.relative_to(REPO_ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        "native_binary_sha256": {name: hashlib.sha256(p.read_bytes()).hexdigest() for name, p in binaries.items()},
    }
    client.close()
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    for section in ("finish_results", "batch_results"):
        for row in report[section]:
            print(section, row["variant"], row["medians"])


if __name__ == "__main__":
    main()
