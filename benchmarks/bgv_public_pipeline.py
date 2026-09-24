#!/usr/bin/env python3
"""Paired ablation of our BGV public pipeline, with unchanged Q120 parameters.

One excluded warmup, fresh seeded owner queries, shuffled variants, complete
ciphertext equality and every distance/top-three checked. Setup is separate.
Local phase sums exclude parsing, network, authentication and concurrent load.
No secret keys or ciphertexts are saved. Run without other GPU/CPU workloads.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys

from bfv_client_matrix import REPO_ROOT, make_data
from coefficient_search_lab import Case, timed

sys.path.insert(0, str(REPO_ROOT))
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, seeded_bgv
from experiments.bfv_search_lab.native_bgv import NativeServer


VARIANTS = {
    "baseline": (0, False),
    "gpu-query-ntt": (1, False),
    "fused": (2, False),
    "tiled": (3, False),
    "fused-native-compact": (2, True),
    "tiled-native-compact": (3, True),
    "gather": (4, False),
    "gather-native-compact": (4, True),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=8192)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--concurrency-repeats", type=int, default=0)
    parser.add_argument("--variants", choices=VARIANTS, nargs="+", default=list(VARIANTS))
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if min(args.num_vectors, args.repeats) < 1 or len(args.variants) != len(set(args.variants)):
        parser.error("Positive counts and distinct variants required")
    if args.concurrency_repeats < 0 or (args.concurrency_repeats and not any(VARIANTS[name][0] == 4 for name in args.variants)):
        parser.error("Concurrency measurements require a gather variant and nonnegative repeats")
    setup = {}
    setup["owner_keygen_s"], case = timed(Case, "bgv", args.ring_degree, 1031, 120, rns_modulus=True)
    rows, query, _ = make_data(args.num_vectors, args.embed_len, 1701)
    padded = 1 << (args.embed_len - 1).bit_length()
    setup["evaluation_keys_s"], keys = timed(trace.evaluation_keys, case.pk, case.sk, padded)
    _, tiles = bgv.coefficient_inputs(query, rows, case.n)
    setup["index_encrypt_s"], index = timed(lambda: [case.encrypt(tile) for tile in tiles])
    setup["index_bytes"] = len(case.pack(index, len(rows)))
    servers, prepared = {}, {}
    setup["cuda"] = {}
    for level in sorted({VARIANTS[name][0] for name in args.variants}):
        plan_s, server = timed(NativeServer, case.pk, keys, residue=True, device="cuda", cuda_level=level)
        prepare_s, handle = timed(server.prepare_index, index, len(rows))
        servers[level], prepared[level] = server, handle
        maximum = min(padded, len(index))
        setup["cuda"][level] = {
            "plan_s": plan_s, "index_prepare_s": prepare_s,
            "index_device_bytes": len(index) * 4 * case.n * 8,
            "workspace_coefficient_bytes": (4 + maximum * (26 if level >= 4 else 28 if level >= 2 else 30)) * case.n * 8,
        }
    # Independent CPU implementation, checked outside all online timings.
    cpu = NativeServer(case.pk, keys, residue=True)
    cpu_index = cpu.prepare_index(index, len(rows))
    samples, warmups = {name: [] for name in args.variants}, {}
    rng = random.Random(20260925)
    full_checks = compact_checks = 0
    for repeat in range(args.repeats + 1):
        current = query.copy()
        if repeat:
            current[(repeat - 1) % len(current)] ^= 1
        encode_s, encoded = timed(lambda current=current: bgv.coefficient_inputs(current, [], case.n)[0])
        encrypt_s, packet = timed(seeded_bgv.encrypt, encoded, case.pk, case.sk)
        expand_s, encrypted = timed(seeded_bgv.expand, packet, case.pk)
        expected_distances = [sum(a != b for a, b in zip(current, row, strict=True)) for row in rows]
        full_reference = cpu.search(encrypted, cpu_index) if not repeat else None
        compact_reference = None
        order = args.variants.copy()
        rng.shuffle(order)
        for name in order:
            level, integrated = VARIANTS[name]
            server = servers[level]
            compact_s = 0.0
            if integrated:
                evaluate_s, small = timed(server.search_compact, encrypted, prepared[level])
            else:
                evaluate_s, response = timed(server.search, encrypted, prepared[level])
                compact_s, small = timed(lambda response=response: [compact.compact(c, case.pk) for c in response])
                if full_reference is None:
                    full_reference = response
                else:
                    assert response == full_reference
                    full_checks += len(response)
            # Comparisons are outside measured phases, including native compact
            # versus the Python rounding of a full response from the same query.
            if compact_reference is None:
                compact_reference = small
            else:
                assert small == compact_reference
                compact_checks += len(small)
            if not repeat:
                assert small == [compact.compact(c, case.pk) for c in full_reference]
            pack_s, wire = timed(compact.pack, small, len(rows), args.embed_len, case.pk)
            decrypt_s, plaintexts = timed(lambda small=small: [compact.decrypt(c, case.pk, case.sk) for c in small])
            decode_s, distances = timed(trace.decode, plaintexts, len(rows), args.embed_len, case.pk)
            assert distances == expected_distances
            top_s, top = timed(lambda distances=distances: sorted(range(len(rows)), key=lambda i: (distances[i], i))[:3])
            assert top == sorted(range(len(rows)), key=lambda i: (expected_distances[i], i))[:3]
            phases = {
                "query_encode_s": encode_s, "query_encrypt_s": encrypt_s,
                "server_query_expand_s": expand_s,
                "server_evaluate_s": evaluate_s, "server_separate_compact_s": compact_s,
                "response_pack_s": pack_s, "client_decrypt_s": decrypt_s,
                "client_decode_s": decode_s, "client_top3_s": top_s,
            }
            sample = {
                **phases, "local_phases_s": sum(phases.values()),
                "server_evaluate_and_compact_s": evaluate_s + compact_s,
                "query_bytes": len(packet), "response_bytes": len(wire),
                "query_plus_response_bytes": len(packet) + len(wire),
                "response_ciphertexts": len(small),
            }
            if repeat:
                samples[name].append(sample)
            else:
                warmups[name] = sample
            print(f"{name}, round {repeat}: evaluation+compact={evaluate_s + compact_s:.4f}s, "
                  f"local phases={sample['local_phases_s']:.4f}s", file=sys.stderr, flush=True)
    concurrency = None
    if args.concurrency_repeats:
        from bgv_request_throughput import run
        concurrency = run(servers[4], prepared[4], case, rows, query, args.concurrency_repeats)
    paths = [Path(__file__).resolve(), REPO_ROOT / "benchmarks/coefficient_search_lab.py",
             REPO_ROOT / "benchmarks/bfv_client_matrix.py", REPO_ROOT / "benchmarks/bgv_request_throughput.py"]
    lab = REPO_ROOT / "experiments/bfv_search_lab"
    paths += sorted(lab.glob("*.py"))
    paths += sorted((lab / "_native").glob("*.h")) + sorted((lab / "_native").glob("*.cuh"))
    paths += [lab / "_native" / name for name in ("bindings.cpp", "bindings.cu", "Makefile")]
    paths += sorted((REPO_ROOT / "src/cuhepy/bfv/_cpu_ext").glob("*.h"))
    paths += sorted((REPO_ROOT / "src/cuhepy/bfv/_gpu_ext").glob("*.cuh"))
    paths += [REPO_ROOT / "src/cuhepy/bfv/scheme.py", REPO_ROOT / "src/cuhepy/types.py"]
    binaries = {"cuda": Path(next(iter(servers.values()))._native.__file__), "cpu": Path(cpu._native.__file__)}
    report = {
        "kind": "paired_homemade_bgv_public_pipeline", "utc": datetime.now(UTC).isoformat(),
        "command": sys.argv, "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip(),
        "platform": platform.platform(), "python": sys.version,
        "cpu": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), platform.machine()),
        "gpu": subprocess.check_output(["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"], text=True).strip(),
        "num_vectors": len(rows), "dimension": args.embed_len, "n": case.n, "t": case.t,
        "q_hex": format(case.q, "x"), "q_bits": case.q.bit_length(), "eta": case.pk.eta,
        "digit_bits": keys.digit_bits, "terminal_bits": 32, "seeded_query": True,
        "variant_definitions": {name: {"cuda_level": VARIANTS[name][0], "compaction_in_evaluate": VARIANTS[name][1]} for name in args.variants},
        "notes": __doc__, "setup": setup, "warmup": warmups,
        "concurrency": concurrency,
        "results": [{"variant": name, "samples": entries,
                     "medians": {key: statistics.median(row[key] for row in entries) for key in entries[0]}}
                    for name, entries in samples.items()],
        "all_distances_and_stable_top3_correct": True,
        "exact_full_ciphertexts_compared": full_checks, "exact_compact_ciphertexts_compared": compact_checks,
        "cpu_oracle_checked_on_warmup": True,
        "sha256": {str(path.relative_to(REPO_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths},
        "native_binary_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()},
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    for row in report["results"]:
        print(row["variant"], row["medians"])


if __name__ == "__main__":
    main()
