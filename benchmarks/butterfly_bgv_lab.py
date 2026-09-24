#!/usr/bin/env python3
"""Paired, exact BGV joint-packing experiment; no security-equivalence claim.

All variants share each fresh query, index, modulus and evaluation keys. Native
setup caches public index/key NTTs. Report that setup and resident byte count
separately; timings include native query/result conversions, but no network or
attestation. Python variants make the first pilot slow; select only the native
variants for a large workload after checking exact ciphertexts on the pilot.
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
from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import compact_bgv
from experiments.bfv_search_lab.native_bgv import NativeServer


def main():
    variants = [f"{backend}-{circuit}" for backend in ("python", "native", "residue", "cuda")
                for circuit in ("per-tile", "butterfly")]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=65)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--q-bits", type=int, default=96)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--variants", choices=variants, nargs="+", default=variants[:4])
    parser.add_argument("--rns-modulus", action="store_true")
    parser.add_argument("--terminal-bits", type=int, default=0)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if min(args.num_vectors, args.repeats) < 1 or len(set(args.variants)) != len(args.variants):
        parser.error("Positive counts and distinct variants required")
    if not args.rns_modulus and any(name.startswith(("residue", "cuda")) for name in args.variants):
        parser.error("Residue/CUDA variants require --rns-modulus and fresh keys")
    setup = {}
    setup["owner_keygen_s"], case = timed(Case, "bgv", args.ring_degree, 1031, args.q_bits, karatsuba=True, rns_modulus=args.rns_modulus)
    rows, query, _ = make_data(args.num_vectors, args.embed_len, 1701)
    padded = 1 << (args.embed_len - 1).bit_length()
    setup["evaluation_keys_s"], keys = timed(trace.evaluation_keys, case.pk, case.sk, padded)
    _, tiles = bgv.coefficient_inputs(query, rows, case.n)
    setup["index_encrypt_s"], index = timed(lambda: [case.encrypt(tile) for tile in tiles])
    setup["index_bytes"] = len(case.pack(index, len(rows)))
    from cuhepy.bfv._cpu_ext import _bfv_rns
    servers, prepared_indices, binaries = {}, {}, {}
    setup["backends"] = {}
    for backend in sorted({name.split("-")[0] for name in args.variants} - {"python"}):
        residue = backend in ("residue", "cuda")
        plan_s, server = timed(NativeServer, case.pk, keys, residue=residue, device="cuda" if backend == "cuda" else "cpu")
        prepare_s, prepared = timed(server.prepare_index, index, len(rows))
        servers[backend], prepared_indices[backend] = server, prepared
        info = dict(_bfv_rns.ring_info(_bfv_rns.create_ring(case.n, format(case.q, "x"), keys.digit_bits, True, residue, 2 if residue else 0)))
        prime_count = info["residue_prime_count"] if residue else len(info["primes"])
        setup["backends"][backend] = {"plan_s": plan_s, "index_prepare_s": prepare_s,
            "arithmetic": info, "index_ntt_bytes": len(index) * 2 * case.n * 8 * prime_count}
        binaries[backend] = Path(server._native.__file__)
    setup["evaluation_key_raw_coefficient_bytes"] = (len(keys.rotations) + 1) * len(keys.relin) * 2 * ((case.n * case.q.bit_length() + 7) // 8)
    samples, warmups = {name: [] for name in args.variants}, {}
    rng = random.Random(20260924)
    ciphertext_checks = 0
    for repeat in range(args.repeats + 1):
        current = query.copy()
        if repeat:
            current[(repeat - 1) % len(current)] ^= 1
        encode_s, encoded = timed(lambda current=current: bgv.coefficient_inputs(current, [], case.n)[0])
        encrypt_s, encrypted = timed(case.encrypt, encoded)
        expected = [sum(a != b for a, b in zip(current, row, strict=True)) for row in rows]
        query_pack_s, query_wire = timed(case.pack, [encrypted], 1)
        order, answers = args.variants.copy(), {}
        rng.shuffle(order)
        for name in order:
            joint = name.endswith("butterfly")
            backend = name.split("-")[0]
            if backend != "python":
                server_s, response = timed(servers[backend].search, encrypted, prepared_indices[backend], joint=joint)
            else:
                method = butterfly.search if joint else trace.search
                server_s, response = timed(method, encrypted, index, len(rows), case.pk, keys)
            answers[name] = response
            compact_s = 0.0
            if args.terminal_bits:
                compact_s, small = timed(lambda response=response: [compact_bgv.compact(c, case.pk, args.terminal_bits) for c in response])
                decrypt_s, plaintexts = timed(lambda small=small: [compact_bgv.decrypt(c, case.pk, case.sk) for c in small])
                pack_s, wire = timed(compact_bgv.pack, small, len(rows), args.embed_len, case.pk)
            else:
                decrypt_s, plaintexts = timed(lambda response=response: [case.decrypt(c) for c in response])
                pack_s, wire = timed(case.pack, response, len(rows))
            decode_s, distances = timed(trace.decode, plaintexts, len(rows), args.embed_len, case.pk)
            assert distances == expected
            top_s, top = timed(lambda distances=distances: sorted(range(len(rows)), key=lambda i: (distances[i], i))[:3])
            assert top == sorted(range(len(rows)), key=lambda i: (expected[i], i))[:3]
            sample = {
                "query_encode_s": encode_s, "query_encrypt_s": encrypt_s,
                "query_pack_s": query_pack_s, "server_s": server_s,
                "response_pack_s": pack_s, "client_decrypt_s": decrypt_s,
                "server_compact_s": compact_s,
                "client_decode_s": decode_s, "client_top3_s": top_s,
                "local_phases_s": encode_s + encrypt_s + query_pack_s + server_s + compact_s + pack_s + decrypt_s + decode_s + top_s,
                "query_bytes": len(query_wire), "response_bytes": len(wire),
                "query_plus_response_bytes": len(query_wire) + len(wire),
                "response_ciphertexts": len(response),
                "public_phase_bound_bits": max(c.phase_bound for c in response).bit_length(),
            }
            if repeat:
                samples[name].append(sample)
            else:
                warmups[name] = sample
            print(f"{name}, round {repeat}: server={server_s:.4f}s, local phases={sample['local_phases_s']:.4f}s", file=sys.stderr, flush=True)
        for algorithm in ("per-tile", "butterfly"):
            compared = [value for name, value in answers.items() if name.endswith(algorithm)]
            for actual in compared[1:]:
                assert actual == compared[0]
                ciphertext_checks += len(actual)
    total_automorphisms = sum(butterfly.schedule(padded, [1] * min(padded, len(index) - start), 0)[1] for start in range(0, len(index), padded))
    sources = [Path(__file__).resolve(), REPO_ROOT / "benchmarks/coefficient_search_lab.py"]
    sources += [REPO_ROOT / "experiments/bfv_search_lab" / name for name in (
        "shallow_bgv.py", "trace_bgv.py", "butterfly_bgv.py", "native_bgv.py", "compact_bgv.py",
        "_native/trace_server.h", "_native/residue_trace.h", "_native/bindings.cpp", "_native/Makefile",
        "_native/cuda_trace.cuh", "_native/bindings.cu",
    )]
    sources += [REPO_ROOT / "src/cuhepy/bfv/_cpu_ext" / name for name in ("rns_ntt.h", "profile.h", "bfv_residue.h", "bfv_server.h", "rns_scale.h", "packed_wire.h")]
    sources += [REPO_ROOT / "src/cuhepy/bfv/_gpu_ext" / name for name in ("server.cuh", "kernels.cuh")]
    report = {
        "kind": "paired_bgv_trace_butterfly_experiment",
        "utc": datetime.now(UTC).isoformat(), "command": sys.argv,
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip(),
        "platform": platform.platform(), "python": sys.version,
        "gpu": subprocess.check_output(["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"], text=True).strip() if "cuda" in servers else None,
        "num_vectors": len(rows), "dimension": args.embed_len,
        "n": case.n, "t": case.t, "q_bits": case.q.bit_length(), "digit_bits": keys.digit_bits,
        "rns_modulus": args.rns_modulus, "terminal_bits": args.terminal_bits,
        "notes": "Same keys, encrypted index, and fresh query per paired round; shuffled order, one excluded warmup. "
        "Native setup caches public index/key NTTs. CPU variants are single-threaded; CUDA uses the local GPU. "
        "Local phases include native boundary conversions and wire packing but exclude wire parsing, network and attestation. "
        "No reviewed security equivalence with production BFV or SEAL. Bounds establish arithmetic correctness only. "
        "No secret keys or ciphertext bytes are saved.",
        "setup": setup, "warmup": warmups,
        "results": [{"variant": name, "samples": entries, "medians": {key: statistics.median(row[key] for row in entries) for key in entries[0]}} for name, entries in samples.items()],
        "operation_counts": {"relinearizations": len(index), "per_tile_automorphisms": len(index) * len(keys.rotations), "butterfly_automorphisms": total_automorphisms},
        "all_distances_and_stable_top3_correct": True,
        "exact_cross_backend_ciphertexts_checked": ciphertext_checks,
        "sha256": {str(path.relative_to(REPO_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
        "native_binary_sha256": {name: hashlib.sha256(binary.read_bytes()).hexdigest() for name, binary in binaries.items()},
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    for row in report["results"]:
        print(row["variant"], row["medians"])


if __name__ == "__main__":
    main()
