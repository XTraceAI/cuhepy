#!/usr/bin/env python3
"""Paired homemade BGV owner ablations with an unchanged CUDA level-4 server.

Same keys, encrypted index, parameters and plaintext query within each round;
fresh independent encryption randomness for EACH variant/request, no token pool.
One excluded warmup; shuffled order; setup/cache preparation recorded separately.
Every distance/top-three and every returned plaintext coefficient is checked.
Local phase sums exclude response parsing, network, authentication and load.
No keys, seeds, plaintext data or ciphertexts are written to the report.
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
from experiments.bfv_search_lab import compact_bgv as compact, seeded_bgv, owner_bgv
from experiments.bfv_search_lab.native_bgv import NativeServer


VARIANTS = {
    "reference": "Original seeded encryption, scalar stream decoding, generic GMP product/decryption",
    "bulk": "Bulk fresh error sampling and stream decoding; generic GMP private products",
    "ternary": "Bulk sampling/decoding plus exact shifted-ternary GMP private products",
    "native": "Bulk stream decoding plus separate C++/GMP private encryption/decryption",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=8192)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--terminal-bits", type=int, default=25)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--variants", choices=VARIANTS, nargs="+", default=list(VARIANTS))
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if min(args.num_vectors, args.repeats) < 1 or len(set(args.variants)) != len(args.variants):
        parser.error("Positive counts and distinct variants required")
    if not 1 <= args.embed_len <= 515 or args.ring_degree not in (2048, 4096, 8192, 16384, 32768):
        parser.error("This t=1031 experiment requires dimensions 1..515 and N=2048..32768")
    if not 16 <= args.terminal_bits <= 60:
        parser.error("Terminal precision must be 16..60 bits; the correctness bound may still refuse it")
    setup = {}
    print("Preparing common keys and encrypted index", file=sys.stderr, flush=True)
    setup["owner_keygen_s"], case = timed(Case, "bgv", args.ring_degree, 1031, 120, rns_modulus=True)
    rows, query, _ = make_data(args.num_vectors, args.embed_len, 1701)
    padded = 1 << (args.embed_len - 1).bit_length()
    setup["evaluation_keys_s"], keys = timed(trace.evaluation_keys, case.pk, case.sk, padded)
    _, tiles = bgv.coefficient_inputs(query, rows, case.n)
    setup["index_encrypt_s"], index = timed(lambda: [case.encrypt(tile) for tile in tiles])
    setup["index_bytes"] = len(case.pack(index, len(rows)))
    setup["cuda_plan_s"], server = timed(NativeServer, case.pk, keys, residue=True, device="cuda", cuda_level=4)
    setup["index_prepare_s"], prepared = timed(server.prepare_index, index, len(rows))
    cpu = NativeServer(case.pk, keys, residue=True)
    cpu_index = cpu.prepare_index(index, len(rows))
    owners, setup["owners"] = {}, {}
    for name in args.variants:
        if name == "reference":
            setup["owners"][name] = {"create_s": 0.0, "prepare_terminal_s": 0.0}
            continue
        create_s, client = timed(owner_bgv.OwnerClient, case.pk, case.sk,
                                 ternary=name != "bulk", native=name == "native")
        terminal_s = timed(client.prepare_terminal, args.terminal_bits)[0] if name != "bulk" else 0.0
        owners[name] = client
        setup["owners"][name] = {"create_s": create_s, "prepare_terminal_s": terminal_s}
    samples, warmups = {name: [] for name in args.variants}, {}
    rng = random.Random(20260928)
    coefficients_checked = ciphertexts_checked = expanded_checked = 0
    for repeat in range(args.repeats + 1):
        current = [rng.randrange(2) for _ in query]
        encode_s, encoded = timed(lambda current=current: bgv.coefficient_inputs(current, [], case.n)[0])
        expected = [sum(a != b for a, b in zip(current, row, strict=True)) for row in rows]
        expected_top = sorted(range(len(rows)), key=lambda i: (expected[i], i))[:3]
        order = args.variants.copy()
        rng.shuffle(order)
        for name in order:
            if name == "reference":
                encrypt_s, packet = timed(seeded_bgv.encrypt, encoded, case.pk, case.sk)
                expand_s, encrypted = timed(seeded_bgv.expand, packet, case.pk)
            else:
                encrypt_s, packet = timed(owners[name].encrypt, encoded)
                expand_s, encrypted = timed(owner_bgv.expand, packet, case.pk)
            server_s, small = timed(server.search_compact, encrypted, prepared, bits=args.terminal_bits)
            pack_s, wire = timed(compact.pack, small, len(rows), args.embed_len, case.pk)
            if name == "reference":
                decrypt_s, plaintexts = timed(lambda small=small: [compact.decrypt(c, case.pk, case.sk) for c in small])
            else:
                decrypt_s, plaintexts = timed(lambda small=small, name=name: [owners[name].decrypt_compact(c) for c in small])
            decode_s, distances = timed(trace.decode, plaintexts, len(rows), args.embed_len, case.pk)
            top_s, top = timed(lambda distances=distances: sorted(range(len(rows)), key=lambda i: (distances[i], i))[:3])
            # All oracles run outside the measured phases. Fresh encryption means
            # ciphertexts differ ACROSS variants; compare each with its own oracle.
            assert distances == expected and top == expected_top
            assert plaintexts == [compact.decrypt(c, case.pk, case.sk) for c in small]
            coefficients_checked += case.n * len(small)
            assert encrypted == seeded_bgv.expand(packet, case.pk)
            expanded_checked += 1
            if not repeat:
                full = cpu.search(encrypted, cpu_index)
                assert small == [compact.compact(c, case.pk, args.terminal_bits) for c in full]
                ciphertexts_checked += len(small)
            phases = {
                "query_encode_s": encode_s, "query_encrypt_s": encrypt_s,
                "server_query_expand_s": expand_s, "server_evaluate_and_compact_s": server_s,
                "response_pack_s": pack_s, "client_decrypt_s": decrypt_s,
                "client_decode_s": decode_s, "client_top3_s": top_s,
            }
            entry = {
                **phases, "local_phases_s": sum(phases.values()),
                "client_phases_s": encode_s + encrypt_s + decrypt_s + decode_s + top_s,
                "server_phases_s": expand_s + server_s + pack_s,
                "query_bytes": len(packet), "response_bytes": len(wire),
                "query_plus_response_bytes": len(packet) + len(wire),
                "response_ciphertexts": len(small),
                "phase_bound": max(c.phase_bound for c in small),
            }
            if repeat:
                samples[name].append(entry)
            else:
                warmups[name] = entry
            print(f"{name}, round {repeat}: encrypt={encrypt_s:.4f}s, decrypt={decrypt_s:.4f}s, "
                  f"local phases={entry['local_phases_s']:.4f}s", file=sys.stderr, flush=True)
    # Record public source/build provenance, never private cache contents.
    sources = [Path(__file__).resolve(), REPO_ROOT / "benchmarks/coefficient_search_lab.py",
               REPO_ROOT / "benchmarks/bfv_client_matrix.py", REPO_ROOT / "src/cuhepy/bfv/scheme.py",
               REPO_ROOT / "src/cuhepy/types.py"]
    lab = REPO_ROOT / "experiments/bfv_search_lab"
    sources += sorted(lab.glob("*.py"))
    for directory in (lab / "_native", lab / "_owner", REPO_ROOT / "src/cuhepy/bfv/_cpu_ext",
                      REPO_ROOT / "src/cuhepy/bfv/_gpu_ext"):
        for pattern in ("*.h", "*.cuh", "*.cpp", "*.cu", "*.pyi", "Makefile"):
            sources += sorted(directory.glob(pattern))
    binaries = {"cuda": Path(server._native.__file__), "cpu": Path(cpu._native.__file__)}
    if "native" in owners:
        binaries["owner"] = Path(owners["native"]._product._native.__file__)
    report = {
        "kind": "paired_homemade_bgv_owner_pipeline", "utc": datetime.now(UTC).isoformat(),
        "command": sys.argv, "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip(),
        "platform": platform.platform(), "python": sys.version,
        "cpu": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), platform.machine()),
        "gpu": subprocess.check_output(["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"], text=True).strip(),
        "num_vectors": len(rows), "dimension": args.embed_len, "n": case.n, "t": case.t,
        "q_hex": format(case.q, "x"), "q_bits": case.q.bit_length(), "eta": case.pk.eta,
        "digit_bits": keys.digit_bits, "terminal_bits": args.terminal_bits, "cuda_level": 4,
        "variant_definitions": {name: VARIANTS[name] for name in args.variants},
        "notes": __doc__, "setup": setup, "warmup": warmups,
        "results": [{"variant": name, "samples": entries,
                     "medians": {key: statistics.median(row[key] for row in entries) for key in entries[0]}}
                    for name, entries in samples.items()],
        "all_distances_and_stable_top3_correct": True,
        "plaintext_coefficients_compared": coefficients_checked,
        "exact_expanded_queries_compared": expanded_checked,
        "exact_cpu_compact_ciphertexts_compared": ciphertexts_checked,
        "sha256": {str(path.relative_to(REPO_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
        "native_binary_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()},
    }
    for client in owners.values():
        client.close()
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    for row in report["results"]:
        print(row["variant"], row["medians"])


if __name__ == "__main__":
    main()
