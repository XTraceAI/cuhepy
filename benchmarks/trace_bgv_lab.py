#!/usr/bin/env python3
"""Encrypted trace-packing pilot at the full ring degree, CPU reference only.

Compares the same index/query with and without projection. No GPU extrapolation
or security claim. A small vector count keeps the unoptimized key switching
practical; full-index bounds and raw payload counts are explicitly analytical.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import platform
import statistics
import sys

from bfv_client_matrix import REPO_ROOT, make_data
from coefficient_search_lab import Case, timed

sys.path.insert(0, str(REPO_ROOT))
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=65)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--q-bits", type=int, default=96)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.num_vectors < 1 or args.repeats < 1:
        parser.error("Positive counts/repeats required")
    case = Case("bgv", args.ring_degree, 1031, args.q_bits, karatsuba=True)
    rows, query, _ = make_data(args.num_vectors, args.embed_len, 1701)
    padded = 1 << (args.embed_len - 1).bit_length()
    setup = {}
    setup["evaluation_keys_s"], keys = timed(
        lambda: trace.evaluation_keys(case.pk, case.sk, padded)
    )
    setup["evaluation_key_raw_coefficient_bytes"] = sum(
        len(key) * 2 * ((case.n * case.q.bit_length() + 7) // 8)
        for key in (keys.relin, *(key for _, key in keys.rotations))
    )
    setup["evaluation_key_bytes_note"] = (
        "Raw fixed-bit coefficient count; no evaluation-key wire format is implemented"
    )
    _, tiles = bgv.coefficient_inputs(query, rows, case.n)
    setup["index_encrypt_s"], index = timed(lambda: [case.encrypt(tile) for tile in tiles])
    setup["index_bytes"] = len(case.pack(index, len(rows)))
    samples = {"unrepacked": [], "trace-packed": []}
    warmup = {}
    for repeat in range(args.repeats + 1):
        current = query.copy()
        if repeat:
            current[(repeat - 1) % len(current)] ^= 1
        expected = [sum(a != b for a, b in zip(current, row, strict=True)) for row in rows]
        for name in list(samples) if repeat % 2 else list(reversed(samples)):
            sample = {}
            qp, _ = bgv.coefficient_inputs(current, [], case.n)
            sample["query_encrypt_s"], encrypted = timed(case.encrypt, qp)
            if name == "trace-packed":
                sample["server_s"], response = timed(
                    trace.search, encrypted, index, len(rows), case.pk, keys
                )
            else:
                sample["server_s"], response = timed(case.evaluate, encrypted, index)
            sample["client_decrypt_s"], plaintexts = timed(
                lambda response=response: [case.decrypt(ct) for ct in response]
            )
            decode = (
                (
                    lambda plaintexts=plaintexts: trace.decode(
                        plaintexts, len(rows), args.embed_len, case.pk
                    )
                )
                if name == "trace-packed"
                else (
                    lambda plaintexts=plaintexts: bgv.decode_coefficients(
                        plaintexts, len(rows), args.embed_len, case.n, case.t
                    )
                )
            )
            sample["client_score_decode_s"], distances = timed(decode)
            assert distances == expected
            sample["response_bytes"] = len(case.pack(response, len(rows)))
            sample["query_bytes"] = len(case.pack([encrypted], 1))
            sample["response_ciphertexts"] = len(response)
            sample["phase_bound_bits"] = max(ct.phase_bound for ct in response).bit_length()
            if repeat:
                samples[name].append(sample)
            else:
                warmup[name] = sample
            print(
                f"{name}, round {repeat}: server={sample['server_s']:.3f}s",
                file=sys.stderr,
                flush=True,
            )
    full_tiles = (8192 + case.n // padded - 1) // (case.n // padded)
    bound = trace.projected_bound(case.pk, keys, min(full_tiles, padded))
    projection = {
        "kind": "analytical_8192_candidate_bound_and_raw_bytes_NOT_a_runtime_measurement",
        "input_tiles": full_tiles,
        "response_ciphertexts": (8192 + case.n - 1) // case.n,
        "raw_response_bytes": ((8192 + case.n - 1) // case.n)
        * 2
        * ((case.n * case.q.bit_length() + 7) // 8),
        "phase_bound_bits": bound.bit_length(),
        "conservative_no_wrap_bound_holds": 2 * bound < case.q,
        "relinearizations": full_tiles,
        "projection_automorphisms": full_tiles * (padded.bit_length() - 1),
        "packing_automorphisms": 0,
    }
    sources = [
        Path(__file__).resolve(),
        REPO_ROOT / "experiments/bfv_search_lab/trace_bgv.py",
        REPO_ROOT / "experiments/bfv_search_lab/shallow_bgv.py",
    ]
    report = {
        "kind": "cpu_encrypted_trace_packing_pilot_no_attestation",
        "utc": datetime.now(UTC).isoformat(),
        "command": sys.argv,
        "python": sys.version,
        "platform": platform.platform(),
        "num_vectors": len(rows),
        "dimension": args.embed_len,
        "n": case.n,
        "t": case.t,
        "q_bits": case.q.bit_length(),
        "digit_bits": keys.digit_bits,
        "notes": "Same encrypted index and independently encrypted queries for both references. "
        "CPU Python/GMP only; no native key switching or GPU implementation. "
        "Phase bounds are public conservative correctness bounds, not security estimates. "
        "Timings are arithmetic phases, not complete framed/network search latency. "
        "Response bytes include generic coefficient framing; trace circuit binding is not an authenticated wire protocol. "
        "Unrepacked plaintext reveals extra correlations; owner is authorized for all input data.",
        "setup": setup,
        "warmup": warmup,
        "results": [
            {
                "variant": name,
                "samples": rows,
                "medians": {k: statistics.median(v[k] for v in rows) for k in rows[0]},
            }
            for name, rows in samples.items()
        ],
        "full_workload_projection": projection,
        "all_distances_correct": True,
        "sha256": {
            str(p.relative_to(REPO_ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sources
        },
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    for row in report["results"]:
        print(row["variant"], row["medians"])


if __name__ == "__main__":
    main()
