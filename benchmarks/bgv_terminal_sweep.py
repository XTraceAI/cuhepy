#!/usr/bin/env python3
"""Paired terminal-precision sweep with unchanged homemade BGV keys and circuit.

Each fresh query is reused across requested terminal moduli in shuffled order.
Check the conservative bound BEFORE each native call; compare complete compact
ciphertexts with Python rounding and all plaintext coefficients with decryption
before reduction. This is arithmetic assurance, not a security certification.
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=8192)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--terminal-bits", type=int, nargs="+", default=[24, 25, 26, 28, 32])
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if min(args.num_vectors, args.repeats) < 1 or len(set(args.terminal_bits)) != len(args.terminal_bits):
        parser.error("Positive counts and distinct terminal sizes required")
    setup = {}
    setup["owner_keygen_s"], case = timed(Case, "bgv", args.ring_degree, 1031, 120, rns_modulus=True)
    rows, query, _ = make_data(args.num_vectors, args.embed_len, 1701)
    padded = 1 << (args.embed_len - 1).bit_length()
    setup["evaluation_keys_s"], keys = timed(trace.evaluation_keys, case.pk, case.sk, padded)
    _, tiles = bgv.coefficient_inputs(query, rows, case.n)
    setup["index_encrypt_s"], index = timed(lambda: [case.encrypt(tile) for tile in tiles])
    setup["cuda_plan_s"], server = timed(NativeServer, case.pk, keys, residue=True, device="cuda", cuda_level=4)
    setup["index_prepare_s"], prepared = timed(server.prepare_index, index, len(rows))
    samples, warmups, rejected = {bits: [] for bits in args.terminal_bits}, {}, {}
    moduli = {bits: compact.terminal_modulus(case.q, case.t, bits) for bits in args.terminal_bits}
    rng = random.Random(20260927)
    coefficients_checked = ciphertexts_checked = 0
    for repeat in range(args.repeats + 1):
        current = [rng.randrange(2) for _ in query]
        encode_s, encoded = timed(lambda current=current: bgv.coefficient_inputs(current, [], case.n)[0])
        encrypt_s, packet = timed(seeded_bgv.encrypt, encoded, case.pk, case.sk)
        expand_s, encrypted = timed(seeded_bgv.expand, packet, case.pk)
        full = server.search(encrypted, prepared)
        full_plaintext = [bgv.decrypt(ct, case.pk, case.sk) for ct in full]
        expected = [sum(a != b for a, b in zip(current, row, strict=True)) for row in rows]
        order = args.terminal_bits.copy()
        rng.shuffle(order)
        for bits in order:
            p = moduli[bits]
            # Public worst-case arithmetic bound, not the sampled private noise.
            bound = max(int((p * ct.phase_bound + case.q - 1) // case.q) + ((case.n + 1) * case.t + 1) // 2 for ct in full)
            if 2 * bound >= p:
                try:
                    server.search_compact(encrypted, prepared, bits=bits)
                except ValueError as error:
                    if "correctness bound" not in str(error):
                        raise
                else:
                    raise AssertionError("Unsafe terminal bound was accepted")
                rejected[bits] = {"reason": "conservative correctness bound reaches P/2",
                                  "p": int(p), "phase_bound": bound, "twice_bound_minus_p": 2 * bound - int(p)}
                continue
            server_s, small = timed(server.search_compact, encrypted, prepared, bits=bits)
            assert small == [compact.compact(ct, case.pk, bits) for ct in full]
            ciphertexts_checked += len(small)
            decrypt_s, plaintexts = timed(lambda small=small: [compact.decrypt(ct, case.pk, case.sk) for ct in small])
            assert plaintexts == full_plaintext
            coefficients_checked += case.n * len(small)
            pack_s, wire = timed(compact.pack, small, len(rows), len(query), case.pk)
            decode_s, distances = timed(trace.decode, plaintexts, len(rows), len(query), case.pk)
            assert distances == expected
            top_s, top = timed(lambda distances=distances: sorted(range(len(rows)), key=lambda i: (distances[i], i))[:3])
            assert top == sorted(range(len(rows)), key=lambda i: (expected[i], i))[:3]
            phases = {"query_encode_s": encode_s, "query_encrypt_s": encrypt_s,
                      "server_query_expand_s": expand_s, "server_evaluate_and_compact_s": server_s,
                      "response_pack_s": pack_s, "client_decrypt_s": decrypt_s,
                      "client_decode_s": decode_s, "client_top3_s": top_s}
            entry = {**phases, "local_phases_s": sum(phases.values()),
                     "query_bytes": len(packet), "response_bytes": len(wire),
                     "query_plus_response_bytes": len(packet) + len(wire),
                     "phase_bound": bound, "p_over_twice_bound": int(p) / (2 * bound)}
            if repeat:
                samples[bits].append(entry)
            else:
                warmups[bits] = entry
            print(f"terminal {bits}, round {repeat}: {len(wire)} response bytes, "
                  f"local phases={entry['local_phases_s']:.4f}s", file=sys.stderr, flush=True)
    sources = [Path(__file__).resolve(), REPO_ROOT / "benchmarks/coefficient_search_lab.py",
               REPO_ROOT / "benchmarks/bfv_client_matrix.py", REPO_ROOT / "src/cuhepy/bfv/scheme.py",
               REPO_ROOT / "src/cuhepy/types.py"]
    lab = REPO_ROOT / "experiments/bfv_search_lab"
    sources += sorted(lab.glob("*.py")) + sorted((lab / "_native").glob("*.h")) + sorted((lab / "_native").glob("*.cuh"))
    sources += [lab / "_native" / name for name in ("bindings.cpp", "bindings.cu", "Makefile")]
    sources += sorted((REPO_ROOT / "src/cuhepy/bfv/_cpu_ext").glob("*.h")) + sorted((REPO_ROOT / "src/cuhepy/bfv/_gpu_ext").glob("*.cuh"))
    report = {
        "kind": "paired_homemade_bgv_terminal_precision", "utc": datetime.now(UTC).isoformat(),
        "command": sys.argv, "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip(),
        "platform": platform.platform(), "python": sys.version,
        "cpu": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), platform.machine()),
        "gpu": subprocess.check_output(["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"], text=True).strip(),
        "n": case.n, "t": case.t, "q_hex": format(case.q, "x"), "eta": case.pk.eta,
        "dimension": len(query), "num_vectors": len(rows), "digit_bits": keys.digit_bits,
        "moduli": {bits: int(p) for bits, p in moduli.items()},
        "notes": __doc__ + " Local phases exclude setup, parsing, network and attestation. One excluded warmup. No keys/ciphertexts saved.",
        "setup": setup, "warmup": warmups, "rejected": rejected,
        "results": [{"terminal_bits": bits, "samples": entries,
                     "medians": {key: statistics.median(row[key] for row in entries) for key in entries[0]}}
                    for bits, entries in samples.items() if entries],
        "exact_compact_ciphertexts_checked": ciphertexts_checked,
        "every_plaintext_coefficient_checked": coefficients_checked,
        "every_distance_and_stable_top3_correct": ciphertexts_checked > 0,
        "sha256": {str(path.relative_to(REPO_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
        "native_binary_sha256": hashlib.sha256(Path(server._native.__file__).read_bytes()).hexdigest(),
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    for row in report["results"]:
        print(row["terminal_bits"], row["medians"])
    print("rejected", rejected)


if __name__ == "__main__":
    main()
