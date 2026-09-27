#!/usr/bin/env python3
"""Paired full-size native CPU/CUDA test of EXACT coordinate folding (E22).

Homemade BGV throughout. Local synthetic owner fixture, generic conservative
bounds, identical encryption ring/moduli, terminal precision and kernel options.
This compares representations in the ordinary native API; it is not a new
production service benchmark or a comparison with every optimized codec/path.
"""

# ruff: noqa: E402 -- standalone benchmark imports the repository sandbox.

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import UTC, datetime
import gc
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import structured_fixture, timed
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import folded_filter as folded
from experiments.bfv_search_lab import linear_packing as packing
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab.native_bgv import NativeServer


def run(args):
    _, rows = structured_fixture(args.count, args.dimension, args.groups, 0, 2806)
    setup = {}
    setup["fold_preprocessing_s"], folded_plan = timed(folded.prepare, rows, args.dimension)
    assert folded_plan.max_error == 0
    full = folded.FoldPlan(args.dimension, tuple(range(args.dimension)), tuple((j, 0) for j in range(args.dimension)), 0)
    plans = {"full": full, "folded": folded_plan}
    setup["keygen_s"], (pk, sk) = timed(bgv.key_gen, args.ring_degree, q_bits=120, rns_modulus=True)
    width = (pk.q.bit_length() + 7) // 8
    cases = {}
    with closing(owner.OwnerClient(pk, sk, native=True, rns=True)) as client:
        setup["terminal_prepare_s"] = timed(client.prepare_terminal, 32)[0]
        for name, plan in plans.items():
            print(f"Preparing {name}: {plan.features} features", file=sys.stderr, flush=True)
            encode_s, (_, tiles, padded) = timed(folded.inputs, plan, 0, rows, pk.n)
            key_s, keys = timed(trace.evaluation_keys, pk, sk, padded)
            index_s, encrypted = timed(lambda tiles=tiles: [owner.expand(client.encrypt(p), pk) for p in tiles])
            entry = {"index_encode_s": encode_s, "evaluation_keys_s": key_s, "index_encrypt_expand_s": index_s,
                     "features": plan.features, "padded": padded, "index_ciphertexts": len(tiles),
                     "index_full_coefficient_bytes": len(tiles) * 2 * pk.n * width,
                     "evaluation_key_coefficient_bytes": (1 + len(keys.rotations)) * len(keys.relin) * 2 * pk.n * width}
            del tiles
            for device in args.devices:
                prepare_s, server = timed(NativeServer, pk, keys, residue=True, device=device,
                                          cuda_level=4 if device == "cuda" else 0,
                                          ntt_variant="indexed" if device == "cuda" else "baseline")
                index_prepare_s, prepared = timed(server.prepare_index, encrypted, len(rows))
                cases[name + "/" + device] = (name, server, prepared)
                entry[device] = {"server_prepare_s": prepare_s, "index_prepare_s": index_prepare_s}
            setup[name] = entry
            del encrypted, keys
            gc.collect()
        samples = {name: [] for name in cases}
        warmup = {}
        rng = random.Random(2807)
        for repeat in range(args.repeats + 1):
            query = rng.getrandbits(args.dimension) if repeat % 2 else rows[rng.randrange(len(rows))] ^ 31
            expected = [(query ^ row).bit_count() for row in rows]
            expected_top = sorted((d, i) for i, d in enumerate(expected))[:3]
            queries = {}
            for name, plan in plans.items():
                encode_s, (qp, _, _) = timed(folded.inputs, plan, query, [], pk.n)
                encrypt_s, packet = timed(client.encrypt, qp)
                expand_s, cipher = timed(owner.expand, packet, pk)
                queries[name] = (cipher, encode_s, encrypt_s, expand_s, len(packet))
            order = list(cases)
            rng.shuffle(order)
            complete = {}
            for label in order:
                name, server, prepared = cases[label]
                cipher, encode_s, encrypt_s, expand_s, query_bytes = queries[name]
                server_s, output = timed(server.search_compact, cipher, prepared, bits=32)
                pack_s, wire = timed(compact.pack, output, len(rows), args.dimension, pk)
                if name in complete:
                    assert wire == complete[name], "CPU and CUDA differ on complete response bytes"
                complete[name] = wire
                decrypt_s, plain = timed(lambda output=output: [client.decrypt_compact(c) for c in output])

                def finish(name=name, plain=plain, padded=server.keys.padded):
                    dots = packing.unpack(plain, len(rows), padded, pk.n, pk.t)
                    distances = folded.decode(plans[name], dots, pk.t)
                    return distances, sorted((d, i) for i, d in enumerate(distances))[:3]

                finish_s, (decoded, top) = timed(finish)
                assert decoded == expected and top == expected_top
                sample = {"server_s": server_s, "encode_s": encode_s, "encrypt_s": encrypt_s,
                          "query_expand_s": expand_s, "response_pack_s": pack_s, "decrypt_s": decrypt_s,
                          "decode_select_s": finish_s,
                          "local_total_s": sum((encode_s, encrypt_s, expand_s, server_s, pack_s, decrypt_s, finish_s)),
                          "query_bytes": query_bytes, "response_bytes": len(wire),
                          "response_ciphertexts": len(output), "query_kind": "uniform" if repeat % 2 else "near-row"}
                if repeat:
                    samples[label].append(sample)
                else:
                    warmup[label] = sample
            print(f"Paired native round {repeat}/{args.repeats}", file=sys.stderr, flush=True)
    medians = {name: {key: statistics.median(r[key] for r in values) for key in values[0] if key != "query_kind"}
               for name, values in samples.items()}
    return {"count": len(rows), "dimension": args.dimension, "unique_rows": len(set(rows)),
            "groups": len(folded_plan.representatives), "n": pk.n, "t": pk.t, "q_bits": pk.q.bit_length(),
            "eta": pk.eta, "digit_bits": 30, "terminal_bits": 32, "setup": setup,
            "warmup": warmup, "samples": samples, "medians": medians,
            "all_distances_and_stable_top3_exact": True,
            "complete_cpu_cuda_bytes_equal": True if len(args.devices) == 2 else None,
            "query_and_response_bytes_equal_between_layouts": all(
                medians[f"full/{d}"][k] == medians[f"folded/{d}"][k]
                for d in args.devices for k in ("query_bytes", "response_bytes")),
            "authentication_implemented": False, "security_parameter_review": "unchanged unreviewed research context"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=8192)
    parser.add_argument("--dimension", type=int, default=512)
    parser.add_argument("--groups", type=int, default=48)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--devices", nargs="+", choices=("cpu", "cuda"), default=["cpu", "cuda"])
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if (not 3 <= args.count <= 32768 or not 5 <= args.dimension <= 512 or not 1 <= args.groups <= args.dimension
            or not 1 <= args.repeats <= 100 or len(set(args.devices)) != len(args.devices)):
        parser.error("Invalid bounded exact-folding workload")
    packing.packing_cost(args.dimension, args.count, args.ring_degree)
    paths = [Path(__file__), ROOT / "benchmarks/certified_filter_lab.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "folded_filter", "linear_packing", "native_bgv", "owner_bgv", "native_owner_bgv", "seeded_bgv",
        "private_bgv", "compact_bgv", "shallow_bgv", "trace_bgv", "butterfly_bgv"))
    modules = ["experiments.bfv_search_lab._native._bgv_trace", "experiments.bfv_search_lab._owner._bgv_owner"]
    if "cuda" in args.devices:
        modules.append("experiments.bfv_search_lab._native._bgv_trace_cuda")
    for module in modules:
        paths.append(Path(importlib.import_module(module).__file__))
    result = {"kind": "exact_folded_bgv_native_paired_local_fixture", "utc": datetime.now(UTC).isoformat(),
              "command": sys.argv, "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "python": platform.python_version(), "platform": platform.platform(),
              "omp_num_threads": os.environ.get("OMP_NUM_THREADS"),
              "source_binary_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
              "notes": "Deliberately redundant columns; every synthetic row is checked for uniqueness. "
                       "Same ring, moduli, secret key, index encryption mode, terminal precision and native API. "
                       "Uniform and near-row queries alternate; paired orders shuffled after a warmup. "
                       "Does not use the separately optimized packed workspace/codec path or binary-only support bound. "
                       "Local compute excludes setup, network, attestation/proofs and independent full-score comparisons. "
                       "Owner keeps the data-derived folding map. Layout size can leak structure. No production speedup claim.",
              "result": run(args)}
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
