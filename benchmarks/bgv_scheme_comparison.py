#!/usr/bin/env python3
"""Same-workload local BGV/BFV/Paillier comparison, including client and framing.

All arithmetic is homemade. SEAL remains a separate correctness oracle. This
trusted local fixture supplies no malicious-server protocol or security-equivalent
parameter claim. Paillier CUDA variants also require a GPU at the client; BFV/BGV
use a CPU client. Setup/network/TLS/attestation/content retrieval are excluded.
"""

import argparse
from contextlib import ExitStack
from datetime import UTC, datetime
from functools import partial
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
from bfv_paillier_latency import bfv_cases, paillier_case, run_query
from bgv_service_pipeline import provenance, timed

sys.path.insert(0, str(REPO_ROOT))
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, owner_bgv, transport_bgv
from experiments.bfv_search_lab.native_bgv import NativeServer

VARIANTS = (
    "paillier-cpu",
    "paillier-cuda",
    "paillier-lookup-cpu",
    "paillier-lookup-cuda",
    "bfv-cpu",
    "bfv-cuda-prepared",
    "bgv-cpu-rns-owner",
    "bgv-cuda-workspace-rns-owner",
)


def bgv_cases(args, rows, stack):
    setup = {}
    setup["keygen_s"], pair = timed(
        bgv.key_gen, args.poly_modulus_degree, q_bits=120, rns_modulus=True
    )
    pk, sk = pair
    setup["evaluation_keys_s"], keys = timed(
        trace.evaluation_keys, pk, sk, 1 << (args.embed_len - 1).bit_length()
    )
    _, plain_index = bgv.coefficient_inputs([0] * args.embed_len, rows, pk.n)
    setup["index_encrypt_s"], index = timed(lambda: [bgv.encrypt(p, pk) for p in plain_index])
    setup["owner_s"], client = timed(owner_bgv.OwnerClient, pk, sk, native=True, rns=True)
    setup["owner_terminal_prepare_s"] = timed(client.prepare_terminal, 25)[0]
    stack.callback(client.close)
    cases = {}
    for name, device in (("bgv-cpu-rns-owner", "cpu"), ("bgv-cuda-workspace-rns-owner", "cuda")):
        if name not in args.variants:
            continue
        setup[device + "_server_s"], server = timed(
            NativeServer,
            pk,
            keys,
            residue=True,
            device=device,
            cuda_level=4 if device == "cuda" else 0,
        )
        setup[device + "_index_prepare_s"], prepared = timed(server.prepare_index, index, len(rows))
        if device == "cuda":
            setup["workspace_prepare_s"], workspace = timed(server.prepare_workspace, prepared)
            stack.callback(workspace.close)
            evaluate = partial(workspace.search_compact, bits=25)
        else:
            evaluate = partial(server.search_compact, index=prepared, bits=25)

        def run(plain, evaluate=evaluate):
            begin = time.perf_counter()
            timings = {}

            def encrypt():
                encoded = bgv.coefficient_inputs(plain, [], pk.n)[0]
                return client.encrypt(encoded)

            timings["query_encrypt_s"], packet = timed(encrypt)
            timings["query_serialize_s"] = 0.0  # Already included in the native owner API.
            timings["query_deserialize_s"], query = timed(owner_bgv.expand, packet, pk)
            timings["server_evaluate_s"], response = timed(evaluate, query)
            timings["response_serialize_s"], wire = timed(
                compact.pack, response, len(rows), args.embed_len, pk
            )
            timings["response_deserialize_s"], parsed = timed(
                transport_bgv.unpack_fixture,
                wire,
                pk,
                count=len(rows),
                dimension=args.embed_len,
                modulus=response[0].modulus,
                bounds=[c.phase_bound for c in response],
            )
            timings["response_decode_s"], result = timed(
                client.finish, parsed, len(rows), args.embed_len
            )
            timings["top3_s"] = 0.0  # Included by the native finisher.
            timings["local_total_s"] = time.perf_counter() - begin
            timings["client_prepare_s"] = timings["query_encrypt_s"]
            timings["server_total_s"] = sum(
                timings[k]
                for k in ("query_deserialize_s", "server_evaluate_s", "response_serialize_s")
            )
            timings["client_finish_s"] = (
                timings["response_deserialize_s"] + timings["response_decode_s"]
            )
            sample = {
                "timings": timings,
                "query_bytes": len(packet),
                "response_bytes": len(wire),
                "query_plus_response_bytes": len(packet) + len(wire),
                "response_ciphertexts": len(response),
            }
            return list(result.distances), [i for i, _ in result.top], sample

        cases[name] = (
            run,
            {
                "config": {
                    "n": pk.n,
                    "t": pk.t,
                    "q_hex": format(pk.q, "x"),
                    "eta": pk.eta,
                    "terminal_bits": 25,
                    "owner_rns": True,
                },
                "setup_timings": setup,
                "client_device": "cpu",
                "server_device": device,
                "shared_setup_group": "bgv",
            },
        )
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=8192)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--poly-modulus-degree", type=int, default=16384)
    parser.add_argument("--alpha-len", type=int, default=280)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--variants", choices=VARIANTS, nargs="+", default=list(VARIANTS))
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if (
        not 3 <= args.num_vectors <= 65536
        or not 1 <= args.embed_len <= 512
        or args.repeats < 1
        or args.poly_modulus_degree not in (2048, 4096, 8192, 16384)
        or not 256 <= args.alpha_len < 1024
    ):
        parser.error("Invalid bounded comparison workload")
    rows, _, _ = make_data(args.num_vectors, args.embed_len, 1701)
    cases, results = {}, {}
    with ExitStack() as stack:
        for name in args.variants:
            if name.startswith("paillier"):
                case = paillier_case(name, args, rows)
                cases[name] = (lambda q, case=case: run_query(case, q, len(rows)), case.info)
        if any(name.startswith("bfv") for name in args.variants):
            for case in bfv_cases(args, rows, stack):
                cases[case.name] = (lambda q, case=case: run_query(case, q, len(rows)), case.info)
        if any(name.startswith("bgv") for name in args.variants):
            cases.update(bgv_cases(args, rows, stack))
        rng = random.Random(20260925)
        for repeat in range(args.repeats + 1):
            query = [rng.randrange(2) for _ in range(args.embed_len)]
            expected = [sum(a != b for a, b in zip(row, query, strict=True)) for row in rows]
            top = sorted(range(len(rows)), key=lambda i: (expected[i], i))[:3]
            order = list(cases)
            rng.shuffle(order)
            for name in order:
                run, _ = cases[name]
                distances, actual_top, sample = run(query)
                if distances != expected or actual_top != top:
                    raise AssertionError(f"Incorrect distances/top-3 for {name}")
                sample["warmup"] = repeat == 0
                results.setdefault(name, []).append(sample)
                print(
                    name,
                    "round",
                    repeat,
                    "local",
                    round(sample["timings"]["local_total_s"], 5),
                    flush=True,
                )
        report = {
            "kind": "same_workload_homemade_scheme_comparison",
            "scope": __doc__,
            "command": sys.argv,
            "utc": datetime.now(UTC).isoformat(),
            "num_vectors": len(rows),
            "dimension": args.embed_len,
            "plaintext_index_seed": 1701,
            "query_and_order_seed": 20260925,
            "python": sys.version,
            "platform": platform.platform(),
            "cpu": subprocess.check_output(["lscpu"], text=True).strip(),
            "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
            "gpu": subprocess.check_output(
                ["nvidia-smi", "--query-gpu=name,driver_version", "--format=csv,noheader"],
                text=True,
            ).strip(),
            "results": [
                {
                    "variant": name,
                    **cases[name][1],
                    "samples": samples,
                    "warm_medians_s": {
                        k: statistics.median(s["timings"][k] for s in samples[1:])
                        for k in samples[0]["timings"]
                    },
                    "query_bytes": samples[0]["query_bytes"],
                    "response_bytes": samples[0]["response_bytes"],
                }
                for name, samples in results.items()
            ],
            "source_and_binary_sha256": provenance(),
            "all_distances_and_top3_correct": True,
        }
        sources = [
            p
            for p in (REPO_ROOT / "src/cuhepy").rglob("*")
            if p.is_file()
            and (
                p.suffix in (".py", ".pyi", ".cu", ".cuh", ".cpp", ".h", ".so")
                or p.name == "Makefile"
            )
        ]
        for path in [
            Path(__file__).resolve(),
            REPO_ROOT / "benchmarks/bfv_paillier_latency.py",
            *sorted(sources),
        ]:
            report["source_and_binary_sha256"][str(path.relative_to(REPO_ROOT))] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
