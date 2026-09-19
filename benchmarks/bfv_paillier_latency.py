#!/usr/bin/env python3
"""Compare local BFV/Paillier search latency, roles, and actual wire sizes.

All responses are generated locally and checked against plaintext. This is a
performance harness, not a protocol for decrypting untrusted server responses.
One warmup precedes the measured queries; setup and network transit are separate.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
import gc
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
from typing import Any

import gmpy2

from bfv_client_matrix import REPO_ROOT, make_data, packet, unpack_packet
from cuhepy.bfv.private import BFVPrivateDecoder
from cuhepy.hamming.bfv import BFVClient
from cuhepy.hamming.paillier import PaillierClient
from cuhepy.hamming.paillier_lookup import PaillierLookupClient

PAILLIER = (
    "paillier-cpu",
    "paillier-cuda",
    "paillier-lookup-cpu",
    "paillier-lookup-cuda",
    "paillier-lookup-hybrid",
)
BFV = ("bfv-cpu", "bfv-cuda", "bfv-cuda-prepared")


def measure(timings: dict[str, float], name: str, fn: Callable[[], Any]) -> Any:
    start = time.perf_counter()
    value = fn()
    timings[name] = time.perf_counter() - start
    return value


def progress(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


@dataclass
class Case:
    name: str
    client: Any
    evaluate: Callable[[list[int]], list[list[int]]]
    decode: Callable[[list[list[int]]], list[int]]
    info: dict[str, Any]


def paillier_case(name: str, args: argparse.Namespace, vectors: list[list[int]]) -> Case:
    setup: dict[str, float] = {}
    lookup = "lookup" in name
    gpu_client = not name.endswith("cpu")
    gpu_server = name.endswith("cuda")
    device = "gpu" if gpu_client else "cpu"
    client = measure(
        setup,
        "key_generation_s",
        lambda: (
            PaillierLookupClient(args.embed_len, 1024, args.alpha_len, device=device)
            if lookup
            else PaillierClient(args.embed_len, 1024, device=device)
        ),
    )
    if client.device != device:
        raise AssertionError("Requested device was not selected")
    config = json.loads(client.stringify_config())
    public = measure(setup, "public_key_export_s", client.stringify_pk)
    pk = measure(setup, "public_key_import_s", lambda: json.loads(public))
    modulus = gmpy2.mpz(pk["n_squared"])
    config["actual_modulus_bits"] = int(pk["n"]).bit_length()
    # Record only the exponent length, never its value or other secret material.
    secret = json.loads(client.stringify_sk())
    config["decryption_exponent_bits"] = int(secret["a" if lookup else "phi"]).bit_length()
    del secret
    if lookup and config["alpha_len"] != args.alpha_len:
        raise AssertionError("Lookup alpha_len differs from requested configuration")
    progress(f"{name}: encrypting {len(vectors)} index vectors")
    index = measure(setup, "index_encrypt_s", lambda: client.encrypt_vec_batch(vectors))
    wire = measure(setup, "index_serialize_s", lambda: packet(index, len(vectors)))
    server_index = measure(setup, "index_deserialize_s", lambda: unpack_packet(wire))
    gpu_evaluate = type(client.client).encode_hamming_server if gpu_server else None

    def evaluate(query: list[int]) -> list[list[int]]:
        if gpu_evaluate is None:
            return [
                [int(gmpy2.mpz(a) * b % modulus) for a, b in zip(query, row, strict=True)]
                for row in server_index
            ]
        # One existing CUDA API call for the full batch, never one launch per row.
        query_chunks = query * len(server_index)
        index_chunks = [c for row in server_index for c in row]
        if lookup:
            flat = [int(c) for c in gpu_evaluate(query_chunks, index_chunks, pk)]
        else:
            flat = [
                int(c, 16)
                for c in gpu_evaluate(
                    [format(c, "x") for c in query_chunks],
                    [format(c, "x") for c in index_chunks],
                    {"n_squared": format(int(modulus), "x")},
                )
            ]
        return [flat[i : i + len(query)] for i in range(0, len(flat), len(query))]

    return Case(
        name,
        client,
        evaluate,
        client.decode_hamming_client_batch,
        {
            "config": config,
            "client_device": device,
            "server_device": "gpu" if gpu_server else "cpu",
            "server_backend": "CUDA public multiplication"
            if gpu_server
            else "GMP public multiplication",
            "setup_timings": setup,
            "public_keys_bytes": len(public.encode()),
            "encrypted_index_bytes": len(wire),
            "index_ciphertexts": len(index),
        },
    )


def bfv_cases(args: argparse.Namespace, vectors: list[list[int]], stack: ExitStack) -> list[Case]:
    setup: dict[str, float] = {}
    owner = measure(
        setup,
        "key_generation_s",
        lambda: BFVClient(
            args.embed_len,
            args.poly_modulus_degree,
            65537,
            180,
            30,
            rns_modulus=True,
            server_backend="residue",
        ),
    )
    decoder = measure(setup, "private_context_s", lambda: BFVPrivateDecoder(owner))
    stack.callback(decoder.close)
    config = json.loads(owner.stringify_config())
    public = measure(setup, "public_key_export_s", owner.stringify_pk)
    progress(f"BFV: encrypting one shared index of {len(vectors)} vectors")
    index = measure(setup, "index_encrypt_s", lambda: owner.encrypt_vec_packed(vectors))
    wire = measure(setup, "index_serialize_s", lambda: packet(index, len(vectors)))
    server_index = measure(setup, "index_deserialize_s", lambda: unpack_packet(wire))
    servers = {}
    cases = []
    for name in BFV:
        if name not in args.variants:
            continue
        backend = "residue" if name == "bfv-cpu" else "cuda"
        if backend not in servers:

            def import_server(backend=backend):
                server = BFVClient(skip_key_gen=True, server_backend=backend)
                server.load_config(config)
                server.load_stringified_keys(public, max_public_key_chars=256 * 1024 * 1024)
                assert server.keys is None
                server._native()  # Plan preparation belongs to setup for every backend.
                return server

            servers[backend] = measure(setup, backend + "_public_plan_s", import_server)
        server = servers[backend]
        resident_bytes = 0
        if name == "bfv-cuda-prepared":
            prepared = measure(
                setup,
                "gpu_index_prepare_s",
                partial(
                    server.prepare_cuda_index,
                    server_index,
                    len(vectors),
                ),
            )
            resident_bytes = prepared.device_bytes
            evaluate = partial(server.encode_hamming_server_prepared, index=prepared)
        else:
            evaluate = partial(
                server.encode_hamming_server_packed, index=server_index, vector_count=len(vectors)
            )
        cases.append(
            Case(
                name,
                owner,
                evaluate,
                partial(decoder.decode_packed, vector_count=len(vectors)),
                {
                    "config": config,
                    "client_device": "cpu",
                    "private_backend": "native BFVPrivateDecoder",
                    "server_device": "cpu" if backend == "residue" else "gpu",
                    "server_backend": backend,
                    "setup_timings": setup,
                    "shared_setup_group": "bfv",
                    "public_keys_bytes": len(public.encode()),
                    "encrypted_index_bytes": len(wire),
                    "index_ciphertexts": len(index),
                    "resident_index_bytes": resident_bytes,
                },
            )
        )
    return cases


def run_query(
    case: Case, query: list[int], count: int
) -> tuple[list[int], list[int], dict[str, Any]]:
    timings: dict[str, float] = {}
    start = time.perf_counter()
    encrypted = measure(timings, "query_encrypt_s", lambda: case.client.encrypt_vec_one(query))
    request = measure(timings, "query_serialize_s", lambda: packet([encrypted], 1))
    received_query = measure(timings, "query_deserialize_s", lambda: unpack_packet(request)[0])
    result = measure(timings, "server_evaluate_s", lambda: case.evaluate(received_query))
    response = measure(timings, "response_serialize_s", lambda: packet(result, count))
    received = measure(timings, "response_deserialize_s", lambda: unpack_packet(response))
    distances = measure(timings, "response_decode_s", lambda: case.decode(received))
    top3 = measure(
        timings, "top3_s", lambda: sorted(range(count), key=lambda i: (distances[i], i))[:3]
    )
    timings["local_total_s"] = time.perf_counter() - start
    timings["client_prepare_s"] = timings["query_encrypt_s"] + timings["query_serialize_s"]
    timings["server_total_s"] = sum(
        timings[k] for k in ("query_deserialize_s", "server_evaluate_s", "response_serialize_s")
    )
    timings["client_finish_s"] = sum(
        timings[k] for k in ("response_deserialize_s", "response_decode_s", "top3_s")
    )
    return (
        distances,
        top3,
        {
            "timings": timings,
            "query_bytes": len(request),
            "response_bytes": len(response),
            "query_plus_response_bytes": len(request) + len(response),
            "response_ciphertexts": len(result),
        },
    )


def benchmark(
    cases: list[Case], args: argparse.Namespace, query: list[int], expected: list[int]
) -> list[dict[str, Any]]:
    samples = {case.name: [] for case in cases}
    expected_top3 = sorted(range(len(expected)), key=lambda i: (expected[i], i))[:3]
    for repeat in range(args.repeats + 1):
        for case in cases if repeat % 2 == 0 else reversed(cases):
            gc.collect()
            progress(f"{case.name}: {'warmup' if repeat == 0 else 'trial ' + str(repeat)}")
            distances, top3, sample = run_query(case, query, len(expected))
            assert distances == expected, f"{case.name}: distance mismatch"
            assert top3 == expected_top3, f"{case.name}: top-three mismatch"
            sample.update(
                {"repeat": repeat, "warmup": repeat == 0, "all_distances_and_top3_correct": True}
            )
            samples[case.name].append(sample)
            progress(
                f"  server {sample['timings']['server_evaluate_s']:.6f}s; local total {sample['timings']['local_total_s']:.6f}s"
            )
    return [
        {
            "variant": case.name,
            **case.info,
            "samples": samples[case.name],
            "warm_medians_s": {
                phase: statistics.median(s["timings"][phase] for s in samples[case.name][1:])
                for phase in samples[case.name][0]["timings"]
            },
            "warm_median_bytes": {
                key: statistics.median(s[key] for s in samples[case.name][1:])
                for key in ("query_bytes", "response_bytes", "query_plus_response_bytes")
            },
            "all_distances_and_top3_correct": True,
        }
        for case in cases
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=8192)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--poly-modulus-degree", type=int, default=16384)
    parser.add_argument("--alpha-len", type=int, default=280)
    parser.add_argument("--repeats", type=int, default=3, help="Measured trials, after one warmup")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument(
        "--variants", nargs="+", choices=(*PAILLIER, *BFV), default=[*PAILLIER, *BFV]
    )
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if (
        args.repeats < 1
        or not 3 <= args.num_vectors <= 65536
        or not 1 <= args.embed_len <= 512
        or not 256 <= args.alpha_len < 1024
    ):
        parser.error("Use repeats>=1, 3..65536 vectors, 1..512 dimensions, and alpha_len>=256")

    def command(*cmd):
        return subprocess.check_output(cmd, cwd=REPO_ROOT, text=True).strip()

    sources = [Path(__file__).resolve(), REPO_ROOT / "benchmarks/bfv_client_matrix.py"]
    sources.extend(
        p
        for p in (REPO_ROOT / "src/cuhepy").rglob("*")
        if p.is_file() and p.suffix in (".py", ".cpp", ".cu", ".cuh", ".h", ".so")
    )
    output = {
        "environment": {
            "utc": datetime.now(UTC).isoformat(),
            "revision": command("git", "rev-parse", "HEAD"),
            "working_tree_dirty": bool(command("git", "status", "--porcelain")),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "gmp": gmpy2.mp_version(),
            "cpu": next(
                line.split(":", 1)[1].strip()
                for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")
            ),
            "gpu": command(
                "nvidia-smi",
                "--query-gpu=name,memory.total,driver_version",
                "--format=csv,noheader",
            ),
            "nvcc": command("nvcc", "--version"),
            "compiler": command("g++-12", "--version"),
        },
        "command": sys.argv,
        "vectors": args.num_vectors,
        "embed_len": args.embed_len,
        "seed": args.seed,
        "notes": (
            "One warmup then measured repeats, with fresh query encryption each time. Same synthetic plaintext corpus/query in every case. "
            "BFV cases share keys/index and alternate order. Paillier cases use independent keys; hybrid uses CUDA client and CPU server. "
            "All server functions receive public inputs only. One batched CUDA server call for Paillier, including existing API conversions. "
            "All GPU APIs complete synchronously. BFV uses the existing native CPU private decoder; only its server runs on CUDA. "
            "Local total times query encryption, common MessagePack framing/parsing, server evaluation, client decode and stable top-three selection. "
            "Setup, plan preparation, resident-index preparation and network transit are excluded. No receipts, attestation, HTTP/TLS or content retrieval. "
            "Both logical roles run on this host, with one physical GPU. Parameter choices are not a claim of equivalent security. "
            "Correctness checks and GC are outside timing; phase medians need not sum to the median total."
        ),
        "source_sha256": {
            str(p.relative_to(REPO_ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(set(sources))
        },
        "results": [],
        "complete": False,
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)

    def save():
        args.json_out.write_text(json.dumps(output, indent=2) + "\n")

    save()
    vectors, query, expected = make_data(args.num_vectors, args.embed_len, args.seed)
    for name in PAILLIER:
        if name in args.variants:
            case = paillier_case(name, args, vectors)
            output["results"].extend(benchmark([case], args, query, expected))
            save()
            del case
            gc.collect()
    if any(name in args.variants for name in BFV):
        with ExitStack() as stack:
            cases = bfv_cases(args, vectors, stack)
            output["results"].extend(benchmark(cases, args, query, expected))
            save()
    output["complete"] = True
    output["finished_utc"] = datetime.now(UTC).isoformat()
    save()
    print(f"Saved {len(output['results'])} cases to {args.json_out}")


if __name__ == "__main__":
    main()
