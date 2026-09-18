#!/usr/bin/env python3
"""Repeated searches on reused BFV/Paillier indexes, with role-level timings.

The raw BFV cases decrypt only honest, locally generated benchmark responses.
The Nitro case uses the existing SYNTHETIC test CA: protocol costs, not AWS/TEE
performance. No secret keys, plaintext content or ciphertexts enter the report.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import importlib.metadata
import json
import platform
import resource
import secrets
import statistics
import subprocess
import sys
import time
from collections.abc import Callable
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar
from unittest.mock import patch

import gmpy2

from bfv_client_matrix import REPO_ROOT, make_data, packet, unpack_packet

from xtrace_sdk.x_vec.crypto.bfv_assurance import bfv_review_policy
from xtrace_sdk.x_vec.crypto.bfv_client import BFVClient
from xtrace_sdk.x_vec.crypto.encryption.bfv_private import BFVPrivateDecoder
from xtrace_sdk.x_vec.crypto.paillier_client import PaillierClient
from xtrace_sdk.x_vec.crypto.paillier_lookup_client import PaillierLookupClient

T = TypeVar("T")
Timings = dict[str, dict[str, float]]
CPU_VARIANTS = (
    "paillier-cpu",
    "paillier-lookup-cpu",
    "bfv-8192",
    "bfv-16384",
    "bfv-nitro-local",
)
VARIANTS = (*CPU_VARIANTS, "paillier-gpu", "paillier-lookup-gpu")


def measure(timings: Timings, name: str, fn: Callable[[], T]) -> T:
    """Time wall and process CPU together; no hidden GC between query phases."""
    wall, cpu = time.perf_counter(), time.process_time()
    result = fn()
    timings[name] = {"wall_s": time.perf_counter() - wall, "cpu_s": time.process_time() - cpu}
    return result


def total(timings: Timings, name: str, phases: tuple[str, ...]) -> None:
    timings[name] = {unit: sum(timings[p][unit] for p in phases) for unit in ("wall_s", "cpu_s")}


def raw_case(
    variant: str, args: argparse.Namespace, vectors: list[list[int]], stack: ExitStack
) -> tuple[dict[str, Any], Callable[..., Any]]:
    """Import only public keys/index into the evaluator, using an actual wire roundtrip."""
    setup: Timings = {}
    n = len(vectors)
    native = variant.startswith("bfv-")
    gpu = variant.endswith("-gpu")
    device = "gpu" if gpu else "cpu"
    if native:
        config = bfv_review_policy().config()
        config["poly_modulus_degree"] = int(variant.split("-")[1])
        client: Any = measure(
            setup, "key_generation", lambda: BFVClient(**config, server_backend="residue")
        )
        decoder = measure(setup, "private_context_import", lambda: BFVPrivateDecoder(client))
        stack.callback(decoder.close)
    elif variant in ("paillier-cpu", "paillier-gpu"):
        client = measure(setup, "key_generation", lambda: PaillierClient(512, 1024, device=device))
    else:
        client = measure(
            setup,
            "key_generation",
            lambda: PaillierLookupClient(512, 1024, args.alpha_len, device=device),
        )
    config = json.loads(client.stringify_config())
    public = measure(setup, "public_key_export", client.stringify_pk)
    public_bytes = len(public.encode())
    if native:

        def import_server() -> BFVClient:
            server = BFVClient(skip_key_gen=True, server_backend="residue")
            server.load_config(config)
            server.load_stringified_keys(public, max_public_key_chars=256 * 1024 * 1024)
            assert server.keys is None
            return server

        server = measure(setup, "public_key_import", import_server)
    else:
        pk = measure(setup, "public_key_import", lambda: json.loads(public))
        modulus = gmpy2.mpz(pk["n_squared"])
        config["actual_modulus_bits"] = int(pk["n"]).bit_length()
        if gpu:
            assert client.device == "gpu"  # Never silently benchmark a CPU fallback.
            # This static evaluator receives only public data. Batch all chunks
            # into one existing CUDA call instead of launching once per vector.
            gpu_evaluate = type(client.client).encode_hamming_server
            config["gpu_max_key_len"] = type(client.client).max_key_len()
    public = ""
    print(f"  encrypting {n} index vectors", file=sys.stderr, flush=True)
    index = measure(
        setup,
        "index_encrypt",
        lambda: client.encrypt_vec_packed(vectors) if native else client.encrypt_vec_batch(vectors),
    )
    index_wire = measure(setup, "index_serialize", lambda: packet(index, n))
    server_index = measure(setup, "index_deserialize", lambda: unpack_packet(index_wire))
    info = {
        "config": config,
        "server_backend": "residue"
        if native
        else ("CUDA public multiplication" if gpu else "gmpy2 public multiplication"),
        "private_backend": "native"
        if native
        else ("existing GPU client" if gpu else "existing CPU client"),
        "client_device": device,
        "server_device": device,
        "setup_timings": setup,
        "setup_sizes": {
            "public_keys_bytes": public_bytes,
            "encrypted_index_bytes": len(index_wire),
        },
        "index_ciphertexts": len(index),
    }

    def run(query: list[int], timings: Timings) -> tuple[list[int], dict[str, int]]:
        encrypted = measure(timings, "query_encrypt", lambda: client.encrypt_vec_one(query))
        request = measure(timings, "query_serialize", lambda: packet([encrypted], 1))
        server_query = measure(timings, "query_deserialize", lambda: unpack_packet(request)[0])

        def evaluate() -> list[list[int]]:
            if native:
                return server.encode_hamming_server_packed(server_query, server_index, n)
            if gpu:
                query_chunks = server_query * n
                index_chunks = [c for row in server_index for c in row]
                if variant == "paillier-gpu":
                    products = gpu_evaluate(
                        [format(c, "x") for c in query_chunks],
                        [format(c, "x") for c in index_chunks],
                        {"n_squared": format(int(modulus), "x")},
                    )
                    flat = [int(c, 16) for c in products]
                else:
                    flat = [int(c) for c in gpu_evaluate(query_chunks, index_chunks, pk)]
                chunks = len(server_query)
                return [flat[i : i + chunks] for i in range(0, len(flat), chunks)]
            return [
                [int(gmpy2.mpz(a) * b % modulus) for a, b in zip(server_query, row, strict=True)]
                for row in server_index
            ]

        ciphers = measure(timings, "server_evaluate", evaluate)
        response = measure(timings, "response_serialize", lambda: packet(ciphers, n))
        received = measure(timings, "response_deserialize", lambda: unpack_packet(response))
        distances = measure(
            timings,
            "response_decode",
            lambda: (
                decoder.decode_packed(received, n)
                if native
                else client.decode_hamming_client_batch(received)
            ),
        )
        total(timings, "client_prepare", ("query_encrypt", "query_serialize"))
        total(
            timings, "server_total", ("query_deserialize", "server_evaluate", "response_serialize")
        )
        total(timings, "client_finish", ("response_deserialize", "response_decode"))
        return distances, {
            "query_bytes": len(request),
            "response_bytes": len(response),
            "receipt_bytes": 0,
            "response_ciphertexts": len(ciphers),
        }

    return info, run


def nitro_case(
    vectors: list[list[int]], stack: ExitStack
) -> tuple[dict[str, Any], Callable[..., Any], Callable[..., Any]]:
    """Use real signing/verification code with test evidence, never an AWS claim."""
    sys.path.insert(0, str(REPO_ROOT))
    from tests.x_vec.nitro_fixtures import PCRS, SyntheticNitro

    from xtrace_sdk.x_vec.crypto import bfv_nitro
    from xtrace_sdk.x_vec.crypto.bfv_attested_client import BFVAttestedClient, BFVAttestedServer
    from xtrace_sdk.x_vec.crypto.bfv_nitro import NitroAttestationPolicy

    issuer = SyntheticNitro()
    stack.enter_context(patch.object(bfv_nitro, "_AWS_ROOT_SHA256", issuer.root_digest))
    setup: Timings = {}
    policy = bfv_review_policy()
    raw = measure(setup, "key_generation", lambda: BFVClient(**policy.config()))
    client = measure(
        setup,
        "private_session_import",
        lambda: BFVAttestedClient(
            raw, secrets.token_bytes(32), NitroAttestationPolicy(PCRS), index_epoch=1, policy=policy
        ),
    )
    # The benchmark owns this session; close its locked native buffers explicitly.
    stack.callback(client._session._private_decoder.close)
    print(
        f"  encrypting {len(vectors)} index vectors (local protocol)", file=sys.stderr, flush=True
    )
    index = measure(setup, "index_encrypt_export", lambda: client.prepare_index(vectors))
    registration = measure(setup, "registration_encode", lambda: client.registration_packet(index))
    endpoint = measure(
        setup,
        "public_server_import",
        lambda: BFVAttestedServer.from_registration(registration, issuer, policy=policy),
    )

    def enroll() -> dict[str, Any]:
        timings: Timings = {}
        hello = measure(timings, "client_challenge", client.begin_attestation)
        document, proof = measure(timings, "server_issue", lambda: endpoint.attest(hello))
        measure(timings, "client_verify", lambda: client.accept_attestation(document, proof))
        return {
            "timings": timings,
            "bytes": len(hello) + len(document) + len(proof),
        }

    def run(query: list[int], timings: Timings) -> tuple[list[int], dict[str, int]]:
        request = measure(timings, "client_prepare", lambda: client.begin_query(query))
        response, receipt = measure(timings, "server_total", lambda: endpoint.search(request))
        distances = measure(
            timings, "client_finish", lambda: client.finish_query(response, receipt)
        )
        return distances, {
            "query_bytes": len(request),
            "response_bytes": len(response),
            "receipt_bytes": len(receipt),
            "response_ciphertexts": (len(vectors) + 16383) // 16384,
        }

    return (
        {
            "config": policy.config(),
            "server_backend": "residue",
            "private_backend": "native",
            "hardware_attestation": False,
            "setup_timings": setup,
            "setup_sizes": {
                "authenticated_setup_bytes": len(index),
                "registration_bytes": len(registration),
            },
            "enrollments": [],
        },
        run,
        enroll,
    )


def benchmark(variant: str, args: argparse.Namespace, count: int) -> dict[str, Any]:
    vectors, query, expected = make_data(count, 512, args.seed)
    expected_top3 = sorted(range(count), key=lambda i: (expected[i], i))[:3]
    print(f"{variant}, {count} x 512: setup", file=sys.stderr, flush=True)
    gc.collect()
    with ExitStack() as stack:
        if variant == "bfv-nitro-local":
            info, run, enroll = nitro_case(vectors, stack)
        else:
            info, run = raw_case(variant, args, vectors, stack)
        samples = []
        for repeat in range(args.repeats):
            # Renew outside query timers so longer experiments respect the SDK's
            # unchanged 300-second lease; report enrollment as a separate cost.
            if variant == "bfv-nitro-local":
                info["enrollments"].append(enroll())
            gc.collect()
            timings: Timings = {}
            wall, cpu = time.perf_counter(), time.process_time()
            distances, sizes = run(query, timings)
            top3 = measure(
                timings,
                "client_top3",
                lambda distances=distances: sorted(range(count), key=lambda i: (distances[i], i))[
                    :3
                ],
            )
            timings["local_end_to_end"] = {
                "wall_s": time.perf_counter() - wall,
                "cpu_s": time.process_time() - cpu,
            }
            total(timings, "client_total", ("client_prepare", "client_finish", "client_top3"))
            if distances != expected or top3 != expected_top3:
                raise AssertionError(f"{variant}: distances/top three differ from plaintext oracle")
            sizes["download_bytes"] = sizes["response_bytes"] + sizes["receipt_bytes"]
            sizes["query_plus_response_bytes"] = sizes["query_bytes"] + sizes["download_bytes"]
            samples.append({"repeat": repeat, "timings": timings, "sizes": sizes, "correct": True})
            print(
                f"  trial {repeat}: client {timings['client_total']['wall_s']:.4f}s, "
                f"server {timings['server_total']['wall_s']:.4f}s, "
                f"total {timings['local_end_to_end']['wall_s']:.4f}s; all {count} distances correct",
                file=sys.stderr,
                flush=True,
            )
        summary = {
            phase: {
                unit: {
                    "first": samples[0]["timings"][phase][unit],
                    "warm_median": statistics.median(
                        s["timings"][phase][unit] for s in samples[1:]
                    ),
                    "warm_min": min(s["timings"][phase][unit] for s in samples[1:]),
                    "warm_max": max(s["timings"][phase][unit] for s in samples[1:]),
                }
                for unit in ("wall_s", "cpu_s")
            }
            for phase in samples[0]["timings"]
        }
        return {
            "variant": variant,
            "vectors": count,
            "embed_len": 512,
            **info,
            "samples": samples,
            "summary": summary,
            "top3": [{"index": i, "distance": expected[i]} for i in expected_top3],
            "all_distances_and_top3_correct": True,
        }


def environment() -> dict[str, Any]:
    def command(*args: str) -> dict[str, Any]:
        try:
            result = subprocess.run(
                args, cwd=REPO_ROOT, capture_output=True, text=True, check=False
            )
            return {
                "returncode": result.returncode,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            }
        except FileNotFoundError:
            return {"error": "executable unavailable"}

    return {
        "utc": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu": next(
            (
                line.split(":", 1)[1].strip()
                for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")
            ),
            "unknown",
        ),
        "gmp": gmpy2.mp_version(),
        "versions": {
            name: importlib.metadata.version(name) for name in ("gmpy2", "pycryptodome", "msgpack")
        },
        "compiler": command("c++", "--version"),
        "revision": command("git", "rev-parse", "HEAD"),
        "working_tree": command("git", "status", "--short"),
        "gpu_probe": command(
            "nvidia-smi", "--query-gpu=name,driver_version", "--format=csv,noheader"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, nargs="+", default=[1024, 8192])
    parser.add_argument("--variants", nargs="+", choices=VARIANTS, default=list(CPU_VARIANTS))
    parser.add_argument(
        "--repeats", type=int, default=4, help="One first search, then warm searches"
    )
    parser.add_argument("--alpha-len", type=int, default=50)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if not 2 <= args.repeats <= 128 or any(not 1 <= n <= 65536 for n in args.num_vectors):
        parser.error("Use 2..128 repeats and 1..65536 vectors")
    if not 4 <= args.alpha_len < 1024:
        parser.error("Use alpha-len in 4..1023")
    paths = [
        Path(__file__),
        Path(__file__).with_name("bfv_client_matrix.py"),
        *REPO_ROOT.glob("src/xtrace_sdk/x_vec/crypto/*.py"),
        *REPO_ROOT.glob("src/xtrace_sdk/x_vec/crypto/encryption/*.py"),
        *REPO_ROOT.glob("src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext/*.cpp"),
        *REPO_ROOT.glob("src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext/*.h"),
        *REPO_ROOT.glob("src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext/*.so"),
        REPO_ROOT / "src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext/Makefile",
        REPO_ROOT / "src/xtrace_sdk/x_vec/utils/xtrace_types.py",
        REPO_ROOT / "tests/x_vec/nitro_fixtures.py",
        *REPO_ROOT.glob("src/xtrace_sdk/x_vec/crypto/paillier*_gpu_ext/*.cu"),
        *REPO_ROOT.glob("src/xtrace_sdk/x_vec/crypto/paillier*_gpu_ext/*.so"),
        *REPO_ROOT.glob("src/xtrace_sdk/x_vec/crypto/paillier*_gpu_ext/Makefile"),
    ]
    output: dict[str, Any] = {
        "environment": environment(),
        "command": sys.argv,
        "seed": args.seed,
        "measurement_notes": (
            "CPU BFV; explicit CPU or GPU Paillier backends, no equivalent-security claim. "
            "CUDA calls are synchronous and include host/device copies and API conversions; process "
            "CPU seconds do not measure GPU device work. Sequential cases in recorded order, no concurrent "
            "benchmarks/tests intended. Each case reuses one key/index with fresh randomized encryption "
            "of the same plaintext query per trial. First search separate from remaining warm trials; "
            "no p95/throughput claim. Wall and process CPU seconds; both logical roles run on this host. "
            "GC before each query, not between phases. Setup and Nitro enrollment excluded from query "
            "timers and recorded separately. Raw cases use common MessagePack with implicit IDs; "
            "Nitro uses real protocol encoding/signatures/private checks but a SYNTHETIC test CA. "
            "No network, NSM, vsock, enclave isolation, HTTP/TLS, content retrieval, or live service. "
            "Same stable top-three sort is timed for every case; correctness checks are outside timers. "
            "Native raw BFV decoding is safe here only because all inputs are generated locally."
        ),
        "source_sha256": {
            str(p.resolve().relative_to(REPO_ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(set(paths))
        },
        "results": [],
        "complete": False,
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    usage_before = resource.getrusage(resource.RUSAGE_SELF)
    for count in args.num_vectors:
        for variant in args.variants:
            output["results"].append(benchmark(variant, args, count))
            args.json_out.write_text(json.dumps(output, indent=2) + "\n")
            gc.collect()
    usage_after = resource.getrusage(resource.RUSAGE_SELF)
    output["process_resources"] = {
        "whole_process_peak_rss_kib_linux": usage_after.ru_maxrss,
        "major_page_faults": usage_after.ru_majflt - usage_before.ru_majflt,
        "swaps": usage_after.ru_nswap - usage_before.ru_nswap,
    }
    output["finished_utc"] = datetime.now(UTC).isoformat()
    output["complete"] = True
    args.json_out.write_text(json.dumps(output, indent=2) + "\n")
    print(f"Saved {len(output['results'])} cases to {args.json_out}")


if __name__ == "__main__":
    main()
