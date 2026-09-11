#!/usr/bin/env python3
"""Compare native BFV server backends on identical keys, queries, and index bytes.

The first search includes lazy evaluation-key preparation. Subsequent searches
reuse the same public-only server. No SEAL, network, GPU or secret server key is
required. Run without concurrent tests/benchmarks for useful timing comparisons.
"""

from __future__ import annotations

import argparse
import cProfile
import hashlib
import importlib.metadata
import json
import platform
import statistics
import subprocess
import sys
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any, cast

import gmpy2

from bfv_client_matrix import REPO_ROOT, make_data, packet, time_call, unpack_packet
from xtrace_sdk.x_vec.crypto.bfv_client import BFVClient
from xtrace_sdk.x_vec.crypto.encryption.bfv import BFV, _rns_coefficient_primes
from xtrace_sdk.x_vec.crypto.encryption.bfv_evaluator import BFVServerBackend


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=1024)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--poly-modulus-degree", type=int, default=8192)
    parser.add_argument("--plain-modulus", type=int, default=65537)
    parser.add_argument("--coeff-modulus-bits", type=int, default=180)
    parser.add_argument("--decomposition-bits", type=int, default=30)
    parser.add_argument(
        "--rns-modulus",
        action="store_true",
        help="Generate fresh keys with a product of 60-bit NTT primes; required by residue",
    )
    parser.add_argument("--response-modulus-bits", type=int, default=50)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument(
        "--repeats",
        type=int,
        default=3,
        help="Searches per backend, including the first cold search",
    )
    parser.add_argument("--json-out", type=Path)
    parser.add_argument(
        "--backends",
        default="reference,optimized",
        help="Comma-separated native backends: reference,optimized,rns,native,residue",
    )
    parser.add_argument(
        "--seal",
        action="store_true",
        help="Also measure the preserved SEAL prototype on the same plaintext workload",
    )
    parser.add_argument(
        "--profile-dir",
        type=Path,
        help="Run one extra warm search per backend under cProfile, outside reported timings",
    )
    parser.add_argument(
        "--native-profile",
        action="store_true",
        help="Collect exclusive C++ phase timings in additional warm searches, outside reported timings",
    )
    args = parser.parse_args()
    if args.num_vectors < 1 or args.repeats < 1 or args.embed_len < 1:
        parser.error("num-vectors, embed-len and repeats must be positive")
    names = args.backends.split(",")
    if (
        not names
        or len(set(names)) != len(names)
        or any(b not in ("reference", "optimized", "rns", "native", "residue") for b in names)
    ):
        parser.error("backends must be distinct native backend names")
    if args.seal and (args.poly_modulus_degree != 8192 or args.plain_modulus != 65537):
        parser.error("the SEAL comparison requires N=8192 and t=65537")
    if args.native_profile and not any(b in ("rns", "native", "residue") for b in names):
        parser.error("native-profile requires the rns, native, or residue backend")
    if "residue" in names and not args.rns_modulus:
        parser.error("residue requires --rns-modulus (fresh keys and index)")
    backends = tuple(cast(BFVServerBackend, name) for name in names)
    vectors, query, expected = make_data(args.num_vectors, args.embed_len, args.seed)
    print("Generating one key set and encrypting the shared input", file=sys.stderr, flush=True)
    setup: dict[str, float] = {}
    setup["key_generation_s"], client = time_call(
        lambda: BFVClient(
            embed_len=args.embed_len,
            poly_modulus_degree=args.poly_modulus_degree,
            plain_modulus=args.plain_modulus,
            coeff_modulus_bits=args.coeff_modulus_bits,
            decomposition_bits=args.decomposition_bits,
            response_modulus_bits=args.response_modulus_bits,
            rns_modulus=args.rns_modulus,
            device="cpu",
        )
    )
    setup["index_encrypt_s"], index = time_call(lambda: client.encrypt_vec_packed(vectors))
    setup["query_encrypt_s"], encrypted_query = time_call(lambda: client.encrypt_vec_one(query))
    index_wire, query_wire = packet(index, len(vectors)), packet([encrypted_query], 1)
    server_index, server_query = unpack_packet(index_wire), unpack_packet(query_wire)[0]
    setup["public_key_export_s"], public_json = time_call(client.stringify_pk)
    config = json.loads(client.stringify_config())
    servers = {}
    for backend in backends:
        server = BFVClient(skip_key_gen=True, server_backend=backend, **config)
        setup[f"{backend}_public_key_import_s"], _ = time_call(
            partial(server.load_stringified_keys, public_json)
        )
        assert server.keys is None
        servers[backend] = server
    key_bytes = len(public_json.encode())
    del public_json

    def evaluate(backend: BFVServerBackend) -> list[list[int]]:
        return servers[backend].encode_hamming_server_packed(
            server_query, server_index, len(vectors)
        )

    seal_info: dict[str, Any] | None = None
    if args.seal:
        sys.path.insert(0, str(REPO_ROOT / "experiments/bfv"))
        from packed_hamming import BfvClient, BfvServer

        print(
            "Preparing the preserved SEAL prototype on the same vectors",
            file=sys.stderr,
            flush=True,
        )
        seal_client = BfvClient(args.embed_len)
        seal_bundle = seal_client.server_bundle()
        seal_server = BfvServer(seal_bundle)
        seal_index, seal_query = (
            seal_client.encrypt_index(vectors),
            seal_client.encrypt_query(query),
        )
        seal_info = {
            "tenseal": importlib.metadata.version("tenseal"),
            "poly_modulus_degree": 8192,
            "plain_modulus": 65537,
            "active_coeff_modulus_bits": [
                p.bit_count()
                for p in seal_client.context.first_context_data().parms().coeff_modulus()
            ],
            "key_coeff_modulus_bits": [
                p.bit_count()
                for p in seal_client.context.key_context_data().parms().coeff_modulus()
            ],
            "security_setting": "SEAL TC128; no equivalent-security claim for native parameters",
            "index_bytes": len(seal_index),
            "query_bytes": len(seal_query),
            "public_key_bytes": len(seal_bundle),
            "timing_notes": "SEAL search includes its serialization, MessagePack and binding temporary-file I/O. Native times exclude outer MessagePack; both include ciphertext decoding, arithmetic, compaction and ciphertext encoding. These are practical server calls with different parameters/formats, not identical arithmetic kernels.",
        }

    measured_backends = (*backends, "seal") if args.seal else backends
    timings: dict[str, list[float]] = {backend: [] for backend in measured_backends}
    order = []
    reference_response: list[list[int]] | None = None
    for repeat in range(args.repeats):
        # Alternate ordering to reduce systematic first/last-run effects.
        for backend_name in measured_backends if repeat % 2 == 0 else measured_backends[::-1]:
            print(
                f"{backend_name}: search {repeat + 1}/{args.repeats}", file=sys.stderr, flush=True
            )
            if backend_name == "seal":
                elapsed, seal_response = time_call(
                    partial(seal_server.search, seal_index, seal_query)
                )
                assert [d for _, d in seal_client.decrypt_distances(seal_response)] == expected
                assert seal_info is not None
                seal_info["response_bytes"] = len(seal_response)
                seal_info["all_distances_correct"] = True
                seal_info["minimum_response_noise_budget_bits"] = min(
                    seal_client.noise_budgets(seal_response)
                )
            else:
                elapsed, response = time_call(
                    partial(evaluate, cast(BFVServerBackend, backend_name))
                )
                if reference_response is None:
                    reference_response = response
                assert response == reference_response, "Native backend ciphertexts differ"
                assert client.decode_hamming_client_packed(response, len(vectors)) == expected
            timings[backend_name].append(elapsed)
            order.append({"backend": backend_name, "repeat": repeat, "server_compute_s": elapsed})
            print(
                f"{backend_name}: {elapsed:.6f} s; all distances verified"
                + ("; identical native ciphertexts" if backend_name != "seal" else ""),
                file=sys.stderr,
                flush=True,
            )

    assert reference_response is not None
    response_wire = packet(reference_response, len(vectors))
    # Profiles are separate extra runs: cProfile substantially distorts Python
    # loop timings and must not be used to calculate benchmark speedups.
    if args.profile_dir:
        args.profile_dir.mkdir(parents=True, exist_ok=True)
        for backend in backends:
            profiler = cProfile.Profile()
            response = profiler.runcall(evaluate, backend)
            profiler.dump_stats(str(args.profile_dir / f"{backend}.prof"))
            assert response == reference_response

    native_phases = {}
    if args.native_profile:
        from xtrace_sdk.x_vec.crypto.bfv_cpu_ext import _bfv_rns

        for backend in backends:
            if backend in ("rns", "native", "residue"):
                response, phases = _bfv_rns.profile_call(partial(evaluate, backend))
                assert response == reference_response
                native_phases[backend] = phases

    summary = {
        backend: {
            "first_search_s": values[0],
            "warm_searches_s": values[1:],
            "warm_median_s": statistics.median(values[1:]) if len(values) > 1 else None,
        }
        for backend, values in timings.items()
    }
    source_paths = [
        Path(__file__).resolve(),
        REPO_ROOT / "benchmarks/bfv_client_matrix.py",
        REPO_ROOT / "src/xtrace_sdk/x_vec/crypto/bfv_client.py",
        REPO_ROOT / "src/xtrace_sdk/x_vec/crypto/encryption/bfv.py",
        REPO_ROOT / "src/xtrace_sdk/x_vec/crypto/encryption/bfv_evaluator.py",
        REPO_ROOT / "src/xtrace_sdk/x_vec/crypto/encryption/bfv_rns.py",
        REPO_ROOT / "src/xtrace_sdk/x_vec/crypto/encryption/bfv_native.py",
        *(REPO_ROOT / "src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext").glob("*.cpp"),
        *(REPO_ROOT / "src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext").glob("*.h"),
        REPO_ROOT / "src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext/Makefile",
        REPO_ROOT / "src/xtrace_sdk/x_vec/utils/xtrace_types.py",
    ]
    if any(b in ("rns", "native", "residue") for b in backends):
        source_paths.extend((REPO_ROOT / "src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext").glob("*.so"))
    if args.seal:
        source_paths.append(REPO_ROOT / "experiments/bfv/packed_hamming.py")
    output: dict[str, Any] = {
        "environment": {
            "utc": datetime.now(UTC).isoformat(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "gmpy2": gmpy2.version(),
            "gmp": gmpy2.mp_version(),
            "revision": subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip(),
            "working_tree_dirty": bool(
                subprocess.run(
                    ["git", "status", "--porcelain"],
                    cwd=REPO_ROOT,
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout.strip()
            ),
        },
        "command": sys.argv,
        "measurement_notes": "One CPU process, identical public keys and encrypted inputs for all native backends. Server times include native ciphertext decoding/encoding, terminal modulus switching and lazy cache preparation; exclude outer MessagePack, key import, encryption and client decryption. First search starts with empty key and mask caches. Warm searches reuse these caches. Order alternates. Profiles, if requested, are additional untimed searches. No network or equal-security comparison to other schemes.",
        "config": config,
        "ciphertext_modulus_hex": format(client._pk()["q"], "x"),
        "ciphertext_modulus_primes": _rns_coefficient_primes(
            args.poly_modulus_degree, args.coeff_modulus_bits
        )
        if args.rns_modulus
        else None,
        "seed": args.seed,
        "vectors": len(vectors),
        "setup_timings": setup,
        "runs": order,
        "summary": summary,
        "first_search_speedup": timings["reference"][0] / timings["optimized"][0]
        if "reference" in timings and "optimized" in timings
        else None,
        "warm_median_speedup": statistics.median(timings["reference"][1:])
        / statistics.median(timings["optimized"][1:])
        if args.repeats > 1 and "reference" in timings and "optimized" in timings
        else None,
        "speedups_relative_to_first_native_backend": {
            backend: {
                "first": timings[backends[0]][0] / values[0],
                "warm_median": statistics.median(timings[backends[0]][1:])
                / statistics.median(values[1:])
                if args.repeats > 1
                else None,
            }
            for backend, values in timings.items()
        },
        "seal_comparison": seal_info,
        "native_phases": native_phases,
        "native_profile_note": "Additional warm searches, excluded from performance samples. Exclusive wall times and call counts; other includes Python, binding overhead and unscoped native work. buffers covers explicit buffer setup; GMP allocations remain charged to their arithmetic phases. Profiles are per-thread and restored after exceptions.",
        "sizes": {
            "encrypted_index_bytes": len(index_wire),
            "public_keys_bytes": key_bytes,
            "query_bytes": len(query_wire),
            "response_bytes": len(response_wire),
            "query_plus_response_bytes": len(query_wire) + len(response_wire),
        },
        "caches": {
            backend: {
                **server._evaluator().cache_info(),
                "server_plan_bytes": server._native().cache_bytes()
                if backend in ("native", "residue")
                else 0,
            }
            for backend, server in servers.items()
        },
        "cache_size_note": "Additional to the existing public key: GMP object payloads including folding constants, or native NTT coefficient arrays and transform tables. Excludes containers, CRT constants and transient allocations; not peak RSS.",
        "minimum_response_noise_budget_bits": min(
            BFV.noise_budget(BFV.ciphertext_from_ints(ct, client._pk()), client._keys())
            for ct in reference_response
        ),
        "identical_ciphertexts": True,
        "all_distances_correct": True,
        "top3": [
            {"index": i, "distance": expected[i]}
            for i in sorted(range(len(vectors)), key=lambda i: (expected[i], i))[:3]
        ],
        "source_sha256": {
            str(path.relative_to(REPO_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in source_paths
        },
    }
    print(json.dumps(output, indent=2))
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
