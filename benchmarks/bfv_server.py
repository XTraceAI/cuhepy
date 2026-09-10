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
import json
import platform
import statistics
import subprocess
import sys
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

import gmpy2

from bfv_client_matrix import REPO_ROOT, make_data, packet, time_call, unpack_packet
from xtrace_sdk.x_vec.crypto.bfv_client import BFVClient
from xtrace_sdk.x_vec.crypto.encryption.bfv import BFV
from xtrace_sdk.x_vec.crypto.encryption.bfv_evaluator import BFVServerBackend


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=1024)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--poly-modulus-degree", type=int, default=8192)
    parser.add_argument("--plain-modulus", type=int, default=65537)
    parser.add_argument("--coeff-modulus-bits", type=int, default=180)
    parser.add_argument("--decomposition-bits", type=int, default=30)
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
        "--profile-dir",
        type=Path,
        help="Run one extra warm search per backend under cProfile, outside reported timings",
    )
    args = parser.parse_args()
    if args.num_vectors < 1 or args.repeats < 1 or args.embed_len < 1:
        parser.error("num-vectors, embed-len and repeats must be positive")
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
            device="cpu",
        )
    )
    setup["index_encrypt_s"], index = time_call(lambda: client.encrypt_vec_packed(vectors))
    setup["query_encrypt_s"], encrypted_query = time_call(lambda: client.encrypt_vec_one(query))
    index_wire, query_wire = packet(index, len(vectors)), packet([encrypted_query], 1)
    server_index, server_query = unpack_packet(index_wire), unpack_packet(query_wire)[0]
    setup["public_key_export_s"], public_json = time_call(client.stringify_pk)
    config = json.loads(client.stringify_config())
    backends: tuple[BFVServerBackend, ...] = ("reference", "optimized")
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

    timings: dict[str, list[float]] = {backend: [] for backend in backends}
    order = []
    reference_response: list[list[int]] | None = None
    for repeat in range(args.repeats):
        # Alternate ordering to reduce systematic first/last-run effects.
        for backend in backends if repeat % 2 == 0 else backends[::-1]:
            print(f"{backend}: search {repeat + 1}/{args.repeats}", file=sys.stderr, flush=True)
            elapsed, response = time_call(partial(evaluate, backend))
            timings[backend].append(elapsed)
            order.append({"backend": backend, "repeat": repeat, "server_compute_s": elapsed})
            if reference_response is None:
                reference_response = response
            assert response == reference_response, "Backend ciphertexts differ"
            assert client.decode_hamming_client_packed(response, len(vectors)) == expected
            print(
                f"{backend}: {elapsed:.6f} s; ciphertexts and all distances verified",
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
        REPO_ROOT / "src/xtrace_sdk/x_vec/utils/xtrace_types.py",
    ]
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
        "measurement_notes": "One CPU process, identical public keys and encrypted inputs for both backends. Server times include native ciphertext decoding/encoding, terminal modulus switching and lazy cache preparation; exclude outer MessagePack, key import, encryption and client decryption. First search starts with empty key and mask caches. Warm searches reuse these caches. Order alternates. Profiles, if requested, are additional untimed searches. No network or equal-security comparison to other schemes.",
        "config": config,
        "seed": args.seed,
        "vectors": len(vectors),
        "setup_timings": setup,
        "runs": order,
        "summary": summary,
        "first_search_speedup": timings["reference"][0] / timings["optimized"][0],
        "warm_median_speedup": statistics.median(timings["reference"][1:])
        / statistics.median(timings["optimized"][1:])
        if args.repeats > 1
        else None,
        "sizes": {
            "encrypted_index_bytes": len(index_wire),
            "public_keys_bytes": key_bytes,
            "query_bytes": len(query_wire),
            "response_bytes": len(response_wire),
            "query_plus_response_bytes": len(query_wire) + len(response_wire),
        },
        "optimized_cached_switch_keys": len(servers["optimized"]._evaluator()._switch_keys),
        "optimized_packed_cache_payload_bytes": sum(
            sys.getsizeof(value)
            for key in servers["optimized"]._evaluator()._switch_keys.values()
            for value in (
                key.low_mask,
                key.bias_coefficient,
                key.bias,
                *(v for pair in key.pairs for v in pair),
            )
        ),
        "cache_size_note": "sys.getsizeof of packed GMP values, including folding constants; additional to the existing public key. Excludes small Python containers and transient arithmetic allocations; not peak RSS.",
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
