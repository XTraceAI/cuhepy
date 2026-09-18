#!/usr/bin/env python3
"""Measure authenticated/result-checked BFV sessions against the same raw inputs.

Both servers use the unchanged residue kernels and identical keys/ciphertexts.
Run without concurrent benchmarks or tests. Only synthetic plaintext is seeded.
No key, ciphertext, verification seed or private fingerprint is written to JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import secrets
import statistics
import subprocess
import sys
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

import gmpy2

from bfv_client_matrix import REPO_ROOT, make_data, packet, time_call
from cuhepy.hamming.bfv import BFVClient
from cuhepy.hamming.bfv_security import (
    BFVExecutionPolicy,
    _authenticated_body,
    _decode_ciphertexts,
    _encode_ciphertexts,
    _unpack,
)
from cuhepy.hamming.bfv_verified import (
    BFVVerifiedClient,
    BFVVerifiedServer,
    _HammingSummary,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=1024)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--repeats", type=int, default=6, help="Includes one cold search")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    if args.num_vectors < 1 or args.embed_len < 1 or args.repeats < 2:
        parser.error("positive dimensions and at least two repeats are required")
    policy = BFVExecutionPolicy(embed_len=args.embed_len)
    if args.num_vectors > policy.max_vectors or args.repeats > policy.max_queries:
        parser.error("workload exceeds the local session policy")
    vectors, query, expected = make_data(args.num_vectors, args.embed_len, args.seed)
    timings: dict[str, list[float]] = {
        name: [] for name in ("raw_server", "verified_server", "raw_client", "verified_client")
    }
    setup_times: dict[str, float] = {}
    print("Preparing shared keys, encrypted index and private summary", file=sys.stderr, flush=True)
    setup_times["key_generation_s"], private = time_call(lambda: BFVClient(**policy.config()))
    auth = secrets.token_bytes(32)
    client = BFVVerifiedClient(private, auth, policy=policy)
    setup_times["encrypt_index_summary_export_auth_s"], setup = time_call(
        lambda: client.prepare_index(vectors)
    )
    setup_times["authenticate_import_setup_s"], verified = time_call(
        lambda: BFVVerifiedServer(setup, auth, policy=policy)
    )
    raw = BFVClient(**policy.config(), skip_key_gen=True, server_backend="residue")
    # Trusted benchmark-only sharing of the same parsed PUBLIC key/index. Both
    # server instances retain independent arithmetic contexts and lazy caches.
    raw.public_key = verified._client._pk()
    assert raw.keys is None and verified._client.keys is None
    pk, index = raw._pk(), verified._index
    setup_times["raw_arithmetic_context_s"], _ = time_call(raw._evaluator)
    setup_times["verified_arithmetic_context_s"], _ = time_call(verified._client._evaluator)
    setup_times["summary_only_preprocess_s"], _ = time_call(
        lambda: _HammingSummary(vectors, args.embed_len, secrets.token_bytes(16))
    )
    summary_samples, runs, query_samples = [], [], []
    raw_response = b""
    response = b""
    request = b""
    query_wire = b""
    count = (
        len(vectors) + policy.params.poly_modulus_degree - 1
    ) // policy.params.poly_modulus_degree

    def raw_search(wire: bytes) -> bytes:
        q = _decode_ciphertexts(wire, pk, 1, policy.max_query_bytes)[0]
        result = raw.encode_hamming_server_packed(q, index, len(vectors))
        return _encode_ciphertexts(result, pk)

    def raw_finish(wire: bytes) -> list[int]:
        cts = _decode_ciphertexts(wire, pk, count, policy.max_response_bytes)
        return private.decode_hamming_client_packed(cts, len(vectors))

    for repeat in range(args.repeats):
        elapsed, request = time_call(lambda: client.begin_query(query))
        query_samples.append(elapsed)
        query_wire = _unpack(
            _authenticated_body(request, auth, 2, policy.max_query_bytes),
            limit=policy.max_query_bytes,
        )[2]

        order = ("raw", "verified") if repeat % 2 == 0 else ("verified", "raw")
        for variant in order:
            elapsed, result = time_call(
                partial(raw_search, query_wire)
                if variant == "raw"
                else partial(verified.search, request)
            )
            timings[f"{variant}_server"].append(elapsed)
            runs.append({"repeat": repeat, "phase": f"{variant}_server", "seconds": elapsed})
            if variant == "raw":
                raw_response = result
            else:
                response = result
            print(f"{variant} server: {elapsed:.6f} s", file=sys.stderr, flush=True)
        response_wire = _unpack(
            _authenticated_body(response, auth, 3, policy.max_response_bytes),
            limit=policy.max_response_bytes,
        )[3]
        assert response_wire == raw_response, "Wrapper changed the evaluated ciphertexts"
        for variant in reversed(order):
            elapsed, distances = time_call(
                partial(raw_finish, raw_response)
                if variant == "raw"
                else partial(client.finish_query, response)
            )
            assert distances == expected, "Incorrect Hamming distances"
            timings[f"{variant}_client"].append(elapsed)
            runs.append({"repeat": repeat, "phase": f"{variant}_client", "seconds": elapsed})
        assert client._summary is not None
        elapsed, valid = time_call(
            lambda: (
                client._summary is not None
                and client._summary.matches(expected, client._summary.expected(query))
            )
        )
        assert valid
        summary_samples.append(elapsed)

    summary = {
        name: {
            "first_s": samples[0],
            "warm_samples_s": samples[1:],
            "warm_median_s": statistics.median(samples[1:]),
        }
        for name, samples in timings.items()
    }
    setup_fields = _unpack(
        _authenticated_body(setup, auth, 1, policy.max_setup_bytes),
        limit=policy.max_setup_bytes,
        array_limit=policy.max_vectors,
    )
    public_bytes, index_bytes = len(setup_fields[2]), len(setup_fields[5])
    query_cts = _decode_ciphertexts(query_wire, pk, 1, policy.max_query_bytes)
    response_cts = _decode_ciphertexts(raw_response, pk, count, policy.max_response_bytes)
    protected_s, protected = time_call(lambda: client.protect_state(secrets.token_bytes(32)))
    sources = [
        Path(__file__).resolve(),
        REPO_ROOT / "benchmarks/bfv_client_matrix.py",
        *(REPO_ROOT / "src/cuhepy").glob("bfv*.py"),
        *(REPO_ROOT / "src/cuhepy/bfv").glob("*.py"),
        *(REPO_ROOT / "src/cuhepy/bfv/_cpu_ext").glob("*.cpp"),
        *(REPO_ROOT / "src/cuhepy/bfv/_cpu_ext").glob("*.h"),
        *(REPO_ROOT / "src/cuhepy/bfv/_cpu_ext").glob("*.so"),
        REPO_ROOT / "src/cuhepy/bfv/_cpu_ext/Makefile",
        REPO_ROOT / "src/cuhepy/types.py",
    ]
    output: dict[str, Any] = {
        "environment": {
            "utc": datetime.now(UTC).isoformat(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "gmpy2": gmpy2.version(),
            "gmp": gmpy2.mp_version(),
            "pycryptodome": importlib.metadata.version("pycryptodome"),
            "msgpack": importlib.metadata.version("msgpack"),
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
        "config": policy.config(),
        "seed": args.seed,
        "vectors": len(vectors),
        "measurement_notes": "Identical keys and ciphertexts, independent public-only residue server contexts. Both server timers include MessagePack ciphertext decode/encode and native arithmetic; verified additionally includes authentication, session checks and outer framing. Index import, arithmetic context creation, encryption and private decryption are excluded from server times. First search has cold key/mask caches; five warm samples by default, alternating order. Client timers include ciphertext decode/decrypt/slot decode; verified adds authentication, ticket handling and private result checking. Query encryption is separately timed outside these phases. No network, remote endpoint, SEAL, security-level claim or constant-time claim.",
        "setup_timings": setup_times,
        "runs": runs,
        "summary": summary,
        "query_encrypt_and_bind_samples_s": query_samples,
        "summary_only_check_samples_s": summary_samples,
        "protect_private_state_s": protected_s,
        "sizes": {
            "public_keys_bytes": public_bytes,
            "index_ciphertext_array_bytes": index_bytes,
            "authenticated_setup_bytes": len(setup),
            "raw_query_array_bytes": len(query_wire),
            "raw_response_array_bytes": len(raw_response),
            "authenticated_query_bytes": len(request),
            "authenticated_response_bytes": len(response),
            "authenticated_query_plus_response_bytes": len(request) + len(response),
            "query_authentication_and_framing_overhead_bytes": len(request) - len(query_wire),
            "response_authentication_and_framing_overhead_bytes": len(response) - len(raw_response),
            "private_verification_payload_bytes": client.verification_state_bytes,
            "protected_private_state_bytes": len(protected),
            "previous_benchmark_encrypted_index_bytes": len(packet(index, len(vectors))),
            "previous_benchmark_query_bytes": len(packet(query_cts, 1)),
            "previous_benchmark_response_bytes": len(packet(response_cts, len(vectors))),
        },
        "identical_ciphertexts": True,
        "all_distances_correct": True,
        "source_sha256": {
            str(p.relative_to(REPO_ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sources
        },
    }
    encoded = json.dumps(output, indent=2)
    print(encoded)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(encoded + "\n")


if __name__ == "__main__":
    main()
