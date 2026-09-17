#!/usr/bin/env python3
"""Measure public recomputation and private decoding on identical BFV ciphertexts.

Run the original and review profiles separately, without concurrent CPU work.
Only synthetic plaintext is seeded. JSON contains measurements and public
parameters, never keys, ciphertexts, signing seeds or private fingerprints.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import resource
import secrets
import statistics
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

import gmpy2

from bfv_client_matrix import REPO_ROOT, make_data, time_call
from cuhepy.bfv.assurance import bfv_review_policy, hamming_noise_bound
from cuhepy.bfv.client import BFVClient
from cuhepy.bfv.guarded_client import (
    BFVGuardedClient,
    BFVPublicVerifier,
    bfv_verifier_public_key,
)
from cuhepy.bfv.security import (
    BFVExecutionPolicy,
    _authenticated_body,
    _decode_ciphertexts,
    _unpack,
)
from cuhepy.bfv.verified_client import BFVVerifiedServer


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("original", "review"), default="review")
    parser.add_argument("--num-vectors", type=int, default=1024)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--repeats", type=int, default=4, help="One cold and three warm trials")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    if min(args.num_vectors, args.embed_len) < 1 or args.repeats < 2:
        parser.error("positive dimensions and at least two repeats are required")
    policy = replace(
        BFVExecutionPolicy() if args.profile == "original" else bfv_review_policy(),
        embed_len=args.embed_len,
    )
    if args.num_vectors > policy.max_vectors or args.repeats > policy.max_queries:
        parser.error("workload exceeds the local session policy")
    vectors, query, expected = make_data(args.num_vectors, args.embed_len, args.seed)
    setup_times: dict[str, float] = {}
    timings: dict[str, list[float]] = {
        name: []
        for name in (
            "server",
            "verifier",
            "python_raw_client",
            "native_raw_client",
            "guarded_client",
        )
    }
    print(f"Preparing {args.profile} profile", file=sys.stderr, flush=True)
    setup_times["key_generation_s"], raw = time_call(lambda: BFVClient(**policy.config()))
    auth, signing_seed = secrets.token_bytes(32), secrets.token_bytes(32)
    setup_times["client_key_snapshot_native_import_s"], client = time_call(
        lambda: BFVGuardedClient(raw, auth, bfv_verifier_public_key(signing_seed), policy=policy)
    )
    setup_times["encrypt_index_summary_export_auth_s"], setup = time_call(
        lambda: client.prepare_index(vectors)
    )
    setup_times["server_setup_import_s"], server = time_call(
        lambda: BFVVerifiedServer(setup, auth, policy=policy)
    )
    setup_times["verifier_setup_import_s"], verifier = time_call(
        lambda: BFVPublicVerifier(
            setup, auth, signing_seed, expected_setup_digest=client.setup_digest, policy=policy
        )
    )
    assert server._client.keys is None and verifier._server._client.keys is None
    setup_times["server_arithmetic_context_s"], _ = time_call(server._client._evaluator)
    setup_times["verifier_arithmetic_context_s"], _ = time_call(verifier._server._client._evaluator)
    native = client._session._private_decoder
    assert native is not None
    pk = raw._pk()
    count = (
        len(vectors) + policy.params.poly_modulus_degree - 1
    ) // policy.params.poly_modulus_degree
    query_times, runs = [], []
    request = response = receipt = b""

    def raw_finish(wire: bytes, use_native: bool) -> list[int]:
        # Benchmark-only direct private primitive access: applications must use
        # finish_query(response, receipt). Both reference timers include parsing.
        cts = _decode_ciphertexts(wire, pk, count, policy.max_response_bytes)
        if use_native:
            return native.decode_packed(cts, len(vectors))
        return raw.decode_hamming_client_packed(cts, len(vectors))

    for repeat in range(args.repeats):
        elapsed, request = time_call(lambda: client.begin_query(query))
        query_times.append(elapsed)
        elapsed, response = time_call(partial(server.search, request))
        timings["server"].append(elapsed)
        print(f"server: {elapsed:.6f} s", file=sys.stderr, flush=True)
        elapsed, receipt = time_call(partial(verifier.approve, request, response))
        timings["verifier"].append(elapsed)
        print(f"verifier: {elapsed:.6f} s", file=sys.stderr, flush=True)
        wire = _unpack(
            _authenticated_body(response, auth, 3, policy.max_response_bytes),
            limit=policy.max_response_bytes,
        )[3]
        variants = ("python_raw_client", "native_raw_client", "guarded_client")
        for name in variants if repeat % 2 == 0 else reversed(variants):
            elapsed, distances = time_call(
                partial(client.finish_query, response, receipt)
                if name == "guarded_client"
                else partial(raw_finish, wire, name == "native_raw_client")
            )
            assert distances == expected, "Incorrect Hamming distances"
            timings[name].append(elapsed)
        runs.append({"repeat": repeat, **{name: samples[-1] for name, samples in timings.items()}})
    setup_fields = _unpack(
        _authenticated_body(setup, auth, 1, policy.max_setup_bytes),
        limit=policy.max_setup_bytes,
        array_limit=policy.max_vectors,
    )
    crypto = REPO_ROOT / "src/cuhepy"
    sources = [
        Path(__file__).resolve(),
        REPO_ROOT / "benchmarks/bfv_client_matrix.py",
        *crypto.glob("bfv*.py"),
        *(crypto / "encryption").glob("bfv*.py"),
        *(crypto / "bfv_cpu_ext").glob("*.cpp"),
        *(crypto / "bfv_cpu_ext").glob("*.h"),
        *(crypto / "bfv_cpu_ext").glob("*.so"),
        crypto / "bfv_cpu_ext/Makefile",
        REPO_ROOT / "src/cuhepy/x_vec/utils/xtrace_types.py",
    ]
    output: dict[str, Any] = {
        "environment": {
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
            "gmpy2": gmpy2.version(),
            "gmp": gmpy2.mp_version(),
            "pycryptodome": importlib.metadata.version("pycryptodome"),
            "msgpack": importlib.metadata.version("msgpack"),
            "compiler": subprocess.run(
                ["c++", "--version"], capture_output=True, text=True, check=True
            ).stdout.splitlines()[0],
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
        "profile": args.profile,
        "config": policy.config(),
        "vectors": len(vectors),
        "seed": args.seed,
        "measurement_notes": "Within each profile all variants use identical keys and evaluated ciphertexts. Server and owner-controlled public-only verifier have independently imported setups and separate residue arithmetic contexts. Server search and verifier approval include authentication, MessagePack and arithmetic; setup import, arithmetic-context creation, query encryption and private decoding are separate. Approval independently recomputes the full result and compares exact bytes before Ed25519 signing. Server then verifier run sequentially; no network or overlap claimed. One cold trial followed by three warm trials by default. Raw Python/native client timers include ciphertext-array parsing and all distance decoding; guarded includes receipt, authentication, replay and private result checks, with alternating client order. No security-level or end-to-end constant-time claim.",
        "setup_timings": setup_times,
        "runs": runs,
        "summary": {
            name: {
                "first_s": samples[0],
                "warm_samples_s": samples[1:],
                "warm_median_s": statistics.median(samples[1:]),
            }
            for name, samples in timings.items()
        },
        "query_encrypt_and_bind_samples_s": query_times,
        "sizes": {
            "public_keys_bytes_per_evaluator": len(setup_fields[2]),
            "encrypted_index_bytes_per_evaluator": len(setup_fields[5]),
            "authenticated_setup_bytes_per_evaluator": len(setup),
            "query_bytes": len(request),
            "response_bytes": len(response),
            "receipt_bytes": len(receipt),
            "client_response_and_receipt_bytes": len(response) + len(receipt),
            "client_query_response_receipt_bytes": len(request) + len(response) + len(receipt),
            "remote_verifier_additional_query_response_input_bytes": len(request) + len(response),
            "private_verification_payload_bytes": client.verification_state_bytes,
            "native_locked_key_bytes": 16 * policy.params.poly_modulus_degree,
            "native_locked_scratch_bytes_per_active_decode": 24 * policy.params.poly_modulus_degree,
        },
        "whole_process_peak_rss_kib_linux": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "noise_bound": hamming_noise_bound(policy, policy.max_vectors).as_dict(),
        "identical_ciphertexts_within_profile": True,
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
