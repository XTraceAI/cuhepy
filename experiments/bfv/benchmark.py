"""Measure actual BFV payloads against an isolated local Git revision of Paillier.

Run from the repository root, for example:
  .venv/bin/python experiments/bfv/benchmark.py --num-vectors 8192 --paillier-ref main
No API calls, checkout changes, real documents, credentials, or secret-key exports.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import heapq
import importlib.metadata
import io
import json
import math
import platform
import random
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import msgpack


REPO = Path(__file__).resolve().parents[2]


def timed(call: Callable[[], Any]) -> tuple[Any, float]:
    start = time.perf_counter()
    value = call()
    return value, time.perf_counter() - start


def dataset(count: int, dimension: int, seed: int) -> tuple[list[list[int]], list[int], list[int]]:
    rng = random.Random(seed)
    query = [rng.randrange(2) for _ in range(dimension)]
    vectors = [[rng.randrange(2) for _ in range(dimension)] for _ in range(count)]
    if vectors:
        vectors[0] = query[:]
    distances = [sum(x != y for x, y in zip(v, query, strict=True)) for v in vectors]
    return vectors, query, distances


def top_k(distances: list[int], k: int) -> list[tuple[int, int]]:
    return heapq.nsmallest(k, enumerate(distances), key=lambda pair: (pair[1], pair[0]))


def run_bfv(args: argparse.Namespace) -> dict[str, Any]:
    from packed_hamming import BfvClient, BfvServer

    vectors, query, expected = dataset(args.num_vectors, args.dimension, args.seed)
    client, keygen_s = timed(lambda: BfvClient(args.dimension))
    public, key_serialize_s = timed(client.server_bundle)
    server, server_setup_s = timed(lambda: BfvServer(public))
    index, index_encrypt_s = timed(lambda: client.encrypt_index(vectors))
    runs = []
    for _ in range(args.repeats):
        query_payload, query_encrypt_s = timed(lambda: client.encrypt_query(query))
        def evaluate(query_payload: bytes = query_payload) -> bytes:
            return server.search(index, query_payload)

        response, server_eval_s = timed(evaluate)

        def decode(response: bytes = response) -> tuple[list[int], list[tuple[int, int]]]:
            values = [distance for _, distance in client.decrypt_distances(response)]
            return values, top_k(values, args.k)

        (distances, selected), client_decode_select_s = timed(decode)
        if distances != expected or selected != top_k(expected, args.k):
            raise AssertionError("BFV distances/top-k differ from the plaintext oracle")
        packet = msgpack.unpackb(response, raw=False)
        runs.append(dict(
            query_bytes=len(query_payload), response_bytes=len(response),
            response_ciphertext_bytes=sum(map(len, packet["ciphertexts"])),
            response_ciphertexts=len(packet["ciphertexts"]), query_encrypt_s=query_encrypt_s,
            server_eval_s=server_eval_s, client_decode_select_s=client_decode_select_s,
            minimum_noise_budget_bits=min(client.noise_budgets(response), default=None),
        ))
    return dict(
        backend="BFV / TenSEAL 0.3.16 sealapi / CPU", poly_modulus_degree=8192,
        plain_modulus=65537, coeff_modulus_bits=[43, 43, 44, 44, 44],
        security_setting="SEAL TC128", final_coeff_modulus_count=1,
        padded_dimension=client.layout.padded_dimension,
        vectors_per_input_ciphertext=client.layout.vectors_per_ciphertext,
        key_bundle_bytes=len(public), keygen_s=keygen_s, key_serialize_s=key_serialize_s,
        server_setup_s=server_setup_s, index_bytes=len(index), index_encrypt_s=index_encrypt_s,
        index_ciphertexts=len(msgpack.unpackb(index, raw=False)["ciphertexts"]),
        all_distances_verified=True, top_k=selected, runs=runs,
    )


def run_paillier_worker(args: argparse.Namespace) -> dict[str, Any]:
    # This subprocess has not imported xtrace_sdk. Prepend the exported revision
    # so the installed editable SDK cannot silently substitute the current branch.
    sys.path.insert(0, str(Path(args.paillier_source) / "src"))
    import gmpy2
    import xtrace_sdk.x_vec.crypto.paillier_client as module
    from xtrace_sdk.x_vec.crypto.encryption.paillier import Paillier

    if not Path(module.__file__).resolve().is_relative_to(Path(args.paillier_source).resolve()):
        raise RuntimeError("Paillier baseline imported from the wrong revision")
    vectors, query, expected = dataset(args.num_vectors, args.dimension, args.seed)
    client, keygen_s = timed(lambda: module.PaillierCPU(embed_len=args.dimension, key_len=args.key_len))
    keys = client.keys

    def binary(value: Any) -> bytes:
        return int(value).to_bytes((int(value).bit_length() + 7) // 8, "little")

    def encrypt_index() -> bytes:
        return msgpack.packb([[[binary(c) for c in client.encrypt(v)], i]
                              for i, v in enumerate(vectors)], use_bin_type=True)

    index, index_encrypt_s = timed(encrypt_index)
    runs = []
    for _ in range(args.repeats):
        def encrypt_query() -> bytes:
            return json.dumps(dict(
                kb_id="benchmark", context_id="0" * 64,
                query=[base64.b64encode(binary(c)).decode("ascii") for c in client.encrypt(query)],
            ), separators=(",", ":")).encode()

        query_payload, query_encrypt_s = timed(encrypt_query)

        def evaluate(query_payload: bytes = query_payload) -> bytes:
            encrypted_query = [gmpy2.mpz(int.from_bytes(base64.b64decode(c), "little"))
                               for c in json.loads(query_payload)["query"]]
            results = []
            for ciphers, record_id in msgpack.unpackb(index, raw=False):
                values = [gmpy2.mpz(int.from_bytes(c, "little")) for c in ciphers]
                result = [binary(Paillier.add(x, q, keys["pk"]))
                          for x, q in zip(values, encrypted_query, strict=True)]
                results.append([result, record_id])
            # The current integration expects server rows [ciphertext_chunks, ID].
            return msgpack.packb(results, use_bin_type=True)

        response, server_eval_s = timed(evaluate)

        def decode(response: bytes = response) -> tuple[list[int], list[tuple[int, int]]]:
            values = [client.decode_hamming_client(ciphers)
                      for ciphers, _ in msgpack.unpackb(response, raw=False)]
            return values, top_k(values, args.k)

        (distances, selected), client_decode_select_s = timed(decode)
        if distances != expected or selected != top_k(expected, args.k):
            raise AssertionError("Paillier distances/top-k differ from the plaintext oracle")
        rows = msgpack.unpackb(response, raw=False)
        runs.append(dict(
            query_bytes=len(query_payload), response_bytes=len(response),
            response_ciphertext_bytes=sum(len(c) for row, _ in rows for c in row),
            response_ciphertexts=sum(len(row) for row, _ in rows),
            query_encrypt_s=query_encrypt_s, server_eval_s=server_eval_s,
            client_decode_select_s=client_decode_select_s,
        ))
    return dict(
        backend="PaillierCPU from exported Git revision", key_len_prime_bits=args.key_len,
        actual_modulus_bits=int(keys["pk"]["n"]).bit_length(),
        key_bundle_bytes=len(client.stringify_pk().encode()), keygen_s=keygen_s,
        index_bytes=len(index), index_encrypt_s=index_encrypt_s,
        index_format="binary MessagePack model; production JSON/base64 ingest is larger",
        all_distances_verified=True, top_k=selected, runs=runs,
    )


def baseline(args: argparse.Namespace, commit: str) -> dict[str, Any]:
    archive = subprocess.check_output(["git", "archive", "--format=tar", commit, "src"], cwd=REPO)
    with tempfile.TemporaryDirectory(prefix="xtrace-paillier-reference-") as directory:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(directory, filter="data")
        command = [sys.executable, str(Path(__file__).resolve()), "--paillier-source", directory,
                   "--num-vectors", str(args.num_vectors), "--dimension", str(args.dimension),
                   "--seed", str(args.seed), "--key-len", str(args.key_len),
                   "--repeats", str(args.repeats), "--k", str(args.k)]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)


def median_runs(result: dict[str, Any]) -> dict[str, float]:
    return {name: statistics.median(run[name] for run in result["runs"])
            for name in ["query_bytes", "response_bytes", "query_encrypt_s", "server_eval_s", "client_decode_select_s"]}


def compare(bfv: dict[str, Any], paillier: dict[str, Any]) -> dict[str, Any]:
    b, p = median_runs(bfv), median_runs(paillier)
    b_roundtrip, p_roundtrip = b["query_bytes"] + b["response_bytes"], p["query_bytes"] + p["response_bytes"]
    saved = p_roundtrip - b_roundtrip
    extra_keys = max(0, bfv["key_bundle_bytes"] - paillier["key_bundle_bytes"])
    extra_index = max(0, bfv["index_bytes"] - paillier["index_bytes"])
    return dict(
        response_reduction_factor=p["response_bytes"] / b["response_bytes"],
        query_plus_response_reduction_factor=p_roundtrip / b_roundtrip,
        bytes_saved_per_query=saved,
        queries_to_amortize_extra_keys=math.ceil(extra_keys / saved) if saved > 0 else None,
        queries_to_amortize_extra_keys_and_index=math.ceil((extra_keys + extra_index) / saved) if saved > 0 else None,
        bfv_medians=b, paillier_medians=p,
        note="Byte-only amortization; excludes HTTP/TLS and content fetch. Timings are local CPU simulation, not production service measurements. Same stable client top-k used for both.",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=2048)
    parser.add_argument("--dimension", type=int, default=512)
    parser.add_argument("--key-len", type=int, default=1024, help="Paillier prime bit length, not modulus bit length")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--k", type=int, default=3)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--paillier-ref", default="main", help="Local Git revision; exported without checkout changes")
    parser.add_argument("--paillier-source", help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, help="Append this run's full measurements as one JSONL record")
    args = parser.parse_args()
    if args.num_vectors < 1 or args.repeats < 1 or args.k < 0:
        parser.error("num-vectors and repeats must be positive; k must be nonnegative")
    if not 1 <= args.dimension <= 4096 or args.dimension >= args.key_len or args.key_len < 1024:
        parser.error("Require 1 <= dimension <= 4096, dimension < key-len, and key-len >= 1024")
    if args.paillier_source:
        print(json.dumps(run_paillier_worker(args)))
        return
    commit = subprocess.check_output(
        ["git", "rev-parse", "--verify", "--end-of-options", args.paillier_ref + "^{commit}"],
        cwd=REPO, text=True,
    ).strip()
    print(f"BFV: {args.num_vectors} vectors, dimension {args.dimension}", file=sys.stderr, flush=True)
    bfv = run_bfv(args)
    print(f"Paillier baseline: {commit}", file=sys.stderr, flush=True)
    paillier = baseline(args, commit)
    result: dict[str, Any] = dict(
        recorded_at_utc=datetime.now(UTC).isoformat(), platform=platform.platform(),
        python=platform.python_version(),
        packages={name: importlib.metadata.version(name) for name in ["tenseal", "gmpy2", "msgpack"]},
        implementation_sha256=hashlib.sha256(Path(__file__).with_name("packed_hamming.py").read_bytes()).hexdigest(),
        benchmark_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        baseline_ref=args.paillier_ref, baseline_commit=commit,
        num_vectors=args.num_vectors, dimension=args.dimension, seed=args.seed, repeats=args.repeats, k=args.k,
    )
    result.update(bfv=bfv, paillier=paillier, comparison=compare(bfv, paillier))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("a") as stream:
            stream.write(json.dumps(result) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
