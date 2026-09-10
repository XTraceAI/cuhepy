#!/usr/bin/env python3
"""CPU BFV/Paillier Hamming comparison with separate setup, compute and wire sizes.

Run from the checkout: .venv/bin/python benchmarks/bfv_client_matrix.py --help
Only synthetic plaintexts are seeded. Encryption always uses scheme randomness.
No network, CUDA, SEAL or XTrace service is required.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import platform
import random
import statistics
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

import gmpy2
import msgpack

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from xtrace_sdk.x_vec.crypto.bfv_client import BFVClient  # noqa: E402
from xtrace_sdk.x_vec.crypto.encryption.bfv import BFV  # noqa: E402
from xtrace_sdk.x_vec.crypto.encryption.paillier import Paillier  # noqa: E402
from xtrace_sdk.x_vec.crypto.paillier_client import PaillierClient  # noqa: E402
from xtrace_sdk.x_vec.crypto.paillier_lookup_client import PaillierLookupClient  # noqa: E402

T = TypeVar("T")
VARIANTS = ("bfv-packed", "bfv-individual", "paillier-cpu", "paillier-lookup-cpu")


def time_call(fn: Callable[[], T]) -> tuple[float, T]:
    gc.collect()
    start = time.perf_counter()
    result = fn()
    return time.perf_counter() - start, result


def packet(ciphers: Sequence[Sequence[int]], count: int) -> bytes:
    """Same MessagePack framing for both schemes; big integers become LE bytes.

    Candidate IDs are implicit positions, so no IDs, content, HTTP or TLS bytes
    are included. Native BFV's per-ciphertext header remains in the measurement.
    """
    return msgpack.packb(
        {
            "vector_count": count,
            "ciphertexts": [
                [int(v).to_bytes(max(1, (int(v).bit_length() + 7) // 8), "little") for v in row]
                for row in ciphers
            ],
        },
        use_bin_type=True,
    )


def unpack_packet(payload: bytes) -> list[list[int]]:
    data = msgpack.unpackb(payload, raw=False)
    return [[int.from_bytes(v, "little") for v in row] for row in data["ciphertexts"]]


def make_data(
    count: int, dimension: int, seed: int
) -> tuple[list[list[int]], list[int], list[int]]:
    rng = random.Random(seed)
    query = [rng.getrandbits(1) for _ in range(dimension)]
    vectors = [[rng.getrandbits(1) for _ in range(dimension)] for _ in range(count)]
    vectors[0] = query[:]
    if count > 1:
        vectors[1] = [1 - bit for bit in query]
    if count > 2:
        vectors[-1] = query[:]
    expected = [sum(a != b for a, b in zip(v, query, strict=True)) for v in vectors]
    return vectors, query, expected


def benchmark(
    variant: str,
    args: argparse.Namespace,
    vectors: list[list[int]],
    query: list[int],
    expected: list[int],
) -> dict[str, Any]:
    n = len(vectors)
    timings: dict[str, float] = {}
    print(f"{variant}: key generation and public server setup", file=sys.stderr, flush=True)
    native = variant.startswith("bfv-")
    client: Any
    if native:
        timings["key_generation_s"], client = time_call(
            lambda: BFVClient(
                embed_len=args.embed_len,
                poly_modulus_degree=args.poly_modulus_degree,
                plain_modulus=args.plain_modulus,
                coeff_modulus_bits=args.coeff_modulus_bits,
                decomposition_bits=args.decomposition_bits,
                response_modulus_bits=args.response_modulus_bits,
                device="cpu",
                server_backend=args.server_backend,
            )
        )
    elif variant == "paillier-cpu":
        timings["key_generation_s"], client = time_call(
            lambda: PaillierClient(args.embed_len, args.key_len, device="cpu")
        )
    else:
        timings["key_generation_s"], client = time_call(
            lambda: PaillierLookupClient(args.embed_len, args.key_len, args.alpha_len, device="cpu")
        )
    timings["public_key_export_s"], public_json = time_call(client.stringify_pk)
    public_key_bytes = len(public_json.encode("utf-8"))
    config = json.loads(client.stringify_config())
    if native:

        def load_server() -> BFVClient:
            result = BFVClient(skip_key_gen=True, server_backend=args.server_backend)
            result.load_config(config)
            result.load_stringified_keys(public_json)
            assert result.keys is None
            return result

        timings["public_key_import_s"], server = time_call(load_server)
    else:
        # Paillier server multiplication needs n^2 only; retain a public dict,
        # not a Paillier client containing the decryption key.
        timings["public_key_import_s"], server_pk = time_call(lambda: json.loads(public_json))
        modulus = gmpy2.mpz(server_pk["n_squared"])
    public_json = ""

    packed = variant == "bfv-packed"
    print(f"{variant}: encrypting {n} vectors and query", file=sys.stderr, flush=True)
    timings["index_encrypt_s"], index = time_call(
        lambda: client.encrypt_vec_packed(vectors) if packed else client.encrypt_vec_batch(vectors)
    )
    timings["query_encrypt_s"], encrypted_query = time_call(lambda: client.encrypt_vec_one(query))
    timings["index_serialize_s"], index_wire = time_call(lambda: packet(index, n))
    timings["query_serialize_s"], query_wire = time_call(lambda: packet([encrypted_query], 1))
    # Feed actual deserialized packets to the evaluator, and do the same for the
    # response. Byte totals are measured lengths, not object-size estimates.
    timings["index_deserialize_s"], server_index = time_call(lambda: unpack_packet(index_wire))
    timings["query_deserialize_s"], server_query = time_call(lambda: unpack_packet(query_wire)[0])

    def evaluate() -> list[list[int]]:
        if packed:
            return server.encode_hamming_server_packed(
                server_query, server_index, n, compact=not args.no_compact
            )
        if native:
            return [
                server.encode_hamming_server(server_query, ct, compact=not args.no_compact)
                for ct in server_index
            ]
        return [
            [int(gmpy2.mpz(a) * b % modulus) for a, b in zip(server_query, row, strict=True)]
            for row in server_index
        ]

    print(f"{variant}: public server evaluation", file=sys.stderr, flush=True)
    timings["server_compute_s"], response = time_call(evaluate)
    timings["response_serialize_s"], response_wire = time_call(lambda: packet(response, n))
    timings["response_deserialize_s"], client_response = time_call(
        lambda: unpack_packet(response_wire)
    )
    timings["client_decode_s"], distances = time_call(
        lambda: (
            client.decode_hamming_client_packed(client_response, n)
            if packed
            else client.decode_hamming_client_batch(client_response)
        )
    )
    if distances != expected:
        raise AssertionError(
            f"{variant}: decrypted distances differ from the plaintext Hamming oracle"
        )
    top3 = sorted(range(n), key=lambda i: (distances[i], i))[:3]
    assert top3 == sorted(range(n), key=lambda i: (expected[i], i))[:3]
    budgets = []
    if native:
        budgets = [
            BFV.noise_budget(BFV.ciphertext_from_ints(ct, client.public_key), client.keys)
            for ct in client_response
        ]
    sizes = {
        "encrypted_index_bytes": len(index_wire),
        "public_keys_bytes": public_key_bytes,
        "query_bytes": len(query_wire),
        "response_bytes": len(response_wire),
        "query_plus_response_bytes": len(query_wire) + len(response_wire),
    }
    print(
        f"{variant}: verified {n} distances; response {len(response_wire):,} bytes",
        file=sys.stderr,
        flush=True,
    )
    return {
        "variant": variant,
        "server_backend": args.server_backend if native else None,
        "vectors": n,
        "embed_len": args.embed_len,
        "config": config,
        "compact": native and not args.no_compact,
        "timings": timings,
        "sizes": sizes,
        "index_ciphertexts": len(index),
        "response_ciphertexts": len(response),
        "minimum_response_noise_budget_bits": min(budgets) if budgets else None,
        "top3": [{"index": i, "distance": distances[i]} for i in top3],
        "correct": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=256)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument(
        "--key-len",
        type=int,
        default=1024,
        help="Paillier prime bit length, as in the existing clients",
    )
    parser.add_argument("--alpha-len", type=int, default=50)
    parser.add_argument("--poly-modulus-degree", type=int, default=8192)
    parser.add_argument("--plain-modulus", type=int, default=65537)
    parser.add_argument("--coeff-modulus-bits", type=int, default=180)
    parser.add_argument("--decomposition-bits", type=int, default=30)
    parser.add_argument("--response-modulus-bits", type=int, default=50)
    parser.add_argument("--no-compact", action="store_true")
    parser.add_argument("--server-backend", choices=("optimized", "reference"), default="optimized")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument(
        "--repeats",
        type=int,
        default=1,
        help="Independent runs; each includes fresh key generation",
    )
    parser.add_argument(
        "--variants",
        default="bfv-packed,paillier-cpu",
        help="Comma-separated: " + ", ".join(VARIANTS),
    )
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    variants = [v.strip() for v in args.variants.split(",")]
    if args.num_vectors < 1 or args.embed_len < 1 or args.repeats < 1:
        parser.error("num-vectors, embed-len and repeats must be positive")
    if any(v not in VARIANTS for v in variants):
        parser.error("unknown variant")
    vectors, query, expected = make_data(args.num_vectors, args.embed_len, args.seed)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    )
    output: dict[str, Any] = {
        "environment": {
            "utc": datetime.now(UTC).isoformat(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "gmpy2": gmpy2.version(),
            "gmp": gmpy2.mp_version(),
            "revision": revision,
            "working_tree_dirty": dirty,
        },
        "command": sys.argv,
        "measurement_notes": "CPU synthetic experiment; no equivalent-security claim. Keys are public JSON including BFV evaluation keys. Index/query/response use common MessagePack framing with LE integer bytes and implicit IDs. No network/HTTP/TLS, secret-key, plaintext-content or AES-content bytes. Timings are separate from serialization; no concurrent test/benchmark processes intended.",
        "seed": args.seed,
        "runs": [],
        "source_sha256": {
            str(path.relative_to(REPO_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [
                Path(__file__).resolve(),
                *(REPO_ROOT / "src/xtrace_sdk/x_vec/crypto").glob("*client.py"),
                *(REPO_ROOT / "src/xtrace_sdk/x_vec/crypto/encryption").glob("*.py"),
                REPO_ROOT / "src/xtrace_sdk/x_vec/utils/xtrace_types.py",
            ]
        },
    }
    for repeat in range(args.repeats):
        for variant in variants:
            row = benchmark(variant, args, vectors, query, expected)
            row["repeat"] = repeat
            output["runs"].append(row)
            gc.collect()
    output["median_timings"] = {
        v: {
            metric: statistics.median(
                row["timings"][metric] for row in output["runs"] if row["variant"] == v
            )
            for metric in output["runs"][0]["timings"]
        }
        for v in variants
    }
    print(json.dumps(output, indent=2))
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
