#!/usr/bin/env python3
"""Paired local research searches: query preparation and partial-sum CUDA.

Synthetic owner-generated inputs only. Includes actual packet sizes and every
online phase; separately charges one-use preprocessing. No network or attestation.
Run with the research CPU/CUDA extensions built in this checkout.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time
from typing import Any

import gmpy2
import msgpack

from bfv_client_matrix import REPO_ROOT, make_data, packet, unpack_packet

sys.path.insert(0, str(REPO_ROOT))
from cuhepy.bfv.cuda import BFVCudaServer
from cuhepy.bfv.private import BFVPrivateDecoder
from cuhepy.hamming.bfv import BFVClient
from experiments.bfv_search_lab.partial import PartialCudaServer, PartialLayout
from experiments.bfv_search_lab.query import OneUseQueryPool, QueryFactory, expand_query


def elapsed(fn, *args, **kwargs):
    start = time.perf_counter()
    value = fn(*args, **kwargs)
    return time.perf_counter() - start, value


def progress(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


@dataclass
class Case:
    name: str
    layout: PartialLayout
    server: Any
    index: Any
    factory: QueryFactory | None = None
    pool: OneUseQueryPool | None = None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=8192)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--skip-cpu-check", action="store_true")
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.num_vectors < 1 or args.repeats < 1:
        parser.error("positive vector count and repeats required")
    setup: dict[str, Any] = {}
    rows, query, expected = make_data(args.num_vectors, args.embed_len, args.seed)
    progress("Generating owner keys")
    setup["keygen_s"], owner = elapsed(
        lambda: BFVClient(
            args.embed_len,
            args.ring_degree,
            65537,
            180,
            30,
            rns_modulus=True,
            server_backend="residue",
        )
    )
    progress(f"Encrypting {len(rows)} distinct index vectors")
    setup["index_encrypt_s"], index = elapsed(lambda: owner.encrypt_vec_packed(rows))
    setup["index_bytes"] = len(packet(index, len(rows)))
    arithmetic = owner._evaluator()._rns
    layout = PartialLayout(args.ring_degree, args.embed_len)
    setup["baseline_plan_s"], baseline = elapsed(
        lambda: BFVCudaServer(arithmetic, layout.padded, 50)
    )
    setup["baseline_upload_s"], resident = elapsed(lambda: baseline.prepare_index(index, len(rows)))
    setup["index_device_bytes_per_plan"] = resident.device_bytes
    setup["baseline_plan_bytes"] = baseline.cache_bytes()
    private = BFVPrivateDecoder(owner)
    cases = [Case("accepted-cuda", layout, baseline, resident)]
    factories = {}
    for seeded, native, codec, name in (
        (False, False, False, "public-python"),
        (False, True, False, "public-native-products"),
        (False, True, True, "public-native-codec"),
        (True, False, False, "seeded-python"),
        (True, True, False, "seeded-native-products"),
        (True, True, True, "seeded-native-codec"),
    ):
        setup[f"{name}_factory_s"], factory = elapsed(
            QueryFactory, owner, seeded=seeded, native=native, native_encode=codec
        )
        factories[name] = factory
        cases.append(Case(name, layout, baseline, resident, factory))
        if codec:
            cases.append(
                Case(name + "-pool", layout, baseline, resident, factory, OneUseQueryPool(factory))
            )
    seeded_native = factories["seeded-native-codec"]
    public_native = factories["public-native-codec"]
    for partials in (2, 4, 8):
        if partials > layout.padded:
            continue
        partial_layout = PartialLayout(layout.n, layout.dimension, partials)
        setup[f"partial_{partials}_plan_s"], server = elapsed(
            PartialCudaServer, arithmetic, partial_layout, 50
        )
        setup[f"partial_{partials}_upload_s"], snapshot = elapsed(
            server.prepare_index, index, len(rows)
        )
        setup[f"partial_{partials}_plan_bytes"] = server.cache_bytes()
        cases.append(
            Case(
                f"partial-{partials}-seeded-native-codec",
                partial_layout,
                server,
                snapshot,
                seeded_native,
            )
        )
        if partials == 2:
            cases.append(
                Case(
                    "partial-2-seeded-native-codec-pool",
                    partial_layout,
                    server,
                    snapshot,
                    seeded_native,
                    OneUseQueryPool(seeded_native),
                )
            )
            cases.append(
                Case(
                    "partial-2-public-native-codec", partial_layout, server, snapshot, public_native
                )
            )
            cases.append(
                Case(
                    "partial-2-public-native-codec-pool",
                    partial_layout,
                    server,
                    snapshot,
                    public_native,
                    OneUseQueryPool(public_native),
                )
            )

    def run(case, plaintext, expected_distances):
        sample = {}
        sample["offline_refill_s"] = elapsed(case.pool.refill)[0] if case.pool else 0.0
        start = time.perf_counter()
        if case.factory is None:
            sample["client_prepare_s"], query_bytes = elapsed(
                lambda: packet([owner.encrypt_vec_one(plaintext)], 1)
            )
            sample["server_expand_s"], query_wire = elapsed(lambda: unpack_packet(query_bytes)[0])
        else:
            encrypt = case.pool.encrypt if case.pool else case.factory.encrypt
            sample["client_prepare_s"], query_bytes = elapsed(lambda: encrypt(plaintext))
            sample["server_expand_s"], query_wire = elapsed(
                lambda: expand_query(query_bytes, owner._pk())
            )
        sample["server_evaluate_s"], response = elapsed(
            lambda: case.server.search_prepared(query_wire, case.index)
        )
        if case.layout.partials == 1:
            sample["response_pack_s"], response_bytes = elapsed(lambda: packet(response, len(rows)))
            sample["client_unpack_s"], received = elapsed(lambda: unpack_packet(response_bytes))
        else:
            # New response layout is explicitly tagged. This identifies the
            # experiment; it does NOT authenticate a malicious evaluator.
            tag = [
                "cuhepy-lab-partials-v1",
                layout.n,
                layout.dimension,
                case.layout.partials,
                len(rows),
            ]
            sample["response_pack_s"], response_bytes = elapsed(
                lambda: msgpack.packb([tag, packet(response, len(rows))])
            )

            def unpack():
                received_tag, body = msgpack.unpackb(response_bytes)
                if received_tag != tag:
                    raise ValueError("Unexpected experimental response layout")
                return unpack_packet(body)

            sample["client_unpack_s"], received = elapsed(unpack)
        sample["client_decode_s"], distances = elapsed(
            lambda: case.layout.decode(owner, received, len(rows), private)
        )
        sample["client_top3_s"], top = elapsed(
            lambda: sorted(range(len(rows)), key=lambda i: (distances[i], i))[:3]
        )
        sample["online_total_s"] = time.perf_counter() - start
        sample["total_with_refill_s"] = sample["online_total_s"] + sample["offline_refill_s"]
        if (
            distances != expected_distances
            or top != sorted(range(len(rows)), key=lambda i: (expected_distances[i], i))[:3]
        ):
            raise AssertionError(f"Incorrect distances/top3: {case.name}")
        sample["query_bytes"], sample["response_bytes"] = len(query_bytes), len(response_bytes)
        sample["query_plus_response_bytes"] = len(query_bytes) + len(response_bytes)
        return sample

    try:
        if not args.skip_cpu_check:
            progress("Checking accepted CUDA ciphertext against CPU residue reference")
            encrypted = owner.encrypt_vec_one(query)
            setup["cpu_reference_s"], reference = elapsed(
                lambda: owner.encode_hamming_server_packed(encrypted, index, len(rows))
            )
            if baseline.search_prepared(encrypted, resident) != reference:
                raise AssertionError("Baseline GPU differs from CPU ciphertext")
            if private.decode_packed(reference, len(rows)) != expected:
                raise AssertionError("CPU reference distances differ")
        samples = {case.name: [] for case in cases}
        warmup = {}
        for case in cases:
            progress(f"Warmup: {case.name}")
            warmup[case.name] = run(case, query, expected)
        order_rng = random.Random(args.seed + 1)
        for repeat in range(args.repeats):
            plaintext = query.copy()
            plaintext[repeat % len(plaintext)] ^= 1
            expected_distances = [
                sum(a != b for a, b in zip(row, plaintext, strict=True)) for row in rows
            ]
            order = cases.copy()
            order_rng.shuffle(order)
            for case in order:
                samples[case.name].append(run(case, plaintext, expected_distances))
            progress(f"Completed paired round {repeat + 1}/{args.repeats}")
        source_paths = [Path(__file__).resolve()]
        source_paths += list((REPO_ROOT / "experiments/bfv_search_lab").glob("*.py"))
        source_paths += list((REPO_ROOT / "src/cuhepy/bfv/_cpu_ext").glob("*.h"))
        source_paths += list((REPO_ROOT / "src/cuhepy/bfv/_gpu_ext").glob("*.cuh"))
        source_paths += [REPO_ROOT / "src/cuhepy/bfv/_cpu_ext/bindings.cpp"]
        binary_paths = list((REPO_ROOT / "src/cuhepy/bfv").glob("_*_ext/*.so"))
        report = {
            "kind": "local_encrypted_benchmark_no_network_or_attestation",
            "utc": datetime.now(UTC).isoformat(),
            "command": sys.argv,
            "git_head": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
            ).strip(),
            "git_status": subprocess.check_output(
                ["git", "status", "--short"], cwd=REPO_ROOT, text=True
            ),
            "python": sys.version,
            "platform": platform.platform(),
            "gmp": gmpy2.mp_version(),
            "gpu": subprocess.check_output(
                [
                    "nvidia-smi",
                    "--query-gpu=name,driver_version,memory.total",
                    "--format=csv,noheader",
                ],
                text=True,
            ).strip(),
            "config": json.loads(owner.stringify_config()),
            "num_vectors": len(rows),
            "notes": "One warmup per case; fresh encryption, distinct query per round, shuffled paired order. "
            "Every distance and stable top3 verified outside timing. Pool refill separately charged; "
            "online time excludes it. Native query products are experimental variable-time owner code. "
            "Partial scores disclose coordinate-block distances to the owner. "
            "Same encrypted index/keys; separate GPU snapshots for each partial layout. "
            "Setup, network, attestation and retrieval excluded. No security-equivalence claim.",
            "sha256": {
                str(p.relative_to(REPO_ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in source_paths + binary_paths
            },
            "setup": setup,
            "warmup": warmup,
            "results": [
                {
                    "variant": case.name,
                    "partials": case.layout.partials,
                    "samples": samples[case.name],
                    "medians": {
                        key: statistics.median(sample[key] for sample in samples[case.name])
                        for key in samples[case.name][0]
                    },
                }
                for case in cases
            ],
            "all_distances_and_top3_correct": True,
        }
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n")
        for row in report["results"]:
            m = row["medians"]
            print(
                f"{row['variant']:34} online={m['online_total_s']:.6f}s "
                f"with-refill={m['total_with_refill_s']:.6f}s "
                f"server={m['server_evaluate_s']:.6f}s bytes={m['query_plus_response_bytes']}"
            )
    finally:
        private.close()


if __name__ == "__main__":
    main()
