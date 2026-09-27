"""Offline paired cost of BGV authentication and private terminal hardening.

Synthetic Nitro evidence is explicitly trusted ONLY inside this benchmark.
There is no hardware attestation or networking in these numbers. All schemes
and arithmetic are homemade. No keys, queries, plaintexts or ciphertexts are
persisted; JSON contains public parameters, timings, byte counts and hashes.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random
import statistics
import subprocess
import time
from unittest.mock import patch

from cuhepy.hamming import bfv_nitro as nitro
from tests.unit.nitro_fixtures import PCRS, SyntheticNitro
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import attested_bgv as attested, compact_bgv as compact
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import compressed_query_bgv as qc, compressed_response_bgv as rc
from experiments.bfv_search_lab.security_bgv import BGVExecutionPolicy


def timed(function):
    start = time.perf_counter()
    value = function()
    return value, (time.perf_counter() - start) * 1000


def run(count, rounds, rounded):
    policy = BGVExecutionPolicy(query_drop_bits=58 if rounded else 0,
                                response_drop_bits=22 if rounded else 0)
    rng = random.Random(451 + count)
    vectors = [[rng.randrange(2) for _ in range(512)] for _ in range(count)]
    query = [rng.randrange(2) for _ in range(512)]
    expected = tuple(sum(a != b for a, b in zip(v, query, strict=True)) for v in vectors)
    setup_start = time.perf_counter()
    pk, sk = bgv.key_gen(policy.n, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, policy.padded)
    _, plains = bgv.coefficient_inputs(query, vectors, pk.n)
    index = [bgv.encrypt(p, pk) for p in plains]
    issuer = SyntheticNitro()
    client = attested.BGVAttestedClient(pk, sk, keys, index, count,
        nitro.NitroAttestationPolicy(PCRS), policy=policy)
    server = attested.BGVAttestedServer(client.registration_packet(), issuer, policy=policy)
    setup_ms = (time.perf_counter() - setup_start) * 1000
    # Test-local trust override has no place in a deployment.
    with patch.object(nitro, "_AWS_ROOT_SHA256", issuer.root_digest):
        _, handshake_ms = timed(lambda: client.accept_attestation(*server.attest(client.begin_attestation())))

    def raw_server(request):
        encrypted = (qc.expand(request[70:-64], pk, dropped_bits=policy.query_drop_bits, backend="native")
                     if rounded else owner.expand(request[70:-64], pk))
        ciphers = server._server.search_compact(encrypted, server._index, bits=policy.terminal_bits)
        packet = compact.pack(ciphers, count, policy.dimension, pk)
        if rounded:
            packet = rc.compress(packet, pk, count=count, dimension=policy.dimension,
                bits=policy.terminal_bits, bounds=client._bounds,
                dropped_bits=policy.response_drop_bits, backend="native")
        return packet

    def raw_finish(response):
        packet, bounds = response, client._bounds
        if rounded:
            packet, bounds = rc.expand(packet, pk, count=count, dimension=policy.dimension,
                bits=policy.terminal_bits, bounds=bounds,
                dropped_bits=policy.response_drop_bits, backend="native")
        # Trusted same-process fixture, not remote authorization.
        return client._encryptor.finish_packed_fixture(packet, packet, count, policy.dimension,
            bounds=bounds, bits=policy.terminal_bits)

    samples, orders = [], []
    for trial in range(rounds + 2):
        request, query_ms = timed(lambda: client.begin_query(query))
        server_order = ["raw", "attested"]
        rng.shuffle(server_order)
        server_times, outputs = {}, {}
        for mode in server_order:
            outputs[mode], server_times[mode] = timed(
                lambda mode=mode, request=request: raw_server(request) if mode == "raw" else server.search(request))
        response, receipt = outputs["attested"]
        if response != outputs["raw"]:
            raise AssertionError("Authenticated evaluator changed the public ciphertext")
        finish_order = ["raw", "protected"]
        rng.shuffle(finish_order)
        finish_times = {}
        for mode in finish_order:
            result, finish_times[mode] = timed(
                lambda mode=mode, response=response, receipt=receipt:
                    raw_finish(response) if mode == "raw" else client.finish_query(response, receipt))
            if result.distances != expected:
                raise AssertionError("BGV result differs from the plaintext oracle")
        if trial >= 2:
            samples.append(dict(query_ms=query_ms, server_raw_ms=server_times["raw"],
                server_attested_ms=server_times["attested"], finish_raw_ms=finish_times["raw"],
                finish_protected_ms=finish_times["protected"]))
            orders.append(dict(server=server_order, finish=finish_order))
    client.close()
    files = [
        "experiments/bfv_search_lab/attested_bgv.py", "experiments/bfv_search_lab/security_bgv.py",
        "experiments/bfv_search_lab/private_bgv.py", "experiments/bfv_search_lab/_owner/bgv_private.h",
        "experiments/bfv_search_lab/_owner/private_bindings.cpp",
        "src/cuhepy/bfv/_cpu_ext/private_decoder.h",
        "benchmarks/bgv_authentication.py",
    ]
    from experiments.bfv_search_lab._owner import _bgv_private, _bgv_owner
    from experiments.bfv_search_lab._native import _bgv_trace
    return dict(
        kind="offline synthetic-Nitro protocol benchmark; no hardware or network",
        git_head=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        policy=asdict(policy), count=count, rounds=rounds, setup_ms=setup_ms,
        synthetic_handshake_ms=handshake_ms, request_bytes=len(request), response_bytes=len(response),
        receipt_bytes=len(receipt), query_authentication_bytes=attested.QUERY_OVERHEAD,
        registration_bytes=len(client._setup) + attested.REGISTRATION_OVERHEAD,
        samples=samples, orders=orders,
        medians={key: statistics.median(s[key] for s in samples) for key in samples[0]},
        source_sha256={file: hashlib.sha256(Path(file).read_bytes()).hexdigest() for file in files},
        binary_sha256={Path(m.__file__).name: hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest()
                       for m in (_bgv_private, _bgv_owner, _bgv_trace)},
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, choices=(1024, 8192), default=8192)
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--rounded", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 3 <= args.rounds <= 100:
        parser.error("Use 3..100 measured rounds")
    result = run(args.count, args.rounds, args.rounded)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["medians"], indent=2))


if __name__ == "__main__":
    main()
