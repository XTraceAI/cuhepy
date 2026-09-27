#!/usr/bin/env python3
"""E20/E21 mathematical models and paired homemade encrypted *toy* pilots.

No CUDA speedup, secure parameter choice, private adaptive-query protocol or
novelty claim. Model counts and measured toy wall times are separate records.
Only synthetic data and aggregate measurements are saved, never key material.
"""

# ruff: noqa: E402 -- standalone benchmark adds the repository root before imports.

from __future__ import annotations

import argparse
from dataclasses import asdict
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experiments.bfv_search_lab import aggregate_bgv as aggregate
from experiments.bfv_search_lab import answer_oracles as answer
from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import deferred_bgv as delayed
from experiments.bfv_search_lab import reduction_oracles as reduction
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


def timed(function, *args, **kwargs):
    start = time.perf_counter()
    result = function(*args, **kwargs)
    return time.perf_counter() - start, result


def medians(samples):
    return {key: statistics.median(row[key] for row in samples) for key in samples[0]}


def model_rows():
    rows = []
    n, padded, t, eta, bits, digit_bits = 16384, 512, 1031, 21, 120, 30
    fresh = t // 2 + t * eta * (2 * n + 1)
    product_bound = n * fresh**2
    switch_bound = t * eta * n * ((1 << digit_bits) - 1) * ((bits + digit_bits - 1) // digit_bits)
    for count in (32, 8192, 16384, 32768):
        tiles = (count + n // padded - 1) // (n // padded)
        for cut in range(padded.bit_length()):
            groups = [reduction.schedule_cost(n, padded, min(padded, tiles - start), cut)
                      for start in range(0, tiles, padded)]
            rows.append({
                "count": count, "n": n, "padded": padded, "cut": cut,
                "switch_calls": sum(group.switch_calls for group in groups),
                "distinct_keys": groups[0].distinct_keys,
                "key_coefficient_bytes": groups[0].key_coefficient_bytes,
                "max_checkpoint_polynomials": max(group.max_checkpoint_polynomials for group in groups),
                "max_switch_error_weight": max(group.switch_error_weight for group in groups),
                "max_phase_bound_bits": max(
                    (group.product_bound_weight * product_bound + group.switch_error_weight * switch_bound).bit_length()
                    for group in groups),
            })
    return rows


def delayed_pilot(repeats):
    n, dimension, count = 64, 16, 128
    rng = random.Random(2026092701)
    rows = [[rng.randrange(2) for _ in range(dimension)] for _ in range(count)]
    keygen_s, (pk, sk) = timed(bgv.key_gen, n, t=1031, q_bits=180, eta=2)
    reference_key_s, reference_keys = timed(trace.evaluation_keys, pk, sk, dimension, 12)
    initial_query = rows[0]
    _, plaintext_index = bgv.coefficient_inputs(initial_query, rows, n)
    index_s, index = timed(lambda: [bgv.encrypt(poly, pk) for poly in plaintext_index])
    setup = {"keygen_s": keygen_s, "index_s": index_s, "reference_keygen_s": reference_key_s}
    variants = ["reference"]
    keys = {}
    for cut in range(dimension.bit_length()):
        name = f"delay-{cut}"
        elapsed, keys[name] = timed(delayed.evaluation_keys, pk, sk, dimension, cut, 12)
        setup[name] = {"keygen_s": elapsed, "source_keys": len(keys[name].sources),
                       "model": asdict(reduction.schedule_cost(n, dimension, dimension, cut, 180, 12))}
        variants.append(name)
    samples = {name: [] for name in variants}
    warmup = {}
    for repeat in range(repeats + 1):
        query = [rng.randrange(2) for _ in range(dimension)]
        qp, _ = bgv.coefficient_inputs(query, [], n)
        encrypted = bgv.encrypt(qp, pk)
        expected = [sum(a != b for a, b in zip(query, row, strict=True)) for row in rows]
        order = variants.copy()
        rng.shuffle(order)
        for name in order:
            method, current_keys = (butterfly.search, reference_keys) if name == "reference" else (delayed.search, keys[name])
            server_s, result = timed(method, encrypted, index, count, pk, current_keys)
            client_s, decoded = timed(lambda result=result: trace.decode([bgv.decrypt(ct, pk, sk) for ct in result], count, dimension, pk))
            assert decoded == expected
            sample = {"server_s": server_s, "decrypt_decode_s": client_s,
                      "phase_bound_bits": max(ct.phase_bound.bit_length() for ct in result),
                      "response_ciphertexts": len(result)}
            if repeat:
                samples[name].append(sample)
            else:
                warmup[name] = sample
        print(f"E20 toy paired round {repeat}/{repeats}", file=sys.stderr, flush=True)
    return {"n": n, "dimension": dimension, "count": count, "t": pk.t, "q_bits": pk.q.bit_length(),
            "digit_bits": 12, "eta": pk.eta, "setup": setup, "warmup": warmup,
            "samples": samples, "medians": {name: medians(values) for name, values in samples.items()},
            "all_distances_exact": True, "security_parameters_reviewed": False}


def aggregate_pilot(repeats):
    n, dimension, count, k = 16, 4, 32, 3
    rng = random.Random(2026092702)
    rows = [[(i >> j) & 1 for j in range(dimension)] for i in range(count)]
    rng.shuffle(rows)
    keygen_s, (pk, sk) = timed(bgv.key_gen, n, t=257, q_bits=180, eta=1)
    aggregate_key_s, aggregate_keys = timed(trace.evaluation_keys, pk, sk, 1, 12)
    packed_key_s, packed_keys = timed(trace.evaluation_keys, pk, sk, dimension, 12)
    initial = [0] * dimension
    aggregate_index_s, (_, index) = timed(aggregate.encrypt_inputs, initial, rows, pk)
    _, plain_index = bgv.coefficient_inputs(initial, rows, n)
    packed_index_s, packed_index = timed(lambda: [bgv.encrypt(p, pk) for p in plain_index])
    samples = {"aggregate": [], "packed-distances": []}
    warmup, transcripts = {}, []

    def scalar(cipher):
        plain = bgv.decrypt(cipher, pk, sk)
        assert not any(plain[1:])
        return plain[0]

    for repeat in range(repeats + 1):
        query = [rng.randrange(2) for _ in range(dimension)]
        expected = sorted((sum(a != b for a, b in zip(query, row, strict=True)), i)
                          for i, row in enumerate(rows))[:k]
        query_s, encrypted = timed(lambda query=query: [bgv.encrypt([bit] + [0] * (n - 1), pk) for bit in query])
        qp, _ = bgv.coefficient_inputs(query, [], n)
        packed_query_s, packed_query = timed(bgv.encrypt, qp, pk)
        order = list(samples)
        rng.shuffle(order)
        for name in order:
            if name == "aggregate":
                server_s, result = timed(aggregate.search, encrypted, index, pk, aggregate_keys)
                owner_s, histogram = timed(lambda result=result: [scalar(ct) for ct in result.histogram])
                prefix_server_s = 0.0
                prefix_owner_s = 0.0

                def count_prefix(distance, lo, hi, current=result):
                    nonlocal prefix_server_s, prefix_owner_s
                    elapsed, cipher = timed(aggregate.prefix_count, current, distance, lo, hi, pk)
                    prefix_server_s += elapsed
                    elapsed, value = timed(scalar, cipher)
                    prefix_owner_s += elapsed
                    return value

                recovery_s, (recovered, transcript) = timed(answer.recover_topk, histogram, count, k, count_prefix)
                assert recovered == expected
                if repeat:
                    transcripts.append([asdict(probe) for probe in transcript])
                sample = {"query_encrypt_s": query_s, "initial_server_s": server_s,
                          "owner_histogram_s": owner_s, "recovery_s": recovery_s,
                          "prefix_server_s": prefix_server_s, "prefix_owner_s": prefix_owner_s,
                          "local_total_s": query_s + server_s + owner_s + recovery_s,
                          "product_calls": result.product_calls, "multiplicative_depth": result.max_depth,
                          "initial_ciphertexts": len(result.histogram), "prefix_ciphertexts": len(transcript),
                          "total_response_ciphertexts": len(result.histogram) + len(transcript),
                          "cached_row_ciphertexts": sum(len(row) for row in result.row_polynomials),
                          "phase_bound_bits": max(ct.phase_bound.bit_length() for ct in result.histogram)}
            else:
                server_s, result = timed(butterfly.search, packed_query, packed_index, count, pk, packed_keys)
                def finish(current=result):
                    distances = trace.decode([bgv.decrypt(ct, pk, sk) for ct in current], count, dimension, pk)
                    return sorted((distance, i) for i, distance in enumerate(distances))[:k]
                client_s, recovered = timed(finish)
                assert recovered == expected
                sample = {"query_encrypt_s": packed_query_s, "initial_server_s": server_s,
                          "owner_finish_s": client_s, "local_total_s": packed_query_s + server_s + client_s,
                          "product_calls": len(packed_index), "multiplicative_depth": 1,
                          "total_response_ciphertexts": len(result),
                          "phase_bound_bits": max(ct.phase_bound.bit_length() for ct in result)}
            if repeat:
                samples[name].append(sample)
            else:
                warmup[name] = sample
        print(f"E21 toy paired round {repeat}/{repeats}", file=sys.stderr, flush=True)
    return {"n": n, "dimension": dimension, "count": count, "k": k, "t": pk.t,
            "q_bits": pk.q.bit_length(), "digit_bits": 12, "eta": pk.eta,
            "setup": {"keygen_s": keygen_s, "aggregate_key_s": aggregate_key_s,
                      "packed_key_s": packed_key_s, "aggregate_inputs_s": aggregate_index_s,
                      "packed_index_s": packed_index_s,
                      "aggregate_index_ciphertexts": count * dimension,
                      "packed_index_ciphertexts": len(packed_index)},
            "samples": samples, "warmup": warmup,
            "medians": {name: medians(values) for name, values in samples.items()},
            "prefix_transcripts": transcripts, "all_stable_topk_exact": True,
            "adaptive_prefix_privacy": "reveals selected distances and ID intervals; not a private protocol",
            "ciphertext_bytes": "not serialized; counts exclude compression, authentication and network",
            "security_parameters_reviewed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("Positive repeat count required")
    sources = [Path(__file__), *(ROOT / "experiments/bfv_search_lab" / name for name in (
        "reduction_oracles.py", "deferred_bgv.py", "answer_oracles.py", "aggregate_bgv.py",
        "shallow_bgv.py", "trace_bgv.py", "butterfly_bgv.py")), ROOT / "src/cuhepy/bfv/scheme.py"]
    result = {
        "kind": "creative_search_algebra_models_and_toy_pilots",
        "utc": datetime.now(UTC).isoformat(), "command": sys.argv,
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sources},
        "python": sys.version, "platform": platform.platform(),
        "cpu": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                     if line.startswith("model name")), platform.machine()),
        "notes": "One excluded warmup; fresh paired queries and shuffled variant order. "
                 "Homemade variable-time Python/GMP on tiny insecure rings. Full conservative phase bounds; "
                 "no HE parameter review, authentication, network or complete private prefix protocol. "
                 "Models are not timings. Large-model Q=120 bits, t=1031, eta=21, digit_bits=30. "
                 "Key sizes count canonical coefficients only, and memory counts exclude temporaries. "
                 "No secret keys or ciphertext contents saved.",
        "e20_models": model_rows(),
        "e20_encrypted_toy": delayed_pilot(args.repeats),
        "e21_models": [{"count": count, "dimension": 512, **answer.scalar_cost(count, 512)}
                       for count in (8192, 32768)],
        "e21_rank_checks": [{"dimension": d, "generic_rank": answer.kernel_rank(d, 2, 17),
                             "degenerate_rank": answer.kernel_rank(d, 1, 17)} for d in range(1, 7)],
        "e21_encrypted_toy": aggregate_pilot(args.repeats),
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(args.json_out)


if __name__ == "__main__":
    main()
