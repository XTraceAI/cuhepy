#!/usr/bin/env python3
"""One-use masked-query pilots with charged preprocessing, state and failures."""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.matrix_arithmetic_lab import digest, timed
from experiments.bfv_search_lab import matrix_bgv_oracle as matrix
from experiments.bfv_search_lab import matrix_linear_check as check
from experiments.bfv_search_lab import matrix_masked_query as masked
from experiments.bfv_search_lab import matrix_search_cost as counts


def pilot(n, rank, seed, mask_space):
    ctx, rng = matrix.Context(n=n, rank=rank), random.Random(seed)
    words = list(range(1 << rank)) + [0, 1, 0]
    ids = list(range(200, 200 + len(words)))
    rng.shuffle(ids)
    secret = matrix.sample_matrix(ctx, rank, rank, rng, small=True)
    out_secret = matrix.sample_matrix(ctx, 1, rank, rng, small=True)[0]
    plain = tuple(tuple(matrix.simd_encode(ctx, tuple((words[i] >> bit) & 1 if i < len(words) else 0
                                                    for i in range(start, start + n)))
                        for bit in range(rank)) for start in range(0, len(words), n))
    index_s, index = timed(matrix.encrypt, ctx, secret, plain, rng)
    # Commit the local fixture including IDs; not a receipt or remote commitment protocol.
    epoch = bytes.fromhex(digest((asdict(ctx), words, ids, index.constant, index.mask)))
    forms = masked.index_conversion_forms(ctx, index)
    sources = {s for row in forms for form in row for s, _ in form.terms}
    values = matrix.source_values(ctx, secret, sources)
    key_s, linear_key = timed(matrix.mask_sources, ctx, values, out_secret, rng)
    conversion_s, converted = timed(masked.convert_index, ctx, index, linear_key, epoch)
    model = counts.masked_cost(rank, effective_dimension=n * rank, rows=len(plain), q_bits=61, digit_bits=8, t=97,
                               mask_space=mask_space)
    assert converted.coefficient_bytes == model["converted_index_coefficient_bytes"]
    assert linear_key.coefficient_bytes == model["one_time_linear_key_bytes"]
    prepared, offline_samples = [], []
    # Prepare the entire pool before choosing/querying any plaintext query.
    for token in range(1 << rank):
        token_id, mask_seed = rng.randbytes(16), rng.randbytes(32)
        owner_s, (ticket, packet) = timed(masked.prepare, ctx, secret, out_secret, mask_seed, epoch, token_id, rng,
                                         mask_space=mask_space)
        server_s, answer = timed(masked.evaluate_offline, ctx, index, packet)
        check_prepare_s, gate = (timed(check.LinearTicket, converted, answer, random.Random(16000 + token))
                                 if mask_space == "constant" else (None, None))
        assert packet.packet.coefficient_bytes == model["offline_query_coefficient_bytes_per_token"]
        offline_samples.append({"token_id": token_id.hex(), "owner_prepare_s": owner_s, "server_prepare_s": server_s,
                                "conditional_check_prepare_s": check_prepare_s,
                                "upload_coefficient_bytes": packet.packet.coefficient_bytes,
                                "stored_answer_coefficient_bytes": len(answer.results) * (rank + 1) * n * 8})
        prepared.append((ticket, answer, gate))
    samples, score_hashes = [], []
    queries = list(range(1 << rank))
    rng.shuffle(queries)
    for query, (ticket, answer, gate) in zip(queries, prepared, strict=True):
        weights = tuple(ctx.constant(1 - 2 * ((query >> bit) & 1)) for bit in range(rank))
        owner_s, request = timed(ticket.consume, weights, epoch)
        online_s, result = timed(masked.evaluate_online, converted, answer, request)
        check_s = None
        if gate is not None:
            check_s, accepted = timed(gate.verify_once, request, result)
            assert accepted  # Before any owner decryption.
        finish_s, decoded = timed(lambda result=result: [matrix.simd_decode(ctx, matrix.decrypt(ctx, c, out_secret)) for c in result])
        distances = [(s + query.bit_count()) % ctx.t for row in decoded for s in row][:len(words)]
        expected = [(word ^ query).bit_count() for word in words]
        assert distances == expected
        assert sorted(zip(distances, ids, strict=True))[:3] == sorted(zip(expected, ids, strict=True))[:3]
        assert len(request.coefficient_body()) == model["online_delta_coefficient_bytes"]
        try:
            ticket.consume(weights, epoch)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Consumed local mask was reused")
        score_hashes.append((query, digest(distances)))
        samples.append({"query_id": query, "token_id": request.token_id.hex(), "owner_request_s": owner_s,
                        "online_server_s": online_s, "decrypt_decode_s": finish_s,
                        "online_upload_coefficient_bytes": len(request.coefficient_body()),
                        "response_coefficient_bytes": len(result) * (rank + 1) * n * 8,
                        "conditional_check_s": check_s,
                        "conditional_check_before_decryption": gate is not None,
                        "all_distances_and_stable_top3_exact": True, "local_reuse_rejected": True})
    return {"parameters": asdict(ctx), "seed": seed, "mask_space": mask_space,
            "rows": len(words), "distinct_rows": len(set(words)),
            "queries": len(queries), "index_epoch": epoch.hex(), "cost": model,
            "index_encrypt_s": index_s, "linear_key_setup_s": key_s, "index_conversion_s": conversion_s,
            "offline_samples": offline_samples, "online_samples": samples,
            "results_sha256": digest(sorted(score_hashes)),
            "median_oracle_online_ms": {f: 1000 * statistics.median(s[f] for s in samples)
                                        for f in ("owner_request_s", "online_server_s", "decrypt_decode_s")}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    pilots = []
    for n, rank in ((2, 1), (4, 2), (4, 4)):
        for space in ("full", "constant"):
            print(f"masked-query pilot n={n} rank={rank} space={space}", file=sys.stderr, flush=True)
            pilots.append(pilot(n, rank, 6140 + n + rank, space))
    paths = ["experiments/bfv_search_lab/matrix_bgv_oracle.py", "experiments/bfv_search_lab/matrix_masked_query.py",
             "experiments/bfv_search_lab/matrix_search_cost.py", "experiments/bfv_search_lab/test_matrix_masked_query.py",
             "experiments/bfv_search_lab/matrix_linear_check.py", "experiments/bfv_search_lab/test_matrix_linear_check.py",
             "benchmarks/matrix_masked_query_lab.py", "benchmarks/matrix_arithmetic_lab.py"]
    report = {"experiment": "E17 one-use masked-query preprocessing on the E28 toy arithmetic",
              "scope": "local exactness/lifecycle experiment; no deployment or end-to-end security claim",
              "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths},
              "pilots": pilots,
              "models": [counts.masked_cost(k, rows=r, mask_space=s) for k in (1, 2, 4, 8, 16, 32, 64, 128)
                         for r in (1, 8, 64) for s in ("full", "constant")],
              "model_profile": {"effective_dimension": 16384, "q_bits": 120, "digit_bits": 30, "t": 65537,
                                "byte_aligned_field_coefficients": True, "security_equivalence_established": False}}
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "encrypted_searches": sum(p["queries"] for p in pilots),
                      "all_distances_and_stable_top3_exact": True}))


if __name__ == "__main__":
    main()
