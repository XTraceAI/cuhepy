#!/usr/bin/env python3
"""E58 owner-AEAD cache provision/acquisition and exact local queries.

No plaintext/ID/rank prohibition is assumed for an authorized owner/client.
Bodies are actual serialized sizes; bandwidth models are not socket timings.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from statistics import mean
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import cache_snapshot as snapshot
from experiments.bfv_search_lab import connect4_fixture as connect4


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--connect4", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--queries", type=int, default=8)
    parser.add_argument("--levels", type=int, nargs="+", choices=(1, 3, 6, 9), default=(9,))
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 4 or not 1 <= args.queries <= 128 or len(set(args.levels)) != len(args.levels):
        parser.error("Invalid bounded cache comparison")
    sources = [(name, timed(fixtures.load, name, args.cache / item["member"])) for name, item in fixtures.SOURCES.items()]
    sources.append(("connect4", timed(connect4.load, args.connect4)))
    cases = []
    for name, (load_s, data) in sources:
        ids, heldout = fixtures.split(data, 3001)
        ids, rows, words = tuple(ids), tuple(data.rows[i] for i in ids), tuple(data.rows[i] for i in heldout[:args.queries])
        for repetition in range(args.repeats):
            modes = ((False, "raw", 9), *( (True, retained, level) for level in args.levels for retained in ("raw", "compressed")))
            for compressed, retained, level in modes[::1 if repetition % 2 == 0 else -1]:
                key_s, key = timed(snapshot.secrets.token_bytes, 32)
                owner_s, (manifest, packet) = timed(snapshot.seal, rows, ids, data.dimension, key,
                                                  compressed=compressed, compression_level=level)
                acquire_s, cache = timed(snapshot.open_snapshot, packet, key, manifest, retained=retained)
                samples = []
                for word in words:
                    query_s, actual = timed(cache.query, word)
                    expected = tuple((row ^ word).bit_count() for row in rows)
                    assert actual.scores == expected and actual.top3 == tuple(sorted(zip(expected, ids, strict=True))[:3])
                    samples.append({"online_local_query_s": query_s, "all_scores_and_stable_top3_exact": True,
                                    "scores_sha256": hashlib.sha256(b"".join(x.to_bytes(2, "little") for x in expected)).hexdigest(), "top3": actual.top3})
                cold = key_s + owner_s + acquire_s
                cases.append({"dataset": name, "fixture_sha256": data.sha256, "load_parse_s_outside_crypto_cost": load_s,
                              "count": len(rows), "distinct_vector_count": len(set(rows)), "dimension": data.dimension,
                              "repetition": repetition, "encrypted_snapshot_compressed": compressed,
                              "compression_level": level if compressed else None, "retained": retained,
                              "key_generation_s": key_s, "owner_serialize_compress_authenticate_s": owner_s,
                              "client_authenticate_decompress_decode_s": acquire_s,
                              "actual_encrypted_packet_bytes": len(packet), "trusted_key_and_manifest_body_bytes_model": 32 + snapshot.HEADER,
                              "retained_body_bytes_model": cache.retained_body_bytes_model,
                              "raw_parse_scratch_body_bytes_model": cache.raw_parse_scratch_bytes_model,
                              "samples": samples, "cold_owner_client_compute_s": cold,
                              "complete_cold_and_all_queries_s": cold + sum(s["online_local_query_s"] for s in samples),
                              "transfer_time_models_s": {str(mbps): 8 * len(packet) / (mbps * 1e6) for mbps in (10, 100, 1000)}})
                print(name, repetition, compressed, retained, level, "packet", len(packet), "cold ms", round(cold * 1000, 3),
                      "query mean ms", round(mean(s["online_local_query_s"] for s in samples) * 1000, 3), file=sys.stderr, flush=True)
    report = metadata([Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "cache_snapshot", "coordinate_cache", "binary_fixtures", "connect4_fixture"))])
    report.update(kind="authenticated_encrypted_cache_acquisition_control", split_seed=3001, cases=cases, connect4_source=connect4.SOURCE,
                  scope="Permitted authorized-client full-cache control with actual AEAD packet sizes. "
                        "Trusted key/current manifest acquisition is a premise, not a deployed channel. "
                        "Data/IDs encrypted at untrusted server; compressed length explicitly leaks. "
                        "Raw and compressed retained bodies exclude Python resident overhead/RSS and transient objects. "
                        "Complete cold cost charges owner serialization/compression/encryption and client parsing once; later exact queries reuse it. "
                        "Fixture loading is reported separately as common input acquisition. No HE/GPU/network timing or novelty claim.")
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cases": len(cases)}))


if __name__ == "__main__":
    main()
