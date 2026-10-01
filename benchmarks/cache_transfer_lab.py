#!/usr/bin/env python3
"""E67 initial actual TCP/full-cache acquisition control on pinned real rows.

Private key/header transfer is an isolated trusted loopback harness, not a
confidential provisioning protocol. No HE-vs-cache deployment win is inferred.
"""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import cache_snapshot as snapshot
from experiments.bfv_search_lab import connect4_fixture as connect4
from experiments.bfv_search_lab import loopback_transfer as transfer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--connect4", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--queries", type=int, default=4)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 16 or not 1 <= args.queries <= 32 or args.json_out.exists():
        parser.error("Bounded pilot and a new result path required")
    cases = []
    inputs = [(name, timed(fixtures.load, name, args.cache / source["member"])) for name, source in fixtures.SOURCES.items()]
    inputs.append(("connect4", timed(connect4.load, args.connect4)))
    for dataset, (load_s, data) in inputs:
        ids, heldout = fixtures.split(data, 3001)
        ids = tuple(ids[:32768])
        rows = tuple(data.rows[i] for i in ids)
        words = tuple(data.rows[i] for i in heldout[64:64+args.queries])
        for repetition in range(args.repeats):
            modes = ((None, "raw"), (1, "raw"), (9, "raw"), (1, "compressed"), (9, "compressed"))
            for level, retained in modes[::1 if repetition % 2 == 0 else -1]:
                key_s, key = timed(secrets.token_bytes, 32)
                owner_s, (manifest, packet) = timed(snapshot.seal, rows, ids, data.dimension, key,
                                                   compressed=level is not None, compression_level=level or 9)
                private = key + manifest.header()
                with transfer.Probe((packet,)) as enrollment:
                    upload_receipt = enrollment.upload(0)
                    stored_packet = enrollment.uploaded[0]
                    upload_connection_s = enrollment.connection_establish_s
                # Separate endpoints/roles: never put the key on the catalog
                # used to represent untrusted cache storage.
                with transfer.Probe((private,)) as owner_channel, transfer.Probe((stored_packet,)) as storage:
                    private_received, private_receipt = owner_channel.transfer(0)
                    received, public_receipt = storage.transfer(0)
                    assert private_received == private
                    parse_s, cache = timed(snapshot.open_snapshot, received, private_received[:32], manifest, retained=retained)
                    samples = []
                    for word in words:
                        query_s, result = timed(cache.query, word)
                        expected = tuple((old ^ word).bit_count() for old in rows)
                        assert result.scores == expected and result.top3 == tuple(sorted(zip(expected, ids, strict=True))[:3])
                        samples.append({"query_s": query_s, "scores_sha256": hashlib.sha256(b"".join(x.to_bytes(2, "little") for x in result.scores)).hexdigest(),
                                        "every_score_id_and_stable_top3_exact": True})
                    enrolled_new_client = owner_channel.connection_establish_s + storage.connection_establish_s + private_receipt["transfer_wall_s"] + public_receipt["transfer_wall_s"] + parse_s
                    cases.append({"dataset": dataset, "fixture_sha256": data.sha256, "count": len(rows),
                                  "distinct_rows": len(set(rows)), "dimension": data.dimension, "common_load_parse_s": load_s,
                                  "repetition": repetition, "compression_level": level, "retained": retained,
                                  "key_generation_s": key_s, "owner_serialize_compress_authenticate_s": owner_s,
                                  "client_authenticate_parse_s": parse_s, "trusted_channel": private_receipt,
                                  "enrollment_upload": upload_receipt, "enrollment_tcp_connect_s": upload_connection_s,
                                  "storage_channel": public_receipt, "tcp_connection_establish_s": owner_channel.connection_establish_s + storage.connection_establish_s,
                                  "new_client_acquire_wall_stage_sum_s": enrolled_new_client,
                                  "cold_owner_client_wall_stage_sum_s": key_s + owner_s + upload_connection_s + upload_receipt["transfer_wall_s"] + enrolled_new_client,
                                  "total_acquisition_application_bytes": sum(r["client_request_frame_bytes"] + r["server_reply_frame_bytes"] + r["payload_bytes"] for r in (private_receipt, public_receipt)),
                                  "total_cold_application_bytes": sum(r["client_request_frame_bytes"] + r["server_reply_frame_bytes"] + r["payload_bytes"] for r in (upload_receipt, private_receipt, public_receipt)),
                                  "retained_body_bytes_model": cache.retained_body_bytes_model,
                                  "samples": samples, "query_source_ids": heldout[64:64+args.queries]})
    paths = [Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "loopback_transfer", "cache_snapshot", "coordinate_cache", "binary_fixtures", "connect4_fixture")),
        ROOT / "benchmarks/dictionary_layout_lab.py", ROOT / "benchmarks/certified_filter_lab.py"]
    result = metadata(paths)
    result.update(kind="actual_loopback_cache_acquisition_control", split_seed=3001, cases=cases,
                  scope="Actual persistent TCP framed payloads and trusted-key/header byte control, loopback only. "
                        "Cold, enrolled-storage/new-client and returning-query costs include serialized provisioning for this cache. "
                        "Actual enrollment upload populates the bytes served to the client; TLS, WAN, TCP/IP headers/retransmissions, durable epoch and RSS excluded. "
                        "AES-GCM authenticates cache before parsing; transport harness does not implement confidential private provisioning. "
                        "No new HE RPC comparison, GPU data, confidence/p95 claim, production assurance or novel mechanism.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cases": len(cases), "local_exact_queries": sum(len(c["samples"]) for c in cases)}))


if __name__ == "__main__":
    main()
