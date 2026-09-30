#!/usr/bin/env python3
"""E60 model cold authorized cache versus optimistic ready remote evaluation.

Cache pays owner AEAD preparation, client acquisition and one actual packet;
remote pays only measured gated online work and nominal query/reply bodies.
Remote setup, owner tokens, private provisioning and framing are omitted to
make a deliberately favorable remote control. Empirical constants are not
latency bounds or measured network behavior. No extrapolation past eight
observed cache/EMVP queries is used for the session-length screen.
"""

# ruff: noqa: E402 -- standalone retained-data analysis.

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from statistics import mean
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-run", type=Path, required=True)
    parser.add_argument("--bgv", type=Path, nargs="+", required=True)
    parser.add_argument("--emvp", type=Path, nargs="+", required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    paths = [args.cache_run.resolve(), *(p.resolve() for p in args.bgv), *(p.resolve() for p in args.emvp)]
    raw = [json.loads(p.read_text()) for p in paths]
    cached, bgv, emvp = raw[0], raw[1:1 + len(args.bgv)], raw[1 + len(args.bgv):]
    datasets = {x["dataset"] for x in bgv}
    if datasets != {x["dataset"] for x in emvp} or len(datasets) != len(bgv) or len(datasets) != len(emvp):
        parser.error("One compatible BGV and EMVP run per dataset is required")
    screens = []
    constants = {}
    for name in sorted(datasets):
        cache_cases = [c for c in cached["cases"] if c["dataset"] == name]
        g, e = next(x for x in bgv if x["dataset"] == name), next(x for x in emvp if x["dataset"] == name)
        assert cache_cases and g["fixture_sha256"] == e["dataset_sha256"] == cache_cases[0]["fixture_sha256"]
        assert g["dimension"] == e["dimension"] == cache_cases[0]["dimension"]
        assert g["count"] == e["index_count"] == cache_cases[0]["count"]
        eligible = [c for c in e["cases"] if c["verified"] and c["native_thread_pinned"]]
        for c in eligible:
            assert [s["scores_sha256"] for s in c["samples"]] == [s["scores_sha256"] for s in cache_cases[0]["samples"]]
        remote_choices = []
        for c in g["cases"]:
            if c["status"] != "measured_research_only":
                continue
            observed = [s for s in c["samples"] if not s["warmup"]]
            assert observed and all(s["complete_gate_before_secret_decrypt"] for s in observed)
            remote_choices.append({"backend": "own_BGV", "kind": c["kind"], "n": c["n"],
                                   "online_compute_s": min(s["online_stage_sum_s"] for s in observed),
                                   "query_and_reply_body_bytes_model": c["geometry"]["online_query_body_bytes"] + c["geometry"]["online_response_body_bytes"]})
        for c in eligible:
            remote_choices.append({"backend": "original_EMVP_private_full_gate", "key_only": c["key_only"],
                                   "online_compute_s": min(s["online_s"] for s in c["samples"]),
                                   "query_and_reply_body_bytes_model": c["native_word_body_models"]["query_bytes"] + c["native_word_body_models"]["response_bytes"]})
        local_choices = []
        groups = {(c["encrypted_snapshot_compressed"], c["compression_level"], c["retained"]) for c in cache_cases}
        for compressed, level, retained in sorted(groups, key=str):
            pair = [c for c in cache_cases if (c["encrypted_snapshot_compressed"], c["compression_level"], c["retained"]) == (compressed, level, retained)]
            assert len(pair) == 2 and len({c["actual_encrypted_packet_bytes"] for c in pair}) == 1
            local_choices.append({"compressed": compressed, "compression_level": level, "retained": retained,
                                  "cold_owner_client_compute_s": mean(c["cold_owner_client_compute_s"] for c in pair),
                                  "online_local_query_s": mean(s["online_local_query_s"] for c in pair for s in c["samples"]),
                                  "actual_download_packet_bytes": pair[0]["actual_encrypted_packet_bytes"],
                                  "retained_body_bytes_model": pair[0]["retained_body_bytes_model"]})
        constants[name] = {"local_choices": local_choices, "optimistic_remote_choices": remote_choices}
        for queries in (1, 2, 4, 8):
            for mbps in (1, 10, 100, 1000, 10000):
                local_costs = [(c["cold_owner_client_compute_s"] + queries * c["online_local_query_s"]
                                + 8 * c["actual_download_packet_bytes"] / (mbps * 1e6), c) for c in local_choices]
                remote_costs = [(queries * (c["online_compute_s"] + 8 * c["query_and_reply_body_bytes_model"] / (mbps * 1e6)), c)
                                for c in remote_choices]
                local_s, local = min(local_costs, key=lambda item: item[0])
                remote_s, remote = min(remote_costs, key=lambda item: item[0])
                screens.append({"dataset": name, "session_queries_model": queries, "bandwidth_Mbps_model": mbps,
                                "cold_cache_compute_plus_nominal_transfer_s": local_s, "chosen_cache": local,
                                "ready_remote_optimistic_compute_plus_nominal_transfer_s": remote_s, "chosen_remote": remote,
                                "cache_cheaper_in_model": local_s <= remote_s})
    result = metadata([Path(__file__), *paths])
    result.update(kind="cache_vs_ready_remote_empirical_cost_screen", inputs=[{"path": str(p.relative_to(ROOT)), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths],
                  constants=constants, screens=screens,
                  scope="Count/time model with empirical constants; no measured bandwidth, RTT, mobile CPU, contention or assurance equivalence. "
                        "Remote uses its fastest measured non-warmup gated sample and no setup/private-token/checker provisioning charges. "
                        "Cache uses both repetition means and pays full AEAD preparation/acquisition and one actual snapshot packet. "
                        "BGV session repetition uses a stationary per-query constant from three timed samples; EMVP/cache each observed eight queries. "
                        "Data/count/dimension hashes match; cache and EMVP all-score query hashes match. "
                        "Different unreviewed protocol/parameter/entropy profiles cannot establish equal-assured-security dominance. "
                        "Independent CPU runs, warm process and small repetitions; no population, novelty or production claim.")
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cache_favorable_cells": sum(s["cache_cheaper_in_model"] for s in screens), "cells": len(screens),
                      "remote_favorable": [s for s in screens if not s["cache_cheaper_in_model"]]}, indent=2))


if __name__ == "__main__":
    main()
