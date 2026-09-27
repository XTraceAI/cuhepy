#!/usr/bin/env python3
"""Paired E15 precision-policy measurements with unchanged homemade BGV kernels.

Fresh queries share keys, index and encryption randomness across policies.
Includes client codecs, GPU evaluation, response codecs and private finishing;
setup and the duplicate known-response fixture gate are recorded separately.
The gate precedes all private processing. This is a trusted synthetic local/TCP
fixture, not GPU authentication, a security estimate or a deployable protocol.
Only public parameters, bounds, timing samples and code hashes are saved.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack, closing
from dataclasses import asdict
from datetime import UTC, datetime
import gc
import hashlib
import json
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time

from bfv_client_matrix import REPO_ROOT, make_data
from bgv_pipeline_followup import Handler, LINKS, Loopback, Variant, expand_response, finish
from bgv_query_compression import check_result
from bgv_service_pipeline import provenance, timed

sys.path.insert(0, str(REPO_ROOT))
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import owner_bgv as owner, compressed_query_bgv as query_codec
from experiments.bfv_search_lab import joint_precision_bgv as planner
from experiments.bfv_search_lab.native_bgv import NativeServer
from experiments.bfv_search_lab.support_bounds_bgv import POLICY, SupportBoundServer


def trials(args, rows, client, workspaces, plans):
    variants = {
        name: Variant(bits=p.terminal_bits, query_drop=p.query_drop, response_drop=p.response_drop)
        for name, p in plans.items()
    }
    handlers = {name: Handler(workspaces[name], args.embed_len, v) for name, v in variants.items()}
    samples, warmup, gate_costs = {}, {}, []
    plain_rng, order_rng = random.Random(20260926), random.Random(20260928)
    # Identical unrounded input must still produce identical COMPLETE wire
    # ciphertexts. Only the trusted public bound changes. Excluded from timing.
    fresh = client.encrypt(bgv.coefficient_inputs(rows[0], [], client.pk.n)[0])
    same_precision = [Handler(w, args.embed_len, Variant())(fresh)[0] for w in workspaces.values()]
    if len(set(same_precision)) != 1:
        raise AssertionError("Changing the bound policy changed the ciphertext arithmetic")
    with closing(Loopback()) as tcp:
        for repeat in range(args.repeats + 1):
            plain = [plain_rng.randrange(2) for _ in range(args.embed_len)]
            expected = tuple(sum(a != b for a, b in zip(row, plain, strict=True)) for row in rows)
            encode_s, encoded = timed(bgv.coefficient_inputs, plain, [], client.pk.n)
            encrypt_s, fresh = timed(client.encrypt, encoded[0])
            packets, known = {}, {}
            for name, v in variants.items():
                compress_s, packet = (0.0, fresh) if v.query_drop is None else timed(
                    query_codec.compress, fresh, client.pk, dropped_bits=v.query_drop, backend="native")
                packets[name] = packet, compress_s
                begin = time.perf_counter()
                known_wire, bounds, _ = handlers[name](packet)
                known_expanded, _ = expand_response(
                    known_wire, client.pk, len(rows), args.embed_len, v, bounds)
                known[name] = known_wire, known_expanded, bounds
                if (len(packet), len(known_wire)) != (plans[name].query_bytes, plans[name].response_bytes):
                    raise AssertionError("Measured packets differ from the exact public byte model")
                gate_costs.append(dict(variant=name, repeat=repeat, seconds=time.perf_counter()-begin))
            order = [(name, "local") for name in variants]
            if args.transport_repeats and repeat <= args.transport_repeats:
                order += [(name, link) for name in variants for link in args.links]
            order_rng.shuffle(order)
            for name, link in order:
                packet, compress_s = packets[name]
                known_wire, known_expanded, bounds = known[name]
                begin = time.perf_counter()
                if link == "local":
                    received, actual_bounds, phases = handlers[name](packet)
                    if actual_bounds != bounds:
                        raise AssertionError("Public bounds changed between duplicate evaluations")
                else:
                    received, phases = tcp.request(packet, handlers[name], link)
                result, private = finish(received, known_wire, known_expanded, bounds, client,
                                         len(rows), args.embed_len, variants[name])
                request_s = time.perf_counter() - begin
                check_result(result, expected)
                phases.update(private)
                phases.update(dict(
                    encode_s=encode_s, encrypt_s=encrypt_s, query_compress_s=compress_s,
                    request_s=request_s, total_s=encode_s+encrypt_s+compress_s+request_s,
                    client_total_s=encode_s+encrypt_s+compress_s+private["client_response_s"],
                    query_bytes=len(packet), response_bytes=len(received),
                    tcp_frame_header_bytes=0 if link == "local" else 8))
                (samples if repeat else warmup).setdefault(name + "/" + link, []).append(phases)
            print("Finished support-bound round", repeat, "of", args.repeats, flush=True)
    return dict(
        variants={name: asdict(v) for name, v in variants.items()},
        samples=samples, warmup=warmup,
        medians={name: {key: statistics.median(row[key] for row in values) for key in values[0]}
                 for name, values in samples.items()},
        excluded_expected_fixture_costs=gate_costs,
        all_distances_and_stable_top3_correct=True, same_precision_complete_ciphertexts_identical=True)


def run_index(args, rows, tiles, pk, keys, client, mode):
    print("Preparing", mode, "index", flush=True)
    encrypt_s, index = timed(lambda: [bgv.encrypt(p, pk) if mode == "public"
                                     else owner.expand(client.encrypt(p), pk) for p in tiles])
    setup = dict(encrypt_and_expand_s=encrypt_s, ciphertexts=len(index),
                 phase_bound_per_tile=index[0].phase_bound,
                 full_coefficient_bytes=len(index)*2*pk.n*((pk.q.bit_length()+7)//8))
    workspaces, selected, planning = {}, {}, {}
    with ExitStack() as stack:
        for name, cls in (("conservative", NativeServer), ("support", SupportBoundServer)):
            setup[name + "_server_s"], server = timed(
                cls, pk, keys, residue=True, device="cuda", cuda_level=4, ntt_variant="indexed")
            setup[name + "_index_prepare_s"], prepared = timed(server.prepare_index, index, len(rows))
            setup[name + "_workspace_prepare_s"], workspace = timed(server.prepare_workspace, prepared)
            workspaces[name] = stack.enter_context(workspace)
            setup[name + "_workspace_coefficient_bytes_before_terminal"] = workspace.coefficient_bytes
            begin = time.perf_counter()
            plans = planner.enumerate_plans(server, prepared, args.embed_len)
            frontier = planner.pareto(plans)
            selected[name] = planner.select(frontier, 1, 1)
            planning[name] = dict(
                planning_s=time.perf_counter()-begin, admissible_plan_count=len(plans),
                pareto_frontier=[asdict(p) for p in frontier], selected=asdict(selected[name]))
        del index
        gc.collect()
        result = trials(args, rows, client, workspaces, selected)
        for name, workspace in workspaces.items():
            setup[name + "_workspace_coefficient_bytes_after_terminal"] = workspace.coefficient_bytes
    return dict(setup=setup, planning=planning, **result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=8192)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--ring-degree", type=int, default=16384, choices=(2048, 4096, 8192, 16384))
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--transport-repeats", type=int, default=5)
    parser.add_argument("--links", nargs="+", choices=tuple(LINKS),
                        default=["10up-100down-40ms", "10Mbps-40ms"])
    parser.add_argument("--index-modes", nargs="+", choices=("public", "owner"), default=["public", "owner"])
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if (not 3 <= args.num_vectors <= 65536 or not 1 <= args.embed_len <= 512
        or not 0 <= args.transport_repeats <= args.repeats <= 100 or args.repeats < 1
        or len(set(args.index_modes)) != len(args.index_modes) or len(set(args.links)) != len(args.links)):
        parser.error("Invalid bounded support experiment workload")
    setup = {}
    setup["keygen_s"], (pk, sk) = timed(bgv.key_gen, args.ring_degree, q_bits=120, rns_modulus=True)
    setup["evaluation_keys_s"], keys = timed(trace.evaluation_keys, pk, sk, 1 << (args.embed_len-1).bit_length())
    rows, _, _ = make_data(args.num_vectors, args.embed_len, 1701)
    _, tiles = bgv.coefficient_inputs([0]*args.embed_len, rows, pk.n)
    results = {}
    with closing(owner.OwnerClient(pk, sk, native=True, rns=True)) as client:
        for bits in (25, 26, 28, 32):
            setup[f"private_terminal_{bits}_prepare_s"] = timed(client.prepare_terminal, bits)[0]
        for mode in args.index_modes:
            results[mode] = run_index(args, rows, tiles, pk, keys, client, mode)
            gc.collect()
    report = dict(
        kind="bgv_joint_support_bound", scope=__doc__, bound_policy=POLICY,
        command=sys.argv, utc=datetime.now(UTC).isoformat(),
        git_head=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip(),
        python=sys.version, platform=platform.platform(),
        gpu=subprocess.check_output(["nvidia-smi", "--query-gpu=name,driver_version,memory.total",
                                     "--format=csv,noheader"], text=True).strip(),
        n=pk.n, t=pk.t, q_hex=format(pk.q, "x"), eta=pk.eta,
        num_vectors=len(rows), dimension=args.embed_len, repeats=args.repeats,
        transport_repeats=args.transport_repeats, plaintext_index_seed=1701,
        query_seed=20260926, variant_order_seed=20260928,
        links_upload_mbps_download_mbps_rtt_ms={name: LINKS[name] for name in args.links},
        plan_ranking="Minimum query+response bytes, independent of codec compute or link asymmetry",
        setup=setup, results=results, source_and_binary_sha256=provenance())
    for name in ("bgv_support_bounds.py", "bgv_pipeline_followup.py", "bgv_query_compression.py", "bgv_transport.py"):
        path = REPO_ROOT / "benchmarks" / name
        report["source_and_binary_sha256"][str(path.relative_to(REPO_ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(args.json_out, flush=True)


if __name__ == "__main__":
    main()
