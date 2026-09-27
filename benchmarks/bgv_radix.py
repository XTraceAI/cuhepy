#!/usr/bin/env python3
"""E16 matched-plaintext radix experiments with complete local/TCP request costs.

Each t/layout needs independent keys and a new encrypted index. This is not a
security-equivalent parameter comparison. Queries share plaintexts, not coins,
across these contexts. The optimized g=1 and generic-decoder g=1 variants share
identical ciphertexts. Fresh encryption, codecs, private decryption, digit
decoding and stable top-3 are included. Setup and duplicate known-response gates
are separate. Gates precede private work; this is not GPU authentication.
Only public parameters, byte counts, timings and source/binary hashes are saved.
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
from bgv_pipeline_followup import Handler, Loopback, LINKS, Variant, expand_response
from bgv_query_compression import check_result
from bgv_service_pipeline import timed, provenance

sys.path.insert(0, str(REPO_ROOT))
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import owner_bgv as owner, transport_bgv as wire
from experiments.bfv_search_lab import compressed_query_bgv as query_codec, joint_precision_bgv as planner
from experiments.bfv_search_lab import radix_bgv as radix
from experiments.bfv_search_lab.radix_client_bgv import RadixClient
from experiments.bfv_search_lab.support_bounds_bgv import SupportBoundServer


class RadixHandler:
    def __init__(self, handler, layout, count):
        self.handler, self.layout, self.count = handler, layout, count

    def __call__(self, packet):
        begin = time.perf_counter()
        inner = self.layout.unwrap(packet, self.count, "query")
        raw, bounds, phases = self.handler(inner)
        out = self.layout.wrap(raw, self.count, "response")
        phases["server_total_s"] = time.perf_counter()-begin
        return out, bounds, phases


def encrypt_tiles(tiles, pk, client, mode):
    return [bgv.encrypt(p, pk) if mode == "public" else owner.expand(client.encrypt(p), pk) for p in tiles]


def prepare(args, rows, mode, stack):
    cases = {}
    for name, group, encoding in (("g1", 1, "distance"), ("balanced2", 2, "balanced"),
                                   ("distance2", 2, "distance"), ("distance3", 3, "distance")):
        print("Preparing", mode, name, flush=True)
        layout, setup = radix.Layout(args.embed_len, group, encoding), {}
        setup["keygen_s"], (pk, sk) = timed(bgv.key_gen, args.ring_degree,
            t=layout.plaintext_modulus(), q_bits=120, rns_modulus=True)
        setup["evaluation_keys_s"], keys = timed(trace.evaluation_keys, pk, sk, layout.padded)
        setup["owner_prepare_s"], client = timed(RadixClient, pk, sk, native=True, rns=True)
        stack.callback(client.close)
        setup["index_encode_s"], encoded = timed(layout.inputs, [0]*args.embed_len, rows, pk.n)
        setup["index_encrypt_s"], encrypted = timed(encrypt_tiles, encoded[1], pk, client, mode)
        setup["server_prepare_s"], server = timed(SupportBoundServer, pk, keys,
            residue=True, device="cuda", cuda_level=4, ntt_variant="indexed")
        setup["index_prepare_s"], index = timed(server.prepare_index, encrypted, layout.groups(len(rows)))
        setup["workspace_prepare_s"], workspace = timed(server.prepare_workspace, index)
        stack.enter_context(workspace)
        setup["planning_s"], candidates = timed(radix.plans, server, index, layout, len(rows))
        frontier = planner.pareto(candidates)
        plan = planner.select(frontier, 1, 1)
        setup["terminal_prepare_s"] = timed(client.prepare_terminal, plan.terminal_bits)[0]
        setup["index_tiles"] = len(encrypted)
        setup["index_phase_bound"] = encrypted[0].phase_bound
        setup["full_index_coefficient_bytes"] = len(encrypted)*2*pk.n*((pk.q.bit_length()+7)//8)
        setup["workspace_coefficient_bytes"] = workspace.coefficient_bytes
        variant = Variant(bits=plan.terminal_bits, query_drop=plan.query_drop, response_drop=plan.response_drop)
        cases[name] = dict(client=client, layout=layout, plan=plan, variant=variant,
            handler=RadixHandler(Handler(workspace, args.embed_len, variant), layout, len(rows)),
            report=dict(layout=asdict(layout), t=pk.t, n=pk.n, q_hex=format(pk.q, "x"), eta=pk.eta,
                setup=setup, selected=asdict(plan), pareto_frontier=[asdict(p) for p in frontier],
                query_bytes=layout.packet_size(plan.query_bytes, len(rows), "query"),
                response_bytes=layout.packet_size(plan.response_bytes, len(rows), "response")))
        del encoded, encrypted, candidates
        gc.collect()
    return cases


def trials(args, rows, cases):
    variants = {"g1-native": "g1", "g1-generic": "g1", "balanced2": "balanced2",
                "distance2": "distance2", "distance3": "distance3"}
    methods = {name: ("native" if name == "g1-native" else "numpy" if args.vectorized_radix else "scalar") for name in variants}
    if args.vectorized_radix:
        for case in ("g1", "distance2", "distance3"):
            variants[case+"-scalar"] = case
            methods[case+"-scalar"] = "scalar"
    samples, warmup, gates = {}, {}, []
    query_rng, order_rng = random.Random(20260927), random.Random(20260929)
    with closing(Loopback()) as tcp:
        for repeat in range(args.repeats+1):
            query = [query_rng.randrange(2) for _ in range(args.embed_len)]
            expected = tuple(sum(a != b for a, b in zip(query, row, strict=True)) for row in rows)
            prepared = {}
            for name, c in cases.items():
                layout, client, plan = c["layout"], c["client"], c["plan"]
                encode_s, encoded = timed(bgv.coefficient_inputs, query, [], client.pk.n)
                encrypt_s, fresh = timed(client.encrypt, encoded[0])
                compress_s, inner = (0.0, fresh) if plan.query_drop is None else timed(
                    query_codec.compress, fresh, client.pk, dropped_bits=plan.query_drop, backend="native")
                wrap_s, packet = timed(layout.wrap, inner, len(rows), "query")
                begin = time.perf_counter()
                known, bounds, _ = c["handler"](packet)
                known_expanded, _ = expand_response(layout.unwrap(known, len(rows), "response"),
                    client.pk, layout.groups(len(rows)), args.embed_len, c["variant"], bounds)
                gates.append(dict(case=name, repeat=repeat, seconds=time.perf_counter()-begin))
                if (len(packet), len(known)) != (c["report"]["query_bytes"], c["report"]["response_bytes"]):
                    raise AssertionError("Radix packets disagree with the exact framed byte model")
                prepared[name] = packet, known, known_expanded, bounds, dict(
                    encode_s=encode_s, encrypt_s=encrypt_s, query_compress_s=compress_s, query_wrap_s=wrap_s)
            order = [(name, "local") for name in variants]
            if args.transport_repeats and repeat <= args.transport_repeats:
                order += [(name, link) for name in variants for link in args.links]
            order_rng.shuffle(order)
            for name, link in order:
                case_name = variants[name]
                c = cases[case_name]
                client, layout, plan = c["client"], c["layout"], c["plan"]
                packet, known, known_expanded, bounds, phases = prepared[case_name]
                phases = phases.copy()
                begin = time.perf_counter()
                if link == "local":
                    actual, actual_bounds, server_phases = c["handler"](packet)
                    if actual_bounds != bounds:
                        raise AssertionError("Radix public bounds changed")
                else:
                    actual, server_phases = tcp.request(packet, c["handler"], link)
                private_begin = time.perf_counter()
                if methods[name] == "native":
                    wire.require_expected_fixture(actual, known)
                    raw, final_bounds = expand_response(layout.unwrap(actual, len(rows), "response"),
                        client.pk, len(rows), args.embed_len, c["variant"], bounds)
                    result = client.finish_packed_fixture(raw, known_expanded, len(rows), args.embed_len,
                        bits=plan.terminal_bits, bounds=final_bounds)
                else:
                    result = client.finish_radix_fixture(actual, known, len(rows), layout, plan,
                        packed=args.packed_radix, vectorized=methods[name] == "numpy")
                phases["client_response_s"] = time.perf_counter()-private_begin
                request_s = time.perf_counter()-begin
                check_result(result, expected)
                phases.update(server_phases)
                prepare_s = sum(phases[k] for k in ("encode_s", "encrypt_s", "query_compress_s", "query_wrap_s"))
                phases.update(request_s=request_s, total_s=prepare_s+request_s,
                    client_total_s=prepare_s+phases["client_response_s"], query_bytes=len(packet),
                    response_bytes=len(actual), tcp_frame_header_bytes=0 if link == "local" else 8)
                (samples if repeat else warmup).setdefault(name+"/"+link, []).append(phases)
            print("Finished radix round", repeat, "of", args.repeats, flush=True)
    return dict(cases={name: c["report"] for name, c in cases.items()}, variants=variants, plaintext_decoders=methods,
        samples=samples, warmup=warmup, excluded_expected_fixture_costs=gates,
        medians={name: {k: statistics.median(row[k] for row in entries) for k in entries[0]}
                 for name, entries in samples.items()}, all_distances_and_stable_top3_correct=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=8192)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--ring-degree", type=int, default=16384, choices=(2048, 4096, 8192, 16384))
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--transport-repeats", type=int, default=5)
    parser.add_argument("--packed-radix", action="store_true", help="Use the retained packed native private boundary before radix decoding")
    parser.add_argument("--vectorized-radix", action="store_true", help="Use NumPy plaintext decoding and retain matched scalar controls")
    parser.add_argument("--links", nargs="+", choices=tuple(LINKS), default=["10up-100down-40ms", "10Mbps-40ms"])
    parser.add_argument("--index-modes", nargs="+", choices=("public", "owner"), default=["public", "owner"])
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if (not 3 <= args.num_vectors <= 32768 or not 1 <= args.embed_len <= 512
        or not 0 <= args.transport_repeats <= args.repeats <= 100 or args.repeats < 1
        or len(set(args.index_modes)) != len(args.index_modes) or len(set(args.links)) != len(args.links)):
        parser.error("Invalid bounded radix workload")
    # Snapshot before setup: unrelated later research files are not part of this run.
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    hashes = provenance()
    for name in ("bgv_radix.py", "bgv_pipeline_followup.py", "bgv_transport.py", "bgv_query_compression.py"):
        path = REPO_ROOT/"benchmarks"/name
        hashes[str(path.relative_to(REPO_ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    rows, _, _ = make_data(args.num_vectors, args.embed_len, 1701)
    results = {}
    for mode in args.index_modes:
        with ExitStack() as stack:
            cases = prepare(args, rows, mode, stack)
            results[mode] = trials(args, rows, cases)
        del cases
        gc.collect()
    report = dict(kind="bgv_radix", scope=__doc__, command=sys.argv, utc=datetime.now(UTC).isoformat(),
        git_head=head,
        python=sys.version, platform=platform.platform(),
        gpu=subprocess.check_output(["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"], text=True).strip(),
        num_vectors=len(rows), dimension=args.embed_len, repeats=args.repeats, transport_repeats=args.transport_repeats,
        packed_radix=args.packed_radix, vectorized_radix=args.vectorized_radix,
        plaintext_index_seed=1701, query_seed=20260927, variant_order_seed=20260929,
        links_upload_mbps_download_mbps_rtt_ms={link: LINKS[link] for link in args.links},
        results=results, source_and_binary_sha256=hashes)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2)+"\n")
    print(args.json_out, flush=True)


if __name__ == "__main__":
    main()
