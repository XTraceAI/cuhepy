#!/usr/bin/env python3
"""Paired rounded-query BGV experiments, with unchanged Q/ring/evaluator.

Separate public-key and owner-encrypted indexes; old seeded queries remain the
baseline in each group. Fresh query encryption is timed once per paired round
and charged to every variant. No private-noise measurements select precision.
TCP is a trusted loopback fixture with a pinned full expected ciphertext before
private work; the excluded duplicate evaluation is NOT a deployable protocol.
Only public parameters, timing samples and source/binary hashes are saved.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import asdict, replace
from datetime import UTC, datetime
from functools import partial
import gc
import hashlib
import json
from pathlib import Path
import platform
import random
import socket
import statistics
import subprocess
import sys
import time

from bfv_client_matrix import REPO_ROOT, make_data
from bgv_service_pipeline import provenance, timed
from bgv_transport import LINKS

sys.path.insert(0, str(REPO_ROOT))
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, owner_bgv as owner
from experiments.bfv_search_lab import compressed_query_bgv as codec, transport_bgv as wire
from experiments.bfv_search_lab.native_bgv import NativeServer


def precision_plan(server, index, terminal_bits):
    """Use the evaluator's actual public bound schedule, including terminal rounding."""
    pk = server.pk
    zeros = tuple([0] * pk.n)
    query = bgv.Ciphertext((zeros, zeros), pk.key_id, 0)
    p = compact.terminal_modulus(pk.q, pk.t, terminal_bits)
    safe, refused = [], []
    for drop in range(1, pk.q.bit_length()):
        encoding = codec.parameters(pk, drop)
        try:
            bounds = server._bounds(replace(query, phase_bound=encoding.query_bound), index, True)
            terminal = [compact.reduced_bound(b, pk, p) for b in bounds]
        except ValueError as error:
            refused.append({"dropped_bits": drop, "reason": str(error)})
            continue
        safe.append(
            {
                **asdict(encoding),
                "response_bounds": bounds,
                "terminal_bounds": terminal,
                "maximum_phase_fraction_q": max(bounds) / int(pk.q),
                "terminal_modulus": int(p),
            }
        )
    if not safe:
        raise ValueError("No admissible query compression precision")
    return {"safe": safe, "refused": refused, "maximum_safe_drop": safe[-1]["dropped_bits"]}


def parse_and_finish(packet, expected_response, client, count, dimension):
    elapsed, parsed = timed(
        wire.unpack_fixture,
        packet,
        client.pk,
        count=count,
        dimension=dimension,
        modulus=expected_response[0].modulus,
        bounds=[c.phase_bound for c in expected_response],
    )
    finish_s, result = timed(client.finish, parsed, count, dimension)
    return result, {"response_parse_s": elapsed, "finish_s": finish_s}


def check_result(result, expected):
    if result.distances != expected or result.top != tuple(
        sorted(enumerate(expected), key=lambda p: (p[1], p[0]))[:3]
    ):
        raise AssertionError("Rounded query changed a distance or the stable top-3")


def local_request(packet, expand, workspace, client, count, dimension, bits):
    start = time.perf_counter()
    expand_s, query = timed(expand, packet)
    evaluate_s, response = timed(workspace.search_compact, query, bits=bits)
    pack_s, outgoing = timed(compact.pack, response, count, dimension, client.pk)
    result, phases = parse_and_finish(outgoing, response, client, count, dimension)
    phases.update(
        {
            "request_s": time.perf_counter() - start,
            "server_expand_s": expand_s,
            "server_evaluate_s": evaluate_s,
            "response_pack_s": pack_s,
            "query_bytes": len(packet),
            "response_bytes": len(outgoing),
        }
    )
    return result, phases


class Loopback:
    """One bounded connection per call; no decision is returned after decryption."""

    def __init__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.settimeout(30)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.pool = ThreadPoolExecutor(max_workers=1)

    def close(self):
        self.listener.close()
        self.pool.shutdown(wait=True)

    def request(
        self,
        packet,
        expand,
        workspace,
        client,
        count,
        dimension,
        bits,
        link,
        expected_wire,
        expected_response,
    ):
        up, down, rtt = LINKS[link]

        def evaluate():
            connection, address = self.listener.accept()
            with connection:
                if address[0] != "127.0.0.1":
                    raise ValueError("Fixture only accepts loopback peers")
                connection.settimeout(30)
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                incoming = wire.receive(connection)
                expand_s, query = timed(expand, incoming)
                evaluate_s, response = timed(workspace.search_compact, query, bits=bits)
                pack_s, outgoing = timed(compact.pack, response, count, dimension, client.pk)
                wire.send(connection, outgoing, mbps=down, delay_ms=rtt / 2)
            return {
                "server_expand_s": expand_s,
                "server_evaluate_s": evaluate_s,
                "response_pack_s": pack_s,
            }

        job = self.pool.submit(evaluate)
        start = time.perf_counter()
        with socket.create_connection(self.listener.getsockname(), timeout=30) as connection:
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            wire.send(connection, packet, mbps=up, delay_ms=rtt / 2)
            received = wire.receive(connection)
        # This MUST precede any private arithmetic, including under Python -O.
        wire.require_expected_fixture(received, expected_wire)
        result, phases = parse_and_finish(received, expected_response, client, count, dimension)
        phases["request_s"] = time.perf_counter() - start
        phases.update(job.result())
        phases.update(
            {
                "query_bytes": len(packet),
                "response_bytes": len(received),
                "tcp_frame_header_bytes": 8,
            }
        )
        return result, phases


def trials(args, rows, server, prepared, client, plan):
    max_drop = plan["maximum_safe_drop"]
    variants = {"seeded": None, "rounded-conservative": max_drop - 2, "rounded-maximum": max_drop}
    samples, warmup, fixture_costs = {}, {}, []
    plain_rng, order_rng = random.Random(20260925), random.Random(20260926)
    with server.prepare_workspace(prepared) as workspace, closing(Loopback()) as tcp:
        for repeat in range(args.repeats + 1):
            plain = [plain_rng.randrange(2) for _ in range(args.embed_len)]
            expected = tuple(sum(a != b for a, b in zip(row, plain, strict=True)) for row in rows)
            encode_s, encoded = timed(bgv.coefficient_inputs, plain, [], client.pk.n)
            encrypt_s, fresh = timed(client.encrypt, encoded[0])
            order = list(variants)
            order_rng.shuffle(order)
            for name in order:
                drop = variants[name]
                if drop is None:
                    compress_s, packet, expand = 0.0, fresh, partial(owner.expand, pk=client.pk)
                else:
                    compress_s, packet = timed(codec.compress, fresh, client.pk, dropped_bits=drop)
                    expand = partial(codec.expand, pk=client.pk, dropped_bits=drop)
                result, phases = local_request(
                    packet, expand, workspace, client, len(rows), args.embed_len, args.terminal_bits
                )
                check_result(result, expected)
                phases.update(
                    {
                        "encode_s": encode_s,
                        "encrypt_s": encrypt_s,
                        "compress_s": compress_s,
                        "total_s": encode_s + encrypt_s + compress_s + phases["request_s"],
                        "dropped_bits": drop,
                    }
                )
                key = name + "/local"
                (samples.setdefault(key, []) if repeat else warmup.setdefault(key, [])).append(
                    phases
                )
                if name == "rounded-conservative" or repeat > args.transport_repeats:
                    continue
                # A duplicate expected response is known before the socket opens.
                # Record but exclude this cost; it is not an efficient verifier.
                gate_begin = time.perf_counter()
                known = workspace.search_compact(expand(packet), bits=args.terminal_bits)
                expected_wire = compact.pack(known, len(rows), args.embed_len, client.pk)
                fixture_costs.append(
                    {"variant": name, "repeat": repeat, "seconds": time.perf_counter() - gate_begin}
                )
                links = list(LINKS)
                order_rng.shuffle(links)
                for link in links:
                    result, phases = tcp.request(
                        packet,
                        expand,
                        workspace,
                        client,
                        len(rows),
                        args.embed_len,
                        args.terminal_bits,
                        link,
                        expected_wire,
                        known,
                    )
                    check_result(result, expected)
                    phases.update(
                        {
                            "encode_s": encode_s,
                            "encrypt_s": encrypt_s,
                            "compress_s": compress_s,
                            "total_s": encode_s + encrypt_s + compress_s + phases["request_s"],
                            "dropped_bits": drop,
                        }
                    )
                    key = name + "/" + link
                    (samples.setdefault(key, []) if repeat else warmup.setdefault(key, [])).append(
                        phases
                    )
            print("Finished round", repeat, "of", args.repeats, flush=True)
    return {
        "variants": variants,
        "samples": samples,
        "warmup": warmup,
        "medians": {
            name: {
                key: statistics.median(row[key] for row in values)
                for key in values[0]
                if key.endswith("_s") or key.endswith("_bytes")
            }
            for name, values in samples.items()
        },
        "excluded_expected_fixture_costs": fixture_costs,
        "all_distances_and_stable_top3_correct": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--num-vectors", type=int, default=8192)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--terminal-bits", type=int, default=25)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--transport-repeats", type=int, default=5)
    parser.add_argument(
        "--index-modes", nargs="+", choices=("public", "owner"), default=["public", "owner"]
    )
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if (
        not 3 <= args.num_vectors <= 65536
        or not 1 <= args.embed_len <= 512
        or args.ring_degree not in (2048, 4096, 8192, 16384, 32768)
        or not 1 <= args.transport_repeats <= args.repeats <= 100
        or not 25 <= args.terminal_bits <= 32
    ):
        parser.error("Invalid bounded compression workload")
    setup = {}
    setup["keygen_s"], (pk, sk) = timed(bgv.key_gen, args.ring_degree, q_bits=120, rns_modulus=True)
    setup["evaluation_keys_s"], keys = timed(
        trace.evaluation_keys, pk, sk, 1 << (args.embed_len - 1).bit_length()
    )
    rows, _, _ = make_data(args.num_vectors, args.embed_len, 1701)
    _, index_plain = bgv.coefficient_inputs([0] * args.embed_len, rows, pk.n)
    results = {}
    with closing(owner.OwnerClient(pk, sk, native=True, rns=True)) as client:
        setup["private_terminal_prepare_s"] = timed(client.prepare_terminal, args.terminal_bits)[0]
        setup["public_server_s"], server = timed(
            NativeServer, pk, keys, residue=True, device="cuda", cuda_level=4
        )
        for mode in args.index_modes:
            print("Preparing", mode, "index", flush=True)
            begin = time.perf_counter()
            index, seeded_bytes = [], 0
            for plain in index_plain:
                if mode == "public":
                    index.append(bgv.encrypt(plain, pk))
                else:
                    packet = client.encrypt(plain)
                    seeded_bytes += len(packet)
                    index.append(owner.expand(packet, pk))
            index_setup = {
                "encrypt_and_expand_s": time.perf_counter() - begin,
                "ciphertexts": len(index),
                "phase_bound_per_tile": index[0].phase_bound,
                "full_coefficient_bytes": len(index) * 2 * ((pk.n * pk.q.bit_length() + 7) // 8),
                "seeded_packet_bytes_sum": seeded_bytes if mode == "owner" else None,
            }
            index_setup["gpu_prepare_s"], prepared = timed(server.prepare_index, index, len(rows))
            plan = precision_plan(server, prepared, args.terminal_bits)
            print(
                mode, "maximum public-bound-admissible drop:", plan["maximum_safe_drop"], flush=True
            )
            results[mode] = {
                "setup": index_setup,
                "plan": plan,
                "trials": trials(args, rows, server, prepared, client, plan),
            }
            del prepared, index
            gc.collect()
    report = {
        "kind": "bgv_plaintext_congruent_query_compression",
        "scope": __doc__,
        "command": sys.argv,
        "utc": datetime.now(UTC).isoformat(),
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "python": sys.version,
        "platform": platform.platform(),
        "gpu": subprocess.check_output(
            ["nvidia-smi", "--query-gpu=name,driver_version", "--format=csv,noheader"], text=True
        ).strip(),
        "n": pk.n,
        "t": pk.t,
        "q_hex": format(pk.q, "x"),
        "eta": pk.eta,
        "num_vectors": len(rows),
        "dimension": args.embed_len,
        "terminal_bits": args.terminal_bits,
        "plaintext_index_seed": 1701,
        "query_seed": 20260925,
        "variant_order_seed": 20260926,
        "links_upload_mbps_download_mbps_rtt_ms": LINKS,
        "setup": setup,
        "results": results,
        "source_and_binary_sha256": provenance(),
    }
    for path in (Path(__file__).resolve(), REPO_ROOT / "benchmarks/bgv_transport.py"):
        report["source_and_binary_sha256"][str(path.relative_to(REPO_ROOT))] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
