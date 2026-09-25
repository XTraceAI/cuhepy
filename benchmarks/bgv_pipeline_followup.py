#!/usr/bin/env python3
"""Paired homemade BGV compute and joint precision experiments.

Includes fresh owner encryption, query codecs, public server work, response
framing/codecs, parsing, private finishing and stable top-3. Workspaces, index
and private terminal caches are prepared outside requests. Variants share each
fresh encryption and use shuffled order, with one excluded warmup round.

Trusted local/TCP fixture only: complete expected response bytes are pinned by
an excluded duplicate evaluation BEFORE private work. TCP closes before private
processing; there is no decryption-dependent acknowledgement. This is not a
deployable authentication protocol or a measurement of verifier/attestation cost.
Only public parameters, sizes, timing samples and source/binary hashes are saved.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
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
from bgv_query_compression import check_result
from bgv_service_pipeline import provenance, timed
from bgv_transport import LINKS as PREVIOUS_LINKS

sys.path.insert(0, str(REPO_ROOT))
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, owner_bgv as owner
from experiments.bfv_search_lab import compressed_query_bgv as query_codec
from experiments.bfv_search_lab import compressed_response_bgv as response_codec
from experiments.bfv_search_lab import joint_precision_bgv as planner, transport_bgv as wire
from experiments.bfv_search_lab.native_bgv import NativeServer, GPUWorkspace

LINKS = {**PREVIOUS_LINKS, "100up-10down-40ms": (100, 10, 40)}


@dataclass(frozen=True)
class Variant:
    ntt: str = "indexed"
    gpu_terminal: bool = True
    packed: bool = True
    bits: int = 25
    query_drop: int | None = None
    response_drop: int | None = None
    codec_backend: str = "native"


class Handler:
    """The server receives public context and encrypted input only."""

    def __init__(self, workspace: GPUWorkspace, dimension: int, variant: Variant):
        self.workspace, self.dimension, self.variant = workspace, dimension, variant
        self.pk, self.count = workspace.server.pk, workspace.index.count

    def __call__(self, packet):
        v = self.variant
        if v.query_drop is None:
            expand_s, query = timed(owner.expand, packet, self.pk)
        else:
            expand_s, query = timed(
                query_codec.expand,
                packet,
                self.pk,
                dropped_bits=v.query_drop,
                backend=v.codec_backend,
            )
        if v.packed:
            evaluate_s, (raw, bounds) = timed(
                self.workspace.search_packet,
                query,
                self.dimension,
                bits=v.bits,
                gpu_terminal=v.gpu_terminal,
            )
            pack_s = 0.0  # Framing is included in search_packet's evaluate_s.
        else:
            evaluate_s, response = timed(
                self.workspace.search_compact, query, bits=v.bits, gpu_terminal=v.gpu_terminal
            )
            pack_s, raw = timed(compact.pack, response, self.count, self.dimension, self.pk)
            bounds = [c.phase_bound for c in response]
        round_s = 0.0
        if v.response_drop is not None:
            round_s, raw = timed(
                response_codec.compress,
                raw,
                self.pk,
                count=self.count,
                dimension=self.dimension,
                bits=v.bits,
                bounds=bounds,
                dropped_bits=v.response_drop,
                backend=v.codec_backend,
            )
        return (
            raw,
            bounds,
            {
                "server_expand_s": expand_s,
                "server_evaluate_s": evaluate_s,
                "response_pack_s": pack_s,
                "response_round_s": round_s,
                "server_total_s": expand_s + evaluate_s + pack_s + round_s,
            },
        )


class Loopback:
    """Bounded localhost pacing fixture; all private work stays in the caller."""

    def __init__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.settimeout(30)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.pool = ThreadPoolExecutor(max_workers=1)

    def close(self):
        self.listener.close()
        self.pool.shutdown(wait=True)

    def request(self, packet, handler, link):
        up, down, rtt = LINKS[link]

        def evaluate():
            connection, address = self.listener.accept()
            with connection:
                if address[0] != "127.0.0.1":
                    raise ValueError("Fixture only accepts loopback peers")
                connection.settimeout(30)
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                incoming = wire.receive(connection)
                outgoing, _, phases = handler(incoming)
                wire.send(connection, outgoing, mbps=down, delay_ms=rtt / 2)
            return phases

        job = self.pool.submit(evaluate)
        with socket.create_connection(self.listener.getsockname(), timeout=30) as connection:
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            wire.send(connection, packet, mbps=up, delay_ms=rtt / 2)
            received = wire.receive(connection)
        return received, job.result()


def expand_response(packet, pk, count, dimension, variant, bounds):
    if variant.response_drop is None:
        return packet, bounds
    return response_codec.expand(
        packet,
        pk,
        count=count,
        dimension=dimension,
        bits=variant.bits,
        bounds=bounds,
        dropped_bits=variant.response_drop,
        backend=variant.codec_backend,
    )


def finish(packet, expected_wire, expected_expanded, bounds, client, count, dimension, variant):
    begin = time.perf_counter()
    wire.require_expected_fixture(packet, expected_wire)
    expand_s, (raw, final_bounds) = timed(
        expand_response, packet, client.pk, count, dimension, variant, bounds
    )
    if variant.packed:
        finish_s, result = timed(
            client.finish_packed_fixture,
            raw,
            expected_expanded,
            count,
            dimension,
            bits=variant.bits,
            bounds=final_bounds,
        )
        parse_s = 0.0  # Canonical parsing is included in native finish_s.
    else:
        wire.require_expected_fixture(raw, expected_expanded)
        parse_s, parsed = timed(
            wire.unpack_fixture,
            raw,
            client.pk,
            count=count,
            dimension=dimension,
            modulus=compact.terminal_modulus(client.pk.q, client.pk.t, variant.bits),
            bounds=final_bounds,
        )
        finish_s, result = timed(client.finish, parsed, count, dimension)
    return result, {
        "response_expand_s": expand_s,
        "response_parse_s": parse_s,
        "finish_s": finish_s,
        "client_response_s": time.perf_counter() - begin,
    }


def trials(args, rows, client, workspaces, variants, *, transport):
    handlers = {name: Handler(workspaces[v.ntt], args.embed_len, v) for name, v in variants.items()}
    samples, warmup, fixture_costs = {}, {}, []
    plain_rng, order_rng = random.Random(20260925), random.Random(20260927)
    with closing(Loopback()) as tcp:
        for repeat in range(args.repeats + 1):
            plain = [plain_rng.randrange(2) for _ in range(args.embed_len)]
            expected = tuple(sum(a != b for a, b in zip(row, plain, strict=True)) for row in rows)
            encode_s, encoded = timed(bgv.coefficient_inputs, plain, [], client.pk.n)
            encrypt_s, fresh = timed(client.encrypt, encoded[0])
            packets, known = {}, {}
            for name, variant in variants.items():
                if variant.query_drop is None:
                    compress_s, packet = 0.0, fresh
                else:
                    compress_s, packet = timed(
                        query_codec.compress,
                        fresh,
                        client.pk,
                        dropped_bits=variant.query_drop,
                        backend=variant.codec_backend,
                    )
                packets[name] = (packet, compress_s)
                begin = time.perf_counter()
                known_wire, bounds, _ = handlers[name](packet)
                known_expanded, _ = expand_response(
                    known_wire, client.pk, len(rows), args.embed_len, variant, bounds
                )
                known[name] = (known_wire, known_expanded, bounds)
                if len(packet) != planner.query_size(client.pk, variant.query_drop) or len(
                    known_wire
                ) != response_codec.packet_size(
                    client.pk, len(rows), args.embed_len, variant.bits, variant.response_drop
                ):
                    raise AssertionError("Measured packet sizes differ from public byte model")
                fixture_costs.append(
                    {"variant": name, "repeat": repeat, "seconds": time.perf_counter() - begin}
                )
            if not transport and len({item[0] for item in known.values()}) != 1:
                raise AssertionError("Compute variants changed complete ciphertext bytes")
            for name, variant in variants.items():
                if variant.codec_backend == "native-gmp":
                    reference = name.removesuffix("-gmp")
                    if packets[name][0] != packets[reference][0] or known[name] != known[reference]:
                        raise AssertionError(
                            "Fixed-word and GMP codecs changed complete packets/bounds"
                        )
            order = [(name, "local") for name in variants]
            if transport and repeat <= args.transport_repeats:
                order += [(name, link) for name in variants for link in LINKS]
            order_rng.shuffle(order)
            for name, link in order:
                packet, compress_s = packets[name]
                known_wire, known_expanded, bounds = known[name]
                start = time.perf_counter()
                if link == "local":
                    received, actual_bounds, phases = handlers[name](packet)
                    if actual_bounds != bounds:
                        raise AssertionError("Public bound changed between fixture and request")
                else:
                    received, phases = tcp.request(packet, handlers[name], link)
                result, client_phases = finish(
                    received,
                    known_wire,
                    known_expanded,
                    bounds,
                    client,
                    len(rows),
                    args.embed_len,
                    variants[name],
                )
                request_s = time.perf_counter() - start
                check_result(result, expected)
                phases.update(client_phases)
                phases.update(
                    {
                        "encode_s": encode_s,
                        "encrypt_s": encrypt_s,
                        "query_compress_s": compress_s,
                        "request_s": request_s,
                        "total_s": encode_s + encrypt_s + compress_s + request_s,
                        "client_total_s": encode_s
                        + encrypt_s
                        + compress_s
                        + client_phases["client_response_s"],
                        "query_bytes": len(packet),
                        "response_bytes": len(received),
                        "tcp_frame_header_bytes": 0 if link == "local" else 8,
                    }
                )
                (samples if repeat else warmup).setdefault(name + "/" + link, []).append(phases)
            print(
                "Finished",
                "joint" if transport else "compute",
                "round",
                repeat,
                "of",
                args.repeats,
                flush=True,
            )
    return {
        "variants": {name: asdict(v) for name, v in variants.items()},
        "samples": samples,
        "warmup": warmup,
        "medians": {
            name: {key: statistics.median(row[key] for row in values) for key in values[0]}
            for name, values in samples.items()
        },
        "excluded_expected_fixture_costs": fixture_costs,
        "all_distances_and_stable_top3_correct": True,
        "compute_ciphertexts_identical": not transport,
    }


def compute_variants():
    return {
        "baseline": Variant("baseline", False, False),
        "indexed-only": Variant("indexed", False, False),
        "gpu-terminal-only": Variant("baseline", True, False),
        "packed-only": Variant("baseline", False, True),
        "indexed-gpu-terminal": Variant("indexed", True, False),
        "all-compute": Variant(),
    }


def joint_variants(server, prepared, dimension):
    plans = planner.enumerate_plans(server, prepared, dimension)
    frontier = planner.pareto(plans)
    baseline = next(
        p
        for p in plans
        if p.query_drop is None and p.response_drop is None and p.terminal_bits == 25
    )
    query_only = min(
        (p for p in plans if p.terminal_bits == 25 and p.response_drop is None),
        key=lambda p: p.total_bytes,
    )
    choices = {
        "seeded": baseline,
        "query-only": query_only,
        "balanced": planner.select(frontier, 1, 1),
        "upload": planner.select(frontier, 10, 100),
        "download": planner.select(frontier, 100, 10),
    }
    names, aliases, variants = {}, {}, {}
    for name, p in choices.items():
        if p in names:
            aliases[name] = names[p]
            continue
        names[p] = name
        variants[name] = Variant(
            bits=p.terminal_bits, query_drop=p.query_drop, response_drop=p.response_drop
        )
    return variants, {
        "admissible_plan_count": len(plans),
        "pareto_frontier": [asdict(p) for p in frontier],
        "selected": {name: asdict(p) for name, p in choices.items()},
        "aliases": aliases,
        "ranking_scope": "Transfer bytes only, excluding codec compute. Measure actual totals below.",
    }


def run_index(args, rows, tiles, pk, keys, client, mode):
    print("Preparing", mode, "index", flush=True)
    begin = time.perf_counter()
    index = [
        bgv.encrypt(p, pk) if mode == "public" else owner.expand(client.encrypt(p), pk)
        for p in tiles
    ]
    setup = {
        "encrypt_and_expand_s": time.perf_counter() - begin,
        "ciphertexts": len(index),
        "phase_bound_per_tile": index[0].phase_bound,
        "full_coefficient_bytes": len(index) * 2 * pk.n * pk.q.bit_length() // 8,
    }
    servers, prepared, workspaces, result = {}, {}, {}, {}
    with ExitStack() as stack:
        for ntt in ("baseline", "indexed") if args.mode != "joint" else ("indexed",):
            setup[ntt + "_server_s"], server = timed(
                NativeServer, pk, keys, residue=True, device="cuda", cuda_level=4, ntt_variant=ntt
            )
            servers[ntt] = server
            setup[ntt + "_index_prepare_s"], prepared[ntt] = timed(
                server.prepare_index, index, len(rows)
            )
            setup[ntt + "_workspace_prepare_s"], workspace = timed(
                server.prepare_workspace, prepared[ntt]
            )
            workspaces[ntt] = stack.enter_context(workspace)
            setup[ntt + "_workspace_coefficient_bytes_before_terminal"] = (
                workspace.coefficient_bytes
            )
        del index
        gc.collect()
        if args.mode != "joint":
            result["compute"] = trials(
                args, rows, client, workspaces, compute_variants(), transport=False
            )
        if args.mode != "compute":
            variants, plan = joint_variants(servers["indexed"], prepared["indexed"], args.embed_len)
            print(
                "Joint variants:",
                list(variants),
                "frontier points:",
                len(plan["pareto_frontier"]),
                flush=True,
            )
            result["joint_plan"] = plan
            if args.compare_codecs:
                variants.update(
                    {
                        name + "-gmp": replace(v, codec_backend="native-gmp")
                        for name, v in list(variants.items())
                        if name != "seeded"
                    }
                )
            result["joint"] = trials(args, rows, client, workspaces, variants, transport=True)
        for ntt, workspace in workspaces.items():
            setup[ntt + "_workspace_coefficient_bytes_after_terminal"] = workspace.coefficient_bytes
    return {"setup": setup, **result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("compute", "joint", "all"), default="all")
    parser.add_argument("--num-vectors", type=int, default=8192)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--transport-repeats", type=int, default=5)
    parser.add_argument(
        "--compare-codecs",
        action="store_true",
        help="Pair the fixed-word codec with the retained GMP mapping",
    )
    parser.add_argument("--index-modes", nargs="+", choices=("public", "owner"), default=["public"])
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if (
        not 3 <= args.num_vectors <= 65536
        or not 1 <= args.embed_len <= 512
        or args.ring_degree not in (2048, 4096, 8192, 16384, 32768)
        or not 1 <= args.transport_repeats <= args.repeats <= 100
        or len(set(args.index_modes)) != len(args.index_modes)
    ):
        parser.error("Invalid bounded pipeline workload")
    setup = {}
    setup["keygen_s"], (pk, sk) = timed(bgv.key_gen, args.ring_degree, q_bits=120, rns_modulus=True)
    setup["evaluation_keys_s"], keys = timed(
        trace.evaluation_keys, pk, sk, 1 << (args.embed_len - 1).bit_length()
    )
    rows, _, _ = make_data(args.num_vectors, args.embed_len, 1701)
    _, tiles = bgv.coefficient_inputs([0] * args.embed_len, rows, pk.n)
    results = {}
    with closing(owner.OwnerClient(pk, sk, native=True, rns=True)) as client:
        for bits in (25, 26, 28, 32):
            setup[f"private_terminal_{bits}_prepare_s"] = timed(client.prepare_terminal, bits)[0]
        for mode in args.index_modes:
            results[mode] = run_index(args, rows, tiles, pk, keys, client, mode)
            gc.collect()
    report = {
        "kind": "bgv_compute_and_joint_precision",
        "scope": __doc__,
        "command": sys.argv,
        "utc": datetime.now(UTC).isoformat(),
        "git_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
        ).strip(),
        "python": sys.version,
        "platform": platform.platform(),
        "gpu": subprocess.check_output(
            ["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"],
            text=True,
        ).strip(),
        "n": pk.n,
        "t": pk.t,
        "q_hex": format(pk.q, "x"),
        "eta": pk.eta,
        "num_vectors": len(rows),
        "dimension": args.embed_len,
        "repeats": args.repeats,
        "transport_repeats": args.transport_repeats,
        "plaintext_index_seed": 1701,
        "query_seed": 20260925,
        "variant_order_seed": 20260927,
        "links_upload_mbps_download_mbps_rtt_ms": LINKS,
        "setup": setup,
        "results": results,
        "source_and_binary_sha256": provenance(),
    }
    for name in ("bgv_pipeline_followup.py", "bgv_query_compression.py", "bgv_transport.py"):
        path = REPO_ROOT / "benchmarks" / name
        report["source_and_binary_sha256"][str(path.relative_to(REPO_ROOT))] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(args.json_out, flush=True)


if __name__ == "__main__":
    main()
