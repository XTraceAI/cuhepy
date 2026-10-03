#!/usr/bin/env python3
"""SB01 fixed matched arithmetic/acquisition fixture, not a secure remote service.

Existing homemade arithmetic is imported only after the explicit execution mode
is selected. New code schedules/tracks existing public APIs; it changes no scheme,
parameter guard or native kernel. Every private finish receives a response from
this trusted local fixture. No key, ciphertext, nonce or vector is saved.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime
import gc
import hashlib
import heapq
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
BASE = "11e1690d4c4a90a718e5f2b8a98e79b4757a59bd"
BGV_BASELINE = ROOT.parent / "research-data/revalidation-20261001/raw/earlier-bgv-owner-pipeline-32768-block01.json"
VARIANTS = (
    "bgv-public-index-cuda-workspace",
    "bfv-cuda-prepared",
    "paillier-lookup-cuda",
    "paillier-lookup-hybrid",
    "authenticated-raw-cache",
)
PHASES = (
    "client_prepare_s", "server_total_s", "client_finish_s", "local_total_s"
)
RESOURCE_CAPS = {"worker_wall_s": 1200, "worker_cpu_s": 3600,
                 "sampled_worker_rss_bytes": 16 << 30, "sampled_worker_gpu_bytes": 8 << 30}


def validate_resource_caps(caps):
    if (type(caps) is not dict or set(caps) != set(RESOURCE_CAPS)
            or any(type(v) is not int or not 0 < v <= RESOURCE_CAPS[k] for k, v in caps.items())):
        raise ValueError("Invalid/missing/widened supervised resource caps")
    return True


@dataclass(frozen=True)
class Plan:
    mode: str
    count: int
    dimension: int = 512
    n: int = 16384
    measured_queries: int = 5
    update_count: int = 32

    def validate(self):
        if self.mode not in ("main", "intrinsic"):
            raise ValueError("Unknown activation mode")
        expected = (32768, 5, 32) if self.mode == "main" else (16, 1, 16)
        values = (self.count, self.measured_queries, self.update_count)
        if (any(type(x) is not int for x in (*values, self.dimension, self.n))
                or values != expected or self.dimension != 512 or self.n != 16384):
            raise ValueError("Only the frozen main/intrinsic fixtures are permitted")
        return self


def queries(plan, warmup):
    plan.validate()
    if (len(warmup) != plan.dimension
            or any(type(x) is not int or x not in (0, 1) for x in warmup)):
        raise ValueError("Invalid warmup query")
    rng = random.Random(20261003)
    words = [[0] * plan.dimension, [1] * plan.dimension,
             [j % 2 for j in range(plan.dimension)]]
    words.extend([[rng.randrange(2) for _ in range(plan.dimension)] for _ in range(2)])
    return [list(warmup), *words[:plan.measured_queries]]


def orders(rounds):
    if type(rounds) is not int or not 1 <= rounds <= 6:
        raise ValueError("Invalid bounded round count")
    rng = random.Random(2026100301)
    result = []
    for _ in range(rounds):
        order = list(VARIANTS)
        rng.shuffle(order)
        result.append(order)
    return result


def scores(rows, query):
    expected = [sum(a != b for a, b in zip(row, query, strict=True)) for row in rows]
    return expected, sorted(range(len(rows)), key=lambda i: (expected[i], i))[:3]


def packed_word(bits):
    return sum(bit << j for j, bit in enumerate(bits))


def score_digest(values):
    return hashlib.sha256(b"".join(x.to_bytes(2, "little") for x in values)).hexdigest()


def summarize(samples):
    measured = [s for s in samples if not s["warmup"]]
    if not measured:
        raise ValueError("No measured samples")
    if any(set(s["timings"]) != set(measured[0]["timings"]) for s in measured):
        raise ValueError("Inconsistent timing boundaries")
    return {key: {"median": statistics.median(s["timings"][key] for s in measured),
                  "minimum": min(s["timings"][key] for s in measured),
                  "maximum": max(s["timings"][key] for s in measured)}
            for key in measured[0]["timings"]}


def replacement_geometry(plan, variant):
    """The registered prefix update changes one HE tile, not an arbitrary slice."""
    plan.validate()
    if variant not in VARIANTS:
        raise ValueError("Unknown replacement variant")
    positions = tuple(range(plan.update_count))
    if variant in VARIANTS[:2]:
        # Existing BFV/BGV capacity is N/d=32; no partial second tile is allowed.
        ciphertexts = (plan.update_count + 31) // 32
    elif variant in VARIANTS[2:4]:
        ciphertexts = plan.update_count
    else:
        ciphertexts = None  # Cache replaces its entire authenticated snapshot.
    return positions, ciphertexts


def validate_complete(plan, report):
    """No partial, duplicated, unmatched or failed cohort earns complete status."""
    plan.validate()
    rows, updates = report.get("results"), report.get("updates")
    if type(rows) is not list or type(updates) is not list or len(rows) != 5 or len(updates) != 5:
        raise ValueError("Incomplete cohort")
    if ({r.get("variant") for r in rows} != set(VARIANTS)
            or {r.get("variant") for r in updates} != set(VARIANTS)):
        raise ValueError("Missing/duplicate cohort variant")
    digests = {}
    for row in rows:
        samples = row.get("samples")
        if type(samples) is not list or len(samples) != plan.measured_queries + 1:
            raise ValueError("Missing measured/warmup calls")
        if not row.get("setup_timings"):
            raise ValueError("Unpaid setup")
        for i, sample in enumerate(samples):
            if (type(sample.get("repeat")) is not int or sample["repeat"] != i
                    or sample.get("warmup") is not (i == 0)
                    or sample.get("all_scores_and_top3_correct") is not True
                    or not set(PHASES) <= set(sample.get("timings", {}))):
                raise ValueError("Missing/invalid correctness or phase boundaries")
            for key in ("query_bytes", "response_bytes"):
                if type(sample.get(key)) is not int or sample[key] < 0:
                    raise ValueError("Invalid actual packet size")
            stamp = (sample.get("query_plaintext_sha256"), sample.get("scores_sha256"))
            if None in stamp or (i in digests and stamp != digests[i]):
                raise ValueError("Unmatched plaintext query/scores")
            digests[i] = stamp
    for update in updates:
        if (type(update.get("replacement_rows")) is not int
                or update["replacement_rows"] != plan.update_count
                or update.get("all_scores_and_top3_correct") is not True
                or type(update.get("delta_packet_bytes")) is not int
                or update["delta_packet_bytes"] <= 0):
            raise ValueError("Incomplete update transition")
    return True


class Recorder:
    """Append-only public phase boundaries; never persist returned objects."""

    def __init__(self, path):
        self.stream = Path(path).open("x")
        self.events = 0
        self.pending = []

    def event(self, kind, **fields):
        self.pending.append({"kind": kind, "monotonic": time.monotonic(),
                             "utc": datetime.now(UTC).isoformat(), **fields})
        self.events += 1

    def flush(self):
        for event in self.pending:
            self.stream.write(json.dumps(event) + "\n")
        self.stream.flush()
        self.pending.clear()

    def phase(self, target, name, function, *args, event_flush=False, **kwargs):
        self.event("phase_begin", target=target, phase=name)
        if event_flush:
            self.flush()
        begin = time.perf_counter()
        try:
            result = function(*args, **kwargs)
        except BaseException:
            self.event("phase_failed", target=target, phase=name)
            if event_flush:
                self.flush()
            raise
        elapsed = time.perf_counter() - begin
        self.event("phase_end", target=target, phase=name, elapsed_s=elapsed)
        if event_flush:
            self.flush()
        return elapsed, result

    def close(self):
        self.flush()
        self.stream.close()


def dependencies():
    """Load the existing implementations after caller activation, never in tests."""
    for directory in (ROOT / "src", ROOT, ROOT / "benchmarks"):
        sys.path.insert(0, str(directory))
    import gmpy2
    import msgpack
    from bfv_client_matrix import make_data, packet, unpack_packet
    from coefficient_search_lab import Case
    from cuhepy.bfv.private import BFVPrivateDecoder
    from cuhepy.hamming.bfv import BFVClient
    from cuhepy.hamming.paillier_lookup import PaillierLookupClient
    from experiments.bfv_search_lab import cache_snapshot, compact_bgv, owner_bgv
    from experiments.bfv_search_lab import shallow_bgv, trace_bgv, transport_bgv
    from experiments.bfv_search_lab.native_bgv import NativeServer
    return SimpleNamespace(**locals())


class Adapter:
    def __init__(self, name, plan, rows, rec, d):
        self.name, self.plan, self.rows, self.rec, self.d = name, plan, rows, rec, d
        self.setup, self.info = {}, {"variant": name}
        self.close_callbacks = []

    def setup_phase(self, key, fn, *args, **kwargs):
        elapsed, value = self.rec.phase(self.name, key, fn, *args, event_flush=True, **kwargs)
        self.setup[key] = elapsed
        return value

    def tick(self, timings, key, fn, *args, **kwargs):
        elapsed, value = self.rec.phase(self.name, key, fn, *args, **kwargs)
        timings[key] = elapsed
        return value

    def close(self):
        failures = []
        for fn in reversed(self.close_callbacks):
            try:
                fn()
            except BaseException as error:
                failures.append({"type": type(error).__name__, "message": str(error)})
        self.close_callbacks.clear()
        return failures


class PaillierAdapter(Adapter):
    def prepare(self):
        self.client = self.setup_phase("key_generation_s", self.d.PaillierLookupClient,
                                      512, 1024, 280, device="gpu")
        if self.client.device != "gpu":
            raise AssertionError("Requested Paillier GPU client did not load")
        config = json.loads(self.client.stringify_config())
        public = self.setup_phase("public_key_export_s", self.client.stringify_pk)
        self.pk = self.setup_phase("public_key_import_s", json.loads, public)
        self.modulus = self.d.gmpy2.mpz(self.pk["n_squared"])
        config["actual_modulus_bits"] = int(self.pk["n"]).bit_length()
        # Record only the exponent length, never secret values.
        secret = json.loads(self.client.stringify_sk())
        config["decryption_exponent_bits"] = int(secret["a"]).bit_length()
        del secret
        if config["alpha_len"] != 280:
            raise AssertionError("Lookup profile drift")
        index = self.setup_phase("index_encrypt_s", self.client.encrypt_vec_batch, self.rows)
        wire = self.setup_phase("index_serialize_s", self.d.packet, index, len(self.rows))
        self.index = self.setup_phase("index_deserialize_s", self.d.unpack_packet, wire)
        self.info.update(config=config, client_device="gpu",
                         server_device="gpu" if self.name.endswith("cuda") else "cpu",
                         public_keys_bytes=len(public.encode()), encrypted_index_bytes=len(wire))

    def evaluate(self, query):
        if self.name.endswith("hybrid"):
            return [[int(self.d.gmpy2.mpz(a) * b % self.modulus)
                     for a, b in zip(query, row, strict=True)] for row in self.index]
        fn = type(self.client.client).encode_hamming_server
        flat = [int(c) for c in fn(query * len(self.index),
                                  [c for row in self.index for c in row], self.pk)]
        return [flat[i:i + len(query)] for i in range(0, len(flat), len(query))]

    def run(self, query):
        return common_run(self, query, self.client.encrypt_vec_one,
                          self.client.decode_hamming_client_batch)

    def update(self, rows):
        return common_update(self, rows, self.client.encrypt_vec_batch, self.d.packet,
                             self.d.unpack_packet, lambda: None)


class BFVAdapter(Adapter):
    def prepare(self):
        self.client = self.setup_phase(
            "key_generation_s", self.d.BFVClient, 512, 16384, 65537, 180, 30,
            rns_modulus=True, server_backend="residue")
        self.decoder = self.setup_phase("private_context_s", self.d.BFVPrivateDecoder, self.client)
        self.close_callbacks.append(self.decoder.close)
        config = json.loads(self.client.stringify_config())
        public = self.setup_phase("public_key_export_s", self.client.stringify_pk)
        index = self.setup_phase("index_encrypt_s", self.client.encrypt_vec_packed, self.rows)
        wire = self.setup_phase("index_serialize_s", self.d.packet, index, len(self.rows))
        self.index = self.setup_phase("index_deserialize_s", self.d.unpack_packet, wire)

        def import_server():
            server = self.d.BFVClient(skip_key_gen=True, server_backend="cuda")
            server.load_config(config)
            server.load_stringified_keys(public, max_public_key_chars=256 * 1024 * 1024)
            if server.keys is not None:
                raise AssertionError("Public BFV server contains a secret")
            server._native()
            return server

        self.server = self.setup_phase("public_plan_import_s", import_server)
        self.prepared = self.setup_phase("gpu_index_prepare_s", self.server.prepare_cuda_index,
                                         self.index, len(self.rows))
        self.info.update(config=config, client_device="cpu", server_device="gpu",
                         public_keys_bytes=len(public.encode()), encrypted_index_bytes=len(wire),
                         resident_index_bytes=self.prepared.device_bytes,
                         native_plan_bytes=self.server._native().cache_bytes())

    def evaluate(self, query):
        return self.server.encode_hamming_server_prepared(query, self.prepared)

    def run(self, query):
        return common_run(self, query, self.client.encrypt_vec_one,
                          lambda c: self.decoder.decode_packed(c, len(self.rows)))

    def update(self, rows):
        def reprepare():
            self.prepared = None
            gc.collect()
            self.prepared = self.server.prepare_cuda_index(self.index, len(self.rows))
        return common_update(self, rows, self.client.encrypt_vec_packed, self.d.packet,
                             self.d.unpack_packet, reprepare)


def common_run(adapter, query, encrypt, decode):
    t, d = {}, adapter.d
    begin = time.perf_counter()
    encrypted = adapter.tick(t, "query_encrypt_s", encrypt, query)
    request = adapter.tick(t, "query_serialize_s", d.packet, [encrypted], 1)
    parsed = adapter.tick(t, "query_deserialize_s", d.unpack_packet, request)[0]
    result = adapter.tick(t, "server_evaluate_s", adapter.evaluate, parsed)
    response = adapter.tick(t, "response_serialize_s", d.packet, result, len(adapter.rows))
    received = adapter.tick(t, "response_deserialize_s", d.unpack_packet, response)
    distances = adapter.tick(t, "response_decode_s", decode, received)
    top = adapter.tick(t, "top3_s", lambda: heapq.nsmallest(3, range(len(distances)),
                                                         key=lambda i: (distances[i], i)))
    t.update(local_total_s=time.perf_counter() - begin,
             client_prepare_s=t["query_encrypt_s"] + t["query_serialize_s"],
             server_total_s=t["query_deserialize_s"] + t["server_evaluate_s"]
             + t["response_serialize_s"],
             client_finish_s=t["response_deserialize_s"] + t["response_decode_s"] + t["top3_s"])
    return list(distances), top, {"timings": t, "query_bytes": len(request),
                                  "response_bytes": len(response)}


def common_update(adapter, rows, encrypt, pack, unpack, reprepare):
    t, d = {}, adapter.d
    begin = time.perf_counter()
    positions, expected_ciphertexts = replacement_geometry(adapter.plan, adapter.name)
    if len(rows) != len(positions):
        raise ValueError("Replacement rows differ from registered aligned prefix")
    delta = adapter.tick(t, "replacement_encrypt_s", encrypt, rows)
    if len(delta) != expected_ciphertexts:
        raise ValueError("Replacement tile coverage differs from registered geometry")
    body = adapter.tick(t, "replacement_serialize_s", pack, delta, len(rows))
    envelope = [b"cuhepy-lab-SB01-delta-v1", adapter.name, len(adapter.rows), 512,
                list(positions), body]
    packet = adapter.tick(t, "delta_frame_s", d.msgpack.packb, envelope, use_bin_type=True)

    def apply():
        parsed = d.msgpack.unpackb(packet, raw=False)
        if parsed != envelope:
            raise AssertionError("Local delta frame roundtrip differs")
        replacement = unpack(parsed[-1])
        if len(replacement) != expected_ciphertexts:
            raise ValueError("Parsed delta has wrong tile coverage")
        adapter.index[:len(replacement)] = replacement

    adapter.tick(t, "server_delta_parse_replace_s", apply)
    adapter.tick(t, "resident_snapshot_reprepare_s", reprepare)
    t["local_update_total_s"] = time.perf_counter() - begin
    return {"timings": t, "delta_packet_bytes": len(packet),
            "replacement_rows": len(rows), "trusted_local_snapshot_metadata": True,
            "update_protocol_or_security_claim": False}


class BGVAdapter(Adapter):
    def coeff_context(self):
        return SimpleNamespace(mode="bgv", n=self.pk.n, t=self.pk.t, q=self.pk.q,
                               key_id=self.pk.key_id, pk=self.pk)

    def pack_index(self, index, count):
        return self.d.Case.pack(self.coeff_context(), index, count)

    def unpack_index(self, packet, count):
        return self.d.Case.unpack(self.coeff_context(), packet, count, 2)

    def key_frame(self):
        width = (self.pk.q.bit_length() + 7) // 8
        polys = [self.pk.a, self.pk.b]
        polys += [p for key in (self.keys.relin, *(key for _, key in self.keys.rotations))
                  for column in key for p in column]
        payloads = [int(self.d.gmpy2.pack(list(p), width * 8)).to_bytes(self.pk.n * width,
                                                                     "little") for p in polys]
        return self.d.msgpack.packb([b"cuhepy-lab-SB01-BGV-keys-v1", self.pk.n, self.pk.t,
                                    int(self.pk.q).to_bytes(width, "little"), self.pk.eta,
                                    bytes.fromhex(self.pk.key_id), self.keys.padded,
                                    self.keys.digit_bits, self.keys.switch_error_bound,
                                    [x for x, _ in self.keys.rotations], payloads], use_bin_type=True)

    def import_key_frame(self, packet):
        fields = self.d.msgpack.unpackb(packet, raw=False)
        width = (self.pk.q.bit_length() + 7) // 8
        expected = [b"cuhepy-lab-SB01-BGV-keys-v1", self.pk.n, self.pk.t,
                    int(self.pk.q).to_bytes(width, "little"), self.pk.eta,
                    bytes.fromhex(self.pk.key_id), self.keys.padded,
                    self.keys.digit_bits, self.keys.switch_error_bound,
                    [x for x, _ in self.keys.rotations]]
        if type(fields) is not list or len(fields) != 11 or fields[:10] != expected:
            raise AssertionError("Local key context changed")
        _, n, t, q_bytes, eta, key_id, padded, digit_bits, bound, rotations, payloads = fields
        q = self.d.gmpy2.mpz.from_bytes(q_bytes, "little")
        width = len(q_bytes)
        polys = []
        for payload in payloads:
            values = self.d.gmpy2.unpack(self.d.gmpy2.mpz.from_bytes(payload, "little"), width * 8)
            values.extend([self.d.gmpy2.mpz(0)] * (n - len(values)))
            if len(payload) != n * width or len(values) != n or any(not 0 <= x < q for x in values):
                raise AssertionError("Noncanonical local BGV key polynomial")
            polys.append(tuple(values))
        digits = (q.bit_length() + digit_bits - 1) // digit_bits
        if len(polys) != 2 + 2 * digits * (1 + len(rotations)):
            raise AssertionError("Wrong BGV key coefficient count")
        pk = self.d.shallow_bgv.PublicKey(n, t, q, eta, polys[0], polys[1], key_id.hex())
        switch = [tuple(zip(polys[i:i + 2 * digits:2], polys[i + 1:i + 2 * digits:2], strict=True))
                  for i in range(2, len(polys), 2 * digits)]
        keys = self.d.trace_bgv.EvaluationKeys(key_id.hex(), padded, digit_bits, switch[0],
                                             tuple(zip(rotations, switch[1:], strict=True)), bound)
        if pk != self.pk or keys != self.keys:
            raise AssertionError("Public key/evaluation frame changed objects")
        return pk, keys

    def prepare(self):
        self.pk, self.sk = self.setup_phase("keygen_s", self.d.shallow_bgv.key_gen,
                                           16384, q_bits=120, rns_modulus=True)
        self.keys = self.setup_phase("evaluation_keys_s", self.d.trace_bgv.evaluation_keys,
                                     self.pk, self.sk, 512)
        self.info["full_group_metadata_guard"] = self.setup_phase(
            "full_group_metadata_guard_s", self.full_group_metadata_guard)
        self.key_packet = self.setup_phase("public_evaluation_key_frame_s", self.key_frame)
        server_pk, server_keys = self.setup_phase("public_evaluation_key_import_s",
                                                 self.import_key_frame, self.key_packet)
        _, plain_index = self.setup_phase("index_encode_s", self.d.shallow_bgv.coefficient_inputs,
                                          [0] * 512, self.rows, self.pk.n)
        index = self.setup_phase("index_encrypt_s", lambda: [self.d.shallow_bgv.encrypt(p, self.pk)
                                                              for p in plain_index])
        wire = self.setup_phase("index_serialize_s", self.pack_index, index, len(self.rows))
        self.index = self.setup_phase("index_deserialize_s", self.unpack_index, wire, len(self.rows))
        self.client = self.setup_phase("owner_prepare_s", self.d.owner_bgv.OwnerClient,
                                       self.pk, self.sk, native=True, rns=True)
        self.close_callbacks.append(self.client.close)
        self.setup_phase("owner_terminal_prepare_s", self.client.prepare_terminal, 25)
        self.server = self.setup_phase("server_prepare_s", self.d.NativeServer, server_pk, server_keys,
                                       residue=True, device="cuda", cuda_level=4)
        self.prepared = self.setup_phase("index_prepare_s", self.server.prepare_index,
                                         self.index, len(self.rows))
        self.workspace = self.setup_phase("workspace_prepare_s", self.server.prepare_workspace,
                                          self.prepared)
        self.close_callbacks.append(lambda: self.workspace.close() if self.workspace is not None else None)
        self.info.update(config={"n": self.pk.n, "t": self.pk.t, "q_hex": format(self.pk.q, "x"),
                                 "eta": self.pk.eta, "digit_bits": self.keys.digit_bits,
                                 "terminal_bits": 25, "cuda_level": 4, "ntt_variant": "baseline",
                                 "index_law": "public-key-encrypted", "query_law": "owner-seeded"},
                         client_device="cpu", server_device="gpu",
                         public_keys_bytes=len(self.key_packet), encrypted_index_bytes=len(wire),
                         workspace_coefficient_bytes=self.workspace.coefficient_bytes,
                         resident_index_coefficient_bytes=2 * 2 * len(index) * self.pk.n * 8,
                         key_serializer_scope="new canonical benchmark fixed-width frame")
        del plain_index, index, wire
        # Public serialized key bytes are no longer retained in the online loop.
        self.key_packet = None

    def full_group_metadata_guard(self):
        """Pay the largest public bound without large zero tiles or private work."""
        if (self.pk.n, self.pk.t, self.pk.eta, self.keys.padded, self.keys.digit_bits,
                format(self.pk.q, "x")) != (16384, 1031, 21, 512, 30,
                                           "ffffffffffc00020000003bffc0001"):
            raise AssertionError("Frozen BGV profile changed")
        bound = self.pk.n * (self.pk.t // 2 + self.pk.t * self.pk.eta) * self.pk.fresh_bound
        bound += self.keys.switch_error_bound
        for _ in range(9):
            bound = 4 * bound + self.keys.switch_error_bound
        p = self.d.compact_bgv.terminal_modulus(self.pk.q, self.pk.t, 25)
        terminal = self.d.compact_bgv.reduced_bound(bound, self.pk, p)
        if terminal != 8446469:
            raise AssertionError("Largest-group P25 bound differs from frozen baseline")
        return {"profile": "existing_public_index_512_tile_group", "input_tiles": 512,
                "original_phase_bound": bound, "terminal_phase_bound": terminal,
                "terminal_modulus": int(p), "guard_passed": True,
                "new_HE_or_private_samples": 0}

    def run(self, query):
        t, d = {}, self.d
        begin = time.perf_counter()
        encoded = self.tick(t, "query_encode_s", d.shallow_bgv.coefficient_inputs,
                            query, [], self.pk.n)[0]
        packet = self.tick(t, "query_encrypt_frame_s", self.client.encrypt, encoded)
        expanded = self.tick(t, "query_parse_expand_s", d.owner_bgv.expand, packet, self.pk)
        result = self.tick(t, "server_evaluate_compact_s", self.workspace.search_compact,
                           expanded, bits=25)
        response = self.tick(t, "response_frame_s", d.compact_bgv.pack, result,
                             len(self.rows), 512, self.pk)
        parsed = self.tick(t, "response_parse_s", d.transport_bgv.unpack_fixture, response,
                           self.pk, count=len(self.rows), dimension=512,
                           modulus=result[0].modulus, bounds=[c.phase_bound for c in result])
        final = self.tick(t, "client_finish_decode_top3_s", self.client.finish, parsed,
                          len(self.rows), 512)
        t.update(local_total_s=time.perf_counter() - begin,
                 client_prepare_s=t["query_encode_s"] + t["query_encrypt_frame_s"],
                 server_total_s=t["query_parse_expand_s"] + t["server_evaluate_compact_s"]
                 + t["response_frame_s"],
                 client_finish_s=t["response_parse_s"] + t["client_finish_decode_top3_s"])
        return list(final.distances), [i for i, _ in final.top], {
            "timings": t, "query_bytes": len(packet), "response_bytes": len(response)}

    def update(self, rows):
        def encrypt(rows):
            _, tiles = self.d.shallow_bgv.coefficient_inputs([0] * 512, rows, self.pk.n)
            return [self.d.shallow_bgv.encrypt(p, self.pk) for p in tiles]

        def reprepare():
            self.workspace.close()
            self.workspace = None
            self.prepared = None
            gc.collect()
            self.prepared = self.server.prepare_index(self.index, len(self.rows))
            self.workspace = self.server.prepare_workspace(self.prepared)

        return common_update(self, rows, encrypt, self.pack_index,
                             lambda packet: self.unpack_index(packet, len(rows)), reprepare)


class CacheAdapter(Adapter):
    def prepare(self):
        self.words = self.setup_phase("owner_index_encode_s", lambda: tuple(packed_word(row) for row in self.rows))
        self.ids = tuple(range(len(self.rows)))
        self.key = self.setup_phase("key_generation_s", self.d.cache_snapshot.secrets.token_bytes, 32)
        manifest, packet = self.setup_phase("owner_seal_s", self.d.cache_snapshot.seal,
                                            self.words, self.ids, 512, self.key, compressed=False)
        self.cache = self.setup_phase("client_acquire_s", self.d.cache_snapshot.open_snapshot,
                                      packet, self.key, manifest, retained="raw")
        self.info.update(client_device="cpu", server_device="storage_only",
                         public_keys_bytes=0, trusted_key_manifest_body_bytes=32 + self.d.cache_snapshot.HEADER,
                         encrypted_index_bytes=len(packet),
                         retained_body_bytes=self.cache.retained_body_bytes_model,
                         config={"AEAD": "AES-256-GCM", "compressed": False, "retained": "raw",
                                 "current_manifest_and_key_delivery": "trusted premise"})

    def run(self, query):
        t, begin = {}, time.perf_counter()
        word = self.tick(t, "query_encode_s", packed_word, query)
        result = self.tick(t, "local_popcount_top3_s", self.cache.query, word)
        t.update(local_total_s=time.perf_counter() - begin,
                 client_prepare_s=t["query_encode_s"], server_total_s=0.0,
                 client_finish_s=t["local_popcount_top3_s"])
        return list(result.scores), [i for _, i in result.top3], {
            "timings": t, "query_bytes": 0, "response_bytes": 0}

    def update(self, rows):
        t, begin = {}, time.perf_counter()
        words = self.tick(t, "owner_replacement_encode_s", lambda: tuple(packed_word(r) for r in rows))
        self.words = words + self.words[len(words):]
        manifest, packet = self.tick(t, "owner_snapshot_reseal_s", self.d.cache_snapshot.seal,
                                     self.words, self.ids, 512, self.key, compressed=False)
        self.cache = self.tick(t, "client_snapshot_reacquire_s", self.d.cache_snapshot.open_snapshot,
                               packet, self.key, manifest, retained="raw")
        t["local_update_total_s"] = time.perf_counter() - begin
        return {"timings": t, "delta_packet_bytes": len(packet), "replacement_rows": len(rows),
                "update_mode": "full authenticated snapshot", "trusted_local_snapshot_metadata": True,
                "update_protocol_or_security_claim": False}


def provenance():
    paths = [Path(__file__), ROOT / "docs/research/system-selection-measurement-plan-20261003.md"]
    for directory in (ROOT / "src/cuhepy", ROOT / "experiments/bfv_search_lab"):
        paths.extend(p for p in directory.rglob("*") if p.is_file()
                     and (p.suffix in (".py", ".cpp", ".cu", ".h", ".cuh", ".pyi", ".so")
                          or p.name == "Makefile"))
    paths.extend(ROOT / "benchmarks" / x for x in ("bfv_client_matrix.py", "coefficient_search_lab.py"))
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(set(paths))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("main", "intrinsic"), required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--events-out", type=Path, required=True)
    args = parser.parse_args()
    plan = Plan(args.mode, 32768 if args.mode == "main" else 16,
                measured_queries=5 if args.mode == "main" else 1,
                update_count=32 if args.mode == "main" else 16).validate()
    if args.json_out.exists() or args.events_out.exists() or args.json_out == args.events_out:
        parser.error("Each attempt requires fresh distinct output paths")
    if sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE", "0") != "0":
        parser.error("Assertions must be enabled")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.events_out.parent.mkdir(parents=True, exist_ok=True)
    rec = Recorder(args.events_out)
    report = {"kind": "SB01_matched_arithmetic_acquisition" if args.mode == "main" else "SB01_intrinsic_only",
              "mode": args.mode, "plan": vars(plan), "base": BASE, "command": sys.argv,
              "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_binary_sha256": provenance(), "python": sys.version,
              "registered_maximum_resource_caps": RESOURCE_CAPS,
              "existing_full_group_baseline": {"path": str(BGV_BASELINE),
                                               "sha256": hashlib.sha256(BGV_BASELINE.read_bytes()).hexdigest()},
              "python_executable": sys.executable, "state": "created", "complete": False,
              "assurance": {"security_equivalence": False, "malicious_server_release": False,
                            "deployed_freshness": False, "original_main_contribution": False,
                            "WAN_or_cloud_measurement": False, "client_full_cache_permitted": True},
              "results": [], "updates": [], "all_scores_and_top3_correct": False,
              "scope": __doc__}

    def save(state):
        rec.flush()
        report["state"] = state
        report["utc"] = datetime.now(UTC).isoformat()
        temporary = args.json_out.with_name(args.json_out.name + ".progress.tmp")
        with temporary.open("w") as stream:
            stream.write(json.dumps(report, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, args.json_out)

    adapters = []
    try:
        save("created")
        begin = time.perf_counter()
        d = dependencies()
        report["common_dependency_import_s_outside_crypto"] = time.perf_counter() - begin
        begin = time.perf_counter()
        rows, warmup, _ = d.make_data(plan.count, plan.dimension, 1701)
        report["common_corpus_generation_s_outside_crypto"] = time.perf_counter() - begin
        report["corpus_sha256"] = hashlib.sha256(b"".join(packed_word(r).to_bytes(64, "little")
                                                          for r in rows)).hexdigest()
        report["query_order_seed"] = 2026100301
        report["corpus_seed"] = 1701
        classes = {VARIANTS[0]: BGVAdapter, VARIANTS[1]: BFVAdapter,
                   VARIANTS[2]: PaillierAdapter, VARIANTS[3]: PaillierAdapter,
                   VARIANTS[4]: CacheAdapter}
        save("setup")
        for name in VARIANTS:
            adapter = classes[name](name, plan, rows, rec, d)
            adapters.append(adapter)
            adapter.prepare()
            report["results"].append({**adapter.info, "setup_timings": adapter.setup, "samples": []})
            save("setup")
        by_name = {x.name: x for x in adapters}
        result_rows = {r["variant"]: r for r in report["results"]}
        for repeat, (query, order) in enumerate(zip(queries(plan, warmup), orders(plan.measured_queries + 1), strict=True)):
            save("warmup" if repeat == 0 else "measured")
            expected, top = scores(rows, query)
            for name in order:
                rec.event("sample_begin", variant=name, repeat=repeat, warmup=repeat == 0)
                actual, actual_top, sample = by_name[name].run(query)
                if actual != expected or actual_top != top:
                    raise AssertionError("Distances/top3 mismatch: " + name)
                sample.update(repeat=repeat, warmup=repeat == 0,
                              scores_sha256=score_digest(expected), stable_top3=top,
                              query_plaintext_sha256=hashlib.sha256(packed_word(query).to_bytes(64, "little")).hexdigest(),
                              all_scores_and_top3_correct=True)
                sample["query_plus_response_bytes"] = sample["query_bytes"] + sample["response_bytes"]
                result_rows[name]["samples"].append(sample)
                rec.event("sample_end", variant=name, repeat=repeat, warmup=repeat == 0,
                          correct=True, local_total_s=sample["timings"]["local_total_s"])
                save("warmup" if repeat == 0 else "measured")
                print(name, repeat, sample["timings"]["local_total_s"], flush=True)
        save("update")
        replacement = [[1 - bit for bit in row] for row in rows[:plan.update_count]]
        updated_rows = replacement + rows[plan.update_count:]
        expected, top = scores(updated_rows, warmup)
        for name in orders(1)[0]:
            adapter = by_name[name]
            transition = adapter.update(replacement)
            # Client/index counts stay fixed; rows themselves are oracle-only.
            adapter.rows = updated_rows
            actual, actual_top, sample = adapter.run(warmup)
            if actual != expected or actual_top != top:
                raise AssertionError("Updated distances/top3 mismatch: " + name)
            transition.update(variant=name, validation_sample=sample,
                              scores_sha256=score_digest(expected), stable_top3=top,
                              all_scores_and_top3_correct=True)
            report["updates"].append(transition)
            save("update")
        for row in report["results"]:
            row["warm_summary_s"] = summarize(row["samples"])
        validate_complete(plan, report)
        if report["source_binary_sha256"] != provenance():
            raise RuntimeError("Source/binary changed during the cohort")
        report.update(complete=True, all_scores_and_top3_correct=True,
                      total_searches=5 * (plan.measured_queries + 2),
                      checked_distances=5 * (plan.measured_queries + 2) * plan.count,
                      declared_phase_event_count=rec.events)
        save("complete")
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        save("failed")
        raise
    finally:
        cleanup_failures = []
        for adapter in reversed(adapters):
            cleanup_failures.extend(adapter.close())
        report["cleanup_failures"] = cleanup_failures
        if cleanup_failures:
            report["complete"] = False
            save("failed_cleanup")
        else:
            save(report["state"])
        rec.close()


if __name__ == "__main__":
    main()
