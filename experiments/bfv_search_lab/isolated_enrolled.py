"""E79 three-process owner/server/client measurement, not deployed service.

The compute server consumes only actual public socket bodies. Trusted local
controller IPC provisions one owner root and benchmark query inputs; remote
messages use bounded authenticated/private or whitelisted/public codecs.
No shared Python/GIL endpoint measurements. All HE assurance limits remain.
"""

from contextlib import closing
import hashlib
import heapq
import multiprocessing as mp
import os
from pathlib import Path
import resource
import secrets
import socket
import struct
import time

import numpy as np

from benchmarks.enrolled_service_lab import compile_geometry, open_response
from benchmarks.field_frontier_lab import public_space
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import cache_snapshot as snapshot
from experiments.bfv_search_lab import coordinate_cache as caches
from experiments.bfv_search_lab import coordinate_factory
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import enrolled_rpc as rpc
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import loopback_exchange as transport
from experiments.bfv_search_lab.loopback_transfer import receive_exact
from experiments.bfv_search_lab import native_linear_check as checks
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import private_provision as provision
from experiments.bfv_search_lab import verification_lifetime as lifetime


def resources():
    usage = resource.getrusage(resource.RUSAGE_SELF)
    with open("/proc/self/status") as status:
        rss = next(int(line.split()[1]) * 1024 for line in status if line.startswith("VmRSS:"))
    return {"pid": os.getpid(), "process_cpu_s": usage.ru_utime + usage.ru_stime,
            "process_peak_RSS_bytes": usage.ru_maxrss * 1024, "current_RSS_bytes": rss}


def _listener():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.settimeout(40)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    return listener


def _connect(address):
    peer = socket.create_connection(address, timeout=40)
    peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return peer


def _recv(peer):
    prefix = peer.recv(8)
    if not prefix:
        return None
    length, = struct.unpack("<Q", prefix + receive_exact(peer, 8 - len(prefix)))
    if not 1 <= length <= 64 << 20:
        raise ValueError("Isolated frame exceeds bound")
    return receive_exact(peer, length)


def _call(peer, body):
    start, cpu = time.perf_counter(), time.process_time()
    peer.sendall(transport.packet(body))
    reply = _recv(peer)
    if reply is None:
        raise ValueError("Missing isolated response")
    return reply, {"rpc_wall_s": time.perf_counter() - start, "caller_cpu_s": time.process_time() - cpu,
                   "request_body_bytes": len(body), "response_body_bytes": len(reply),
                   "application_bytes": 16 + len(body) + len(reply)}


def _result(result):
    return {"scores_sha256": hashlib.sha256(b"".join(x.to_bytes(2, "little") for x in result.scores)).hexdigest(),
            "top3": result.top3, "score_count": len(result.scores)}


def _server(control):
    initial, calls, handler = resources(), [], None
    with closing(_listener()) as listener:
        control.send(("ready", listener.getsockname(), initial))
        for role in ("owner", "client"):
            peer, _ = listener.accept()
            with closing(peer):
                peer.settimeout(40)
                peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                while (body := _recv(peer)) is not None:
                    start, cpu = time.perf_counter(), time.process_time()
                    if body[:1] == b"B" and handler is None and role == "owner":
                        public = provision.public_context(body[1:])
                        handler = (rpc.LinearServer(public["space"], public["pk"], public["epoch"], budget=public["budget"])
                                   if public["mode"] == "he" else rpc.CacheServer())
                        reply = b"\x01"
                    elif handler is None:
                        raise ValueError("Public bootstrap precedes enrollment")
                    else:
                        reply = handler(body)
                    peer.sendall(transport.packet(reply))
                    calls.append({"role": role, "command": body[:1].decode(), "wall_s": time.perf_counter() - start,
                                  "process_cpu_s": time.process_time() - cpu, "request_body_bytes": len(body),
                                  "response_body_bytes": len(reply), "application_bytes": 16 + len(body) + len(reply),
                                  "resident_after_call": resources(),
                                  "handler_stages": dict(getattr(handler, "last", {}))})
    control.send(("done", {"initial": initial, "final": resources(), "calls": calls,
                           "enrollment_stages": dict(getattr(handler, "enrollment", {})),
                           "receives_private_material": False}))


def _owner(control, server_address, job):
    initial, start, cpu = resources(), time.perf_counter(), time.process_time()
    data = fixtures.load(job["dataset"], Path(job["fixture_path"]))
    ids, heldout = fixtures.split(data, 3001)
    ids, rows = tuple(ids), tuple(data.rows[i] for i in ids)
    query_ids = tuple(heldout[64:64 + job["queries"]])
    words = tuple(data.rows[i] for i in query_ids)
    if len(words) != job["queries"]:
        raise ValueError("Insufficient held-out queries")
    load_s = time.perf_counter() - start
    raw = caches.RawRows(rows, ids, data.dimension)
    raw_samples, expected = [], []
    for word in words:
        local_start, local_cpu = time.perf_counter(), time.process_time()
        result = raw.query(word)
        raw_samples.append({"wall_s": time.perf_counter() - local_start, "process_cpu_s": time.process_time() - local_cpu})
        expected.append(_result(result))
    raw_resources = resources()
    setup_start, setup_cpu = time.perf_counter(), time.process_time()
    root_key, context_id = secrets.token_bytes(32), secrets.token_bytes(32)
    if job["mode"] == "he":
        t = 193 if data.dimension == 126 else 257
        candidate, kind, stages = compile_geometry(rows, ids, data.dimension, "global2048", t, 1)
        maps, s = public_space(candidate)
        groups = [affine.index_features(b.mapping, [rows[i] for i in b.positions]) for b in candidate.blocks]
        pk, sk = masked.key_gen(s, q_bits=32)
        epoch = secrets.token_bytes(32)
        with closing(owner.OwnerClient(pk, sk)) as client:
            captured = rpc.CaptureClient(client)
            index, _ = masked.enroll(s, groups, epoch, captured)
            index_body = b"I" + rpc.bundle(captured.take())
            checker = checks.NativeVectorCheck(index, pk, rounds=fields.rounds(int(pk.q), budget=job["budget"]), budget=job["budget"])
            private = {"mode": "he", "space": s, "pk": pk, "sk": sk, "epoch": epoch,
                       "maps": tuple(maps), "positions": tuple(b.positions for b in candidate.blocks), "ids": ids,
                       "coordinates": tuple(np.asarray(g, dtype=np.int8).tobytes() for g in groups),
                       "checker": provision.checker_material(checker), "dimension": data.dimension, "budget": job["budget"]}
        public = {"mode": "he", "space": s, "pk": pk, "epoch": epoch, "budget": job["budget"]}
        # A conservative FIXED function of public geometry. Actual padding cost
        # is paid; serialized private coefficients do not select the length.
        padded_size = 48 * pk.n + sum(count * (f + 24) for count, f in zip(s.layout.counts, s.layout.features, strict=True)) + 16 * sum(s.dimensions) * data.dimension + 16384 + 12 * len(checker._seeds) * sum(s.column_degrees)
        geometry = {"kind": kind, "n": pk.n, "t": pk.t, "q": int(pk.q),
                    "columns": s.columns, "degrees": s.column_degrees, "replies": s.layout.cost.response_ciphertexts,
                    "checker_rounds": len(checker._seeds), "coordinate_body_bytes": sum(map(len, private["coordinates"]))}
    else:
        key = secrets.token_bytes(32)
        manifest, packet = snapshot.seal(rows, ids, data.dimension, key, compressed=job["level"] is not None,
                                        compression_level=job["level"] or 9)
        index_body = b"I" + packet
        private = {"mode": "cache", "key": key, "manifest": manifest, "retained": job["retained"]}
        public = {"mode": "cache", "space": None, "pk": None, "epoch": None, "budget": job["budget"]}
        padded_size, geometry, stages = 1024, {"snapshot_packet_bytes": len(packet)}, {}
    sealed, private_encoded_bytes = provision.seal(private, root_key, context_id, padded_size)
    root_body = provision.pack({"key": root_key, "context": context_id, "padded_size": padded_size})
    setup_wall, setup_cpu = time.perf_counter() - setup_start, time.process_time() - setup_cpu
    enrollment_start = time.perf_counter()
    with closing(_connect(server_address)) as peer:
        ack, public_bootstrap = _call(peer, b"B" + provision.pack(public))
        assert ack == b"\x01"
        ack, index_upload = _call(peer, index_body)
        assert ack == b"\x01"
    enrollment_wall = time.perf_counter() - enrollment_start
    with closing(_listener()) as listener:
        control.send(("ready", listener.getsockname(), words, tuple(expected), padded_size))
        control.send_bytes(root_body)  # Trusted controller relay, never compute server.
        peer, _ = listener.accept()
        with closing(peer):
            assert _recv(peer) == b"B"
            provision_start, provision_cpu = time.perf_counter(), time.process_time()
            peer.sendall(transport.packet(sealed))
            owner_provision = {"wall_s": time.perf_counter() - provision_start, "process_cpu_s": time.process_time() - provision_cpu,
                               "application_bytes": 17 + len(sealed)}
    control.send(("done", {"initial": initial, "final": resources(), "load_parse_s": load_s,
                           "owner_setup_wall_s": setup_wall, "owner_setup_cpu_s": setup_cpu,
                           "owner_total_wall_s": time.perf_counter() - start, "owner_total_cpu_s": time.process_time() - cpu,
                           "owner_enrollment_wall_s": enrollment_wall, "public_bootstrap": public_bootstrap,
                           "index_upload": index_upload, "private_provision": owner_provision,
                           "private_unpadded_encoding_bytes": private_encoded_bytes, "private_envelope_bytes": len(sealed),
                           "private_padding_bytes": padded_size - 8 - private_encoded_bytes,
                           "owner_root_semantic_bytes": 64, "public_padding_bound_semantic_bytes": 8,
                           "trusted_root_IPC_packet_bytes_per_hop": len(root_body) + 4,
                           "geometry": geometry, "map_stages": stages, "fixture_sha256": data.sha256,
                           "count": len(rows), "dimension": data.dimension, "query_source_ids": query_ids,
                           "retained_owner_raw_samples": raw_samples,
                           "retained_owner_raw_resources": raw_resources}))


def _finish(private, compiled, plaintexts, offsets):
    s, ids = private["space"], private["ids"]
    scores = [None] * len(ids)
    for positions, dots, group in zip(private["positions"], tree.unpack(s.layout, plaintexts), s.map_ids, strict=True):
        for i, value in zip(positions, affine.bit_decode(compiled[group], dots, offsets[group]), strict=True):
            scores[i] = value
    if any(value is None for value in scores):
        raise ValueError("Incomplete isolated score coverage")
    return caches.Result(tuple(scores), tuple(heapq.nsmallest(3, zip(scores, ids, strict=True))))


def _client(control, owner_address, server_address, words, padded_size):
    initial, start, cpu = resources(), time.perf_counter(), time.process_time()
    root_body = control.recv_bytes()
    root = provision.unpack(root_body)  # Trusted LOCAL controller channel.
    if root["padded_size"] != padded_size:
        raise ValueError("Wrong pinned private padding bound")
    bootstrap_start = time.perf_counter()
    with closing(_connect(owner_address)) as peer:
        packet, bootstrap = _call(peer, b"B")
    private = provision.open_private(packet, root["key"], root["context"], padded_size)
    bootstrap_wall = time.perf_counter() - bootstrap_start
    prepared_start, prepared_cpu = time.perf_counter(), time.process_time()
    server_connect_start = time.perf_counter()
    peer = _connect(server_address)
    connection_s = time.perf_counter() - server_connect_start
    samples = []
    if private["mode"] == "he":
        s, pk, sk = private["space"], private["pk"], private["sk"]
        compiled = tuple(affine.compile_bits(p) for p in private["maps"])
        if (len(private["coordinates"]) != len(s.layout.counts)
                or len(private["positions"]) != len(s.layout.counts)
                or len(set(private["ids"])) != len(private["ids"])):
            raise ValueError("Malformed trusted HE geometry")
        groups = [np.frombuffer(raw, dtype=np.int8).reshape(count, f).tolist()
                  for raw, count, f in zip(private["coordinates"], s.layout.counts, s.layout.features, strict=True)]
        checker = provision.restore_checker(s, pk, private["epoch"], private["checker"])
        attempts = lifetime.AttemptBudget(private["budget"])
        gate = attempts.bind(checker)
        with closing(owner.OwnerClient(pk, sk)) as client, closing(peer):
            captured = rpc.CaptureClient(client)
            factory = coordinate_factory.Factory(s, groups, private["epoch"], captured, budget=private["budget"])
            prepared_wall, prepared_cpu = time.perf_counter() - prepared_start, time.process_time() - prepared_cpu
            ready_resources = resources()
            for ordinal, word in enumerate(words):
                query_start, query_cpu = time.perf_counter(), time.process_time()
                token_id = ordinal.to_bytes(16, "little")
                ticket, answer, _ = factory.prepare(token_id)
                gate.prepare_answer(answer)
                answer_packets = captured.take()
                ack, upload = _call(peer, b"A" + token_id + rpc.bundle(answer_packets))
                assert ack == b"\x01"
                transformed = [affine.bit_query_features(p, word) for p in compiled]
                values = tuple(x for weights, _ in transformed for x in weights)
                offsets = tuple(offset for _, offset in transformed)
                request = ticket.consume(values, private["epoch"])
                body, exchange = _call(peer, b"Q" + token_id + request.body())
                plaintexts, stages = open_response(body, request, pk, sk, gate)
                result = _finish(private, compiled, plaintexts, offsets)
                samples.append({"ordinal": ordinal, "warmup": ordinal == 0,
                                "query_wall_s": time.perf_counter() - query_start, "client_query_cpu_s": time.process_time() - query_cpu,
                                "answer_upload": upload, "query_reply": exchange,
                                "application_bytes": upload["application_bytes"] + exchange["application_bytes"],
                                "full_response_body_bytes": len(body), **stages, **_result(result)})
            assert attempts.used == len(words)
    elif private["mode"] == "cache":
        with closing(peer):
            acquisition_start, acquisition_cpu = time.perf_counter(), time.process_time()
            packet, download = _call(peer, b"Q")
            cache = snapshot.open_snapshot(packet, private["key"], private["manifest"], retained=private["retained"])
            acquisition = {"wall_s": time.perf_counter() - acquisition_start, "cpu_s": time.process_time() - acquisition_cpu, **download}
            prepared_wall, prepared_cpu = time.perf_counter() - prepared_start, time.process_time() - prepared_cpu
            ready_resources = resources()
            for ordinal, word in enumerate(words):
                query_start, query_cpu = time.perf_counter(), time.process_time()
                result = cache.query(word)
                samples.append({"ordinal": ordinal, "warmup": ordinal == 0, "query_wall_s": time.perf_counter() - query_start,
                                "client_query_cpu_s": time.process_time() - query_cpu, "application_bytes": 0, **_result(result)})
    else:
        peer.close()
        raise ValueError("Unknown authenticated private mode")
    control.send(("done", {"initial": initial, "ready": ready_resources, "final": resources(), "samples": samples,
                           "bootstrap": bootstrap, "bootstrap_authenticate_decode_wall_s": bootstrap_wall,
                           "private_construct_acquire_wall_s": prepared_wall, "private_construct_acquire_cpu_s": prepared_cpu,
                           "server_connect_s": connection_s, "first_query_after_bootstrap_wall_s": bootstrap_wall + prepared_wall + samples[0]["query_wall_s"],
                           "client_total_wall_s": time.perf_counter() - start, "client_total_cpu_s": time.process_time() - cpu,
                           "acquisition": acquisition if private["mode"] == "cache" else None,
                           "trusted_root_IPC_packet_bytes": len(root_body) + 4,
                           "all_private_setup_transferred": True, "mode": private["mode"]}))


def _worker(target, control, args):
    try:
        target(control, *args)
    except Exception as error:
        control.send(("error", type(error).__name__, str(error)))
    finally:
        control.close()


def _message(control, expected):
    if not control.poll(40):
        raise RuntimeError("Isolated measurement worker timed out")
    message = control.recv()
    if message[0] != expected:
        raise RuntimeError(f"Isolated worker failed: {message[:3]}")
    return message


def run_trial(job):
    """Trusted measurement controller; no private payload goes to server args."""
    context, workers, controls = mp.get_context("spawn"), [], []

    def launch(target, *args):
        parent, child = context.Pipe()
        process = context.Process(target=_worker, args=(target, child, args))
        process.start()
        child.close()
        workers.append(process)
        controls.append(parent)
        return parent

    try:
        start = time.perf_counter()
        server_control = launch(_server)
        _, server_address, _ = _message(server_control, "ready")
        owner_control = launch(_owner, server_address, job)
        _, owner_address, words, expected, padded_size = _message(owner_control, "ready")
        root_body = owner_control.recv_bytes()
        client_launch_start = time.perf_counter()
        client_control = launch(_client, owner_address, server_address, words, padded_size)
        client_control.send_bytes(root_body)
        client = _message(client_control, "done")[1]
        client["controller_new_client_wall_including_process_startup_s"] = time.perf_counter() - client_launch_start
        owner_result = _message(owner_control, "done")[1]
        server = _message(server_control, "done")[1]
        for sample, truth in zip(client["samples"], expected, strict=True):
            assert all(sample[key] == truth[key] for key in truth)
        for process in workers:
            process.join(timeout=5)
            if process.exitcode != 0:
                raise RuntimeError("Isolated worker exited unsuccessfully")
        assert len({v["initial"]["pid"] for v in (client, owner_result, server)}) == 3
        application = sum(c["application_bytes"] for c in server["calls"]) + client["bootstrap"]["application_bytes"]
        return {"job": job, "controller_wall_including_process_startup_s": time.perf_counter() - start,
                "owner": owner_result, "client": client, "server": server,
                "network_application_bytes_all_roles": application,
                "trusted_owner_root_IPC_bytes_two_hops": 2 * (len(root_body) + 4),
                "all_score_ID_top3_exact": True,
                "scope": "Independent Linux process CPU/RSS and actual loopback bytes; trusted local controller/root, volatile epochs and unreviewed research HE. TCP/IP/TLS/WAN/update costs excluded. Import baselines and process startup are reported separately."}
    finally:
        for process in workers:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        for control in controls:
            control.close()
