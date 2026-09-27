"""Trusted loopback TCP experiment, including actual parsing and client finishing.

An excluded local evaluation pins each expected ciphertext before measurement.
This fixture gate avoids decrypting an arbitrary TCP response; its cost is not
a deployment authentication estimate. No client decision goes back to server.
Bandwidth/RTT are application pacing settings, not measured WAN conditions.
"""

from concurrent.futures import ThreadPoolExecutor
import random
import socket
import time

from bgv_service_pipeline import summary, timed
from experiments.bfv_search_lab import compact_bgv as compact, owner_bgv, shallow_bgv as bgv
from experiments.bfv_search_lab import transport_bgv as wire

LINKS = {"loopback": (0, 0, 0), "100Mbps-20ms": (100, 100, 20),
         "10up-100down-40ms": (10, 100, 40), "10Mbps-40ms": (10, 10, 40)}


def experiment(args, case, rows, server, index, client):
    samples = {name: [] for name in LINKS}
    phases = {name: [] for name in LINKS}
    rng = random.Random(20260925)
    warmup, preparation, gate_setup = {}, [], []
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.settimeout(30)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    with server.prepare_workspace(index) as workspace, ThreadPoolExecutor(max_workers=1) as pool:
        try:
            for repeat in range(args.repeats + 1):
                plain = [rng.randrange(2) for _ in range(args.embed_len)]
                encode_s, encoded = timed(bgv.coefficient_inputs, plain, [], case.n)
                encrypt_s, packet = timed(client.encrypt, encoded[0])
                expanded = owner_bgv.expand(packet, case.pk)
                gate_s, known = timed(workspace.search_compact, expanded, bits=args.terminal_bits)
                expected_wire = compact.pack(known, len(rows), args.embed_len, case.pk)
                gate_setup.append(gate_s)
                expected = tuple(sum(a != b for a, b in zip(plain, row, strict=True)) for row in rows)
                preparation.append({"warmup": not repeat, "encode_s": encode_s, "encrypt_s": encrypt_s})
                order = list(LINKS)
                rng.shuffle(order)
                for name in order:
                    up, down, rtt = LINKS[name]

                    def evaluate(down=down, rtt=rtt):
                        connection, address = listener.accept()
                        assert address[0] == "127.0.0.1"
                        with connection:
                            connection.settimeout(30)
                            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            incoming = wire.receive(connection)
                            expand_s, query = timed(owner_bgv.expand, incoming, case.pk)
                            evaluate_s, response = timed(workspace.search_compact, query, bits=args.terminal_bits)
                            pack_s, outgoing = timed(compact.pack, response, len(rows), args.embed_len, case.pk)
                            wire.send(connection, outgoing, mbps=down, delay_ms=rtt / 2)
                        return {"server_expand_s": expand_s, "server_evaluate_s": evaluate_s, "response_pack_s": pack_s}

                    job = pool.submit(evaluate)
                    start = time.perf_counter()
                    with socket.create_connection(listener.getsockname(), timeout=30) as connection:
                        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        wire.send(connection, packet, mbps=up, delay_ms=rtt / 2)
                        received = wire.receive(connection)
                    transfer_complete = time.perf_counter()
                    # Known-ciphertext fixture comparison precedes ALL private work.
                    wire.require_expected_fixture(received, expected_wire)
                    parsed_s, parsed = timed(wire.unpack_fixture, received, case.pk, count=len(rows), dimension=args.embed_len,
                                             modulus=known[0].modulus, bounds=[c.phase_bound for c in known])
                    finish_s, result = timed(client.finish, parsed, len(rows), args.embed_len)
                    ended = time.perf_counter()
                    assert result.distances == expected
                    assert result.top == tuple(sorted(enumerate(expected), key=lambda x: (x[1], x[0]))[:3])
                    row = job.result()
                    row.update({"request_response_s": transfer_complete - start, "parse_s": parsed_s, "finish_s": finish_s,
                                "local_plus_transport_s": ended - start + encode_s + encrypt_s,
                                "query_bytes": len(packet), "response_bytes": len(received), "tcp_frame_header_bytes": 8})
                    if repeat:
                        samples[name].append(row["local_plus_transport_s"])
                        phases[name].append(row)
                    else:
                        warmup[name] = row
        finally:
            listener.close()
    return {"local_plus_transport_seconds": summary(samples), "phases": phases, "warmup": warmup,
            "preparation": preparation, "excluded_expected_ciphertext_evaluation_s": gate_setup,
            "links_upload_mbps_download_mbps_rtt_ms": LINKS, "all_distances_and_stable_top3_correct": True,
            "scope": __doc__}
