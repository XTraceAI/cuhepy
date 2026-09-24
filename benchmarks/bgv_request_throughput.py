"""Same-index concurrent-request experiment, called by bgv_public_pipeline.py.

Fresh query creation and client verification are charged/reported separately.
This measures server throughput with requests already available, not interactive
latency or client throughput. Each worker uses the same immutable plan/index and
its own CUDA stream/workspace. No CUDA graph or fused multi-query kernel is used.
"""

from concurrent.futures import ThreadPoolExecutor
import random
import statistics
import time

from coefficient_search_lab import timed
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, seeded_bgv


def run(server, prepared, case, rows, query, repeats, request_count=4):
    maximum = min(server.keys.padded, len(prepared.phase_bounds))
    scratch = (4 + maximum * 26) * case.n * 8
    if scratch * request_count > (4 << 30):
        raise ValueError("Concurrent experiment exceeds its 4 GiB workspace budget")
    workers = (1, 2, 4)
    samples = {count: [] for count in workers}
    warmups, preparation = {}, []
    rng = random.Random(20260926)
    ciphertext_checks = 0

    def service(packet):
        begin = time.perf_counter()
        expand_s, ct = timed(seeded_bgv.expand, packet, case.pk)
        evaluate_s, small = timed(server.search_compact, ct, prepared)
        pack_s, wire = timed(compact.pack, small, len(rows), len(query), case.pk)
        return small, {
            "service_wall_s": time.perf_counter() - begin,
            "expand_s": expand_s, "evaluate_and_compact_s": evaluate_s,
            "pack_s": pack_s, "response_bytes": len(wire),
        }

    # Executor construction/shutdown is not part of steady-state service time.
    with ThreadPoolExecutor(max_workers=2) as two, ThreadPoolExecutor(max_workers=4) as four:
        pools = {2: two, 4: four}
        for repeat in range(repeats + 1):
            packets, expected = [], []
            query_s = 0.0
            for request in range(request_count):
                current = [rng.randrange(2) for _ in query]
                start = time.perf_counter()
                encoded = bgv.coefficient_inputs(current, [], case.n)[0]
                packets.append(seeded_bgv.encrypt(encoded, case.pk, case.sk))
                query_s += time.perf_counter() - start
                expected.append([sum(a != b for a, b in zip(current, row, strict=True)) for row in rows])
            preparation.append({"warmup": not repeat, "fresh_query_creation_s": query_s,
                                "query_bytes": sum(map(len, packets))})
            order, reference = list(workers), None
            rng.shuffle(order)
            for count in order:
                begin = time.perf_counter()
                outputs = ([service(packet) for packet in packets] if count == 1
                           else list(pools[count].map(service, packets)))
                elapsed = time.perf_counter() - begin
                ciphertexts = [item[0] for item in outputs]
                if reference is None:
                    reference = ciphertexts
                else:
                    assert ciphertexts == reference
                    ciphertext_checks += sum(map(len, ciphertexts))
                client_begin = time.perf_counter()
                for result, distances in zip(ciphertexts, expected, strict=True):
                    plaintexts = [compact.decrypt(ct, case.pk, case.sk) for ct in result]
                    decoded = trace.decode(plaintexts, len(rows), len(query), case.pk)
                    assert decoded == distances
                    assert sorted(range(len(rows)), key=lambda i: (decoded[i], i))[:3] == sorted(range(len(rows)), key=lambda i: (distances[i], i))[:3]
                client_s = time.perf_counter() - client_begin
                entry = {
                    "batch_wall_s": elapsed, "requests_per_second": request_count / elapsed,
                    "service_median_s": statistics.median(item[1]["service_wall_s"] for item in outputs),
                    "service_max_s": max(item[1]["service_wall_s"] for item in outputs),
                    "client_verification_s": client_s,
                    "response_bytes": sum(item[1]["response_bytes"] for item in outputs),
                }
                if repeat:
                    samples[count].append(entry)
                else:
                    warmups[count] = entry
                print(f"concurrency {count}, round {repeat}: {elapsed:.4f}s / {request_count} requests, "
                      f"{entry['requests_per_second']:.2f} requests/s", flush=True)
    return {
        "notes": __doc__, "requests_per_batch": request_count, "repeats": repeats,
        "cuda_level": 4, "workspace_coefficient_bytes_per_request": scratch,
        "preparation": preparation, "warmup": warmups,
        "results": [{"workers": count, "samples": entries,
                     "medians": {key: statistics.median(row[key] for row in entries) for key in entries[0]}}
                    for count, entries in samples.items()],
        "exact_compact_ciphertexts_compared": ciphertext_checks,
        "every_distance_and_stable_top3_correct": True,
    }
