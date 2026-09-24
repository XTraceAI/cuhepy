"""Distinct-query CUDA batching: exact ciphertexts, tails, isolation and bounds."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os
import random

from gmpy2 import mpz
import pytest

from cuhepy.bfv.cuda import cuda_available
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab.native_bgv import NativeServer

native = pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace_cuda")


@pytest.fixture(autouse=True)
def require_gpu():
    if not cuda_available():
        if os.environ.get("CUHEPY_REQUIRE_BGV_CUDA") == "1":
            pytest.fail("CUDA was required but no device is available")
        pytest.skip("An optional CUDA device and extension are required")


@pytest.mark.parametrize("n,dimension", [(8, 1), (16, 3), (64, 31), (2048, 5), (16384, 512)])
def test_batched_ciphertexts_match_cpu_and_single_queries_with_tails(n, dimension):
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 1 << (dimension - 1).bit_length())
    gpu = NativeServer(pk, keys, residue=True, device="cuda", cuda_level=4)
    cpu = NativeServer(pk, keys, residue=True)
    rng = random.Random(n + dimension)
    count = 2 * n + 1 if n <= 64 else 65
    rows = [[rng.randrange(2) for _ in range(dimension)] for _ in range(count)]
    plain_queries = [[rng.randrange(2) for _ in range(dimension)] for _ in range(3)]
    _, tiles = bgv.coefficient_inputs(plain_queries[0], rows, n)
    index = [bgv.encrypt(p, pk) for p in tiles]
    device, host = gpu.prepare_index(index, count), cpu.prepare_index(index, count)
    queries = [bgv.encrypt(bgv.coefficient_inputs(q, [], n)[0], pk) for q in plain_queries]
    queries += [queries[0], queries[1]]  # five requests, partial final waves at 2/3/4
    plain_queries += plain_queries[:2]
    expected = [cpu.search(q, host) for q in queries]
    assert [gpu.search(q, device) for q in queries] == expected
    small = [[compact.compact(c, pk, 25) for c in group] for group in expected]
    for size in (1, 2, 3, 4, 8):
        for shared in (False, True):
            assert gpu.search_many(queries, device, batch_size=size, shared_index=shared) == expected
            assert gpu.search_many_compact(queries, device, batch_size=size, shared_index=shared, bits=25) == small
    for group, query in zip(small, plain_queries, strict=True):
        values = trace.decode([compact.decrypt(c, pk, sk) for c in group], count, dimension, pk)
        assert values == [sum(a != b for a, b in zip(query, row, strict=True)) for row in rows]
    assert gpu.search_many([], device) == []
    assert gpu.search_many_compact(queries, gpu.prepare_index([], 0)) == [[]] * len(queries)


def test_arbitrary_canonical_queries_extremes_and_concurrent_batch_isolation():
    n, pk_sk = 64, bgv.key_gen(64, q_bits=120, rns_modulus=True)
    pk, sk = pk_sk
    keys = trace.evaluation_keys(pk, sk, 8)
    gpu = NativeServer(pk, keys, residue=True, device="cuda", cuda_level=4)
    cpu = NativeServer(pk, keys, residue=True)
    rng = random.Random(9901)

    def cipher():
        return bgv.Ciphertext(tuple(tuple(mpz(rng.randrange(int(pk.q))) for _ in range(n)) for _ in range(2)), pk.key_id, 1)

    index = [cipher() for _ in range(11)]
    device, host = gpu.prepare_index(index, 88), cpu.prepare_index(index, 88)
    queries = [cipher() for _ in range(3)] + [bgv.Ciphertext(((pk.q - 1,) * n, (mpz(0),) * n), pk.key_id, 1)]
    expected = [cpu.search(q, host) for q in queries]
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(gpu.search_many, queries, device, batch_size=size) for size in (2, 4, 3, 1)]
        assert all(f.result() == expected for f in futures)


def test_batched_boundaries_memory_budget_and_no_silent_mode_fallback():
    pk, sk = bgv.key_gen(64, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 8)
    gpu = NativeServer(pk, keys, residue=True, device="cuda", cuda_level=4)
    other = NativeServer(pk, keys, residue=True, device="cuda", cuda_level=3)
    cpu = NativeServer(pk, keys, residue=True)
    query = bgv.encrypt([0] * pk.n, pk)
    index = gpu.prepare_index([query], 1)
    for size in (True, 0, 9):
        with pytest.raises(ValueError):
            gpu.search_many([query], index, batch_size=size)
    for values in ([query] * 33, [replace(query, key_id="bad")]):
        with pytest.raises(ValueError):
            gpu.search_many(values, index)
    with pytest.raises(ValueError):
        gpu.search_many([query], index, shared_index=1)
    with pytest.raises(ValueError):
        gpu.search_many([query], other.prepare_index([query], 1))
    for server in (cpu, other):
        with pytest.raises(ValueError, match="level 4"):
            server.search_many([query], server.prepare_index([query], 1))
    # Exercise the Python allocation gate without constructing a huge device index.
    original_pk, original_keys = gpu.pk, gpu.keys
    try:
        gpu.pk, gpu.keys = replace(pk, n=32768), replace(keys, padded=512)
        wide = replace(index, phase_bounds=(1,) * 512)
        with pytest.raises(ValueError, match="4 GiB"):
            gpu.search_many([query] * 4, wide, batch_size=4)
    finally:
        gpu.pk, gpu.keys = original_pk, original_keys
    pair = tuple(gpu._pack(p) for p in query.components)
    for queries, size, shared in (([], 2, True), ((pair,) * 33, 2, True), ((pair,), True, True),
                                   ((pair,), 0, True), ((pair,), 2, 1), (((b"", b""),), 2, True)):
        with pytest.raises((ValueError, OverflowError)):
            native.search_many(gpu._server, queries, index.handle, size, shared)
    with pytest.raises(ValueError, match="level 4"):
        native.search_many(other._server, (pair,), other.prepare_index([query], 1).handle, 2, True)
