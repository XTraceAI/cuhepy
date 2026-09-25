"""Reusable CUDA scratch: exact results, concurrent leases and lifecycle bounds."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import copy
import os

import pytest

from cuhepy.bfv.cuda import cuda_available
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab.native_bgv import NativeServer

pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace_cuda")


@pytest.fixture(autouse=True)
def require_gpu():
    if not cuda_available():
        if os.environ.get("CUHEPY_REQUIRE_BGV_CUDA") == "1":
            pytest.fail("CUDA was required but no device is available")
        pytest.skip("CUDA extension/device required")


@pytest.mark.parametrize("n,dimension,count", [(16, 3, 33), (2048, 5, 65), (16384, 512, 65)])
def test_reused_workspace_matches_old_path_and_concurrent_requests(n, dimension, count):
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 1 << (dimension - 1).bit_length())
    server = NativeServer(pk, keys, residue=True, device="cuda", cuda_level=4)
    rows = [[(i + j) % 2 for j in range(dimension)] for i in range(count)]
    queries = [bgv.encrypt(bgv.coefficient_inputs([b] * dimension, [], n)[0], pk) for b in (0, 1)]
    _, plain = bgv.coefficient_inputs([0] * dimension, rows, n)
    index = server.prepare_index([bgv.encrypt(p, pk) for p in plain], count)
    expected = [server.search_compact(q, index, bits=25) for q in queries]
    with server.prepare_workspace(index) as first, server.prepare_workspace(index) as second:
        assert first.coefficient_bytes == server.batch_workspace_bytes(index, 1)
        with ThreadPoolExecutor(max_workers=4) as pool:
            jobs = [pool.submit(w.search_compact, queries[i % 2], bits=25)
                    for i, w in enumerate([first, first, second, first, second, second])]
            assert [f.result() for f in jobs] == [expected[i % 2] for i in range(len(jobs))]
        with pytest.raises(ValueError):
            first.search_compact(replace(queries[0], key_id="bad"))
        assert first.search_compact(queries[0], bits=25) == expected[0]
        with pytest.raises(TypeError):
            copy.copy(first)
        first._pid -= 1
        with pytest.raises(RuntimeError, match="fork"):
            first.close()
        first._pid += 1
    first.close()  # Idempotent release.
    with pytest.raises(RuntimeError, match="closed"):
        first.search_compact(queries[0], bits=25)
    empty = server.prepare_workspace(server.prepare_index([], 0))
    assert empty.search_compact(queries[0]) == []
    empty.close()
    with pytest.raises(RuntimeError, match="closed"):
        empty.search_compact(queries[0])


def test_wrong_context_and_backend_refused():
    pk, sk = bgv.key_gen(16, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 4)
    cpu = NativeServer(pk, keys, residue=True)
    gpu = NativeServer(pk, keys, residue=True, device="cuda", cuda_level=4)
    other = NativeServer(pk, keys, residue=True, device="cuda", cuda_level=3)
    with pytest.raises(ValueError):
        gpu.prepare_workspace(cpu.prepare_index([], 0))
    for server in (cpu, other):
        with pytest.raises(ValueError, match="level 4"):
            server.prepare_workspace(server.prepare_index([], 0))
