"""GPU/CPU/GMP equality, including canonical extremes and multi-pass NTTs."""

from concurrent.futures import ThreadPoolExecutor
import os
import random

from gmpy2 import mpz
import pytest

from cuhepy.bfv.cuda import cuda_available
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import butterfly_bgv as butterfly, compact_bgv as compact
from experiments.bfv_search_lab.native_bgv import NativeServer

pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace_cuda")


@pytest.fixture(autouse=True)
def require_gpu():
    if not cuda_available():
        if os.environ.get("CUHEPY_REQUIRE_BGV_CUDA") == "1":
            pytest.fail("A CUDA device was required but is unavailable")
        pytest.skip("Expose a CUDA device and build the optional extensions")


@pytest.mark.parametrize("n,d", [(8, 1), (16, 3), (64, 31), (2048, 5), (16384, 512)])
@pytest.mark.parametrize("level", [0, 1, 2, 3, 4])
def test_gpu_exact_for_joint_and_independent_trace_with_tails(n, d, level):
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 1 << (d - 1).bit_length())
    gpu = NativeServer(pk, keys, residue=True, device="cuda", cuda_level=level)
    cpu = NativeServer(pk, keys, residue=True)
    rng = random.Random(n + d)
    query = [rng.randrange(2) for _ in range(d)]
    rows = [query, [1 - x for x in query]] + [[rng.randrange(2) for _ in range(d)] for _ in range(n + 1 if n <= 64 else 63)]
    qp, tiles = bgv.coefficient_inputs(query, rows, n)
    ct, index = bgv.encrypt(qp, pk), [bgv.encrypt(p, pk) for p in tiles]
    capacity = n // keys.padded
    counts = sorted({0, 1, min(capacity, len(rows)), min(capacity + 1, len(rows)), len(rows)})
    for count in counts:
        chosen = index[:(count + capacity - 1) // capacity]
        device, host = gpu.prepare_index(chosen, count), cpu.prepare_index(chosen, count)
        for joint in (False, True):
            expected = cpu.search(ct, host, joint=joint)
            actual = gpu.search(ct, device, joint=joint)
            assert actual == expected
            assert gpu.search_compact(ct, device, joint=joint) == [compact.compact(c, pk) for c in expected]
            plains = [compact.decrypt(compact.compact(c, pk), pk, sk) for c in actual]
            assert trace.decode(plains, count, d, pk) == [sum(a != b for a, b in zip(query, row, strict=True)) for row in rows[:count]]
    if n <= 64:
        prepared = gpu.prepare_index(index, len(rows))
        expected = butterfly.search(ct, index, len(rows), pk, keys)
        with ThreadPoolExecutor(max_workers=3) as pool:
            assert all(output == expected for output in pool.map(lambda _: gpu.search(ct, prepared), range(3)))


@pytest.mark.parametrize("level", [0, 1, 2, 3, 4])
def test_gpu_canonical_extremes_and_context_boundaries(level):
    pk, sk = bgv.key_gen(64, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 8)
    gpu = NativeServer(pk, keys, residue=True, device="cuda", cuda_level=level)
    cpu = NativeServer(pk, keys, residue=True)
    values = [0, 1, int(pk.q) - 1, int(pk.q) // 2, (1 << 64) - 1, 1 << 64, (1 << 119) - 1]
    rng = random.Random(999)
    # These are public-arithmetic fixtures, not valid bounded decryptable messages.
    # Do not decrypt or interpret their artificial phase_bound metadata.
    ct = bgv.Ciphertext(tuple(tuple(mpz(rng.choice(values)) for _ in range(64)) for _ in range(2)), pk.key_id, 0)
    index = [ct] * 7
    prepared = gpu.prepare_index(index, 56)
    for joint, reference in ((False, trace.search), (True, butterfly.search)):
        assert gpu.search(ct, prepared, joint=joint) == reference(ct, index, 56, pk, keys)
    pair = tuple(gpu._pack(poly) for poly in ct.components)
    with pytest.raises(ValueError):
        gpu._native.search(cpu._server, pair, prepared.handle, True)
    with pytest.raises(ValueError):
        gpu._native.prepare_index(gpu._server, ((b"", b""),))
    bad = pk.q.to_bytes(gpu.width, "little") * pk.n
    with pytest.raises(ValueError, match="Noncanonical"):
        gpu._native.search(gpu._server, (bad, pair[1]), prepared.handle, True)


@pytest.mark.parametrize("level", [0, 3, 4])
def test_repeated_query_uploads_order_before_nonblocking_kernel_consumers(level):
    # A pageable host cudaMemcpy on stream 0 can return before device DMA ends.
    # Previously, later kernels on a nonblocking stream could read stale query
    # words. Warm allocations plus fresh queries expose the missing dependency.
    pk, sk = bgv.key_gen(2048, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 8)
    gpu = NativeServer(pk, keys, residue=True, device="cuda", cuda_level=level)
    cpu = NativeServer(pk, keys, residue=True)
    qp, tiles = bgv.coefficient_inputs([0, 1, 1, 0, 1], [[0, 1, 1, 0, 1]], pk.n)
    index = [bgv.encrypt(tile, pk) for tile in tiles]
    device, host = gpu.prepare_index(index, 1), cpu.prepare_index(index, 1)
    for iteration in range(32):
        ct = bgv.encrypt(qp, pk)
        joint = iteration % 2 == 0
        assert gpu.search(ct, device, joint=joint) == cpu.search(ct, host, joint=joint)
