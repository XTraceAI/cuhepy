"""Actual homemade GPU multiply/relinearize outputs checked from trusted tensors."""

import os
import random

import pytest

from cuhepy.bfv.cuda import cuda_available
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab.checked_switch_bgv import Context
from experiments.bfv_search_lab.native_bgv import NativeServer


@pytest.mark.parametrize('n', [64, 2048, 16384])
def test_existing_cuda_relinearization_and_stage_checker(n):
    pytest.importorskip('experiments.bfv_search_lab._native._bgv_trace_cuda')
    if not cuda_available():
        if os.environ.get('CUHEPY_REQUIRE_BGV_CUDA') == '1':
            pytest.fail('CUDA required but unavailable')
        pytest.skip('CUDA required')
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 1)  # No monomial shift/trace after relin.
    context = Context.from_bgv(pk, keys)
    rng = random.Random(n+2928)
    query = bgv.encrypt([rng.randrange(2) for _ in range(n)], pk)
    tiles = [bgv.encrypt([rng.randrange(2) for _ in range(n)], pk) for _ in range(3)]
    # This trusted tensor construction is an explicit prerequisite, not a
    # claim that checking only relin establishes the preceding GPU product.
    tensors = [bgv.multiply(query, tile, pk, karatsuba=True) for tile in tiles]
    raw = context.pack_full([t.components for t in tensors], 3)
    request = context.begin(raw, len(tiles), b'c'*32)
    gpu = NativeServer(pk, keys, residue=True, device='cuda', cuda_level=4, ntt_variant='indexed')
    result = gpu.search(query, gpu.prepare_index(tiles, len(tiles)*n))
    assert request.check_once(request.result_packet([c.components for c in result])).accepted
    for tensor, actual in zip(tensors, result, strict=True):
        assert bgv.decrypt(tensor, pk, sk) == bgv.decrypt(actual, pk, sk)
