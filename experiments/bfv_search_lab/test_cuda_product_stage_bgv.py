"""Direct RNS stage export: exact independent output, tails and native bounds."""

from concurrent.futures import ThreadPoolExecutor
import os
import struct

import pytest

from cuhepy.bfv.cuda import cuda_available
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab.checked_switch_bgv import Context
from experiments.bfv_search_lab.checked_product_bgv import ProductContext
from experiments.bfv_search_lab.native_check_bgv import NativeCheckArithmetic, NativeProductArithmetic
from experiments.bfv_search_lab.native_bgv import NativeServer


def prepare(n, batch):
    pytest.importorskip('experiments.bfv_search_lab._native._bgv_trace_cuda')
    if not cuda_available():
        if os.environ.get('CUHEPY_REQUIRE_BGV_CUDA') == '1':
            pytest.fail('CUDA required but unavailable')
        pytest.skip('CUDA required')
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 1)
    ctx = Context.from_bgv(pk, keys)
    query = bgv.encrypt([i % 2 for i in range(n)], pk)
    tiles = [bgv.encrypt([int((i+b) % 3 == 0) for i in range(n)], pk) for b in range(batch)]
    server = NativeServer(pk, keys, residue=True, device='cuda', cuda_level=4, ntt_variant='indexed')
    index = server.prepare_index(tiles, batch*n)
    state = ProductContext.prepare(ctx, ctx.pack_full([c.components for c in tiles], 2), batch, b'i'*32)
    native = NativeProductArithmetic(state, NativeCheckArithmetic(ctx))
    return ctx, state, native, server, index, query, ctx.pack_full([query.components], 2)


@pytest.mark.parametrize('n,batch', [(64, 1), (64, 7), (64, 8), (64, 9), (64, 64), (2048, 8), (16384, 8)])
def test_rns_product_export_equals_existing_cuda_and_native_recompute(n, batch):
    ctx, state, native, server, index, query, raw = prepare(n, batch)
    actual = server.product_switch_rns(raw, index)
    assert actual == ctx.pack_full([c.components for c in server.search(query, index)], 2)
    assert actual == native.evaluate(raw)[1]
    request = state.begin(raw, b'q'*32, mode='local', native=native)
    assert request.check_once(request.result_packet(actual)).accepted
    # Independent invocations share only immutable index/key data.
    if n == 64 and batch == 9:
        with ThreadPoolExecutor(max_workers=2) as pool:
            assert list(pool.map(lambda _: server.product_switch_rns(raw, index), range(4))) == [actual]*4


def test_rns_stage_input_context_shape_and_fork_guards(monkeypatch):
    ctx, _, _, server, index, query, raw = prepare(64, 3)
    for value in (b'', raw[:-8], raw+b'x', bytearray(raw), raw[:-8]+struct.pack('<Q', ctx.primes[1])):
        with pytest.raises(ValueError):
            server.product_switch_rns(value, index)
    other = NativeServer(server.pk, server.keys, residue=True, device='cuda', cuda_level=4)
    with pytest.raises(ValueError):
        other.product_switch_rns(raw, index)
    with pytest.raises(ValueError):
        other._native.product_switch_rns(other._server, raw, index.handle)
    for batch in (0, 65):
        invalid = server.prepare_index([query]*batch, batch*ctx.n)
        with pytest.raises(ValueError):
            server.product_switch_rns(raw, invalid)
    cpu = NativeServer(server.pk, server.keys, residue=True)
    with pytest.raises(ValueError):
        cpu.product_switch_rns(raw, index)
    with monkeypatch.context() as patch:
        patch.setattr('experiments.bfv_search_lab.native_bgv.os.getpid', lambda: server._creator_pid+1)
        with pytest.raises(RuntimeError):
            server.product_switch_rns(raw, index)
