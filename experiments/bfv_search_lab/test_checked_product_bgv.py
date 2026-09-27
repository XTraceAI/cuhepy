"""Independent product/switch truth, adversarial joins and one-use lifecycle."""

from concurrent.futures import ThreadPoolExecutor
import copy
import pickle
import random
import struct

import pytest

from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import checked_product_bgv as product
from experiments.bfv_search_lab.checked_switch_bgv import Context
from experiments.bfv_search_lab.native_check_bgv import NativeCheckArithmetic, NativeProductArithmetic
from experiments.bfv_search_lab.test_checked_switch_bgv import schoolbook


def make(n=8, batch=3):
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 1)
    ctx = Context.from_bgv(pk, keys)
    rng = random.Random(932)
    q = int(pk.q)
    query = tuple(tuple(rng.randrange(q) for _ in range(n)) for _ in range(2))
    tiles = [tuple(tuple(rng.randrange(q) for _ in range(n)) for _ in range(2)) for _ in range(batch)]
    # Canonical CRT extremes in the multiplication input.
    tiles[0] = ((q-1,)*n, (0,)*(n-1)+(q-1,))
    tensors, outputs = [], []
    for tile in tiles:
        tensor = (schoolbook(query[0], tile[0], q),
                  tuple((a+b) % q for a, b in zip(schoolbook(query[0], tile[1], q),
                        schoolbook(query[1], tile[0], q), strict=True)),
                  schoolbook(query[1], tile[1], q))
        tensors.append(tensor)
        output = []
        for k in range(2):
            y = tensor[k]
            for j in range(4):
                d = tuple((c >> (30*j)) & ((1 << 30)-1) for c in tensor[2])
                y = tuple((a+b) % q for a, b in zip(y, schoolbook(d, keys.relin[j][k], q), strict=True))
            output.append(y)
        outputs.append(tuple(output))
    raw_query, raw_index = ctx.pack_full([query], 2), ctx.pack_full(tiles, 2)
    state = product.ProductContext.prepare(ctx, raw_index, batch, b'i'*32)
    witness = b''.join(struct.pack(f'<{n}Q', *(int(c % p) for c in t[2])) for t in tensors for p in ctx.primes)
    return ctx, state, raw_query, witness, ctx.pack_full(outputs, 2), tensors, pk, keys


@pytest.fixture(params=[('reference', 'witness'), ('reference', 'local'), ('native', 'witness'), ('native', 'local')])
def case(request):
    data = make()
    backend, mode = request.param
    native = None
    if backend == 'native':
        pytest.importorskip('experiments.bfv_search_lab._verify._bgv_checked')
        native = NativeProductArithmetic(data[1], NativeCheckArithmetic(data[0]))
    return data, native, mode


def begin(case, *, binding=b'q'*32):
    data, native, mode = case
    request = data[1].begin(data[2], binding, mode=mode, native=native)
    return request, request.result_packet(data[4], data[3] if mode == 'witness' else b'')


def mutate(raw, at, p):
    value = struct.unpack_from('<Q', raw, at)[0]
    return raw[:at]+struct.pack('<Q', (value+1) % p)+raw[at+8:]


def test_complete_product_and_switch_against_independent_schoolbook(case):
    request, packet = begin(case)
    result = request.check_once(packet)
    assert result.accepted and result.statement_digest == request.statement_digest
    with pytest.raises(RuntimeError):
        request.check_once(packet)
    data, native, _ = case
    if native is not None:
        assert native.evaluate(data[2], witness=True) == (data[3], data[4])
        assert native.evaluate(data[2]) == (b'', data[4])


@pytest.mark.parametrize('batch,component,limb', [(b, k, limb) for b in range(3) for k in range(2) for limb in range(2)])
def test_every_output_batch_component_limb(case, monkeypatch, batch, component, limb):
    data, _, mode = case
    monkeypatch.setattr(product.secrets, 'randbelow', lambda p: 7)
    request, packet = begin(case)
    offset = len(product.TAG)+32+(len(data[3]) if mode == 'witness' else 0)
    at = offset+8*((batch*4+component*2+limb)*data[0].n+data[0].n-1)
    assert not request.check_once(mutate(packet, at, data[0].primes[limb])).accepted


def test_false_witness_and_correct_switch_cannot_bypass_product_check(case, monkeypatch):
    data, native, mode = case
    ctx, state, query, _, _, tensors, pk, keys = data
    monkeypatch.setattr(product.secrets, 'randbelow', lambda p: 7)
    changed = list(tensors)
    c0, c1, c2 = changed[0]
    changed[0] = (c0, c1, ((c2[0]+1) % int(pk.q),)+c2[1:])
    outputs = []
    for tensor in changed:
        switch = trace._switch(tensor[2], keys.relin, pk, 30)
        outputs.append(tuple(tuple((a+b) % pk.q for a, b in zip(tensor[k], switch[k], strict=True)) for k in range(2)))
    # A correct switch of the wrong tensor passes the old conditional stage.
    old = ctx.begin(ctx.pack_full(changed, 3), state.batch, b'o'*32)
    assert old.check_once(old.result_packet(outputs)).accepted
    witness = b''.join(struct.pack(f'<{ctx.n}Q', *(int(c % p) for c in t[2])) for t in changed for p in ctx.primes)
    request = state.begin(query, b'q'*32, mode=mode, native=native)
    packet = request.result_packet(ctx.pack_full(outputs, 2), witness if mode == 'witness' else b'')
    assert not request.check_once(packet).accepted


def test_wrong_query_index_order_and_index_epoch_are_bound(case, monkeypatch):
    data, native, mode = case
    ctx, state, query, witness, output, *_ = data
    monkeypatch.setattr(product.secrets, 'randbelow', lambda p: 7)
    request = state.begin(mutate(query, 0, ctx.primes[0]), b'q'*32, mode=mode, native=native)
    assert not request.check_once(request.result_packet(output, witness if mode == 'witness' else b'')).accepted
    # Rewrap under the NEW valid digest: rejection must also check arithmetic.
    width = ctx.n*4*8
    swapped = state.raw_index[width:2*width]+state.raw_index[:width]+state.raw_index[2*width:]
    for raw in (swapped, mutate(state.raw_index, 0, ctx.primes[0])):
        other = product.ProductContext.prepare(ctx, raw, state.batch, b'i'*32)
        backend = NativeProductArithmetic(other, native.arithmetic) if native else None
        request = other.begin(query, b'q'*32, mode=mode, native=backend)
        # Unequal test weights prevent the known all-one permutation alias.
        values = iter(range(1, 1+2*product.CHECKS*state.batch))
        monkeypatch.setattr(product.secrets, 'randbelow', lambda p, values=values: next(values))
        assert not request.check_once(request.result_packet(output, witness if mode == 'witness' else b'')).accepted
    request, packet = begin(case)
    epoch = product.ProductContext.prepare(ctx, state.raw_index, state.batch, b'e'*32)
    other = epoch.begin(query, b'q'*32, mode=mode)
    with pytest.raises(ValueError):
        other.check_once(packet)
    assert request.statement_digest != other.statement_digest


@pytest.mark.parametrize('part', ['output', 'witness'])
def test_validate_all_bytes_before_entropy_and_consume_failures(case, monkeypatch, part):
    data, _, mode = case
    request, packet = begin(case)
    if part == 'witness' and mode == 'local':
        bad = packet+b'x'
    else:
        at = len(packet)-8 if part == 'output' else len(product.TAG)+32+len(data[3])-8
        bad = packet[:at]+struct.pack('<Q', data[0].primes[1])+packet[at+8:]
    def fail(_):
        raise AssertionError('Invalid residue reached challenge generation')
    monkeypatch.setattr(product.secrets, 'randbelow', fail)
    with pytest.raises(ValueError):
        request.check_once(bad)
    with pytest.raises(RuntimeError):
        request.check_once(packet)


def test_one_use_binding_concurrency_copy_fork_entropy_and_packet_grammar(case, monkeypatch):
    first, packet = begin(case)
    for fn in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            fn(first)
    with monkeypatch.context() as patch:
        patch.setattr(product.os, 'getpid', lambda: first._pid+1)
        with pytest.raises(RuntimeError):
            first.check_once(packet)
    def attempt(_):
        try:
            return first.check_once(packet).accepted
        except RuntimeError:
            return 'spent'
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(map(str, pool.map(attempt, range(2)))) == ['True', 'spent']
    for mutation in (lambda p: p[:-1], lambda p: p+b'x', bytearray, lambda p: b'x'+p[1:]):
        req, raw = begin(case)
        with pytest.raises(ValueError):
            req.check_once(mutation(raw))
        with pytest.raises(RuntimeError):
            req.check_once(raw)
    for binding in (b'q'*32, b'r'*32):
        other, _ = begin(case, binding=binding)
        with pytest.raises(ValueError):
            other.check_once(packet)
    req, raw = begin(case)
    def unavailable(_):
        raise OSError('no entropy')
    monkeypatch.setattr(product.secrets, 'randbelow', unavailable)
    with pytest.raises(OSError):
        req.check_once(raw)
    with pytest.raises(RuntimeError):
        req.check_once(raw)


def test_input_grammar_and_context_refuse_aliases(case):
    data, native, mode = case
    ctx, state, query, *_ = data
    for raw in (query[:-8], bytearray(query), struct.pack('<Q', ctx.primes[0])+query[8:]):
        with pytest.raises(ValueError):
            state.begin(raw, b'q'*32, mode=mode, native=native)
    for bad_mode in (False, [], 'bogus'):
        with pytest.raises(ValueError):
            state.begin(query, b'q'*32, mode=bad_mode, native=native)
    for batch in (0, 65, True):
        with pytest.raises(ValueError):
            product.ProductContext.prepare(ctx, state.raw_index, batch, b'i'*32)
    with pytest.raises(ValueError):
        product.ProductContext.prepare(ctx, state.raw_index, 3, bytearray(b'i'*32))
    if native:
        other = product.ProductContext.prepare(ctx, state.raw_index, 3, b'o'*32)
        with pytest.raises(ValueError):
            other.begin(query, b'q'*32, mode=mode, native=native)
