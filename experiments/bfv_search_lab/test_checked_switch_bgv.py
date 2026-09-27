"""Checked-stage mutation/lifecycle tests and independent coefficient arithmetic."""

from concurrent.futures import ThreadPoolExecutor
import copy
import itertools
import os
import pickle
import random
import struct

import pytest

from experiments.bfv_search_lab import checked_switch_bgv as check
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab.verification_oracles import batch_error_vanishes


def schoolbook(a, b, q):
    out = [0]*len(a)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[(i+j) % len(a)] += x*y*(-1 if i+j >= len(a) else 1)
    return tuple(x % q for x in out)


@pytest.fixture(params=[False, True], ids=["reference", "native"])
def fixture(request):
    pk, sk = bgv.key_gen(8, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 1)
    context = check.Context.from_bgv(pk, keys)
    rng = random.Random(928)
    tensors = [tuple(tuple(rng.randrange(int(pk.q)) for _ in range(pk.n)) for _ in range(3)) for _ in range(3)]
    tensors[0] = (tuple([0]*8), tuple([int(pk.q)-1]*8), tuple([int(pk.q)-1]*8))
    outputs = []
    for tensor in tensors:
        pair = []
        for k in range(2):
            poly = list(tensor[k])
            for j in range(4):
                digit = [(c >> (30*j)) & ((1 << 30)-1) for c in tensor[2]]
                product = schoolbook(digit, keys.relin[j][k], int(pk.q))
                poly = [(a+b) % int(pk.q) for a, b in zip(poly, product, strict=True)]
            pair.append(tuple(poly))
        outputs.append(tuple(pair))
    native = None
    if request.param:
        pytest.importorskip("experiments.bfv_search_lab._verify._bgv_checked")
        from experiments.bfv_search_lab.native_check_bgv import NativeCheckArithmetic
        native = NativeCheckArithmetic(context)
    return context, context.pack_full(tensors, 3), outputs, native


def begin(fixture, binding=b'b'*32):
    context, raw, outputs, native = fixture
    request = context.begin(raw, len(outputs), binding, native=native)
    return request, request.result_packet(outputs)


def test_complete_relation_against_independent_schoolbook(fixture):
    request, packet = begin(fixture)
    result = request.check_once(packet)
    assert result.accepted
    assert result.statement_digest == request.statement_digest
    assert result.phase_seconds['total_s'] >= sum(v for k, v in result.phase_seconds.items() if k != 'total_s')
    with pytest.raises(RuntimeError):
        request.check_once(packet)


@pytest.mark.parametrize('batch,component,limb', itertools.product(range(3), range(2), range(2)))
def test_every_output_item_component_limb_is_checked(fixture, monkeypatch, batch, component, limb):
    request, packet = begin(fixture)
    ctx = fixture[0]
    at = len(check.TAG)+32+8*((batch*4+component*2+limb)*ctx.n+ctx.n-1)
    value = struct.unpack_from('<Q', packet, at)[0]
    bad = packet[:at]+struct.pack('<Q', (value+1) % ctx.primes[limb])+packet[at+8:]
    # Deterministic nonzero test weights make single-position rejection exact.
    monkeypatch.setattr(check.secrets, 'randbelow', lambda p: 7)
    assert not request.check_once(bad).accepted
    with pytest.raises(RuntimeError):
        request.check_once(packet)


def test_reordering_and_different_trusted_tensor_are_rejected(fixture, monkeypatch):
    numbers = itertools.count(1)
    monkeypatch.setattr(check.secrets, 'randbelow', lambda p: next(numbers) % p)
    request, _ = begin(fixture)
    assert not request.check_once(request.result_packet(list(reversed(fixture[2])))).accepted
    ctx, raw, outputs, native = fixture
    first = struct.unpack_from('<Q', raw)[0]
    changed = struct.pack('<Q', (first+1) % ctx.primes[0])+raw[8:]
    other = ctx.begin(changed, 3, b'b'*32, native=native)
    assert not other.check_once(other.result_packet(outputs)).accepted


def test_header_context_parent_and_nonce_are_bound(fixture):
    a, packet = begin(fixture)
    b, _ = begin(fixture)
    c, _ = begin(fixture, b'c'*32)
    for request in (b, c):
        with pytest.raises(ValueError):
            request.check_once(packet)
        with pytest.raises(RuntimeError):
            request.check_once(request.result_packet(fixture[2]))
    assert a.check_once(packet).accepted


def test_last_coefficient_validated_before_sampling_and_attempt_spent(fixture, monkeypatch):
    request, packet = begin(fixture)
    def forbidden(_):
        raise AssertionError('Entropy must follow complete packet validation')
    monkeypatch.setattr(check.secrets, 'randbelow', forbidden)
    bad = packet[:-8]+struct.pack('<Q', fixture[0].primes[1])
    with pytest.raises(ValueError):
        request.check_once(bad)
    with pytest.raises(RuntimeError):
        request.check_once(packet)


@pytest.mark.parametrize('mutation', [lambda p: p[:-1], lambda p: p+b'\0', bytearray, lambda p: b'x'+p[1:]])
def test_wire_aliases_rejected_and_consumed(fixture, mutation):
    request, packet = begin(fixture)
    with pytest.raises(ValueError):
        request.check_once(mutation(packet))
    with pytest.raises(RuntimeError):
        request.check_once(packet)


def test_entropy_failure_copy_pickle_fork_and_concurrent_reuse(fixture, monkeypatch):
    request, packet = begin(fixture)
    for function in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            function(request)
    with monkeypatch.context() as patch:
        patch.setattr(check.os, 'getpid', lambda: request._pid+1)
        with pytest.raises(RuntimeError):
            request.check_once(packet)
    assert os.getpid() == request._pid
    def attempt(_):
        try:
            return request.check_once(packet).accepted
        except RuntimeError:
            return 'spent'
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(map(str, pool.map(attempt, range(2)))) == ['True', 'spent']
    fresh, packet = begin(fixture)
    def fail(_):
        raise OSError('entropy unavailable')
    monkeypatch.setattr(check.secrets, 'randbelow', fail)
    with pytest.raises(OSError):
        fresh.check_once(packet)
    with pytest.raises(RuntimeError):
        fresh.check_once(packet)


def test_canonical_input_snapshot_and_declared_shape(fixture):
    ctx, raw, outputs, native = fixture
    for value in (raw[:-8], bytearray(raw), struct.pack('<Q', ctx.primes[0])+raw[8:]):
        with pytest.raises(ValueError):
            ctx.begin(value, 3, b'b'*32, native=native)
    for batch in (True, 0, 65):
        with pytest.raises(ValueError):
            ctx.begin(raw, batch, b'b'*32, native=native)
    with pytest.raises(ValueError):
        ctx.begin(raw, 3, b'b', native=native)
    request = ctx.begin(raw, 3, b'b'*32, native=native)
    with pytest.raises(ValueError):
        request.result_packet(outputs[:2])


@pytest.mark.parametrize('p', [2, 3, 5])
def test_exhaustive_batch_soundness_equals_p_to_minus_rank(p):
    weights = list(itertools.product(range(p), repeat=2))
    for a, b, c, d in itertools.product(range(p), repeat=4):
        error = [[a, b], [c, d]]
        rank = 0 if not any((a, b, c, d)) else 1 if (a*d-b*c) % p == 0 else 2
        misses = sum(batch_error_vanishes(error, list(w), p) for w in weights)
        assert misses == p**(2-rank)
        if rank:
            assert misses <= p  # Three independent checks have miss <= p^-3.


def test_equal_weights_and_decompose_after_folding_are_not_valid_shortcuts():
    errors = [[1, 0], [4, 0]]
    assert batch_error_vanishes(errors, [1, 1], 5)
    assert not batch_error_vanishes(errors, [1, 2], 5)
    base = 1 << 30
    separately = ((base-1)+1, 0+0)
    after_sum = (base % base, base//base)
    assert separately != after_sum
