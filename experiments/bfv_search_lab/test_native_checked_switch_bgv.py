"""Native exact arithmetic, accumulator limits and low-level input boundary."""

from dataclasses import replace
import random
import struct

import pytest

from experiments.bfv_search_lab import checked_switch_bgv as checker
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab.native_check_bgv import NativeCheckArithmetic


def make(n, batch):
    pytest.importorskip('experiments.bfv_search_lab._verify._bgv_checked')
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 1)
    ctx = checker.Context.from_bgv(pk, keys)
    native = NativeCheckArithmetic(ctx)
    rng = random.Random(17)
    inputs, outputs = [], []
    for _ in range(batch):
        tensor = [tuple(rng.randrange(int(pk.q)) for _ in range(n)) for _ in range(3)]
        tensor[2] = tuple(int(pk.q)-1 if i % 3 == 0 else 0 if i % 3 == 1 else c for i, c in enumerate(tensor[2]))
        switched = trace._switch(tensor[2], keys.relin, pk, 30)
        inputs.append(tensor)
        outputs.append(tuple(tuple((a+b) % pk.q for a, b in zip(tensor[k], switched[k], strict=True)) for k in range(2)))
    return ctx, native, ctx.pack_full(inputs, 3), outputs


@pytest.mark.parametrize('n,batch', [(8, 64), (128, 5), (2048, 3)])
def test_maximum_weights_canonical_crt_and_native_reference_agreement(n, batch, monkeypatch):
    ctx, native, raw, outputs = make(n, batch)
    monkeypatch.setattr(checker.secrets, 'randbelow', lambda p: p-1)
    for backend in (None, native):
        request = ctx.begin(raw, batch, b'b'*32, native=backend)
        assert request.check_once(request.result_packet(outputs)).accepted
        request = ctx.begin(raw, batch, b'b'*32, native=backend)
        packet = request.result_packet(outputs)
        v = struct.unpack_from('<Q', packet, len(packet)-8)[0]
        packet = packet[:-8]+struct.pack('<Q', (v+1) % ctx.primes[1])
        assert not request.check_once(packet).accepted


def test_native_boundary_rejects_shapes_aliases_contexts_and_weights():
    ctx, native, raw, outputs = make(8, 3)
    api, handle = native._native, native._handle
    result = ctx.pack_full(outputs, 2)
    weights = struct.pack('<18Q', *([1]*18))
    for value in (None, bytearray(raw), raw[:-1], raw+b'x'):
        with pytest.raises((TypeError, ValueError)):
            native.validate(value, 3, 3)
    for batch in (0, True, 65, -1, 1 << 80):
        with pytest.raises((ValueError, OverflowError)):
            native.validate(raw, batch, 3)
    for data in (b'', weights+b'x', struct.pack('<Q', ctx.primes[0])+weights[8:]):
        with pytest.raises(ValueError):
            native.check_arithmetic(raw, result, data, 3)
    with pytest.raises(ValueError):
        api.validate(object(), raw, 3, 3)
    with pytest.raises(ValueError):
        native.check_arithmetic(raw, result[:-8]+struct.pack('<Q', ctx.primes[1]), weights, 3)
    with pytest.raises(ValueError):
        ctx.begin(raw, 3, b'b'*32, native=NativeCheckArithmetic(replace(ctx)))
    with pytest.raises(ValueError):
        NativeCheckArithmetic(replace(ctx, primes=tuple(reversed(ctx.primes))))
    assert api.primes(handle) == ctx.primes
    key = b''.join(struct.pack(f'<{ctx.n}Q', *poly) for limb in ctx.key for column in limb for poly in column)
    for n in (0, 4, 7, 16385, True, 1 << 80):
        with pytest.raises((ValueError, OverflowError)):
            api.create(n, key)
    for raw_key in (bytearray(key), key[:-8], key+b'x', struct.pack('<Q', ctx.primes[0])+key[8:]):
        with pytest.raises(ValueError):
            api.create(ctx.n, raw_key)


def test_direct_zero_weight_identity_is_not_an_authorization_api():
    ctx, native, raw, outputs = make(8, 3)
    result = ctx.pack_full(outputs, 2)
    forged = result[:-8]+struct.pack('<Q', (struct.unpack_from('<Q', result, len(result)-8)[0]+1) % ctx.primes[1])
    # The native primitive deliberately takes trusted weights. Allowing an
    # attacker to supply those weights would make its bool meaningless.
    assert native.check_arithmetic(raw, forged, bytes(18*8), 3)
