"""Product native ABI, exact recomputation, large sums and witness coverage."""

import itertools
import struct

import pytest

from experiments.bfv_search_lab import checked_product_bgv as product
from experiments.bfv_search_lab.native_check_bgv import NativeCheckArithmetic, NativeProductArithmetic
from experiments.bfv_search_lab.test_checked_product_bgv import make, mutate
from experiments.bfv_search_lab.verification_oracles import batch_error_vanishes


@pytest.mark.parametrize('n,batch', [(8, 64), (64, 5)])
def test_large_fold_sums_and_every_witness_limb(n, batch, monkeypatch):
    pytest.importorskip('experiments.bfv_search_lab._verify._bgv_checked')
    ctx, state, query, witness, output, *_ = make(n, batch)
    native = NativeProductArithmetic(state, NativeCheckArithmetic(ctx))
    monkeypatch.setattr(product.secrets, 'randbelow', lambda p: p-1)
    assert native.evaluate(query, witness=True) == (witness, output)
    for mode, backend in itertools.product(('local', 'witness'), (None, native)):
        request = state.begin(query, b'q'*32, mode=mode, native=backend)
        assert request.check_once(request.result_packet(output, witness if mode == 'witness' else b'')).accepted
    for b, limb in itertools.product(range(batch), range(2)):
        request = state.begin(query, b'q'*32, native=native)
        bad = mutate(witness, 8*((b*2+limb)*n+n-1), ctx.primes[limb])
        assert not request.check_once(request.result_packet(output, bad)).accepted


def test_native_product_abi_and_arithmetic_only_weights():
    pytest.importorskip('experiments.bfv_search_lab._verify._bgv_checked')
    ctx, state, query, witness, output, *_ = make()
    arithmetic = NativeCheckArithmetic(ctx)
    native = NativeProductArithmetic(state, arithmetic)
    api, handle = native._native, native._handle
    weights = struct.pack('<18Q', *([1]*18))
    for count in (0, 65, -1, True, 1 << 80):
        with pytest.raises((ValueError, OverflowError)):
            api.product_create(arithmetic._handle, state.raw_index, count)
    for raw in (bytearray(state.raw_index), state.raw_index[:-8], struct.pack('<Q', ctx.primes[0])+state.raw_index[8:]):
        with pytest.raises(ValueError):
            api.product_create(arithmetic._handle, raw, 3)
    for wrong in (object(), arithmetic._handle):
        with pytest.raises(ValueError):
            api.product_evaluate(wrong, query, 0)
    for raw in (bytearray(query), query[:-8], struct.pack('<Q', ctx.primes[0])+query[8:]):
        with pytest.raises(ValueError):
            native.evaluate(raw)
    for mode in (-1, True, 2, 1 << 80):
        with pytest.raises((ValueError, OverflowError)):
            api.product_check(handle, query, witness, output, weights, mode)
    for w, out in ((witness[:-1], output), (bytearray(witness), output), (witness, bytearray(output)),
                   (witness, output[:-1]), (witness[:-8]+struct.pack('<Q', ctx.primes[1]), output)):
        with pytest.raises(ValueError):
            api.product_check(handle, query, w, out, weights, 0)
    for w in (b'', weights+b'x', struct.pack('<Q', ctx.primes[0])+weights[8:]):
        with pytest.raises(ValueError):
            api.product_check(handle, query, witness, output, w, 0)
    with pytest.raises(ValueError):
        api.product_validate(handle, witness, output, 1)
    with pytest.raises(ValueError):
        NativeProductArithmetic(state, NativeCheckArithmetic(make()[0]))
    with pytest.raises(ValueError):
        native.evaluate(query, witness=1)
    forged = mutate(output, 0, ctx.primes[0])
    for mode in ('witness', 'local'):
        # Public arithmetic helper is deliberately NOT a soundness interface.
        assert native.check_arithmetic(query, witness if mode == 'witness' else b'', forged, bytes(18*8), mode)


@pytest.mark.parametrize('p', [2, 3])
def test_joint_three_equation_error_matrix_soundness(p):
    weights = list(itertools.product(range(p), repeat=2))
    for error in itertools.product(range(p), repeat=6):
        rows = [list(error[:3]), list(error[3:])]
        nonzero = any(error)
        rank = 0 if not nonzero else 1
        if any((rows[0][i]*rows[1][j]-rows[0][j]*rows[1][i]) % p
               for i, j in itertools.combinations(range(3), 2)):
            rank = 2
        misses = sum(batch_error_vanishes(rows, list(w), p) for w in weights)
        assert misses == p**(2-rank)
        if nonzero:
            assert misses <= p
