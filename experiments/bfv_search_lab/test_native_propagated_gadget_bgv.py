"""Whole-output native/reference equality and bounded public boundary faults."""

from dataclasses import replace
import os
import random

import pytest

from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import native_propagated_gadget_bgv as native
from experiments.bfv_search_lab import propagated_gadget_bgv as propagated
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


@pytest.fixture(scope="module")
def backend():
    path = os.environ.get("CUHEPY_GADGET_BACKEND")
    if not path:
        pytest.skip("Set CUHEPY_GADGET_BACKEND to an explicit isolated prototype")
    return native.load_backend(path)


@pytest.mark.parametrize("n,dimension,t", [(8, 3, 17), (16, 5, 17), (32, 9, 37)])
def test_entire_native_Q_and_compact_frames_equal_public_reference(
    n, dimension, t, backend
):
    pk, sk = bgv.key_gen(n, t=t, q_bits=120, eta=1, rns_modulus=True)
    padded = 1 << (dimension - 1).bit_length()
    keys = trace.evaluation_keys(pk, sk, padded, digit_bits=30)
    rng = random.Random(64067 + n)
    rows = [[rng.randrange(2) for _ in range(dimension)] for _ in range(n + 1)]
    query = [rng.randrange(2) for _ in range(dimension)]
    qp, tiles = bgv.coefficient_inputs(query, rows, n)
    request, index = bgv.encrypt(qp, pk), [bgv.encrypt(p, pk) for p in tiles]
    for propagate in (False, True):
        plan = native.NativePlan(pk, keys, backend, propagate=propagate)
        for count in (n // 2, n, n + 1):
            chosen = index[: (count + n // padded - 1) // (n // padded)]
            prepared = plan.prepare(chosen, count)
            expected = propagated.make_trace(
                request,
                chosen,
                count,
                dimension,
                pk,
                keys,
                propagate=propagate,
                terminal_bits=16,
            )
            actual = plan.search(request, prepared, terminal_bits=16)
            assert (
                tuple(tuple(tuple(map(int, p)) for p in c.components) for c in actual)
                == expected.full_output
            )
            assert (
                compact.pack(
                    [compact.compact(c, pk, 16) for c in actual], count, dimension, pk
                )
                == expected.response
            )
            # Private diagnostic follows full public whole-Q/frame equality.
            plains = [bgv.decrypt(c, pk, sk) for c in actual]
            assert trace.decode(plains, count, dimension, pk) == [
                sum(a != b for a, b in zip(query, row, strict=True))
                for row in rows[:count]
            ]


@pytest.fixture(scope="module")
def plans(backend):
    pk, sk = bgv.key_gen(8, t=17, q_bits=120, eta=1, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 4, digit_bits=30)
    a, b = native.NativePlan(pk, keys, backend), native.NativePlan(pk, keys, backend)
    ct = bgv.encrypt([0] * 8, pk)
    return a, b, ct, a.prepare([ct], 1)


@pytest.mark.parametrize(
    "fault", ["shape", "noncanonical", "mutable", "mixed_context", "unsafe_bound"]
)
def test_native_boundary_and_public_guard_reject_faults(fault, plans):
    a, b, ct, index = plans
    pair = tuple(native.fixed(p, 8, int(a.pk.q)) for p in ct.components)
    if fault == "mixed_context":
        with pytest.raises(ValueError, match="Mixed"):
            b.search(ct, index, terminal_bits=16)
    elif fault == "unsafe_bound":
        with pytest.raises(ValueError, match="guard"):
            a.search(replace(ct, phase_bound=int(a.pk.q // 4)), index, terminal_bits=16)
    else:
        if fault == "shape":
            pair = (pair[0][:-1], pair[1])
        elif fault == "noncanonical":
            pair = (int(a.pk.q).to_bytes(15, "little") + pair[0][15:], pair[1])
        else:
            pair = (bytearray(pair[0]), pair[1])
        with pytest.raises(ValueError):
            a.backend.search(a.handle, pair, index.handle)


def test_shared_public_H_and_pair_digit_state_are_charged(plans):
    a, _, _, _ = plans
    assert a.backend.state_sizes(a.handle) == (4 * 2 * 2 * 8 * 8, 2 * 4 * 2 * 8 * 8)
