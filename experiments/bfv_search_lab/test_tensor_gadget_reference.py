"""Malformed complete follow-up traces and pre-evaluation public guards."""

from dataclasses import replace

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import tensor_gadget_reference as reference


@pytest.fixture(scope="module")
def fixture():
    pk, sk = bgv.key_gen(16, t=17, q_bits=120, eta=1)
    keys = {b: trace.evaluation_keys(pk, sk, 8, b) for b in (30, 14, 18)}
    qp, tiles = bgv.coefficient_inputs(
        [0, 1, 0, 1, 0], [[(i >> j) & 1 for j in range(5)] for i in range(8)], 16
    )
    return pk, keys, bgv.encrypt(qp, pk), [bgv.encrypt(p, pk) for p in tiles]


@pytest.mark.parametrize("rule,bits", [("mixed14", 14), ("tensor18", 18)])
@pytest.mark.parametrize(
    "fault", ["unused_output", "mutable_frame", "foreign_cut", "snapshot"]
)
def test_malformed_complete_relation_is_rejected_before_private_work(
    rule, bits, fault, fixture, monkeypatch
):
    pk, keys, query, index = fixture
    supplied = reference.make_trace(query, index, 8, 5, pk, keys[30], keys[bits], rule)
    if fault == "unused_output":
        pair = supplied.full_output[0]
        supplied = replace(
            supplied,
            full_output=(((*pair[0][:-1], (pair[0][-1] + 1) % int(pk.q)), pair[1]),),
        )
    elif fault == "mutable_frame":
        supplied = replace(supplied, response=bytearray(supplied.response))
    elif fault == "foreign_cut":
        supplied = replace(supplied, cuts=(object(), *supplied.cuts[1:]))
    else:
        poly = index[0].components[0]
        changed = (mpz((int(poly[0]) + 1) % int(pk.q)), *poly[1:])
        index = [
            replace(index[0], components=(changed, index[0].components[1])),
            *index[1:],
        ]
    calls = []
    monkeypatch.setattr(bgv, "decrypt", lambda *_: calls.append(True))
    monkeypatch.setattr(compact, "decrypt", lambda *_: calls.append(True))
    assert not reference.check_trace(
        query, index, 8, 5, pk, keys[30], keys[bits], rule, supplied
    )
    assert not calls


@pytest.mark.parametrize("rule,bits", [("mixed14", 14), ("tensor18", 18)])
def test_unsafe_honest_phase_assumption_is_rejected_before_evaluator_work(
    rule, bits, fixture, monkeypatch
):
    pk, keys, query, index = fixture
    query = replace(query, phase_bound=int(pk.q // 3))
    calls = []
    monkeypatch.setattr(bgv, "multiply", lambda *_args, **_kwargs: calls.append(True))
    with pytest.raises(ValueError):
        reference.make_trace(query, index, 8, 5, pk, keys[30], keys[bits], rule)
    assert not calls
