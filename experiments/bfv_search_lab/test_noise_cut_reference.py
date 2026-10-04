"""Complete per-node replay, with rejection before private diagnostics."""

from dataclasses import replace

from gmpy2 import mpz
import pytest

from benchmarks.propagated_gadget_encrypted_lab import frame_decrypt, physical_decrypt
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import noise_cut_planner as planner
from experiments.bfv_search_lab import noise_cut_reference as reference
from experiments.bfv_search_lab import propagated_gadget_bgv as gadget
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


@pytest.fixture(scope="module")
def fixture():
    pk, sk = bgv.key_gen(16, t=17, q_bits=120, eta=1)
    keys = {bits: trace.evaluation_keys(pk, sk, 8, bits) for bits in (14, 18, 30)}
    query_plain = [0, 1, 0, 1, 0]
    rows = [[(i >> j) & 1 for j in range(5)] for i in range(10)]
    qp, tiles = bgv.coefficient_inputs(query_plain, rows, 16)
    return (
        pk,
        sk,
        keys,
        bgv.encrypt(qp, pk),
        [bgv.encrypt(p, pk) for p in tiles],
        query_plain,
        rows,
    )


def selected(pk, keys, query, index, bits, seeded):
    contexts = reference.profiles(query, index, 10, 5, pk, keys[30], keys[bits])
    return tuple(
        planner.select(planner.frontier(p, len(index), seeded)[0]).plan
        for p in contexts
    )


@pytest.mark.parametrize("bits", [14, 18, 30])
@pytest.mark.parametrize("seeded", [False, True])
def test_half_plus_one_per_node_plaintexts_match_canonical_and_truth(
    bits, seeded, fixture
):
    pk, sk, keys, query, index, qp, rows = fixture
    plans = selected(pk, keys, query, index, bits, seeded)
    supplied = reference.make_trace(
        query, index, 10, 5, pk, keys[30], keys[bits], plans
    )
    assert reference.check_trace(
        query, index, 10, 5, pk, keys[30], keys[bits], plans, supplied
    )
    canonical = gadget.make_trace(query, index, 10, 5, pk, keys[30], propagate=False)
    assert gadget.check_trace(
        query, index, 10, 5, pk, keys[30], canonical, propagate=False
    )
    plain = physical_decrypt(supplied, pk, sk)
    assert (
        plain == frame_decrypt(supplied, pk, sk) == physical_decrypt(canonical, pk, sk)
    )
    assert trace.decode(plain, 10, 5, pk) == [
        sum(a != b for a, b in zip(qp, row, strict=True)) for row in rows
    ]
    if bits == 14 and not seeded:
        assert any(c.kind == "derived14" for c in supplied.cuts)


@pytest.mark.parametrize(
    "fault",
    [
        "unused_Q_coordinate",
        "frame",
        "foreign_cut",
        "mutable_frame",
        "mutable_bound",
        "plan",
        "snapshot",
        "query",
        "foreign_child",
        "key_schedule",
    ],
)
def test_malformed_context_or_relation_never_invokes_private_work(
    fault, fixture, monkeypatch
):
    pk, _sk, keys, query, index, _qp, _rows = fixture
    plans = selected(pk, keys, query, index, 14, False)
    supplied = reference.make_trace(query, index, 10, 5, pk, keys[30], keys[14], plans)
    rotations = keys[14]
    if fault == "unused_Q_coordinate":
        pair = supplied.full_output[0]
        supplied = replace(
            supplied,
            full_output=(((*pair[0][:-1], (pair[0][-1] + 1) % int(pk.q)), pair[1]),),
        )
    elif fault == "frame":
        supplied = replace(
            supplied,
            response=supplied.response[:-1] + bytes([supplied.response[-1] ^ 1]),
        )
    elif fault == "foreign_cut":
        supplied = replace(supplied, cuts=(object(), *supplied.cuts[1:]))
    elif fault == "mutable_frame":
        supplied = replace(supplied, response=bytearray(supplied.response))
    elif fault == "mutable_bound":
        supplied = replace(supplied, bounds=list(supplied.bounds))
    elif fault == "plan":
        plans = (replace(plans[0], count=plans[0].count + 1),)
    elif fault in ("snapshot", "query"):
        old = query if fault == "query" else index[0]
        c0 = old.components[0]
        changed = replace(
            old,
            components=(
                (mpz((int(c0[0]) + 1) % int(pk.q)), *c0[1:]),
                old.components[1],
            ),
        )
        if fault == "query":
            query = changed
        else:
            index = [changed, *index[1:]]
    elif fault == "foreign_child":
        plans = (replace(plans[0], left=object()),)
    else:
        rotations = replace(rotations, rotations=rotations.rotations[::-1])
    calls = []
    monkeypatch.setattr(bgv, "decrypt", lambda *_: calls.append(True))
    monkeypatch.setattr(compact, "decrypt", lambda *_: calls.append(True))
    assert not reference.check_trace(
        query, index, 10, 5, pk, keys[30], rotations, plans, supplied
    )
    assert not calls


def test_unsafe_trusted_phase_guard_runs_before_any_evaluation(fixture, monkeypatch):
    pk, _sk, keys, query, index, _qp, _rows = fixture
    plans = selected(pk, keys, query, index, 14, False)
    query = replace(query, phase_bound=int(pk.q // 3))
    calls = []
    monkeypatch.setattr(bgv, "multiply", lambda *_args, **_kwargs: calls.append(True))
    with pytest.raises(ValueError, match="Unsafe"):
        reference.make_trace(query, index, 10, 5, pk, keys[30], keys[14], plans)
    assert not calls
