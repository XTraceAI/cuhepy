"""Complete residual relation is checked without an HE expected-response oracle."""

from dataclasses import replace

import pytest

from experiments.bfv_search_lab import noise_cut_planner as planner
from experiments.bfv_search_lab import noise_cut_reference as reference
from experiments.bfv_search_lab import noise_cut_relation as relation
from experiments.bfv_search_lab import propagated_gadget_bgv as gadget
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


@pytest.fixture(scope="module")
def fixture():
    pk, sk = bgv.key_gen(16, t=17, q_bits=120, eta=1)
    keys = {b: trace.evaluation_keys(pk, sk, 8, b) for b in (14, 18, 30)}
    qp, tiles = bgv.coefficient_inputs(
        [0, 1, 0, 1, 0], [[(i >> j) & 1 for j in range(5)] for i in range(10)], 16
    )
    query, index = bgv.encrypt(qp, pk), [bgv.encrypt(p, pk) for p in tiles]
    cases = {}
    for bits, seeded in ((14, False), (18, True), (30, False)):
        contexts = reference.profiles(query, index, 10, 5, pk, keys[30], keys[bits])
        plans = tuple(
            planner.select(planner.frontier(p, 5, seeded)[0]).plan for p in contexts
        )
        supplied = reference.make_trace(
            query, index, 10, 5, pk, keys[30], keys[bits], plans
        )
        sources = tuple(
            relation.Source(c.group, c.level, c.node, c.source)
            for c in supplied.cuts
            if c.kind.startswith("canonical")
        )
        compiled = relation.compile_relation(
            query, index, 10, 5, pk, keys[30], keys[bits], plans
        )
        cases[bits] = compiled, sources, supplied.full_output, plans, supplied
    return pk, keys, query, index, cases


@pytest.mark.parametrize("bits", [14, 18, 30])
def test_complete_relation_covers_tensor_sources_and_all_output_coordinates(
    bits, fixture
):
    _pk, _keys, _query, _index, cases = fixture
    compiled, sources, outputs, _plans, supplied = cases[bits]
    assert relation.holds(compiled, sources, outputs)
    assert len(compiled.residuals) == len(sources) + 2 * len(outputs)
    assert len(sources) == sum(c.kind.startswith("canonical") for c in supplied.cuts)


def test_compilation_and_checking_do_not_call_HE_replay_or_private_work(
    fixture, monkeypatch
):
    pk, keys, query, index, cases = fixture
    _old, sources, outputs, plans, _supplied = cases[14]

    def forbidden(*_args, **_kwargs):
        pytest.fail("No HE evaluator, expected-response or private oracle permitted")

    for module, name in (
        (bgv, "multiply"),
        (bgv, "decrypt"),
        (gadget, "make_trace"),
        (gadget, "switched"),
        (gadget, "integer_product"),
        (reference, "make_trace"),
    ):
        monkeypatch.setattr(module, name, forbidden)
    compiled = relation.compile_relation(
        query, index, 10, 5, pk, keys[30], keys[14], plans
    )
    assert relation.holds(compiled, sources, outputs)


@pytest.mark.parametrize(
    "fault",
    [
        "product_source",
        "last_output",
        "missing",
        "duplicate",
        "reordered",
        "mutable_source",
        "noncanonical_source",
        "foreign_source",
        "mutable_outputs",
    ],
)
def test_every_source_and_full_output_is_bound(fault, fixture):
    pk, _keys, _query, _index, cases = fixture
    compiled, sources, outputs, _plans, _supplied = cases[14]
    if fault in ("product_source", "noncanonical_source"):
        z = sources[0].polynomial
        first = (z[0] + 1) % int(pk.q) if fault == "product_source" else int(pk.q)
        sources = (replace(sources[0], polynomial=(first, *z[1:])), *sources[1:])
    elif fault == "last_output":
        pair = outputs[-1]
        outputs = (
            *outputs[:-1],
            ((*pair[0][:-1], (pair[0][-1] + 1) % int(pk.q)), pair[1]),
        )
    elif fault == "missing":
        sources = sources[:-1]
    elif fault == "duplicate":
        sources = (*sources[:-1], sources[0])
    elif fault == "reordered":
        sources = sources[::-1]
    elif fault == "mutable_source":
        sources = (
            replace(sources[0], polynomial=list(sources[0].polynomial)),
            *sources[1:],
        )
    elif fault == "foreign_source":
        sources = (object(), *sources[1:])
    else:
        outputs = list(outputs)
    assert not relation.holds(compiled, sources, outputs)


def test_unsafe_context_rejects_before_graph_creation(fixture, monkeypatch):
    pk, keys, query, index, cases = fixture
    plans = cases[14][3]
    calls = []
    monkeypatch.setattr(relation, "Builder", lambda *_: calls.append(True))
    with pytest.raises(ValueError, match="unsafe"):
        relation.compile_relation(
            replace(query, phase_bound=int(pk.q // 3)),
            index,
            10,
            5,
            pk,
            keys[30],
            keys[14],
            plans,
        )
    assert not calls
