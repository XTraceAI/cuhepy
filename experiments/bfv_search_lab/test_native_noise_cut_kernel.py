"""Exact complete two-prime native residuals, with no release authority."""

from dataclasses import replace
import copy
import os
import pickle

import pytest

from benchmarks.noise_cut_relation_lab import opaque
from experiments.bfv_search_lab import native_noise_cut_kernel as native
from experiments.bfv_search_lab import noise_cut_fusion as fusion
from experiments.bfv_search_lab import noise_cut_reference as reference
from experiments.bfv_search_lab import noise_cut_relation as relation
from experiments.bfv_search_lab import noise_cut_shape as shape
from experiments.bfv_search_lab import propagated_gadget_bgv as gadget
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


@pytest.fixture(scope="module", params=[native.Kernel, native.WireKernel])
def native_case(request):
    path = os.getenv("CUHEPY_NOISE_CUT_KERNEL")
    if not path:
        pytest.skip("Explicit isolated native kernel is required")
    backend = native.load_backend(path)
    if request.param is native.WireKernel and not hasattr(
        backend, "cuhepy_noise_cut_create_wire"
    ):
        pytest.skip("Explicit isolated native wire kernel is required")
    pk, sk = bgv.key_gen(8, t=11, q_bits=120, eta=1, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 4, 30)
    qp, tiles = bgv.coefficient_inputs(
        [0, 1, 0], [[(i >> j) & 1 for j in range(3)] for i in range(6)], 8
    )
    query, index = bgv.encrypt(qp, pk), [bgv.encrypt(p, pk) for p in tiles]
    profiles = reference.profiles(query, index, 6, 3, pk, keys, keys)
    plans = (opaque(1, 3),)
    supplied = reference.make_trace(query, index, 6, 3, pk, keys, keys, plans)
    statement = relation.compile_relation(query, index, 6, 3, pk, keys, keys, plans)
    template = shape.compile_shape(
        profiles, plans, local_boundaries=True, paired_kernels=True
    )
    public = shape.concrete_constants(template, index, keys, {30: keys}, int(pk.q))
    graph = fusion.fuse(
        template.graph, fusion.Limits(64, 4096, 3, 400_000, 12_000_000)
    ).graph
    kernel = request.param.prepare(statement, graph, public, backend)
    sources = tuple(
        relation.Source(c.group, c.level, c.node, c.source)
        for c in supplied.cuts
        if c.kind.startswith("canonical")
    )
    return kernel, statement, sources, supplied.full_output, public, backend


def test_native_complete_residual_vectors_equal_schoolbook_in_both_actual_primes(
    native_case,
):
    kernel, statement, sources, outputs, _public, _backend = native_case
    assert kernel.holds(sources, outputs)
    expected = relation.residuals(statement, sources, outputs)
    assert kernel.residuals(sources, outputs) == tuple(
        tuple(tuple(x % p for x in row) for p in kernel.primes) for row in expected
    )
    assert kernel.primes[0] * kernel.primes[1] == statement.q


@pytest.mark.parametrize(
    "fault",
    [
        "product",
        "last_output",
        "missing",
        "duplicate",
        "reordered",
        "mutable",
        "noncanonical",
        "last_malformed",
    ],
)
def test_native_adapter_rejects_complete_source_or_output_fault(fault, native_case):
    kernel, _statement, sources, outputs, _public, _backend = native_case
    q = kernel.graph.q
    if fault in ("product", "noncanonical"):
        row = sources[0].polynomial
        value = (row[0] + 1) % q if fault == "product" else q
        sources = (replace(sources[0], polynomial=(value, *row[1:])), *sources[1:])
    elif fault == "last_output":
        pair = outputs[-1]
        outputs = (*outputs[:-1], ((*pair[0][:-1], (pair[0][-1] + 1) % q), pair[1]))
    elif fault == "missing":
        sources = sources[:-1]
    elif fault == "duplicate":
        sources = (*sources[:-1], sources[0])
    elif fault == "reordered":
        sources = sources[::-1]
    elif fault == "mutable":
        sources = list(sources)
    else:
        pair = outputs[-1]
        outputs = (*outputs[:-1], (pair[0], (*pair[1][:-1], q)))
    assert not kernel.holds(sources, outputs)


def test_one_limb_only_forgery_does_not_pass(native_case):
    kernel, _statement, sources, outputs, _public, _backend = native_case
    pair = outputs[-1]
    outputs = (
        *outputs[:-1],
        ((*pair[0][:-1], (pair[0][-1] + kernel.primes[0]) % kernel.graph.q), pair[1]),
    )
    residuals = kernel.residuals(sources, outputs)
    assert all(not any(row[0]) for row in residuals)
    assert any(any(row[1]) for row in residuals)
    assert not kernel.holds(sources, outputs)


def test_vanishing_at_one_NTT_coordinate_never_grants_acceptance(native_case):
    kernel, _statement, sources, outputs, _public, _backend = native_case
    n, q, (p0, p1) = kernel.graph.n, kernel.graph.q, kernel.primes
    candidate, psi = 2, 0
    while not psi:
        value = pow(candidate, (p0 - 1) // (2 * n), p0)
        if pow(value, n, p0) == p0 - 1:
            psi = value
        candidate += 1
    delta = ((-p1 * psi) % q, p1, *((0,) * (n - 2)))
    assert sum(x * pow(psi, i, p0) for i, x in enumerate(delta)) % p0 == 0
    assert all(x % p1 == 0 for x in delta)
    pair = outputs[-1]
    changed = tuple((x + y) % q for x, y in zip(pair[0], delta, strict=True))
    outputs = (*outputs[:-1], (changed, pair[1]))
    assert not kernel.holds(sources, outputs)
    assert any(any(row[0]) for row in kernel.residuals(sources, outputs))


def test_native_evaluation_and_preparation_do_not_call_HE_replay_or_private_work(
    native_case, monkeypatch
):
    kernel, statement, sources, outputs, public, backend = native_case

    def forbidden(*_args, **_kwargs):
        pytest.fail("No private or expected-response oracle in a residual kernel")

    for module, name in (
        (bgv, "multiply"),
        (bgv, "decrypt"),
        (gadget, "make_trace"),
        (gadget, "integer_product"),
        (gadget, "switched"),
        (reference, "make_trace"),
        (relation, "residuals"),
    ):
        monkeypatch.setattr(module, name, forbidden)
    prepared = native.Kernel.prepare(statement, kernel.graph, public, backend)
    assert prepared.holds(sources, outputs)
    assert all(
        not any(row) for pair in prepared.residuals(sources, outputs) for row in pair
    )


def test_wrong_original_Q_rejects_before_native_creation(native_case, monkeypatch):
    kernel, statement, _sources, _outputs, public, backend = native_case
    calls = []
    monkeypatch.setattr(
        backend, "cuhepy_noise_cut_create", lambda *_args: calls.append(True)
    )
    with pytest.raises(ValueError, match="original Q"):
        native.Kernel.prepare(
            replace(statement, q=statement.q - 1),
            replace(kernel.graph, q=kernel.graph.q - 1),
            public,
            backend,
        )
    assert not calls


@pytest.mark.parametrize("code", [9, 4])
def test_native_unknown_or_cyclic_descriptor_rejects(code, native_case):
    kernel, _statement, _sources, _outputs, _public, backend = native_case
    descriptors = native.words([code, 0, 0, 1, 1])
    roots, public = native.words([0]), native.words([])
    assert not backend.cuhepy_noise_cut_create(
        kernel.graph.n, *kernel.primes, 1, descriptors, 1, roots, 1, public, 0
    )


def test_malformed_last_native_binding_rejects_before_arithmetic(native_case):
    kernel, _statement, sources, outputs, _public, backend = native_case
    inputs = kernel._inputs(sources, outputs)
    inputs[-1] = kernel.primes[1]
    assert (
        backend.cuhepy_noise_cut_check(kernel.handle, inputs, len(kernel.input_names))
        == -1
    )


def test_kernel_has_no_secret_challenge_or_release_authority(native_case):
    kernel = native_case[0]
    assert not hasattr(kernel, "sign")
    assert not hasattr(kernel, "decrypt")
    assert not hasattr(kernel, "admit_and_release")


def test_native_wire_entire_body_is_immutable_and_canonical(native_case):
    kernel, _statement, sources, outputs, _public, _backend = native_case
    if type(kernel) is not native.WireKernel:
        return
    body = kernel.body(sources, outputs)
    assert kernel.holds_bytes(body)
    for invalid in (
        bytearray(body),
        body[:-1],
        body + b"\0",
        body[:-15] + kernel.graph.q.to_bytes(15, "little"),
    ):
        assert not kernel.holds_bytes(invalid)
    with pytest.raises(ValueError):
        kernel.residuals_bytes(body[:-15] + kernel.graph.q.to_bytes(15, "little"))


def test_original_query_is_owner_enrolled_and_not_part_of_server_wire(native_case):
    kernel, statement, sources, outputs, public, backend = native_case
    if type(kernel) is not native.WireKernel:
        return
    fixed = []
    for name, row in statement.trusted_inputs:
        if name == ("query", 0):
            row = ((row[0] + 1) % statement.q, *row[1:])
        fixed.append((name, row))
    changed = native.WireKernel.prepare(
        replace(statement, trusted_inputs=tuple(fixed)), kernel.graph, public, backend
    )
    assert not changed.holds_bytes(kernel.body(sources, outputs))


def test_immutable_native_handle_copies_keep_the_owning_object_alive(native_case):
    kernel = native_case[0]
    assert copy.copy(kernel) is kernel
    assert copy.deepcopy(kernel) is kernel
    with pytest.raises(TypeError, match="serialized"):
        pickle.dumps(kernel)


def test_native_handle_rejects_wrong_process_before_backend_use(
    native_case, monkeypatch
):
    kernel, _statement, sources, outputs, _public, _backend = native_case
    monkeypatch.setattr(native.os, "getpid", lambda: kernel.owner_pid + 1)
    assert not kernel.holds(sources, outputs)
    with pytest.raises(ValueError):
        kernel.residuals(sources, outputs)
