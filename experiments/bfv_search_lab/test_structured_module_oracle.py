"""E80 independent coefficient matrices, exact outer recovery and gate ordering."""

from contextlib import closing
from dataclasses import replace
import itertools
import random

import gmpy2
from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import structured_module_oracle as module
from experiments.bfv_search_lab import structured_operator_oracle as scalar
from experiments.bfv_search_lab import structured_registration_oracle as old
from experiments.bfv_search_lab.test_supported_decoder import CASES, inputs


def matrix(op):
    """Independent signed columns; never calls the module forward/map."""
    result = []
    for output in range(op.rows):
        block, position = divmod(output, op.n)
        row = []
        for degree, column in zip(op.degrees, op.generators, strict=True):
            for k in range(degree):
                shift = k * (op.n // degree)
                row.append(column[block][(position - shift) % op.n] * (1 if position >= shift else -1))
        result.append(tuple(row))
    return tuple(result)


def fixture(n=8, degrees=(2, 4), replies=1, seed=80001):
    rng, q = random.Random(seed + n), 97
    op = scalar.Operator(n, q, replies, degrees,
                         tuple(tuple(tuple(rng.randrange(-q // 2 + 1, q // 2 + 1) for _ in range(n))
                                     for _ in range(2 * replies)) for _ in degrees))
    return op, rng


def registration(mod, rng, *, rank=2, rounds=4, query_bound=8):
    q = module.candidate_modulus(width=mod.original.width, inner_q=mod.original.q, query_bound=query_bound)
    A = tuple(tuple(tuple(rng.randrange(q) for _ in range(mod.m)) for _ in range(rank)) for _ in range(mod.b))
    C = tuple((1,) * mod.a for _ in range(rounds))
    return module.register(mod, A, C, q, b"e" * 32, "a" * 64, query_bound=query_bound)


@pytest.mark.parametrize("n,degrees,replies,m", [
    (n, degrees, replies, m) for n in (8, 16, 32) for degrees in ((2, 4, 8), (4, 8), (8, 8))
    for replies in (1, 2) for m in (1, 2, 4, 8) if all(d % m == 0 for d in degrees)
])
def test_independent_integer_forward_adjoint_basis_H_Z_and_bounds(n, degrees, replies, m):
    op, rng = fixture(n, degrees, replies)
    mod, dense = module.module(op, m), matrix(op)
    x = tuple(rng.randrange(-8, 9) for _ in range(op.width))
    y = tuple(rng.randrange(-8, 9) for _ in range(op.rows))
    expected = tuple(sum(a * b for a, b in zip(row, x, strict=True)) for row in dense)
    assert module.unpack_outputs(mod, module.forward(mod, module.pack_inputs(mod, x))) == expected
    transposed = tuple(sum(row[j] * v for row, v in zip(dense, y, strict=True)) for j in range(op.width))
    assert module.unpack_inputs(mod, module.adjoint(mod, module.pack_outputs(mod, y))) == transposed
    assert module.unpack_inputs(mod, module.pack_inputs(mod, x)) == x
    assert module.unpack_outputs(mod, module.pack_outputs(mod, y)) == y
    for j in range(op.width):
        basis = tuple(int(i == j) for i in range(op.width))
        assert module.unpack_outputs(mod, module.forward(mod, module.pack_inputs(mod, basis))) == tuple(row[j] for row in dense)
    st = registration(mod, rng)
    # Independently expand each CRS column's signed Y rotations into scalar D*A.
    for j in range(st.rank):
        for h in range(m):
            shifted = tuple(tuple(p[(i - h) % m] * (1 if i >= h else -1) for i in range(m))
                            for p in (row[j] for row in st.crs))
            coords = module.unpack_inputs(mod, shifted)
            expected_h = tuple(sum(a * b for a, b in zip(row, coords, strict=True)) % st.outer_q for row in dense)
            hint_shifted = tuple(tuple(p[(i - h) % m] * (1 if i >= h else -1) % st.outer_q for i in range(m))
                                 for p in (row[j] for row in st.hint))
            assert module.unpack_outputs(mod, hint_shifted) == expected_h
    # Z*u = C*D*u with arbitrary signed u, not only an encrypted honest query.
    packed = module.pack_inputs(mod, x)
    assert module.matvec(st.fingerprints, packed, m, st.outer_q) == module._challenge(st.challenges, module.forward(mod, packed), m, st.outer_q)
    assert all(abs(v) <= st.norm_bound for row in st.fingerprints for p in row for v in p)


def test_incompatible_subring_projection_lift_and_digit_controls():
    op, _ = fixture(degrees=(1, 4))
    with pytest.raises(ValueError):
        module.module(op, 2)
    op, _ = fixture(degrees=(4, 8))
    mod = module.module(op, 4)
    assert module.compatible_projection(mod, (0, 2, 4, 6))
    assert not module.compatible_projection(mod, (0,))
    bad = replace(op, generators=tuple(tuple(tuple(x + op.q for x in p) for p in col) for col in op.generators))
    with pytest.raises(ValueError):
        module.module(bad, 4)
    for base in (4, 16):
        example = old.digit_factorization_counterexample(base, 97)
        assert example["factorization_fails"]


@pytest.mark.parametrize("error", [((1, 0), (0, 0)), ((1, 2), (-1, -2)), ((0, 0), (1, 2))])
def test_fixed_nonzero_module_error_has_at_most_one_half_survival_per_binary_row(error):
    accepted = 0
    choices = tuple(itertools.product((0, 1), repeat=2))
    for C in itertools.product(choices, repeat=2):
        accepted += module._challenge(C, error, 2, 97) == ((0, 0), (0, 0))
    assert accepted <= len(choices) ** 2 // 4


def test_remainder_is_required_and_centered_rounding_handles_boundaries():
    p, W, bound = 97, 4, 20
    q = next(q for q in range(40000, 90000) if gmpy2.is_prime(q)
             and 2 * W * (p // 2) < q // p
             and not module.correctness(rows=16, width=W, inner_q=p, query_bound=bound, eta=1, outer_q=q)["strict_rounding_safe"])
    op, rng = fixture(degrees=(4,))
    mod = module.module(op, 4)
    A = tuple((tuple(rng.randrange(q) for _ in range(4)),) for _ in range(mod.b))
    with pytest.raises(ValueError, match="rounding bound"):
        module.register(mod, A, ((1,) * mod.a,), q, b"e" * 32, "a" * 64, query_bound=bound)
    st = registration(mod, rng, query_bound=p // 2)
    gate = module.FixtureSession(st)
    for i, x in enumerate(itertools.product((-p // 2 + 1, p // 2), repeat=W)):
        secret = tuple(tuple(rng.randrange(-1, 2) for _ in range(mod.m)) for _ in range(st.rank))
        e = tuple(tuple(rng.randrange(-1, 2) for _ in range(mod.m)) for _ in range(mod.b))
        request = gate.issue(module.pack_inputs(mod, x), secret, e, i.to_bytes(16, "little"))
        recovered = gate.recover_once(request.token_id, module.server_reply(mod, request, st.outer_q))
        assert module.unpack_outputs(mod, recovered) == scalar.forward(op, x)


@pytest.mark.parametrize("fault", ["tamper", "truncate", "epoch", "binding", "token", "out_of_range", "wrong_type"])
def test_reject_retires_registration_before_secret_arithmetic(fault, monkeypatch):
    op, rng = fixture(degrees=(4, 8))
    mod = module.module(op, 4)
    st = registration(mod, rng)
    gate = module.FixtureSession(st)
    request = gate.issue(((1, 0, 0, 0),) * mod.b, ((1, 0, 0, 0),) * st.rank,
                         ((1, 0, 0, 0),) * mod.b, bytes(16))
    reply = module.server_reply(mod, request, st.outer_q)
    if fault == "tamper":
        reply = replace(reply, values=((reply.values[0][0] + 1,) + reply.values[0][1:], *reply.values[1:]))
    elif fault == "truncate":
        reply = replace(reply, values=reply.values[:-1])
    elif fault == "out_of_range":
        reply = replace(reply, values=((st.outer_q,) + reply.values[0][1:], *reply.values[1:]))
    elif fault == "wrong_type":
        reply = object()
    else:
        field = "token_id" if fault == "token" else fault
        reply = replace(reply, **{field: {"epoch": b"z" * 32, "binding": "b" * 64, "token": b"x" * 16}[fault]})
    calls = []
    monkeypatch.setattr(gate, "_remove_mask", lambda *_: calls.append(True))
    assert gate.recover_once(request.token_id, reply) is None
    assert not calls and gate.retired
    with pytest.raises(RuntimeError):
        gate.issue(((0,) * mod.m,) * mod.b, ((0,) * mod.m,) * st.rank, ((0,) * mod.m,) * mod.b, b"x" * 16)


def encrypted_case(descriptor):
    s, words, groups, ids, binding = inputs(*descriptor)
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    rng = random.Random(80112)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, b"e" * 32, client)
    op = scalar.from_index(index, pk)
    m = min(op.degrees)
    mod = module.module(op, m)
    st = registration(mod, rng)
    gate = module.FixtureSession(st)
    for word in range(16):
        values = tuple((1 - 2 * (word >> j & 1)) % 17 for _ in s.dimensions for j in range(4))
        corrections = crt.corrections(s, values)
        forms = tuple(v for p in corrections for v in p)
        secret = tuple(tuple(rng.randrange(-1, 2) for _ in range(m)) for _ in range(st.rank))
        error = tuple(tuple(rng.randrange(-1, 2) for _ in range(m)) for _ in range(mod.b))
        request = gate.issue(module.pack_inputs(mod, forms), secret, error, word.to_bytes(16, "little"))
        recovered = gate.recover_once(request.token_id, module.server_reply(mod, request, st.outer_q))
        flat = module.unpack_outputs(mod, recovered)
        assert flat == scalar.forward(op, forms)
        norms = tuple(sum(map(abs, p)) for p in corrections)
        bounds = tuple(sum(v * col[i].phase_bound for v, col in zip(norms, index.columns, strict=True))
                       for i in range(op.replies))
        ciphertexts = tuple(bgv.Ciphertext(tuple(tuple(mpz(x) for x in flat[(2 * i + j) * op.n:(2 * i + j + 1) * op.n])
                                                   for j in range(2)), pk.key_id, bounds[i]) for i in range(op.replies))
        dots = tree.unpack(s.layout, [bgv.decrypt(c, pk, sk) for c in ciphertexts])
        assert dots == crt.scores(s, groups, values)
        scores = tuple((int(v) + word.bit_count()) % 17 for row in dots for v in row)
        expected = tuple((word ^ old).bit_count() for row in words for old in row)
        assert scores == expected
        flat_ids = tuple(i for row in ids for i in row)
        assert sorted(zip(scores, flat_ids, strict=True))[:3] == sorted(zip(expected, flat_ids, strict=True))[:3]
    return {"n": op.n, "degrees": op.degrees, "m": m, "L": op.rows, "W": op.width,
            "inner_q": int(pk.q), "outer_q": st.outer_q, "outer_bits": st.outer_q.bit_length(),
            "toy_outer_rank": st.rank, "toy_binary_rows": len(st.challenges), "exact_search_queries": 16,
            "every_inner_ciphertext_score_ID_top3_exact": True,
            "private_phase_bound_max": max(bounds), "owner_built_registration_only": True,
            "recovery_with_nonzero_outer_error": True}


@pytest.mark.parametrize("descriptor", CASES)
def test_full_outer_recovery_then_original_inner_BGV_exact_scores_IDs_ties(descriptor):
    assert encrypted_case(descriptor)["exact_search_queries"] == 16


def test_scalar_profile_has_no_structure_and_nonzero_costs_are_charged():
    a = module.count_screen(n=2048, replies=4, degrees=(1,) * 85, inner_q=4294955009, query_bound=96, m=1)
    assert a["outer_hint_coefficients"] == a["L"] * 2048
    assert a["outer_reply_body_bytes"] > a["recovered_inner_reply_body_bytes"]
    assert a["client_registration_body_bytes"] > a["H_body_bytes"]
    assert a["correctness"]["strict_rounding_safe"]
    with pytest.raises(ValueError):
        module.count_screen(n=2048, replies=4, degrees=(1,) * 85, inner_q=4294955009, query_bound=96, m=32)
