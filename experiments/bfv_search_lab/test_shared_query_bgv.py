"""Q74 exact semantics, signed branches, complete binding and public guards."""

from dataclasses import replace
from math import prod

from gmpy2 import mpz
import msgpack
import pytest

from cuhepy.bfv.scheme import _rns_coefficient_primes
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import noise_cut_fusion as fusion
from experiments.bfv_search_lab import noise_cut_relation as relation
from experiments.bfv_search_lab import propagated_gadget_bgv as gadget
from experiments.bfv_search_lab import seeded_bgv as seeded
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_bgv as shared
from experiments.bfv_search_lab.shared_query_bounds import Profile


@pytest.fixture(scope="module", params=[(16, 3, 11), (32, 5, 19)])
def fixture(request):
    n, d, t = request.param
    pk, sk = bgv.key_gen(n, t=t, q_bits=120, eta=1, rns_modulus=True)
    p = int(compact.terminal_modulus(pk.q, t, 25))
    keys = shared.evaluation_keys(pk, sk, d)
    query_bits = tuple(j % 2 for j in range(d))
    rows = tuple(tuple((i >> j) & 1 for j in range(d)) for i in range(n + 1))
    query = seeded.expand(seeded.encrypt(shared.encode_query(query_bits, n, t), pk, sk), pk)
    cases = {}
    for mode in ("owner", "public_key"):
        index = tuple(
            seeded.expand(seeded.encrypt(poly, pk, sk), pk)
            if mode == "owner"
            else bgv.encrypt(poly, pk)
            for poly in shared.encode_index(rows, n, d)
        )
        for policy in ("canonical30", "derived_last30"):
            profile = Profile(n, d, int(pk.q), p, t, 1, mode, policy)
            ctx = shared.enroll(
                profile, pk, query, index, tuple(100 + 3 * i for i in range(n + 1)), keys
            )
            rel = shared.compile_relation(ctx)
            tape, expanded = shared.produce(ctx, pk)
            cases[mode, policy] = ctx, rel, tape, expanded
    return pk, sk, query_bits, rows, cases


@pytest.mark.parametrize("mode", ["owner", "public_key"])
@pytest.mark.parametrize("policy", ["canonical30", "derived_last30"])
def test_original_query_to_exact_scores_and_full_frame(fixture, mode, policy):
    pk, sk, bits, rows, cases = fixture
    ctx, rel, tape, expanded = cases[mode, policy]
    assert shared.accepts(ctx, rel, tape)
    phase = ctx.profile.envelope()["output_phase_bound"]
    actual = [
        bgv.decrypt(
            bgv.Ciphertext(tuple(tuple(map(mpz, a)) for a in pair), pk.key_id, phase), pk, sk
        )
        for pair in tape.full_output
    ]
    expected = [
        (len(bits) - 2 * sum(x != y for x, y in zip(bits, row, strict=True))) % pk.t for row in rows
    ]
    assert [x for row in actual for x in row] == expected + [0] * (ctx.groups * pk.n - len(rows))
    leaf_bound = ctx.profile.envelope()["expanded_phase_bound"]
    for j, pair in enumerate(expanded):
        plain = bgv.decrypt(
            bgv.Ciphertext(tuple(tuple(map(mpz, a)) for a in pair), pk.key_id, leaf_bound), pk, sk
        )
        value = (1 - 2 * bits[j]) % pk.t if j < len(bits) else 0
        assert plain == [value] + [0] * (pk.n - 1)
    assert len(tape.sources) == ctx.profile.inventory(len(rows), 2)["source_polynomials"]
    assert len(rel.residuals) == len(tape.sources) + 2 * ctx.groups
    # Two components cover the unused coordinates in the partial second group.
    assert tape.response == shared.expected_frame(ctx, tape.full_output)


def test_every_source_and_terminal_component_is_bound(fixture):
    _pk, _sk, _bits, _rows, cases = fixture
    for ctx, rel, tape, _ in cases.values():
        for slot, source in enumerate(tape.sources):
            poly = (*source.polynomial[:-1], (source.polynomial[-1] + 1) % ctx.profile.q)
            bad = replace(
                tape,
                sources=(
                    *tape.sources[:slot],
                    replace(source, polynomial=poly),
                    *tape.sources[slot + 1 :],
                ),
            )
            assert not shared.accepts(ctx, rel, bad)
        for g, pair in enumerate(tape.full_output):
            for c in range(2):
                changed = (*pair[c][:-1], (pair[c][-1] + 1) % ctx.profile.q)
                other = (changed, pair[1]) if c == 0 else (pair[0], changed)
                outputs = (*tape.full_output[:g], other, *tape.full_output[g + 1 :])
                assert not shared.accepts(
                    ctx,
                    rel,
                    replace(
                        tape, full_output=outputs, response=shared.expected_frame(ctx, outputs)
                    ),
                )


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "order",
        "duplicate",
        "mutable",
        "negative",
        "Q",
        "boolean",
        "foreign_limb",
        "extra_output",
        "short_output",
        "bool_label",
    ],
)
def test_canonical_common_Q_grammar_rejects(fixture, fault):
    pk, _sk, _bits, _rows, cases = fixture
    ctx, rel, tape, _ = cases["owner", "derived_last30"]
    sources, outputs = tape.sources, tape.full_output
    if fault == "missing":
        sources = sources[:-1]
    elif fault == "order":
        sources = sources[::-1]
    elif fault == "duplicate":
        sources = (*sources[:-1], sources[0])
    elif fault == "mutable":
        sources = list(sources)
    elif fault in ("negative", "Q", "boolean", "foreign_limb"):
        value = {
            "negative": -1,
            "Q": int(pk.q),
            "boolean": True,
            "foreign_limb": (sources[0].polynomial[0] + _rns_coefficient_primes(pk.n, 120)[0])
            % int(pk.q),
        }[fault]
        value = int(value) if fault == "foreign_limb" else value
        sources = (
            replace(sources[0], polynomial=(value, *sources[0].polynomial[1:])),
            *sources[1:],
        )
    elif fault == "bool_label":
        sources = (replace(sources[0], level=False), *sources[1:])
    elif fault == "extra_output":
        outputs = (*outputs, outputs[0])
    else:
        outputs = (outputs[0][0][:-1], outputs[0][1]), *outputs[1:]
    assert not shared.accepts(ctx, rel, replace(tape, sources=sources, full_output=outputs))


@pytest.mark.parametrize(
    "fault",
    [
        "query",
        "index",
        "IDs",
        "policy",
        "key",
        "response",
        "frame_header",
        "unused_frame_coordinate",
    ],
)
def test_frozen_context_and_complete_packet_binding(fixture, fault):
    _pk, _sk, _bits, _rows, cases = fixture
    ctx, rel, tape, _ = cases["owner", "derived_last30"]
    if fault in ("query", "index"):
        pair = ctx.query if fault == "query" else ctx.index[0]
        changed = (((pair[0][0] + 1) % ctx.profile.q, *pair[0][1:]), pair[1])
        ctx = (
            replace(ctx, query=changed)
            if fault == "query"
            else replace(ctx, index=(changed, *ctx.index[1:]))
        )
    elif fault == "IDs":
        ctx = replace(ctx, ids=ctx.ids[::-1])
    elif fault == "policy":
        ctx = replace(ctx, profile=replace(ctx.profile, policy="canonical30"))
    elif fault == "key":
        ctx = replace(ctx, key_id="0" * 64)
    elif fault == "response":
        tape = replace(tape, response=tape.response + b"\0")
    else:
        header, body = msgpack.unpackb(tape.response, raw=False)
        if fault == "frame_header":
            header[-1] += 1
        else:
            value = bytearray(body[-1][0])
            value[-1] ^= 1
            body[-1][0] = bytes(value)
        tape = replace(tape, response=msgpack.packb([header, body], use_bin_type=True))
    assert not shared.accepts(ctx, rel, tape)


def test_checker_has_no_producer_replay_or_private_arithmetic(fixture, monkeypatch):
    _pk, _sk, _bits, _rows, cases = fixture

    def forbidden(*_args, **_kwargs):
        pytest.fail("The independent public checker must not call this")

    for module, name in (
        (shared, "produce"),
        (shared, "_ring_product"),
        (gadget, "switched"),
        (gadget, "integer_product"),
        (bgv, "decrypt"),
        (compact, "decrypt"),
        (compact, "compact"),
    ):
        monkeypatch.setattr(module, name, forbidden)
    for ctx, rel, tape, _ in cases.values():
        assert shared.accepts(ctx, rel, tape)


def test_supplied_digest_does_not_authorize_a_weakened_graph(fixture):
    _pk, _sk, _bits, _rows, cases = fixture
    ctx, rel, tape, _ = cases["owner", "derived_last30"]
    # A correct digest alone must not permit erasing output/source constraints.
    forged = replace(rel, residuals=())
    pair = tape.full_output[-1]
    changed = (*tape.full_output[:-1], (((pair[0][0] + 1) % ctx.profile.q, *pair[0][1:]), pair[1]))
    bad = replace(tape, full_output=changed, response=shared.expected_frame(ctx, changed))
    assert not shared.accepts(ctx, forged, bad)
    assert not shared.accepts(ctx, forged, tape)


def test_symbolic_known_control_is_identical_on_every_residual(fixture):
    _pk, _sk, _bits, _rows, cases = fixture
    for ctx, rel, tape, _ in cases.values():
        graph, layouts = shared.symbolic_graph(ctx.profile, ctx.groups)
        bindings = fusion.bindings(rel, tape.sources, tape.full_output)
        constants = {fusion.Public(name): row for name, row in shared.public_constants(ctx).items()}
        assert layouts == rel.source_layout
        assert fusion.evaluate(graph, bindings, constants) == relation.residuals(
            rel, tape.sources, tape.full_output
        )
        assert not any(any(row) for row in fusion.evaluate(graph, bindings, constants))


def test_signed_minus_state_and_all_cross_terms(fixture):
    _pk, _sk, _bits, _rows, cases = fixture
    ctx, _rel, tape, _ = cases["owner", "derived_last30"]
    level = ctx.profile.levels - 2
    source = next(x for x in tape.sources if x.level == level)
    digits = gadget.canonical_digits(source.polynomial, ctx.profile.q, 30)
    exponent, key = ctx.rotations[level]
    matrix = gadget.public_a_digits(key, ctx.profile.q, 30)
    plus, minus = shared.branch_states(digits, exponent, -(1 << level), matrix)
    inverse = pow(exponent, -1, 2 * ctx.profile.n)
    for j in range(ctx.profile.ell):
        left = gadget.permute(digits[j], inverse)
        correction = tuple(
            sum(gadget.integer_product(digits[a], matrix[a][j])[i] for a in range(ctx.profile.ell))
            for i in range(ctx.profile.n)
        )
        assert plus[j] == tuple(x + y for x, y in zip(left, correction, strict=True))
        assert minus[j] == gadget.permute(
            tuple(x - y for x, y in zip(left, correction, strict=True)), shift=-(1 << level)
        )
        assert max(map(abs, plus[j] + minus[j])) <= ctx.profile.retained_state_bound
    # A diagonal-only approximation omits real radix cross terms.
    diagonal = tuple(
        x + y
        for x, y in zip(
            gadget.permute(digits[0], inverse),
            gadget.integer_product(digits[0], matrix[0][0]),
            strict=True,
        )
    )
    assert diagonal != plus[0]


@pytest.mark.parametrize(
    "bits,mode,policy,safe",
    [
        (120, "owner", "canonical30", True),
        (120, "public_key", "canonical30", False),
        (120, "owner", "derived_last30", False),
        (120, "public_key", "derived_last30", False),
        (180, "owner", "canonical30", True),
        (180, "public_key", "canonical30", True),
        (180, "owner", "derived_last30", True),
        (180, "public_key", "derived_last30", True),
    ],
)
def test_exact_source_profile_public_screen(bits, mode, policy, safe):
    q = prod(map(int, _rns_coefficient_primes(16384, bits)))
    profile = Profile(
        16384, 512, q, int(compact.terminal_modulus(mpz(q), 1031, 25)), 1031, 21, mode, policy
    )
    assert profile.envelope()["admitted"] is safe
    if not safe:
        with pytest.raises(ValueError, match="Unsafe"):
            profile.require_safe()


def test_unsafe_guard_precedes_any_evaluator_or_graph_work(fixture, monkeypatch):
    pk, _sk, _bits, _rows, cases = fixture
    ctx, _rel, _tape, _ = cases["owner", "derived_last30"]
    q = prod(map(int, _rns_coefficient_primes(16384, 120)))
    unsafe = Profile(
        16384,
        512,
        q,
        int(compact.terminal_modulus(mpz(q), 1031, 25)),
        1031,
        21,
        "owner",
        "derived_last30",
    )
    ctx = replace(ctx, profile=unsafe)

    def forbidden(*_args, **_kwargs):
        pytest.fail("Arithmetic/graph work before the public guard")

    monkeypatch.setattr(shared, "_ring_product", forbidden)
    monkeypatch.setattr(relation, "Builder", forbidden)
    with pytest.raises(ValueError, match="Unsafe"):
        shared.produce(ctx, pk)
    with pytest.raises(ValueError, match="Unsafe"):
        shared.compile_relation(ctx)
