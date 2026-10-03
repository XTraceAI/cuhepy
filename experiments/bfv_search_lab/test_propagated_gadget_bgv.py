"""Independent modular identities, whole public relation and no-wrap negatives."""

from dataclasses import replace
import random

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import admissible_trace_oracle as admitted
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import native_boundary_oracle as oracle
from experiments.bfv_search_lab import propagated_gadget_bgv as propagated
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


def algebra_trial(n, rng, q=65537, bits=4):
    """Schoolbook oracle compares the GMP switch, then whole-state identities."""
    ell, g, h = (q.bit_length() + bits - 1) // bits, 5, 9
    key0 = tuple(
        tuple(tuple(mpz(rng.randrange(q)) for _ in range(n)) for _ in range(2))
        for _ in range(ell)
    )
    key1 = tuple(
        tuple(tuple(mpz(rng.randrange(q)) for _ in range(n)) for _ in range(2))
        for _ in range(ell)
    )
    key2 = tuple(
        tuple(tuple(mpz(rng.randrange(q)) for _ in range(n)) for _ in range(2))
        for _ in range(ell)
    )
    a0 = propagated.public_a_digits(key0, q, bits)
    states, original = [], []
    sources = []
    for _ in range(2):
        c1 = tuple(rng.randrange(q) for _ in range(n))
        source = oracle.automorphism(c1, g, q)
        d = propagated.canonical_digits(source, q, bits)
        result = propagated.switched(d, key0, q)
        expected = tuple(
            tuple(
                sum(
                    oracle.multiply(row, tuple(map(int, column[k])), q)[i]
                    for row, column in zip(d, key0, strict=True)
                )
                % q
                for i in range(n)
            )
            for k in range(2)
        )
        assert result == expected
        state = propagated.unary_state(d, g, a0)
        output = oracle.add(c1, result[1], q)
        assert propagated.recompose(state, bits, q) == output
        assert max(abs(x) for row in state for x in row) <= ((1 << bits) - 1) * (
            1 + ell * n * ((1 << bits) - 1)
        )
        states.append(state)
        original.append(output)
        sources.append(d)
    shift = n // 4
    d1 = propagated.source_state(states[0], states[1], shift, h)
    source1 = oracle.automorphism(
        oracle.add(original[0], oracle.monomial(original[1], shift, q), q, -1), h, q
    )
    assert propagated.recompose(d1, bits, q) == source1
    correction1 = propagated.switched(d1, key1, q)
    fused = propagated.fused_correction(
        sources[0], sources[1], g, h, shift, a0, key1, q
    )
    assert correction1 == fused
    state1 = propagated.next_state(
        states[0], states[1], shift, d1, propagated.public_a_digits(key1, q, bits)
    )
    c1_1 = oracle.add(
        oracle.add(original[0], oracle.monomial(original[1], shift, q), q),
        correction1[1],
        q,
    )
    assert propagated.recompose(state1, bits, q) == c1_1
    d2 = propagated.source_state(state1, None, n // 8, 17)
    assert propagated.recompose(d2, bits, q) == oracle.automorphism(c1_1, 17, q)
    result2 = propagated.switched(d2, key2, q)
    state2 = propagated.next_state(
        state1, None, n // 8, d2, propagated.public_a_digits(key2, q, bits)
    )
    assert propagated.recompose(state2, bits, q) == oracle.add(c1_1, result2[1], q)
    return {
        "n": n,
        "switches_checked": 4,
        "full_modular_coefficients_checked": 4 * n,
        "fused_correction_coefficients_checked": 2 * n,
        "maximum_first_propagated_digit_abs": max(abs(x) for d in d1 for x in d),
        "maximum_second_propagated_digit_abs": max(abs(x) for d in d2 for x in d),
        "exact_source_and_C1_relations": True,
    }


@pytest.mark.parametrize("n", [8, 16])
def test_three_switch_stage_relations_and_public_fusion(n):
    rng = random.Random(64065 + n)
    for _ in range(12):
        assert algebra_trial(n, rng)["exact_source_and_C1_relations"]


def test_radix_componentwise_product_is_not_a_homomorphic_gadget():
    d = propagated.canonical_digits((17,), 65537, 4)
    assert propagated.recompose(
        tuple(tuple(x * x for x in row) for row in d), 4, 65537
    ) == (17,)
    assert 17 * 17 != 17


@pytest.mark.parametrize("n", [8, 16])
def test_binary_minus_cut_cannot_determine_plus_without_an_extra_witness(n):
    q, shift = 65537, n // 4
    right = (1,) + (0,) * (n - 1)
    left = oracle.monomial(right, shift, q)
    zero = (0,) * n
    assert (
        oracle.automorphism(
            oracle.add(left, oracle.monomial(right, shift, q), q, -1), 5, q
        )
        == zero
    )
    assert oracle.add(left, oracle.monomial(right, shift, q), q) != zero


@pytest.mark.parametrize("kind", ["unbounded", "independent_limb", "bool", "shape"])
def test_recomposition_without_one_bounded_integer_representation_is_rejected(kind):
    q, bits = 221, 2
    d = propagated.canonical_digits((0,), q, bits)
    if kind == "unbounded":
        d = (
            (4,),
            (-1,),
            (0,),
            (0,),
        )  # Even exact integer cancellation is insufficient.
    elif kind == "independent_limb":
        d = ((1,), (3,), (0,), (0,))  # Valid mod13, invalid globally mod221.
    elif kind == "bool":
        d = ((False,), *d[1:])
    else:
        d = d[:-1]
    with pytest.raises(ValueError, match="common-integer"):
        propagated.validate_digits((0,), d, bits, q, 3)
    # Previously recorded exact counterexamples remain known-method negatives.
    negative = admitted.negative_controls()
    assert negative["unbounded_decoded"] != negative["expected"]
    assert negative["RNS_decoded"] != negative["RNS_expected"]


def fixed_model(tiles=256, stages=1):
    n, t, eta, q = 16384, 1031, 21, int("ffffffffffc00020000003bffc0001", 16)
    return propagated.model(
        n,
        q,
        t,
        eta,
        512,
        tiles,
        30,
        t // 2 + t * eta,
        t // 2 + t * eta * (2 * n + 1),
        propagated_stages=stages,
        terminal=33548413,
    )


def test_fixed_Q120_single_propagation_passes_but_further_stage_fails():
    one, two = fixed_model(stages=1), fixed_model(stages=2)
    assert one["Q_guard"] and one["terminal_guard"]
    assert one["removed_source_cuts"] == 128 and one["body_saving_bytes"] == 30 * 2**20
    assert not two["Q_guard"] and not two["terminal_guard"]
    assert one["fused_extra_online_ring_products"] > 0
    assert one["shared_fused_H_body_bytes"] > 0


def test_full_group_falls_back_without_claiming_removed_sources():
    full = fixed_model(512)
    assert not full["free_unary_anchor"] and full["removed_source_cuts"] == 0
    assert full["shared_fused_H_body_bytes"] == 0


def fixture():
    pk, sk = bgv.key_gen(16, t=17, q_bits=120, eta=1)
    keys = trace.evaluation_keys(pk, sk, 8, digit_bits=4)
    query, rows = [0, 1, 0, 1, 1], [[(i >> j) & 1 for j in range(5)] for i in range(8)]
    plain, tiles = bgv.coefficient_inputs(query, rows, pk.n)
    request, index = bgv.encrypt(plain, pk), [bgv.encrypt(tile, pk) for tile in tiles]
    return request, index, len(rows), 5, pk, sk, keys


def test_small_homemade_full_plaintext_and_scores_agree():
    request, index, count, dim, pk, sk, keys = fixture()
    alt = propagated.make_trace(request, index, count, dim, pk, keys)
    control = propagated.make_trace(
        request, index, count, dim, pk, keys, propagate=False
    )
    assert propagated.check_trace(request, index, count, dim, pk, keys, alt)
    assert alt.full_output != control.full_output

    def plaintexts(tr):
        return [
            bgv.decrypt(
                bgv.Ciphertext(
                    tuple(tuple(map(mpz, p)) for p in pair), pk.key_id, bound
                ),
                pk,
                sk,
            )
            for pair, bound in zip(tr.full_output, tr.bounds, strict=True)
        ]

    assert plaintexts(alt) == plaintexts(control)
    assert trace.decode(plaintexts(alt), count, dim, pk) == trace.decode(
        plaintexts(control), count, dim, pk
    )


@pytest.mark.parametrize(
    "fault",
    ["unused_output", "response", "gadget", "request", "policy", "bound", "cut_count"],
)
def test_full_relation_rejects_mutations_without_private_arithmetic(fault, monkeypatch):
    request, index, count, dim, pk, _, keys = fixture()
    supplied = propagated.make_trace(request, index, count, dim, pk, keys)
    if fault == "unused_output":
        pair = supplied.full_output[0]
        changed = (*pair[0][:-1], (pair[0][-1] + 1) % int(pk.q))
        supplied = replace(supplied, full_output=((changed, pair[1]),))
    elif fault == "response":
        supplied = replace(
            supplied,
            response=supplied.response[:-1] + bytes([supplied.response[-1] ^ 1]),
        )
    elif fault == "gadget":
        cut = supplied.cuts[0]
        digits = (((cut.digits[0][0] + 1), *cut.digits[0][1:]), *cut.digits[1:])
        supplied = replace(
            supplied, cuts=(replace(cut, digits=digits), *supplied.cuts[1:])
        )
    elif fault == "request":
        p = request.components[0]
        request = replace(
            request,
            components=(
                (mpz((int(p[0]) + 1) % int(pk.q)), *p[1:]),
                request.components[1],
            ),
        )
    elif fault == "policy":
        supplied = replace(supplied, policy="wrong")
    elif fault == "bound":
        supplied = replace(supplied, bounds=(0,))
    else:
        supplied = replace(supplied, cuts=supplied.cuts[:-1])
    calls = []
    monkeypatch.setattr(bgv, "decrypt", lambda *_: calls.append(True))
    monkeypatch.setattr(compact, "decrypt", lambda *_: calls.append(True))
    assert not propagated.check_trace(request, index, count, dim, pk, keys, supplied)
    assert not calls


@pytest.mark.parametrize(
    "fault",
    ["boolean_count", "mutable_frame", "mutable_polynomial", "foreign_cut_type"],
)
def test_exact_replay_uses_strict_immutable_grammar_not_Python_coercive_equality(fault):
    request, index, count, dim, pk, _, keys = fixture()
    supplied = propagated.make_trace(request, index, count, dim, pk, keys)
    if fault == "boolean_count":
        supplied = replace(supplied, count=True)
    elif fault == "mutable_frame":
        supplied = replace(supplied, response=bytearray(supplied.response))
    elif fault == "mutable_polynomial":
        pair = supplied.full_output[0]
        supplied = replace(supplied, full_output=((list(pair[0]), pair[1]),))
    else:
        supplied = replace(supplied, cuts=(object(), *supplied.cuts[1:]))
    assert not propagated.check_trace(request, index, count, dim, pk, keys, supplied)
