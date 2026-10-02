"""The correct public unit bridge, independent BGV decode and negative margins."""

from itertools import product

import pytest

from experiments.bfv_search_lab import bgv_unit_bridge as bridge
from experiments.bfv_search_lab import score_phase_bridge_oracle as oracle
from experiments.bfv_search_lab import shallow_bgv as bgv


@pytest.mark.parametrize("q,t", ((17, 3), (101, 5), (103, 5), (323, 5), (257, 17)))
def test_all_centered_phases_convert_with_known_permutation(q, t):
    for sign in (-1, 1):
        context = bridge.unit_parameters(q, t, sign=sign)
        for signed in range(-(q // 2), q // 2 + 1):
            phase = signed % q
            changed = context["multiplier"] * phase % q
            assert bridge.scaled_decode_reference(changed, q, t, sign=sign) == signed % t


def test_every_mask_key_and_centered_phase_at_small_modulus():
    q, t, checked = 17, 3, 0
    context = bridge.unit_parameters(q, t)
    for a, secret, signed in product(range(q), (-1, 0, 1), range(-8, 9)):
        original = oracle.Sample((a,), (signed - a * secret) % q, q)
        changed = oracle.Sample((context["multiplier"] * a % q,),
                                context["multiplier"] * original.b % q, q)
        assert bridge.scaled_decode_reference(oracle.sample_phase(changed, (secret,)), q, t) == signed % t
        checked += 1
    assert checked == 867


@pytest.mark.parametrize("components", (2, 3))
def test_all_small_ring_ciphertexts_convert_every_original_phase(components):
    q, t = 3, 2
    for values in product(range(q), repeat=2 * components):
        original = tuple(values[i:i + 2] for i in range(0, len(values), 2))
        changed = bridge.convert(original, q, t)
        for secret in product(range(q), repeat=2):
            before = oracle.ring_phase(original, secret, q)
            after = oracle.ring_phase(changed, secret, q)
            for a, b in zip(before, after, strict=True):
                assert bridge.scaled_decode_reference(b, q, t) == oracle.decode_bgv(a, q, t)


def test_unit_carry_corrects_the_E85_counterexample():
    context, secret = bridge.unit_parameters(101, 5), (1,)
    assert context["multiplier"] == 81 and context["plaintext_permutation_multiplier"] == 4
    for a, b in ((0, 0), (100, 1)):
        sample = oracle.Sample((a * 81 % 101,), b * 81 % 101, 101)
        assert bridge.scaled_decode_reference(oracle.sample_phase(sample, secret), 101, 5) == 0
    # Sign -1 at Q=1 mod t is the ordinary BFV Delta, with identity permutation.
    standard = bridge.unit_parameters(101, 5, sign=-1)
    assert standard["multiplier"] == 20 and standard["plaintext_permutation_multiplier"] == 1


def test_unit_then_torus_switch_matches_all_declared_safe_cases():
    q, t, target, checked = 101, 5, 256, 0
    context = bridge.unit_parameters(q, t)
    bound = bridge.switched_bound(q, t, target, 10, 2)
    assert bound["sufficient_strict_margin"]
    for a in product((0, 1, 50, 100), repeat=2):
        for secret in product((-1, 0, 1), repeat=2):
            for signed in range(-10, 11):
                b = (signed - sum(x * s for x, s in zip(a, secret, strict=True))) % q
                unit = oracle.Sample(tuple(x * context["multiplier"] % q for x in a),
                                     b * context["multiplier"] % q, q)
                torus = oracle.scale_sample(unit, target, q)
                permuted = oracle.decode_scaled(oracle.sample_phase(torus, secret), target, t)
                assert permuted * context["plaintext_permutation_inverse"] % t == signed % t
                checked += 1
    assert checked == 3024


def test_original_BGV_correctness_does_not_guarantee_new_torus_margin():
    assert not bridge.switched_bound(101, 5, 8, 50, 1)["sufficient_strict_margin"]
    context = bridge.unit_parameters(101, 5)
    failures = []
    for a, signed in product(range(101), range(-50, 51)):
        unit = oracle.Sample((a * context["multiplier"] % 101,),
                             (signed - a) * context["multiplier"] % 101, 101)
        torus = oracle.scale_sample(unit, 8, 101)
        decoded = oracle.decode_scaled(oracle.sample_phase(torus, (1,)), 8, 5)
        if decoded * context["plaintext_permutation_inverse"] % 5 != signed % 5:
            failures.append((a, signed))
    assert failures  # Require actual errors, rather than treating a loose bound as proof.


def test_homemade_BGV_depth_one_product_differential():
    pk, sk = bgv.key_gen(n=8, t=17, q_bits=32, eta=1)
    left, right = [1, 0, 1, 1, 0, 1, 0, 0], [0, 1, 1, 0, 0, 1, 0, 1]
    result = bgv.multiply(bgv.encrypt(left, pk), bgv.encrypt(right, pk), pk)
    expected = bgv.decrypt(result, pk, sk)
    transformed = bridge.convert(tuple(tuple(int(x) for x in poly) for poly in result.components), int(pk.q), pk.t)
    # Direct schoolbook decryption differs from shallow_bgv's GMP ring product.
    q, n = int(pk.q), pk.n
    def multiply(a, b):
        output = [0] * n
        for i, x in enumerate(a):
            for j, y in enumerate(b):
                output[(i + j) % n] += x * y * (1 if i + j < n else -1)
        return tuple(x % q for x in output)
    secret = tuple(int(x) for x in sk.s)
    squared = multiply(secret, secret)
    phase = tuple((a + b + c) % q for a, b, c in zip(transformed[0],
                  multiply(transformed[1], secret), multiply(transformed[2], squared), strict=True))
    assert [bridge.scaled_decode_reference(x, q, pk.t) for x in phase] == expected


def test_inverse_unit_map_recovers_every_public_component():
    original = ((0, 1, 50, 100), (13, 17, 23, 71), (19, 0, 98, 7))
    q, t = 101, 5
    changed = bridge.convert(original, q, t)
    assert tuple(tuple(x * t % q for x in poly) for poly in changed) == original


@pytest.mark.parametrize("q,t", ((15, 3), (True, 2), (17, 17)))
def test_nonunit_invalid_context_rejected(q, t):
    with pytest.raises(ValueError):
        bridge.unit_parameters(q, t)


def test_original_component_range_and_conditional_phase_bound_required():
    with pytest.raises(ValueError):
        bridge.convert(((101,), (1,)), 101, 5)
    with pytest.raises(ValueError):
        bridge.convert(((1,),), 101, 5)
    with pytest.raises(ValueError):
        bridge.switched_bound(101, 5, 256, 51, 1)
    with pytest.raises(ValueError):
        bridge.unit_parameters(101, 5, sign=True)
