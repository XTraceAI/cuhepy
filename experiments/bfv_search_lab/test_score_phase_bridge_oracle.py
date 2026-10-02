"""Independent exhaustive extraction and conditional conversion boundaries."""

from fractions import Fraction
from itertools import product

import pytest

from experiments.bfv_search_lab import score_phase_bridge_oracle as oracle


@pytest.mark.parametrize("component_count", (2, 3))
def test_extraction_matches_all_degree_two_ring_phases(component_count):
    q, checked = 3, 0
    for coefficients in product(range(q), repeat=2 * component_count):
        components = tuple(coefficients[i:i + 2] for i in range(0, len(coefficients), 2))
        for secret in product(range(q), repeat=2):
            powers = oracle.secret_powers(secret, q, component_count)
            flat = tuple(x for power in powers for x in power)
            phase = oracle.ring_phase(components, secret, q)
            for k in range(2):
                assert oracle.sample_phase(oracle.extract(components, k, q), flat) == phase[k]
                checked += 1
    assert checked == (1458 if component_count == 2 else 13122)


def test_four_coefficient_wrap_sign_and_nontrivial_squared_secret():
    q, secret = 17, (1, 16, 1, 0)
    components = ((2, 3, 5, 7), (11, 13, 16, 2), (3, 1, 6, 9))
    powers = oracle.secret_powers(secret, q, 3)
    assert powers[1] != secret
    for k, phase in enumerate(oracle.ring_phase(components, secret, q)):
        sample = oracle.extract(components, k, q)
        assert oracle.sample_phase(sample, sum(powers, ())) == phase
    assert oracle.extract(components, 0, q).a[:4] == (11, 15, 1, 4)


def test_c2_omission_changes_the_bound_original_phase():
    components, secret, q = ((0, 0), (0, 0), (1, 0)), (1, 0), 17
    assert oracle.ring_phase(components, secret, q) == (1, 0)
    assert oracle.ring_phase(components[:2], secret, q) == (0, 0)


def test_bfv_switch_all_declared_masks_keys_messages_and_errors():
    q, t, target, checked = 101, 5, 256, 0
    for a in product((0, 1, 50, 100), repeat=2):
        for secret in product((-1, 0, 1), repeat=2):
            bound = oracle.bfv_switch_bound(q, t, target, 1, sum(abs(s) for s in secret))
            assert bound["sufficient_strict_margin"]
            for message, noise in product(range(t), (-1, 0, 1)):
                b = (q // t * message + noise - sum(x * s for x, s in zip(a, secret, strict=True))) % q
                sample = oracle.Sample(a, b, q)
                assert oracle.decode_scaled(oracle.sample_phase(sample, secret), q, t) == message
                changed = oracle.scale_sample(sample, target, q)
                assert oracle.decode_scaled(oracle.sample_phase(changed, secret), target, t) == message
                checked += 1
    assert checked == 2160


def test_floor_remainder_and_rounding_secret_norm_are_paid():
    bound = oracle.bfv_switch_bound(101, 5, 256, 1, 2)
    assert bound["error_bound"] == Fraction(6123, 1010)
    assert bound["nearest_message_margin"] == Fraction(128, 5)
    assert not oracle.bfv_switch_bound(101, 5, 8, 1, 2)["sufficient_strict_margin"]
    # Large phase noise can cross an actual decoding boundary, not just fail a bound.
    sample = oracle.Sample((0,), 11, 101)
    assert oracle.decode_scaled(oracle.sample_phase(oracle.scale_sample(sample, 256, 101), (0,)), 256, 5) == 1


def test_rounding_ties_use_repo_rule_and_strict_margins():
    assert [oracle.nearest(x, 2) for x in (-3, -1, 1, 3)] == [-1, 0, 1, 2]
    # Exact midpoint between adjacent messages decodes to the upper one.
    assert oracle.decode_scaled(8, 64, 4) == 1
    assert not oracle.bfv_switch_bound(100, 4, 8, 0, 1)["sufficient_strict_margin"]


def test_bgv_ordinary_bfv_modulus_switch_has_wrong_encoding():
    sample = oracle.Sample((0,), 1, 101)
    assert oracle.decode_bgv(oracle.sample_phase(sample, (0,)), 101, 5) == 1
    converted = oracle.scale_sample(sample, 256, 101)
    assert oracle.decode_scaled(oracle.sample_phase(converted, (0,)), 256, 5) == 0


def test_bgv_plaintext_modulus_scaling_loses_unknown_Q_carry():
    zero, wrapped, secret = oracle.Sample((0,), 0, 101), oracle.Sample((100,), 1, 101), (1,)
    assert oracle.sample_phase(zero, secret) == oracle.sample_phase(wrapped, secret) == 0
    assert oracle.decode_scaled(oracle.sample_phase(oracle.scale_sample(zero, 256, 5), secret), 256, 5) == 0
    assert oracle.decode_scaled(oracle.sample_phase(oracle.scale_sample(wrapped, 256, 5), secret), 256, 5) == 1


def test_crt_reconstruction_and_one_limb_substitution_are_not_authentication():
    moduli = (17, 19)
    for value in range(323):
        residues = tuple(value % p for p in moduli)
        assert oracle.crt_value(residues, moduli) == value
        changed = ((residues[0] + 1) % 17, residues[1])
        assert oracle.crt_value(changed, moduli) != value
    assert oracle.crt_value((0, 0), moduli) == 0
    assert oracle.crt_value((1, 0), moduli) == 171


def test_arbitrary_full_domain_threshold_needs_padding_or_different_PBS():
    table = (1, 1, 1, 0)
    full = tuple(oracle.negacyclic_lookup(table, h) for h in range(8))
    assert full != tuple(int(h < 3) for h in range(8))
    assert full[4] == -1
    # Restricted domain is padded into the first half; this is a known control.
    assert full[:4] == tuple(int(h < 3) for h in range(4))


@pytest.mark.parametrize("bad", (True, -1, 101))
def test_noncanonical_sample_body_is_rejected(bad):
    with pytest.raises(ValueError):
        oracle.scale_sample(oracle.Sample((1,), bad, 101), 256, 101)


def test_caps_wrong_components_and_CRT_context_are_rejected():
    with pytest.raises(ValueError):
        oracle.extract(((0,) * 16,) * 3, 0, 17)
    with pytest.raises(ValueError):
        oracle.extract(((0, 1), (1,)), 0, 17)
    with pytest.raises(ValueError):
        oracle.crt_value((17, 0), (17, 19))
    with pytest.raises(ValueError):
        oracle.crt_value((0, 0), (17, 17))
    with pytest.raises(ValueError):
        oracle.bfv_switch_bound(101, 5, 256, -1, 2)
