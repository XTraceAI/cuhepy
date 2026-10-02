"""Full message/error/permutation checks and precision falsifiers for E89."""

from itertools import product
from math import gcd

import pytest

from experiments.bfv_search_lab import odd_domain_lut as lut


@pytest.mark.parametrize("t,degree", [(3, 4), (3, 16), (5, 16), (9, 32), (17, 64)])
def test_every_message_permutation_admitted_error_and_signed_ring_shift(t, degree):
    functions = (tuple(range(t)), tuple((h * h + 3) % 17 for h in range(t)), tuple(int(h <= t // 3) for h in range(t)))
    for permutation in range(1, t):
        if gcd(permutation, t) != 1:
            continue
        assert lut.spacing(t, degree, permutation) == degree // t
        for values in functions:
            table = lut.compile_lut(values, degree, permutation=permutation)
            for h, center in enumerate(lut.centers(t, degree, permutation)):
                for error in range(-table.allowed_integer_error, table.allowed_integer_error + 1):
                    rotation = (center + error) % (2 * degree)
                    assert lut.evaluate(table, rotation) == lut.roundtrip_reference(table, rotation) == values[h]


def test_whole_arbitrary_nonzero_output_function_space():
    # Complete 3^3 output functions in a small output ring, not a handpicked LUT.
    for values in product(range(3), repeat=3):
        table = lut.compile_lut(values, 16, p=3)
        for h, center in enumerate(lut.centers(3, 16)):
            for error in range(-table.allowed_integer_error, table.allowed_integer_error + 1):
                assert lut.evaluate(table, (center + error) % 32) == values[h]


@pytest.mark.parametrize("t", [2, 4, 8])
def test_even_incompatible_antipodes_reject_general_lut(t):
    points = lut.centers(t, 16)
    assert points[t // 2] == 16 and points[0] == 0
    with pytest.raises(ValueError):
        lut.compile_lut(tuple(range(t)), 16)


def test_insufficient_ring_degree_and_over_radius_failure():
    with pytest.raises(ValueError):
        lut.compile_lut(tuple(range(17)), 16)
    table = lut.compile_lut((1, 2, 3), 16)
    failures = sum(lut.evaluate(table, (center + delta) % 32) != h + 1
                   for h, center in enumerate(lut.centers(3, 16)) for delta in range(-16, 17))
    assert failures > 0


def test_componentwise_rounding_can_move_zero_phase_outside_lookup_margin():
    q, mask, secret, body = 65537, (4097,) * 4, (1,) * 4, 49149
    assert (body + sum(a * s for a, s in zip(mask, secret, strict=True))) % q == 0
    changed = lut.scale_phase(mask, body, secret, q, 8)
    assert changed == 2  # Valid original zero phase, two rotation positions of accumulated rounding.
    table = lut.compile_lut((1, 2, 3), 4)
    assert table.allowed_integer_error == 0 and lut.evaluate(table, changed) != 1


@pytest.mark.parametrize("t,degree,permutation", [(3, 3, 1), (True, 16, 1), (5, 16, 0), (9, 32, 3)])
def test_invalid_lookup_geometries(t, degree, permutation):
    with pytest.raises(ValueError):
        lut.centers(t, degree, permutation)


def test_final_modulus_switch_rounding_remains_when_Q_grows():
    from benchmarks.odd_domain_lut_lab import precision_card

    profile={"n":2048,"modeled_Q":8884180307969,"t":193,"phase_bound":4442090139648,
             "dataset":"toy","profile":"toy"}
    small=precision_card(profile,2048,512)
    assert small["allowed_integer_rotation_error"]==4
    assert small["component_rounding_and_center_quantization_bound"]=="257"
    assert small["no_larger_Q_can_pass_THIS_worst_case_bound"]
    assert small["optional_self_consistent_new_prime_context"] is None
    large=precision_card(profile,131072,512)
    assert large["allowed_integer_rotation_error"]==339
    assert not large["no_larger_Q_can_pass_THIS_worst_case_bound"]
    assert large["optional_self_consistent_new_prime_context"] is not None
    assert large["complete_selection_authentication_ID_coverage_cost"] is None
    # Larger rank can win a component count, without a latency/security claim.
    shape=next(s for s in large["rank_width_component_shapes"] if s["rank"]==4 and s["width"]==8)
    assert shape["component_product_target_20percent_only"]
    assert not shape["same_security_level_or_PBS_parameters_approved"]
