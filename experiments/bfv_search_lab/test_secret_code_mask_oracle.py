"""E82 independent finite laws, minimal-support counts and carry controls."""

from fractions import Fraction
from itertools import product

import pytest

from experiments.bfv_search_lab import secret_code_mask_oracle as oracle


def test_individually_uniform_blocks_have_an_exact_joint_syndrome():
    p = ((1, 0), (0, 1), (1, 1))
    law = oracle.joint_projection_law(p, 3)
    assert oracle.rank(p, 3) == 2 and len(law) == 9
    for i in range(3):
        assert {sum(count for r, count in law.items() if r[i] == x) for x in range(3)} == {3}
    assert all((r[2] - r[0] - r[1]) % 3 == 0 for r in law)
    # A query shift outside that public subspace changes an exact invariant.
    shifted = {(*r[:2], (r[2] + 1) % 3) for r in law}
    assert not shifted.intersection(law)


def test_full_joint_rank_is_uniform_but_supplies_no_entropy_saving():
    p = ((1, 0, 1), (0, 1, 1), (0, 0, 1))
    law = oracle.joint_projection_law(p, 3)
    assert oracle.rank(p, 3) == 3 and len(law) == 27
    assert set(law.values()) == {1}


def test_secret_line_has_a_distinguishable_single_query_law():
    left = oracle.secret_line_transcript_law(((0, 0, 0),), 3)
    right = oracle.secret_line_transcript_law(((1, 0, 0),), 3)
    # Independently: zero has mass 1/q, every nonzero vector mass
    # (q-1)/(q*(q**n-1)); translation changes two entries.
    expected = Fraction(1, 3) - Fraction(2, 3 * 26)
    assert oracle.total_variation(left, right) == expected == Fraction(4, 13)


def test_uniform_fixed_offset_hides_constant_queries_but_not_differences():
    zero, other = (0, 0, 0), (1, 0, 0)
    left = oracle.secret_line_transcript_law((zero, zero), 3, affine_offset=True)
    same = oracle.secret_line_transcript_law((other, other), 3, affine_offset=True)
    changed = oracle.secret_line_transcript_law((zero, other), 3, affine_offset=True)
    assert left == same
    assert oracle.total_variation(left, changed) == Fraction(4, 13)


@pytest.mark.parametrize("bits,prime", ((2, 3), (3, 5), (4, 5), (5, 3), (6, 3)))
def test_bitline_minimal_support_formula_by_all_codewords(bits, prime):
    actual = set(oracle.enumerate_minimal_supports(bits, prime))
    expected = set(oracle.predicted_minimal_supports(bits))
    assert actual == expected and len(actual) == bits + 2 ** bits
    for pattern in product((0, 1), repeat=bits):
        receiver = {2 * i + b for i, b in enumerate(pattern)}
        assert sum(bool(receiver.intersection(s)) for s in actual) == len(actual) - 1


@pytest.mark.parametrize("bits,prime", ((2, 3), (3, 5)))
def test_projection_recipient_extra_view_has_an_exact_simulator(bits, prime):
    real, simulated = oracle.bitline_real_and_simulated_laws(bits, prime)
    assert real == simulated
    for a, b, x, y, observations in real:
        assert y == (a * x + b) % prime == sum(observations) % prime


def test_centered_plain_field_relation_is_not_a_full_ciphertext_field_relation():
    # Canonical t=5 sum is 4 (centered -1), not the sum of lifts 2+2.
    assert oracle.field_lift(4, 5) == -1
    assert (oracle.field_lift(2, 5) * 2 - oracle.field_lift(4, 5)) % 17 == 5


def test_oracle_caps_and_canonical_fields_precede_allocation():
    with pytest.raises(ValueError):
        oracle.secret_line_transcript_law(((0,) * 4,) * 4, 17, affine_offset=True)
    with pytest.raises(ValueError):
        oracle.joint_projection_law(((True,),), 3)
    with pytest.raises(ValueError):
        oracle.enumerate_minimal_supports(7, 17)
    with pytest.raises(ValueError):
        oracle.bitline_projection(1, (0, 0), 3, 3)
    with pytest.raises(ValueError):
        oracle.rank(((1,),), 15)
