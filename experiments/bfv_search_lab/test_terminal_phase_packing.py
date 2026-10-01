"""Signed carry, independent negacyclic phase and optimistic body controls."""

import itertools

import pytest

from experiments.bfv_search_lab import reduction_oracles as integer
from experiments.bfv_search_lab import terminal_phase_packing as packing


def test_exhaustive_signed_phase_packing_preserves_full_Q_before_score_reduction():
    n, q, t, count = 2, 17, 3, 0
    bound = packing.integer_bound(n, q, 1)
    for c0 in itertools.product((-8, 0, 8), repeat=n):
        for c1 in itertools.product((-8, 0, 8), repeat=n):
            for secret in itertools.product((-1, 0, 1), repeat=n):
                product = integer.ring_product(c1, secret)
                phases = tuple(a+b for a, b in zip(c0, product, strict=True))
                # Independent closed form for N=2, with the negative wrap.
                assert phases == (c0[0]+c1[0]*secret[0]-c1[1]*secret[1],
                                  c0[1]+c1[0]*secret[1]+c1[1]*secret[0])
                packets = packing.pack(phases, bound, 31)
                restored = packing.unpack(packets, n, bound, 31)
                assert restored == phases
                residues = []
                for x in phases:
                    while x > q//2:
                        x -= q
                    while x < -q//2:
                        x += q
                    residues.append(x % t)
                assert packing.field_decode(restored, q, t) == tuple(residues)
                count += 1
    assert count == 729


def test_bias_and_Q_carry_are_both_necessary():
    assert packing.field_decode((18,), 17, 3) == (1,)
    assert packing.field_decode((18,), 17, 3) != (18 % 3,)
    # Naive signed concatenation borrows into the next limb.
    naive, mask = -1, 15
    assert tuple((naive >> (4*j)) & mask for j in range(2)) == (15, 15)
    packets = packing.pack((-1, 0), 7, 8)
    assert packing.unpack(packets, 2, 7, 8) == (-1, 0)
    with pytest.raises(ValueError, match="Noncanonical"):
        packing.unpack((256,), 2, 7, 8)
    with pytest.raises(ValueError, match="range"):
        packing.unpack((15,), 1, 7, 8)


def test_raw_integer_additive_control_loses_even_before_new_key_and_proof():
    control = packing.cost(n=16384, q=4294955009, phases=16384)
    assert control["biased_phase_limb_bits"] == 47
    assert control["additive_to_full_body_ratio"] > 1
    assert control["additive_reply_body_bytes"] > control["ideal_public_C1_recipe_C0_body_bytes"]
    assert not control["rescaling_or_smaller_modulus_correctness_established"]
