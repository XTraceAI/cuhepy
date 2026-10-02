"""E88 full tiny phases, block reuse and slot-diagonal counterexamples."""

from itertools import product
from random import Random

import pytest

from experiments.bfv_search_lab import orbit_common_mask as orbit
from experiments.bfv_search_lab.test_batched_score_bridge import phase_reference, powers_reference, product_reference


def check_blocks(components, source, q):
    common = orbit.view(components, q)
    assert orbit.restore(common) == components
    families = powers_reference(source, len(components), q)
    expected = phase_reference(components, source, q)
    assert orbit.local_phases(common, families) == expected
    equalities = 0
    for start in range(common.n):
        for width in range(1, common.n - start + 1):
            masks, bodies = orbit.block(common, start, width)
            canonical = tuple(orbit.orbit_rows(secret, q)[:width] for secret in families)
            actual = tuple((bodies[k] + sum(sum(a * s for a, s in zip(mask, rows[k], strict=True))
                                          for mask, rows in zip(masks, canonical, strict=True))) % q
                           for k in range(width))
            assert actual == expected[start:start + width]
            equalities += width
    return equalities


@pytest.mark.parametrize("count", [2, 3])
def test_all_tiny_ring_views_and_all_blocks(count):
    for source in product(range(3), repeat=2):
        for values in product(range(3), repeat=2 * count):
            components = tuple(values[i:i + 2] for i in range(0, len(values), 2))
            check_blocks(components, source, 3)


@pytest.mark.parametrize("n", [4, 8, 16])
def test_seeded_all_block_shapes_and_prefix_support(n):
    rng = Random(n + 25)
    for prefix in range(1, n + 1):
        source = tuple(rng.choice((-1, 0, 1)) for _ in range(prefix)) + (0,) * (n - prefix)
        components = tuple(tuple(rng.randrange(17) for _ in range(n)) for _ in range(3))
        check_blocks(components, source, 17)
        for width in range(1, n + 1):
            support = orbit.public_union_support(n, prefix, width)
            assert len(support) == min(n, prefix + width - 1)
            for row in orbit.orbit_rows(source, 17)[:width]:
                assert all(x == 0 for j, x in enumerate(row) if j not in support)


def test_complete_orbit_secret_law_differs_from_independent_matrix():
    matrices = {orbit.orbit_rows(secret, 17) for secret in product((-1, 0, 1), repeat=2)}
    assert len(matrices) == 9
    # Independent two length-2 ternary secrets admit 3^4 matrices instead.
    assert 3**4 == 81 and ((1, 0), (1, 0)) not in matrices


@pytest.mark.parametrize("n", [2, 4, 8])
def test_every_binary_slot_diagonal_ring_membership(n):
    commuting = [diagonal for diagonal in product((0, 1), repeat=n)
                 if orbit.diagonal_commutes_shift(diagonal, 17)]
    assert commuting == [(0,) * n, (1,) * n]


def test_full_toy_input_domain_rejects_coefficientwise_ring_product_surrogate():
    diagonal, bad, total = (1, 0), 0, 0
    for values in product(range(3), repeat=2):
        expected = tuple(d * x % 3 for d, x in zip(diagonal, values, strict=True))
        surrogate = product_reference(diagonal, values, 3)
        bad += surrogate != expected
        total += 1
    assert total == 9 and bad == 6


def test_same_mask_same_secret_shortcut_reveals_message_difference():
    mask, secret, messages, q = (4, 7), (1, -1), (2, 6), 17
    bodies = tuple((m - sum(a * s for a, s in zip(mask, secret, strict=True))) % q for m in messages)
    assert (bodies[0] - bodies[1]) % q == (messages[0] - messages[1]) % q
    assert orbit.orbit_rows(secret, q)[0] != orbit.orbit_rows(secret, q)[1]


@pytest.mark.parametrize("start,width", [(True, 1), (0, 0), (1, 2), (-1, 1)])
def test_invalid_block_coverage(start, width):
    with pytest.raises(ValueError):
        orbit.block(orbit.view(((0, 1), (1, 0)), 17), start, width)


def test_paid_orbit_keys_compare_shared_baseline_and_compact_key_control():
    from benchmarks.orbit_common_mask_lab import key_card

    profile = {"n": 4, "replies": 1, "dataset": "toy", "profile": "toy"}
    card = key_card(profile, 2, 2)
    assert card["common_input_dimension_after_public_support_trim"] == 3
    assert card["CM_BSK_unseeded_u64_bytes_per_binary_indicator"] == 1769472
    assert card["shared_ordinary_BSK_unseeded_u64_bytes_per_binary_indicator"] == 524288
    assert card["CM_vs_shared_ordinary_unseeded_key_coefficient_ratio"] == "27/8"
    assert card["dense_product_count_ratio_not_latency_prediction"] == "27/16"
    assert card["CM_PBS_blocks_required_for_all_coefficients"] == 2
    assert len(card["CM_Appendix_C1_four_compact_regeneration_terms_u64_bytes"]) == 4
    assert card["compact_authentication_and_stable_ID_winner_trace_costs"] is None
    assert card["published_seeded_formula_vs_literal_requires_artifact_or_format_review"]
    assert card["signed_ternary_two_indicator_families_would_double_base_keys"]
