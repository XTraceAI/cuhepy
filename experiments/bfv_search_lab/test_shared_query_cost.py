"""Q75 independent finite-grammar oracle and known-control whole-vector checks.

The graph fixtures are arbitrary public ring instances, not HE key contexts.
They test algebra/compiler equality, not encryption correctness or assurance.
"""

from dataclasses import asdict, replace
from itertools import permutations
from math import prod
import random

from gmpy2 import mpz
import pytest

from cuhepy.bfv.scheme import _rns_coefficient_primes
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import noise_cut_fusion as fusion
from experiments.bfv_search_lab import noise_cut_shape as shape
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_bgv as shared
from experiments.bfv_search_lab import shared_query_cost as cost
from experiments.bfv_search_lab.shared_query_bounds import Profile


def exhaustive(points):
    """Independent all-pairs oracle, with explicit strict inequality and ties."""
    answer = []
    for i, point in enumerate(points):
        less = False
        for j, other in enumerate(points):
            if i == j:
                continue
            comparison = [other.costs[k][1] - point.costs[k][1] for k in range(len(point.costs))]
            if max(comparison) <= 0 and min(comparison) < 0:
                less = True
                break
        if not less:
            answer.append(point.name)
    return tuple(sorted(answer))


@pytest.mark.parametrize("seed", range(6))
def test_finite_selector_matches_exhaustive_oracle_and_preserves_ties(seed):
    rng = random.Random(seed)
    points = tuple(
        cost.Point(
            str(i), tuple((name, rng.randrange(10)) for name in ("wire", "work", "state", "update"))
        )
        for i in range(8)
    )
    points = (*points[:-1], cost.Point("tie", points[0].costs))
    expected = exhaustive(points)
    for order in (points, points[::-1], tuple(rng.sample(points, len(points)))):
        assert tuple(p.name for p in cost.frontier(order)) == expected


def test_evaluator_only_and_full_cost_choose_different_declared_options():
    points = (
        cost.Point("low_evaluator_work", (("evaluator", 5), ("wire", 100), ("checker", 80))),
        cost.Point("balanced", (("evaluator", 8), ("wire", 20), ("checker", 30))),
        cost.Point("dominated", (("evaluator", 12), ("wire", 40), ("checker", 50))),
    )
    for order in permutations(points):
        assert {p.name for p in cost.frontier(order)} == {"low_evaluator_work", "balanced"}
    assert min(points, key=lambda p: p.costs[0][1]).name == "low_evaluator_work"
    assert min(points, key=lambda p: sum(v for _, v in p.costs)).name == "balanced"
    # Synthetic discriminator only, not a measured deployment speedup.


@pytest.mark.parametrize(
    "fault", ["empty", "duplicate", "coordinates", "mutable", "negative", "boolean"]
)
def test_selector_rejects_incomplete_or_incomparable_cards(fault):
    p = cost.Point("a", (("x", 1),))
    with pytest.raises(ValueError):
        if fault == "negative":
            cost.Point("a", (("x", -1),))
        elif fault == "boolean":
            cost.Point("a", (("x", True),))
        else:
            cost.frontier(
                {
                    "empty": (),
                    "duplicate": (p, p),
                    "coordinates": (p, cost.Point("b", (("y", 1),))),
                    "mutable": [p],
                }[fault]
            )


@pytest.mark.parametrize("policy", ["canonical30", "derived_last30"])
def test_same_known_Karatsuba_pairing_fusion_preserves_all_residuals(policy):
    n, d, t = 16, 3, 11
    q = prod(map(int, _rns_coefficient_primes(n, 120)))
    p = int(compact.terminal_modulus(mpz(q), t, 25))
    profile = Profile(n, d, q, p, t, 1, "owner", policy)
    rng = random.Random(7504)

    def poly():
        return tuple(rng.randrange(q) for _ in range(n))

    def key():
        return tuple((poly(), poly()) for _ in range(profile.ell))

    ctx = shared.Context(
        profile,
        "0" * 64,
        (poly(), poly()),
        tuple((poly(), poly()) for _ in range(2 * d)),
        tuple(range(n + 1)),
        key(),
        tuple((1 + n // (1 << level), key()) for level in range(profile.levels)),
    )
    pk = bgv.PublicKey(n, t, mpz(q), 1, poly(), poly(), ctx.key_id)
    transcript, _ = shared.produce(ctx, pk)
    rel = shared.compile_relation(ctx)
    graph, layouts = shared.symbolic_graph(profile, ctx.groups, karatsuba=True, paired=True)
    assert layouts == rel.source_layout
    constants = {fusion.Public(name): row for name, row in shared.public_constants(ctx).items()}
    direct, rewritten = shape.direct_graph(graph), fusion.fuse(graph).graph
    for bad in (False, True):
        sources = transcript.sources
        if bad:
            first = sources[0]
            sources = (
                replace(first, polynomial=((first.polynomial[0] + 1) % q, *first.polynomial[1:])),
                *sources[1:],
            )
        bindings = fusion.bindings(rel, sources, transcript.full_output)
        expected = fusion.evaluate(direct, bindings, fusion.coefficients(direct, constants))
        assert (
            fusion.evaluate(rewritten, bindings, fusion.coefficients(rewritten, constants))
            == expected
        )
        assert any(any(row) for row in expected) is bad


def test_paid_cards_keep_integer_state_and_full_updates_separate():
    q = prod(map(int, _rns_coefficient_primes(16, 120)))
    p = int(compact.terminal_modulus(mpz(q), 11, 25))
    profile = Profile(16, 3, q, p, 11, 1, "owner", "derived_last30")
    card = cost.compile_card(profile, 17, 2, "same_bounded_generic_fusion", "cached_public_recipes")
    assert card["producer"]["additional_exact_integer_state_ring_products"] == profile.ell**2
    assert card["fixed_32_row_update_model"]["feature_ciphertexts_reencrypted"] == profile.dimension
    assert dict(card["point"].costs)["whole_terminal_roundings"] == 4 * profile.n
    assert card["ledger"]["online"]["fresh_row_field_elements"] == 0
    assert card["unknown_complete_service_costs"]
    assert asdict(card["point"])["name"].startswith("derived_last30/")
