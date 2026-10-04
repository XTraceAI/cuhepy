"""Q75 finite resource selector and paid shared-query cost cards.

Ordinary Pareto selection is a known control. No optimality is claimed outside
the registered policy/rewrite/residency grammar. Counts are sufficient models,
not timings, native peaks, security estimates or complete deployment prices.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.bfv_search_lab import noise_cut_fusion as fusion
from experiments.bfv_search_lab import noise_cut_shape as shape
from experiments.bfv_search_lab import shared_query_bgv as shared


@dataclass(frozen=True)
class Point:
    name: str
    costs: tuple[tuple[str, int], ...]

    def __post_init__(self):
        if (
            type(self.name) is not str
            or not self.name
            or type(self.costs) is not tuple
            or not self.costs
            or any(
                type(pair) is not tuple
                or len(pair) != 2
                or type(pair[0]) is not str
                or type(pair[1]) is not int
                or pair[1] < 0
                for pair in self.costs
            )
            or len({k for k, _ in self.costs}) != len(self.costs)
        ):
            raise ValueError("Unique nonnegative exact-integer resource coordinates required")


def dominates(a, b):
    if tuple(k for k, _ in a.costs) != tuple(k for k, _ in b.costs):
        raise ValueError("Matched resource coordinates required")
    pairs = tuple(zip((v for _, v in a.costs), (v for _, v in b.costs), strict=True))
    return all(x <= y for x, y in pairs) and any(x < y for x, y in pairs)


def frontier(points):
    """Incremental antichain within one explicit finite grammar; ties survive."""
    if (
        type(points) is not tuple
        or not points
        or any(type(p) is not Point for p in points)
        or len({p.name for p in points}) != len(points)
    ):
        raise ValueError("Complete unique immutable cost cards required")
    keys = tuple(k for k, _ in points[0].costs)
    if any(tuple(k for k, _ in p.costs) != keys for p in points):
        raise ValueError("Matched resource coordinates required")
    kept = []
    for candidate in points:
        if any(dominates(p, candidate) for p in kept):
            continue
        kept = [p for p in kept if not dominates(candidate, p)]
        kept.append(candidate)
    return tuple(sorted(kept, key=lambda p: p.name))


def compile_card(profile, count, primes, rewrite, residency):
    if rewrite not in ("direct_generic", "same_bounded_generic_fusion") or residency not in (
        "cached_public_recipes",
        "per_use_public_recipe_recomputation",
    ):
        raise ValueError("Outside registered rewrite/residency grammar")
    inventory = profile.inventory(count, primes)
    graph, layouts = shared.symbolic_graph(
        profile, inventory["groups"], karatsuba=True, paired=True
    )
    boundaries = ()
    if rewrite == "direct_generic":
        graph = shape.direct_graph(graph)
    else:
        compiled = fusion.fuse(graph, fusion.Limits())
        graph, boundaries = compiled.graph, compiled.boundaries
    # Zero rounds: full-coordinate equality, no randomized batching authorized.
    ledger = fusion.resource_ledger(graph, rounds=0, primes=primes)
    ledger["scope"] = (
        f"Sufficient exact symbolic DAG/recipe counts for {primes} actual uint64 prime limbs; whole-coordinate comparison, no random row. No native peaks/timing, canonical extraction/CRT, framing, attestation/private work, or parameter approval."
    )
    online, setup, streaming = (
        ledger[k]
        for k in ("online", "cached_preparation", "on_demand_public_preparation_per_query")
    )
    cached = residency == "cached_public_recipes"
    _recipes, _finals, dependencies = fusion.public_recipes(graph)
    changed = sum(
        any(
            atom.name[0] in ("index", "index-sum", "index-digit")
            and atom.name[1] < profile.dimension
            for atom in atoms
        )
        for atoms in dependencies.values()
    )
    state_products = inventory["retained_integer_state_anchor_nodes"] * profile.ell**2
    # Both siblings share the correction. Signed permutation/add work remains.
    producer = {
        "switch_ring_products": 2 * profile.ell * (profile.padded - 1 + inventory["groups"]),
        "known_Karatsuba_tensor_ring_products": 3 * profile.dimension * inventory["groups"],
        "reference_four_product_tensor_ring_products": 4 * profile.dimension * inventory["groups"],
        "additional_exact_integer_state_ring_products": state_products,
        "additional_integer_state_polynomial_add_sub_passes": inventory[
            "retained_integer_state_anchor_nodes"
        ]
        * (profile.ell**2 + 2 * profile.ell),
        "additional_integer_state_signed_permutation_passes": inventory[
            "retained_integer_state_anchor_nodes"
        ]
        * 2
        * profile.ell,
        "integer_state_signed_coefficient_bound_bits": profile.retained_state_bound.bit_length()
        if state_products
        else 0,
        "canonical_source_coefficients_extracted": len(layouts) * profile.n,
        "scope": "Arithmetic inventory. Q74 producer uses four products; three-product known rewrite is exact-checked for Q75 graph but no native timing or optimized producer measurement. Integer state has larger operands and is not equated to one modular product in latency.",
    }
    prices = {
        "witness_and_terminal_Q_coefficient_body_bytes": inventory[
            "source_and_terminal_Q_body_bytes"
        ],
        "evaluation_key_Q_coefficient_body_bytes": inventory[
            "evaluation_key_Q_coefficient_body_bytes"
        ],
        "encrypted_index_body_bytes": inventory["index_coefficient_and_seed_body_bytes"],
        "query_seed_and_coefficient_body_bytes": inventory[
            "seeded_query_coefficient_and_seed_body_bytes"
        ],
        "compact_response_coefficient_body_bytes": inventory[
            "complete_compact_coefficient_body_bytes"
        ],
        "producer_modular_ring_products": producer["switch_ring_products"]
        + producer["known_Karatsuba_tensor_ring_products"],
        "producer_additional_integer_ring_products": state_products,
        "verifier_input_forward_prime_NTTs": online["input_forward_prime_NTTs"],
        "verifier_DAG_word_products": online["DAG_word_product_count"],
        "verifier_add_sub_words": online["polynomial_add_sub_passes"] * profile.n * primes,
        "verifier_permutation_words": online["polynomial_automorphism_permutation_passes"]
        * profile.n
        * primes,
        "verifier_all_residual_zero_comparisons": len(graph.residuals) * profile.n * primes,
        "common_Q_digit_mask_extracts": len(layouts) * profile.n * profile.ell,
        "whole_terminal_roundings": 2 * inventory["groups"] * profile.n,
        "cached_setup_forward_prime_NTTs": setup["public_atomic_forward_prime_NTTs"]
        if cached
        else 0,
        "cached_setup_word_products": setup["setup_word_products"] if cached else 0,
        "public_preparation_per_query_forward_prime_NTTs": 0
        if cached
        else streaming["per_query_public_atomic_forward_prime_NTTs"],
        "public_preparation_per_query_word_products": 0
        if cached
        else streaming["per_query_public_setup_word_products"],
        "scheduled_dynamic_live_RNS_word_bytes": online["live_dynamic_RNS_word_bytes"],
        "cached_public_multiplier_RNS_word_bytes": setup["cached_public_multiplier_RNS_word_bytes"]
        if cached
        else 0,
        "public_preparation_scheduled_peak_RNS_word_bytes": setup[
            "scheduled_public_setup_live_RNS_word_bytes"
        ]
        if cached
        else streaming["sufficient_public_recipe_peak_RNS_word_bytes"],
        "extra_raw_key_A_digit_body_bytes": inventory[
            "additional_shared_key_A_canonical_digit_body_bytes"
        ],
        "first_group_32_row_update_invalidated_cached_RNS_bytes": changed * profile.n * primes * 8
        if cached
        else 0,
    }
    name = f"{profile.policy}/{rewrite}/{residency}"
    return {
        "point": Point(name, tuple(prices.items())),
        "inventory": inventory,
        "producer": producer,
        "ledger": ledger,
        "source_layout_count": len(layouts),
        "fusion_boundary_count": len(boundaries),
        "graph_nodes": len(graph.nodes),
        "fixed_32_row_update_model": {
            "placement": "Up to 32 existing rows within the first group; affects all its feature ciphertexts. No key/context change.",
            "existing_rows_changed": min(32, count, profile.n),
            "feature_ciphertexts_reencrypted": profile.dimension,
            "public_base_component_prime_NTTs": 2 * profile.dimension * primes,
            "affected_union_of_cached_recipe_polynomials": changed,
            "scope": "Dependency invalidation only; actual authenticated encryption/update/preparation critical path remains unmeasured.",
        },
        "unknown_complete_service_costs": [
            "key generation/encryption/client acquisition and decryption/selection latency",
            "native common-Q unpack/range/CRT/digit work and coefficient rounding latency",
            "NTT roots/scratch/maps, allocation and measured peak memory",
            "packet headers/parsing/serialization/signing/transport and actual critical path",
            "authenticated updates/durable epoch/restart/freshness/attestation and private side channels",
        ],
        "originality": "The equally specialized known combination uses exactly this program and every rewrite/residency choice. No new algebra or optimal compiler from this card.",
    }


def replay_card(profile, count, primes):
    """Known equally rewritten canonical replay; all canonical boundaries paid."""
    inventory = profile.inventory(count, primes)
    switches = profile.padded - 1 + inventory["groups"]
    return {
        "source_witness_bytes": 0,
        "untrusted_terminal_Q_body_bytes": 0,
        "query_and_compact_response_body_bytes": inventory[
            "seeded_query_coefficient_and_seed_body_bytes"
        ]
        + inventory["complete_compact_coefficient_body_bytes"],
        "canonical_switches": switches,
        "known_modular_ring_products": 2 * profile.ell * switches
        + 3 * profile.dimension * inventory["groups"],
        "canonical_digit_forward_prime_NTTs": switches * profile.ell * primes,
        "original_query_forward_prime_NTTs": 2 * primes,
        "source_reconstruction_inverse_prime_NTTs": switches * primes,
        "terminal_inverse_prime_NTTs": 2 * inventory["groups"] * primes,
        "canonical_source_common_Q_CRT_coefficients": switches * profile.n,
        "whole_terminal_roundings": 2 * inventory["groups"] * profile.n,
        "expansion_stages_with_internal_canonical_boundary": profile.levels,
        "reuse_and_generic_rewrites": "Same feature-major layout, once-per-query expansion, lazy relin, Karatsuba, cache/streaming/fusion possibilities. These producer-stage counts are not a verifier latency lower bound.",
        "status": "Unmeasured paired replay model; do not price as old unoptimized replay or claim exact optimal NTT schedule.",
    }
