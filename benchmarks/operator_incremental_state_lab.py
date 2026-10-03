#!/usr/bin/env python3
"""Q59 bounded exact algebra and static update-support panel, no timings."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random

from experiments.bfv_search_lab import operator_incremental_state as update
from experiments.bfv_search_lab import operator_state_discriminator as state


def tiny_panel():
    cards = []
    rng = random.Random(5903)
    for n, padded, tiles in ((8, 4, 3), (16, 8, 8)):
        graph = state.butterfly_graph(n, padded, tiles, 2)
        symbols = {a.symbol for node in graph.nodes for _, op in node.inputs
                   for a, _ in op.terms if a.symbol}
        fixed = {name: tuple(rng.randrange(18721) for _ in range(n)) for name in sorted(symbols)}
        diagnostic_supports = {"one-row-tile-support": frozenset((0,)),
                               "one-tile-support": frozenset((0,)),
                               "dispersed-tile-support": frozenset(range(0, tiles, 2)),
                               "whole-snapshot-support": frozenset(range(tiles))}
        for policy in ("every-local", "product-cut", "maximal-affine"):
            cuts = state.cuts_for(graph, policy)
            equations = state.compile_equations(graph, cuts)
            signature = update.index_dependency_invariant(equations)
            for label, changed_tiles in diagnostic_supports.items():
                after = dict(fixed)
                for tile in changed_tiles:
                    for k in range(2):
                        name = f"index:{tile}:{k}"
                        after[name] = tuple(rng.randrange(18721) for _ in range(n))
                delta, changed = update.index_delta(fixed, after)
                for prime in (97, 193):
                    for round_id in range(3):
                        coins = update.DiagnosticCoins(prime, tuple((s, rng.randrange(prime)) for s in equations),
                                                       tuple(rng.randrange(prime) for _ in range(n)))
                        before = update.query_adjoints(equations, fixed, coins)
                        fresh = update.query_adjoints(equations, after, coins)
                        difference = update.query_adjoints(equations, delta, coins, delta=True)
                        generic_difference = update.query_adjoints(equations, delta, coins, delta=True,
                                                                   dense_control=True)
                        incremental = update.apply_delta(before, difference, prime)
                        assert incremental == fresh and difference == generic_difference
                        card = {"n": n, "padded": padded, "tiles": tiles, "policy": policy,
                                "edit": label, "diagnostic_changed_tiles": sorted(changed_tiles),
                                "prime": prime, "round": round_id, "equal_coefficients": 2*n,
                                "same_as_generic": True, "fixed_coins_public_diagnostic": True,
                                "nonquery_map_signature": signature, "changed_polynomial_names": list(changed),
                                "fresh_state_sha256": hashlib.sha256(json.dumps(fresh).encode()).hexdigest()}
                        cards.append(card)
    return {"cards": cards, "exact_state_comparisons": len(cards),
            "exact_query_adjoint_coefficients": sum(c["equal_coefficients"] for c in cards),
            "scope": "public polynomial-shaped diagnostics; no HE keys/encryption or actual owner updates"}


def large_support_panel(census_report):
    cards = []
    for vectors in (8192, 32768):
        active = [256] if vectors == 8192 else [512, 512]
        total_tiles, groups = vectors//32, len(active)
        graphs = [state.butterfly_graph(16384, 512, m, 4) for m in active]
        scripts = update.edit_scripts(vectors, 32)
        for policy in ("every-local", "product-cut", "maximal-affine"):
            counted = next(c for c in census_report["group_cards"]
                           if c["tiles"] == active[0] and c["policy"] == policy)
            index_counts = counted["index_atoms_per_tile"]
            sources = sum(g.tiles+g.rotations for g in graphs)
            cuts = sum(len(state.cuts_for(g, policy)) for g in graphs)
            optional = sum(len(state.cuts_for(g, policy)-g.mandatory) for g in graphs)
            fully_bundled = (2+sources*4+optional)*16384*2*3*8
            for label, rows in scripts.items():
                changed = frozenset(row//32 for row in rows)
                by_group, start, value_closure = [], 0, []
                touched_atoms = 0
                for graph in graphs:
                    local = frozenset(i-start for i in changed if start <= i < start+graph.tiles)
                    by_group.append(sorted(local))
                    value_closure.append(update.semantic_invalidation(graph, local))
                    touched_atoms += sum(index_counts[i] for i in local)
                    start += graph.tiles
                cards.append({"vectors": vectors, "policy": policy, "edit": label,
                              "row_count": len(rows), "changed_tile_count": len(changed),
                              "changed_tile_positions": sorted(changed), "changed_by_group": by_group,
                              "formal_tile_index_atoms_invalidated": touched_atoms,
                              "fixed_key_basis_atoms_invalidated_under_same_coins": 0,
                              "query_adjoint_vectors_invalidated_per_prime_round": 2,
                              "query_adjoint_changed_bytes_uint64_model": 2*16384*2*3*8,
                              "changed_encrypted_tile_full_Q_body_bytes_model": len(changed)*2*16384*15,
                              "canonical_value_dependency_closure": sum(c["canonical_source_values"] for c in value_closure),
                              "terminal_polynomials_depending_on_edits": sum(c["terminal_polynomials"] for c in value_closure),
                              "fresh_coin_control_all_chosen_adjoints_invalidated": True,
                              "fresh_coin_fully_bundled_vector_state_bytes_model": fully_bundled,
                              "fresh_coin_u_v_elements_model": 2*3*(cuts+16384),
                              "groups": groups, "all_static_counts_no_measured_latency": True})
    assert len(cards) == 24
    return {"cards": cards, "scope": "exact symbolic source geometry and public row-to-tile scripts; actual encrypted GPU update not implemented"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--census-results", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    if (args.output_directory/"operator-incremental-state-results.json").exists():
        raise FileExistsError("Keep earlier raw evidence; use a new output directory")
    args.output_directory.mkdir(parents=True, exist_ok=True)
    raw = args.census_results.read_bytes()
    census_report = json.loads(raw)
    report = {"schema_version": 1, "task": "Q59/B4-first-component", "date": "2026-10-03",
              "census_input_sha256": hashlib.sha256(raw).hexdigest(), "census_input_path": str(args.census_results),
              "tiny": tiny_panel(), "large_support": large_support_panel(census_report),
              "decision": "known linear update/adjoint control; exact equality, no original survivor and no reusable-state security approval",
              "unimplemented": ["authenticated live GPU tile replacement", "atomic epoch publication",
                                "TEE/receipt/attempt persistence", "adaptive update/reuse proof", "measured update cohort"],
              "source_sha256": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (
                  Path(update.__file__), Path(state.__file__), Path(__file__))}}
    (args.output_directory/"operator-incremental-state-results.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({"exact_state_comparisons": report["tiny"]["exact_state_comparisons"],
                      "exact_query_adjoint_coefficients": report["tiny"]["exact_query_adjoint_coefficients"],
                      "large_support_cards": len(report["large_support"]["cards"]), "decision": report["decision"]}))


if __name__ == "__main__":
    main()
