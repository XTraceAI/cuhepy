#!/usr/bin/env python3
"""Run Q57 finite STATIC models/oracles; this records no execution timings."""

from __future__ import annotations

import argparse
import hashlib
from itertools import product
import json
from pathlib import Path

from experiments.bfv_search_lab import operator_state_discriminator as state


def group_card(n, padded, tiles, policy):
    graph = state.butterfly_graph(n, padded, tiles)
    cuts = state.cuts_for(graph, policy)
    counted = state.census(graph, cuts)
    ledger = state.body_ledger(graph, cuts)
    dictionary = counted.pop("fixed_dictionary")
    return {"n": n, "padded": padded, "tiles": tiles, "policy": policy,
            **counted, **ledger}, dictionary


def minimal_nonadditive(optional_cut_penalty=3):
    graph = state.butterfly_graph(8, 4, 2, 2)
    choices = ("product:0:0", "product:0:1")
    cards = []
    for flags in product((False, True), repeat=2):
        selected = frozenset(n for n, yes in zip(choices, flags, strict=True) if yes)
        cuts = graph.mandatory | selected
        counted = state.census(graph, cuts)
        equations = state.compile_equations(graph, cuts)
        generic_atoms = {a for expression in equations.values() for op in expression.values()
                         for a, _ in op.terms}
        assert len(generic_atoms) == counted["all_atomic_operators"]
        cards.append({"cuts": sorted(selected),
                      "fixed_basis": counted["fixed_atomic_operators"],
                      "index_basis": counted["index_atomic_operators"],
                      "all_basis": counted["all_atomic_operators"],
                      "declared_static_objective": counted["all_atomic_operators"]+optional_cut_penalty*len(selected),
                      "generic_same_objective": len(generic_atoms)+optional_cut_penalty*len(selected)})
    # The intentionally weak additive predictor uses exact baseline marginals.
    base, second, first, both = cards
    for card in cards:
        selected = set(card["cuts"])
        predicted = base["all_basis"]
        if choices[0] in selected:
            predicted += first["all_basis"]-base["all_basis"]
        if choices[1] in selected:
            predicted += second["all_basis"]-base["all_basis"]
        card["additive_prediction_objective"] = predicted+optional_cut_penalty*len(selected)
    return {"n": 8, "padded": 4, "tiles": 2, "digits": 2,
            "cards": cards,
            "fixed_state_mixed_difference": base["fixed_basis"]+both["fixed_basis"]-first["fixed_basis"]-second["fixed_basis"],
            "exact_selected": min(cards, key=lambda a: a["declared_static_objective"])["cuts"],
            "additive_selected": min(cards, key=lambda a: a["additive_prediction_objective"])["cuts"],
            "optional_cut_penalty": optional_cut_penalty,
            "units": "one cost unit per atomic adjoint; declared penalty per optional canonical polynomial; illustrative, not bytes/timing",
            "weight_choice": "penalty3 selected after inspecting the four dictionaries to expose a choice difference; penalty1 retained as initial exploratory control",
            "generic_containment": True,
            "originality_survivor": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    args.output_directory.mkdir(parents=True, exist_ok=True)
    cards = []
    # The 8k geometry is a partial 256-tile group at D512; 32k has two
    # complete 512-tile groups. Keys/shape are shared across the two groups.
    for tiles in (256, 512):
        for policy in ("every-local", "product-cut", "maximal-affine"):
            card, dictionary = group_card(16384, 512, tiles, policy)
            filename = f"dictionary-n16384-d512-t{tiles}-{policy}.json"
            raw = json.dumps(dictionary, separators=(",", ":")).encode()+b"\n"
            (args.output_directory/filename).write_bytes(raw)
            card["dictionary_file"] = filename
            card["dictionary_file_sha256"] = hashlib.sha256(raw).hexdigest()
            cards.append(card)
            print(json.dumps({k: card[k] for k in ("tiles", "policy", "cuts", "fixed_atomic_operators", "index_atomic_operators")}), flush=True)
    results = {"schema_version": 1, "task": "Q57/B2", "date": "2026-10-03",
               "scope": "static exact normalized symbolic native-butterfly operators; no numeric enrolled-key equivalence/minimum state/measurements",
               "group_cards": cards, "minimal_nonadditive": minimal_nonadditive(),
               "decision": "literal sharing/selected-cut proposal contained by strongest generic normalization; no Q58 original candidate",
               "geometries": [{"vectors": 8192, "n": 16384, "padded": 512,
                                "active_group_tiles": [256], "relinearizations": 256, "rotations": 511},
                               {"vectors": 32768, "n": 16384, "padded": 512,
                                "active_group_tiles": [512, 512], "relinearizations": 1024, "rotations": 1022}],
               "security_model": "canonical sources/terminal constrained; exact bilinear control from plan; this runner performs no admission or secret operation",
               "source_sha256": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (
                   Path(state.__file__), Path(__file__),
                   Path("experiments/bfv_search_lab/_native/trace_server.h"),
                   Path("experiments/bfv_search_lab/_native/residue_trace.h"))}}
    (args.output_directory/"operator-state-results.json").write_text(json.dumps(results, indent=2)+"\n")


if __name__ == "__main__":
    main()
