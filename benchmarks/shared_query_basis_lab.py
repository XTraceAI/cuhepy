#!/usr/bin/env python3
"""E30 index-only common/local curves and full-degree encrypted comparisons.

No held-out query chooses a direction, a layout, or a measured curve point.
All offline token costs are charged by the same E29 measurement harness.
Raw-coordinate stripping and a single global affine map are explicit controls.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from copy import copy
from dataclasses import asdict
from functools import cache
import importlib
import json
from pathlib import Path
import sys

import gmpy2

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.crt_masked_bgv_lab import run_prepared
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import rank_partition as partition
from experiments.bfv_search_lab import shared_query_basis as shared


@cache
def word_modulus(n, bits):
    q = ((1 << bits) - 2) // (2 * n) * (2 * n) + 1
    while not gmpy2.is_prime(q):
        q -= 2 * n
    return q


def model_for(s):
    # A correctness-only choice, not a security estimate. Keep the full N.
    bits = next(b for b in (32, 40) if 2 * space.cost(s, q_bits=b)["worst_case_phase_bound"] < word_modulus(s.layout.context.n, b))
    return space.cost(s, q_bits=bits, rounds=5 if bits == 32 else 4)


def query_space(candidate, map_ids, plan):
    layout = tree.layout(candidate.layout.context, tuple(plan.features[i] for i in map_ids), candidate.layout.counts)
    return space.space(layout, map_ids, shared=plan.shared)


def private_body(plan, original_maps):
    # Zero-shared endpoint uses the unmodified E29 representation/byte count.
    return (shared.canonical_map(plan) if plan.shared else b"".join(affine.canonical_map(p) for p in original_maps))


def curve_record(candidate, map_ids, plan, original_maps):
    s = query_space(candidate, map_ids, plan)
    model = model_for(s)
    private = len(private_body(plan, original_maps))
    return {"shared": plan.shared, "residual_ranks": [p.rank for p in plan.residuals],
            "private_map_body_bytes": private,
            "map_plus_checker_epoch_body_bytes": private + model["checker_epoch_seeded_body_bytes"],
            "private_coordinate_entries": sum(len(b.positions) * plan.features[i] for b, i in zip(candidate.blocks, map_ids, strict=True)),
            "cost_model": model}


def one_group(rows, d, mapping):
    layout = tree.layout(tree.context(16384, ("",)), (mapping.features,), (len(rows),))
    blocks = (partition.Block("", tuple(range(len(rows))), mapping),)
    return partition.Candidate(layout, blocks, (), partition.epoch_digest(rows, d), d, partition.map_body_bytes(blocks), None)


def owner_state(result, s):
    """Explicit body model, not Python/GMP heap usage or a network serializer.

    Retain the full pk/sk polynomials actually supplied to this prototype, not
    an unimplemented seed/ternary compressed key. Per-row coordinates belong
    to the offline owner/service and are priced separately from online state.
    """
    c, setup = result["cost_model"], result["setup"]
    body = {"public_and_secret_key_coefficient_bytes": 3 * c["n"] * ((c["q_bits"] + 7) // 8),
            "ordered_stable_id_bytes": setup["common_stable_id_bytes"],
            "private_map_bytes": setup["private_map_body_bytes"],
            "private_checker_seed_and_hint_bytes": c["checker_epoch_seeded_body_bytes"],
            "column_bound_u64_bytes": c["coordinate_columns"] * c["replies"] * 8,
            "canonical_public_space_json_bytes": len(json.dumps(asdict(s), sort_keys=True, separators=(",", ":")).encode()),
            "epoch_and_key_digest_bytes": 64, "three_budget_counter_u64_bytes": 24}
    return {"epoch_body_components": body, "epoch_body_total_bytes": sum(body.values()),
            "per_pending_token_body_bytes": 32 + 16 + c["checker_token_residue_body_bytes"] + c["replies"] * 8,
            "per_spent_token_id_bytes": 16,
            "offline_plaintext_coordinate_u16_body_bytes": setup["private_coordinate_entries"] * 2,
            "scope": "Modeled canonical/raw integer bodies with full provided key polynomials. Not heap/RSS or a transport format. "
                     "No authentication keys, crash-safe journal, Python objects, compiled-map duplicates or transient ciphertext/challenge buffers. "
                     "One ordered stable-ID array assumed. Offline service keeps index coordinates separately."}


def prepare(args):
    data = fixtures.load(args.dataset, args.cache_dir / fixtures.SOURCES[args.dataset]["member"])
    ids, holdout = fixtures.split(data, args.seed)
    rows = [data.rows[i] for i in ids]
    setup = {"n": 16384, "t": 1153, "eta": 21}
    setup["order_s"], order = timed(dictionary.metric_order, rows, data.dimension, 32)
    setup["fit_s"], original = timed(partition.prepare, rows, data.dimension, order, target=32, policy="hybrid")
    setup["allocation_s"] = 0.0
    alternatives = []
    for slots in (1, 2, 4, 8, 16, 32, 64):
        if slots >= len(set(b.mapping for b in original.blocks)):
            seconds, c = timed(partition.reallocate, original, rows, slots)
            setup["allocation_s"] += seconds
            alternatives.append((slots, c))
    slots, candidate = min(alternatives, key=lambda item: (item[1].layout.cost.response_ciphertexts, item[0]))
    setup["allocation_candidates"] = [{"slots": k, "old_input_tiles": c.layout.cost.input_tiles,
                                       "response_ciphertexts": c.layout.cost.response_ciphertexts, "selected": k == slots}
                                      for k, c in alternatives]
    maps = tuple(dict.fromkeys(b.mapping for b in candidate.blocks))
    map_ids = tuple(maps.index(b.mapping) for b in candidate.blocks)
    fit_s, curve = timed(shared.trajectory, maps, limit=args.limit)
    raw_fit_s, raw_curve = timed(shared.trajectory, maps, limit=args.limit, strategy="raw")
    records = [curve_record(candidate, map_ids, p, maps) for p in curve]
    raw_records = [curve_record(candidate, map_ids, p, maps) for p in raw_curve]
    # Predeclared state/index decisions. No query or measured latency input.
    eligible = [r for r in records if r["cost_model"]["expanded_index_body_bytes"] <= records[0]["cost_model"]["expanded_index_body_bytes"]]
    equal_index = min(eligible, key=lambda r: (r["map_plus_checker_epoch_body_bytes"], r["shared"]))["shared"]
    word_candidates = [r for r in records if r["cost_model"]["q_bits"] == 32]
    word_choice = min(word_candidates, key=lambda r: (r["cost_model"]["expanded_index_body_bytes"],
                                                     r["map_plus_checker_epoch_body_bytes"]))["shared"] if word_candidates else None
    chosen = [("local", 0), ("equal_index", equal_index), ("shared32", min(32, len(curve) - 1))]
    if word_choice is not None:
        chosen.append(("small_word", word_choice))
    curves = {"dataset": args.dataset, "seed": args.seed, "fixture_sha256": data.sha256,
              "index_count": len(rows), "dimension": data.dimension, "partition_setup": setup,
              "shared_fit_s": fit_s, "raw_stripping_fit_s": raw_fit_s,
              "private_original_maps": len(maps), "slots": slots,
              "overlap_curve": records, "raw_coordinate_curve": raw_records,
              "measured_points": chosen, "chosen_without_future_queries": True}
    cases = []
    if args.curves_only:
        return curves, cases
    # Reverse case order across splits and alternate native/GMP order per query.
    for label, k in chosen if args.seed % 2 else reversed(chosen):
        p = curve[k]
        s = query_space(candidate, map_ids, p)
        case_setup = dict(setup, shared_basis_fit_s=fit_s, shared_count=k,
                          residual_ranks=[p.rank for p in p.residuals], query_direction_strategy="overlap")
        case_setup["coordinate_enroll_s"], groups = timed(lambda p=p: [shared.index_features(p, i, [rows[j] for j in b.positions])
                                                                  for b, i in zip(candidate.blocks, map_ids, strict=True)])
        case_setup["query_compile_s"], compiled = timed(shared.compile_bits, p)
        body = private_body(p, maps)
        case_args = copy(args)
        case_args.layout, case_args.q_bits, case_args.alternate_order = label, model_for(s)["q_bits"], True
        case_setup["q_bits_requested"] = case_args.q_bits
        print("case", label, "shared", k, "q_bits", case_args.q_bits, file=sys.stderr, flush=True)
        result = run_prepared(case_args, data, ids, holdout, rows, candidate, case_setup, s, groups, body,
                              private_map_bytes=len(body), query_transform=compiled.query)
        result["dataset"] = args.dataset
        result["owner_state_model"] = owner_state(result, s)
        cases.append(result)
    global_fit_s, global_map = timed(affine.prepare, rows, data.dimension)
    raw_map = affine.Plan(data.dimension, 1153, 0, tuple(range(data.dimension)),
                          tuple(tuple(int(i == j) for j in range(data.dimension)) for i in range(data.dimension)))
    for label, mapping in (("global", global_map), ("raw", raw_map)):
        c = one_group(rows, data.dimension, mapping)
        s = space.space(c.layout, (0,))
        case_setup = {"n": 16384, "t": 1153, "eta": 21, "order_s": 0.0, "fit_s": global_fit_s if label == "global" else 0.0,
                      "allocation_s": 0.0, "allocation_candidates": [{"slots": 1, "old_input_tiles": c.layout.cost.input_tiles,
                                                                     "response_ciphertexts": c.layout.cost.response_ciphertexts, "selected": True}]}
        case_setup["coordinate_enroll_s"], groups = timed(lambda mapping=mapping: [affine.index_features(mapping, rows)])
        case_args = copy(args)
        case_args.layout, case_args.q_bits, case_args.alternate_order = label, model_for(s)["q_bits"], True
        case_setup["q_bits_requested"] = case_args.q_bits
        body = affine.canonical_map(mapping)
        print("case", label, "rank", mapping.rank, file=sys.stderr, flush=True)
        result = run_prepared(case_args, data, ids, holdout, rows, c, case_setup, s, groups, body,
                              private_map_bytes=0 if label == "raw" else len(body))
        result["dataset"] = args.dataset
        result["owner_state_model"] = owner_state(result, s)
        cases.append(result)
    return curves, cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=3001)
    parser.add_argument("--dataset", choices=tuple(fixtures.SOURCES), default="mushroom")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--curves-only", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.repeats <= 8 or args.limit is not None and not 0 <= args.limit <= 256:
        parser.error("Expected 1..8 measured queries and a bounded trajectory")
    paths = [Path(__file__), ROOT / "benchmarks/crt_masked_bgv_lab.py", ROOT / "benchmarks/dictionary_layout_lab.py",
             ROOT / "benchmarks/certified_filter_lab.py", ROOT / "src/cuhepy/bfv/scheme.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "shared_query_basis", "test_shared_query_basis", "crt_query_space", "crt_masked_bgv", "crt_linear_check", "crt_native_bgv",
        "dyadic_crt", "linear_packing", "rank_partition", "affine_dictionary", "binary_fixtures", "folded_dictionary", "folded_filter",
        "owner_bgv", "seeded_bgv", "shallow_bgv", "transport_bgv"))
    paths.extend([ROOT / "experiments/bfv_search_lab/_subring/bindings.cpp", ROOT / "experiments/bfv_search_lab/_subring/Makefile",
                  Path(importlib.import_module("experiments.bfv_search_lab._subring._crt_subring").__file__)])
    report = metadata(paths)
    curves, cases = prepare(args)
    report.update({"kind": "exact_common_and_local_query_directions", "curves": curves, "encrypted_cases": cases,
                   "scope": "Research only. Homemade full-N encryption and single-thread C++ public arithmetic. No GPU or SEAL. "
                            "Conditional trusted preprocessing/checking; no complete security or parameter approval. "
                            "Ranks and geometry leak; private maps stay with owner. Full declared-coordinate one-use masks. "
                            "Body counts omit authentication/transport and durable state. Owner keeps plaintext coordinates for token generation. "
                            "Common stable IDs and key material are separate; new query basis is not free state. "
                            "Same E29 holdout queries are reused; diagnostic timings, not an independent statistical evaluation."})
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cases": len(cases), "curve_points": len(curves["overlap_curve"])}))


if __name__ == "__main__":
    main()
