#!/usr/bin/env python3
"""E31 fixed-index-size hierarchical query/intersection experiment.

The complete sharing-depth curve is index-only. Controls include unchanged
local maps, equal-row merging without intersections, and global/raw maps.
Every encrypted variant uses the full homemade BGV ring and the same checker.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from copy import copy
from dataclasses import asdict
import importlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.crt_masked_bgv_lab import run_prepared
from benchmarks.dictionary_layout_lab import metadata
from benchmarks.shared_query_basis_lab import model_for, one_group, owner_state
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import hierarchical_query_basis as hierarchy
from experiments.bfv_search_lab import rank_partition as partition


def scheduled_space(candidate, plan):
    ids, _ = hierarchy.schedule(plan)
    layout = tree.layout(candidate.layout.context, plan.features, candidate.layout.counts)
    return space.space(layout, tuple(range(len(plan.features))), coordinate_ids=ids)


def record(s, body, **extra):
    model = model_for(s)
    geometry = len(json.dumps(asdict(s), sort_keys=True, separators=(",", ":")).encode())
    return dict(extra, private_map_body_bytes=len(body), public_space_json_bytes=geometry,
                map_plus_checker_epoch_body_bytes=len(body) + model["checker_epoch_seeded_body_bytes"],
                maps_checker_geometry_body_bytes=len(body) + model["checker_epoch_seeded_body_bytes"] + geometry,
                column_degrees=s.column_degrees, cost_model=model)


def uniform_candidate(candidate, rows, *, regroup=False):
    """Split a coalesced leaf into equal-capacity slots without changing rows.

    Balanced rounding cannot increase the number of full reply ciphertexts.
    Optional reordering permutes whole slots; every stable row appears once.
    """
    depth = max(len(b.path) for b in candidate.blocks)
    chunks = []
    for b in candidate.blocks:
        pieces = 1 << (depth - len(b.path))
        for i in range(pieces):
            positions = b.positions[len(b.positions) * i // pieces:len(b.positions) * (i + 1) // pieces]
            chunks.append((positions, b.mapping))
    order = hierarchy.overlap_order(tuple(p for _, p in chunks)) if regroup else tuple(range(len(chunks)))
    paths = tuple(format(i, f"0{depth}b") if depth else "" for i in range(len(chunks)))
    blocks = tuple(partition.Block(path, chunks[i][0], chunks[i][1]) for path, i in zip(paths, order, strict=True))
    ctx = tree.context(candidate.layout.context.n, paths, candidate.layout.context.prime)
    layout = tree.layout(ctx, tuple(b.mapping.features for b in blocks), tuple(len(b.positions) for b in blocks))
    result = partition.Candidate(layout, blocks, candidate.cuts, candidate.source_digest,
                                 candidate.dimension, partition.map_body_bytes(blocks), candidate.target)
    if (sorted(i for b in blocks for i in b.positions) != list(range(len(rows)))
            or layout.cost.response_ciphertexts > candidate.layout.cost.response_ciphertexts):
        raise AssertionError("Regrouping changed coverage or exceeded the existing reply budget")
    return result, order


def prepare(args):
    data = fixtures.load(args.dataset, args.cache_dir / fixtures.SOURCES[args.dataset]["member"])
    ids, holdout = fixtures.split(data, args.seed)
    rows = [data.rows[i] for i in ids]
    setup = {"n": 16384, "t": 1153, "eta": 21}
    setup["order_s"], order = timed(dictionary.metric_order, rows, data.dimension, 32)
    setup["fit_s"], original = timed(partition.prepare, rows, data.dimension, order, target=32, policy="hybrid")
    alternatives = []
    setup["allocation_s"] = 0.0
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
    local = space.space(candidate.layout, map_ids)
    local_body = b"".join(affine.canonical_map(p) for p in maps)
    curves, plans = [], {}
    for depth in range(-1, max(len(b.path) for b in candidate.blocks)):
        fit_s, p = timed(hierarchy.prepare, candidate.layout.context, tuple(b.mapping for b in candidate.blocks), max_depth=depth)
        s = scheduled_space(candidate, p)
        body = hierarchy.canonical_map(p)
        curves.append(record(s, body, max_depth=depth, hierarchy_fit_s=fit_s,
                             node_ranks={node.path: node.basis.rank for node in p.nodes},
                             laminar_coordinate_count=sum(node.basis.rank for node in p.nodes)))
        plans[depth] = p
    # One predeclared state objective includes the larger public schedule.
    best = min(curves, key=lambda r: (r["maps_checker_geometry_body_bytes"], r["max_depth"]))["max_depth"]
    selected = [("local", None), ("flat_equal", -1), ("root_intersection", 0), ("hierarchy", max(plans))]
    if best not in (-1, 0, max(plans)):
        selected.append(("state_selected", best))
    controls = {"local": record(local, local_body)}
    reordered = {}
    geometry_curves = []
    for label, regroup in (("uniform_hierarchy", False), ("regrouped_hierarchy", True)):
        regroup_s, (c, permutation) = timed(uniform_candidate, candidate, rows, regroup=regroup)
        fit_s, p = timed(hierarchy.prepare, c.layout.context, tuple(b.mapping for b in c.blocks))
        s, body = scheduled_space(c, p), hierarchy.canonical_map(p)
        geometry_curves.append(record(s, body, label=label, regroup_s=regroup_s, hierarchy_fit_s=fit_s,
                                      slot_permutation=permutation, node_ranks={node.path: node.basis.rank for node in p.nodes},
                                      laminar_coordinate_count=sum(node.basis.rank for node in p.nodes)))
        reordered[label] = (c, p)
    global_fit_s, global_map = timed(affine.prepare, rows, data.dimension)
    raw_map = affine.Plan(data.dimension, 1153, 0, tuple(range(data.dimension)),
                          tuple(tuple(int(i == j) for j in range(data.dimension)) for i in range(data.dimension)))
    control_maps = (("global", global_map), ("raw", raw_map))
    for name, mapping in control_maps:
        c = one_group(rows, data.dimension, mapping)
        controls[name] = record(space.space(c.layout, (0,)), b"" if name == "raw" else affine.canonical_map(mapping))
    info = {"dataset": args.dataset, "seed": args.seed, "fixture_sha256": data.sha256,
            "index_count": len(rows), "dimension": data.dimension, "partition_setup": setup,
            "slots": slots, "private_original_maps": len(maps), "sharing_depth_curve": curves,
            "controls": controls, "measured_points": selected, "state_selected_depth": best,
            "geometry_curve": geometry_curves,
            "chosen_without_future_queries": True}
    cases = []
    if args.curves_only:
        return info, cases
    for label, depth in selected if args.seed % 2 else reversed(selected):
        case_setup = dict(setup)
        if depth is None:
            s, body, query = local, local_body, None
            case_setup["coordinate_enroll_s"], groups = timed(lambda: [affine.index_features(b.mapping, [rows[i] for i in b.positions])
                                                                     for b in candidate.blocks])
        else:
            p = plans[depth]
            s, body = scheduled_space(candidate, p), hierarchy.canonical_map(p)
            case_setup.update({k: v for k, v in curves[depth + 1].items() if k in ("max_depth", "hierarchy_fit_s", "node_ranks")})
            case_setup["coordinate_enroll_s"], groups = timed(lambda p=p: [hierarchy.index_features(p, i, [rows[j] for j in b.positions])
                                                                         for i, b in enumerate(candidate.blocks)])
            case_setup["query_compile_s"], compiled = timed(hierarchy.compile_bits, p)
            query = compiled.query
        case_args = copy(args)
        case_args.layout, case_args.q_bits, case_args.alternate_order = label, model_for(s)["q_bits"], True
        case_setup["q_bits_requested"] = case_args.q_bits
        print("case", label, "depth", depth, "degrees", s.column_degrees, file=sys.stderr, flush=True)
        result = run_prepared(case_args, data, ids, holdout, rows, candidate, case_setup, s, groups, body,
                              private_map_bytes=len(body), query_transform=query)
        result["dataset"], result["column_degrees"] = args.dataset, s.column_degrees
        result["owner_state_model"] = owner_state(result, s)
        cases.append(result)
    for label in reordered if args.seed % 2 else reversed(reordered):
        c, p = reordered[label]
        rec = next(r for r in geometry_curves if r["label"] == label)
        s, body = scheduled_space(c, p), hierarchy.canonical_map(p)
        case_setup = dict(setup, regroup_s=rec["regroup_s"], hierarchy_fit_s=rec["hierarchy_fit_s"],
                          slot_permutation=rec["slot_permutation"])
        case_setup["coordinate_enroll_s"], groups = timed(lambda p=p, c=c: [hierarchy.index_features(p, i, [rows[j] for j in b.positions])
                                                                for i, b in enumerate(c.blocks)])
        case_setup["query_compile_s"], compiled = timed(hierarchy.compile_bits, p)
        case_args = copy(args)
        case_args.layout, case_args.q_bits, case_args.alternate_order = label, model_for(s)["q_bits"], True
        case_setup["q_bits_requested"] = case_args.q_bits
        print("case", label, "degrees", s.column_degrees, file=sys.stderr, flush=True)
        result = run_prepared(case_args, data, ids, holdout, rows, c, case_setup, s, groups, body,
                              private_map_bytes=len(body), query_transform=compiled.query)
        result["dataset"], result["column_degrees"] = args.dataset, s.column_degrees
        result["owner_state_model"] = owner_state(result, s)
        cases.append(result)
    for label, mapping in control_maps if args.seed % 2 else reversed(control_maps):
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
        result["dataset"], result["column_degrees"] = args.dataset, s.column_degrees
        result["owner_state_model"] = owner_state(result, s)
        cases.append(result)
    return info, cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=3001)
    parser.add_argument("--dataset", choices=tuple(fixtures.SOURCES), default="mushroom")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--curves-only", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.repeats <= 8:
        parser.error("Expected 1..8 measured queries")
    paths = [Path(__file__), ROOT / "benchmarks/crt_masked_bgv_lab.py", ROOT / "benchmarks/shared_query_basis_lab.py",
             ROOT / "benchmarks/dictionary_layout_lab.py", ROOT / "benchmarks/certified_filter_lab.py", ROOT / "src/cuhepy/bfv/scheme.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "hierarchical_query_basis", "test_hierarchical_query_basis", "shared_query_basis", "crt_query_space", "crt_masked_bgv",
        "crt_linear_check", "crt_native_bgv", "dyadic_crt", "linear_packing", "rank_partition", "affine_dictionary", "binary_fixtures",
        "folded_dictionary", "folded_filter", "owner_bgv", "seeded_bgv", "shallow_bgv", "transport_bgv"))
    paths.extend([ROOT / "experiments/bfv_search_lab/_subring/bindings.cpp", ROOT / "experiments/bfv_search_lab/_subring/Makefile",
                  Path(importlib.import_module("experiments.bfv_search_lab._subring._crt_subring").__file__)])
    report = metadata(paths)
    curves, cases = prepare(args)
    report.update({"kind": "exact_hierarchical_query_intersections", "curves": curves, "encrypted_cases": cases,
                   "scope": "Research only. Homemade full-N BGV and single-thread C++ public arithmetic; no SEAL/GPU. "
                            "Fresh owner-encrypted one-use answers and hidden conditional checking require trusted preparation. "
                            "No new security/parameter assurance. Exact form IDs add equality/rank/geometry leakage. "
                            "All declared coordinates receive full-field masks, including the dummy coordinate. "
                            "Body costs omit transport/authentication/journaling. Owner keeps plaintext coordinates offline. "
                            "Same E29/E30 holdout queries, one warmup then diagnostic timings; not independent statistical evaluation."})
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cases": len(cases), "depth_points": len(curves["sharing_depth_curve"])}))


if __name__ == "__main__":
    main()
