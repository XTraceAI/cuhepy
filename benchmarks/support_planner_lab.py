#!/usr/bin/env python3
"""E65 support-aware exact static catalog versus greedy occupancy balancing.

Complete bounded toy grammar, independent Cartesian allocation and every
decoder column; all binary queries preserve every score/ID/tie. Counts and
search cost only: no claimed useful lifetime/GPU gain or new cryptography.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import decryption_support as support
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import representation_planner as planner
from experiments.bfv_search_lab.representation_contract import Profile, Workload
from experiments.bfv_search_lab import support_planner as supported


def key(plan):
    return planner.signature(plan.choice), plan.allocation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--random-cases", type=int, default=0)
    parser.add_argument("--seed", type=int, default=67501)
    args = parser.parse_args()
    if not 0 <= args.random_cases <= 32:
        parser.error("Bounded0..32 additional tiny random catalogs required")
    datasets = (("two_affine_planes", (0, 1, 2, 3, 8, 9, 10, 11), 4),
                ("unequal_planes", (0, 1, 2, 4, 5, 6), 3),
                ("duplicate_rows", (0, 0, 1, 1, 4, 4, 5, 5), 3),
                ("full_cube", tuple(range(8)), 3),
                ("unequal_replicated_planes", (0, 1, 2, 3) * 3 + (8, 9, 10, 11), 4))
    cases, score_checks = [], 0
    for name, rows, d in datasets:
        for n in (16, 32):
            for share in (False, True):
                w, p = Workload(rows, tuple(100 - i for i in range(len(rows))), d), Profile(n, 17, eta=1)
                root = oracle.median_tree(w, 1)
                if name == "unequal_replicated_planes":
                    root = oracle.Node("", tuple(range(16)), (oracle.Node("0", tuple(range(12))),
                                                               oracle.Node("1", tuple(range(12, 16)))))
                search_s, result = timed(supported.search, w, root, p, equal_forms=share, limit=10000)
                exhaustive, _ = oracle.enumerate_plans(w, root, (p,), slots=(1, 2, 4), equal_forms=share)
                expected = set()
                for full in exhaustive:
                    assert set(supported.allocations(full)) == set(supported.cartesian_oracle_counts(full))
                    for counts in supported.cartesian_oracle_counts(full):
                        candidate = supported.view(supported.redistribute(full, counts))
                        expected.add((key(full), counts, candidate.static_vector))
                assert expected == {(key(x.compiled), x.compiled.candidate.layout.counts, x.static_vector) for x in result.plans}
                by_geometry = {}
                for view in result.plans:
                    assert view.certificate == support.matrix_oracle(view.compiled.candidate.layout)
                    assert sum(map(len, view.certificate.kept_c0)) >= len(rows)
                    geometry = key(view.compiled)
                    if geometry not in by_geometry or view.response_body_bytes_model < by_geometry[geometry].response_body_bytes_model:
                        by_geometry[geometry] = view
                    for word in range(1 << d):
                        values, offsets = oracle.query(view.compiled, word)
                        groups = [[list(row) for row in group] for group in view.compiled.groups]
                        dots = space.scores(view.compiled.query_space, groups, values)
                        polys = [[x % 17 if i in kept else 0 for i, x in enumerate(poly)]
                                 for poly, kept in zip(space.outputs(view.compiled.candidate.layout, dots), view.certificate.kept_c0, strict=True)]
                        scores = oracle.decode(view.compiled, polys, offsets)
                        assert scores == w.expected(word) and w.top_k(scores) == w.top_k(w.expected(word))
                        score_checks += 1
                original = {key(v.compiled): v for v in result.original_controls}
                balanced = {key(v.compiled): v for v in result.balanced_controls}
                refinement_s, refinements = timed(lambda: tuple(supported.refine_balancing(v.compiled) for v in result.original_controls))
                refined = {key(v.compiled): v for v, _, _ in refinements}
                changes = [{"allocation": full.compiled.allocation,
                            "map_ranks": tuple(m.rank for m in full.compiled.maps),
                            "greedy_original_counts": full.compiled.candidate.layout.counts,
                            "simple_balanced_counts": balanced[k].compiled.candidate.layout.counts,
                            "optimal_support_counts": optimum.compiled.candidate.layout.counts,
                            "full_response_bytes": full.compiled.resources.response_body_bytes,
                            "original_projected_bytes_model": full.response_body_bytes_model,
                            "balanced_projected_bytes_model": balanced[k].response_body_bytes_model,
                            "optimal_projected_bytes_model": optimum.response_body_bytes_model}
                           for k, optimum in by_geometry.items() if (full := original[k]).response_body_bytes_model != optimum.response_body_bytes_model
                           or balanced[k].response_body_bytes_model != optimum.response_body_bytes_model]
                cases.append({"workload": name, "rows": rows, "dimension": d, "n": n, "equal_forms": share,
                              "fixed_discovery_child_counts": tuple(len(child.positions) for child in root.children),
                              "search_s": search_s, "compile_attempts": result.original_compile_attempts,
                              "row_allocation_attempts": result.row_allocation_attempts,
                              "retained_plans": len(result.plans), "static_frontier_plans": len(result.frontier),
                              "independent_cartesian_and_boundary_grammar_agree": True,
                              "every_decoder_matrix_column_checked": True, "all_binary_queries_all_plans_exact": True,
                              "minimum_original_projected_online_bytes_model": min(v.static_vector[0] for v in original.values()),
                              "minimum_balanced_projected_online_bytes_model": min(v.static_vector[0] for v in balanced.values()),
                              "minimum_joint_projected_online_bytes_model": min(v.static_vector[0] for v in result.plans),
                              "minimum_refined_projected_online_bytes_model": min(v.static_vector[0] for v in refined.values()),
                              "refinement_s": refinement_s, "refinement_evaluations": sum(e for _, e, _ in refinements),
                              "fixed_geometry_refinement_not_optimal_count": sum(refined[k].response_body_bytes_model > v.response_body_bytes_model
                                                                                for k, v in by_geometry.items()),
                              "fixed_geometry_balancing_not_optimal_count": sum(balanced[k].response_body_bytes_model > v.response_body_bytes_model
                                                                               for k, v in by_geometry.items()),
                              "fixed_geometry_changes": changes})
    rng, random_cases = random.Random(args.seed), []
    for ordinal in range(args.random_cases):
        d, count, n = rng.randrange(2, 5), rng.randrange(3, 13), rng.choice((16, 32, 64))
        rows, cut = tuple(rng.randrange(1 << d) for _ in range(count)), rng.randrange(1, count)
        w, p = Workload(rows, tuple(range(count)), d), Profile(n, 17, eta=1)
        root = oracle.Node("", tuple(range(count)), (oracle.Node("0", tuple(range(cut))), oracle.Node("1", tuple(range(cut, count)))))
        search_s, result = timed(supported.search, w, root, p, equal_forms=True)
        grouped = {}
        for view in result.plans:
            assert view.certificate == support.matrix_oracle(view.compiled.candidate.layout)
            k = key(view.compiled)
            grouped[k] = min(grouped.get(k, view.response_body_bytes_model), view.response_body_bytes_model)
        for view in result.original_controls:
            assert set(supported.allocations(view.compiled)) == set(supported.cartesian_oracle_counts(view.compiled))
        controls = supported.pareto(result.original_controls + result.balanced_controls)
        control_vectors = {v.static_vector for v in controls}
        missing = tuple(v for v in result.frontier if v.static_vector not in control_vectors)
        refinement_s, refinements = timed(lambda: tuple(supported.refine_balancing(v.compiled) for v in result.original_controls))
        refined_controls = supported.pareto(tuple(v for v, _, _ in refinements) + result.original_controls + result.balanced_controls)
        refined_vectors = {v.static_vector for v in refined_controls}
        random_cases.append({"ordinal": ordinal, "dimension": d, "rows": rows, "n": n, "split": cut,
                             "search_s": search_s, "retained_plans": len(result.plans),
                             "independent_cartesian_allocations_and_decoder_columns_checked": True,
                             "fixed_geometries_balancing_not_optimal": sum(v.response_body_bytes_model > grouped[key(v.compiled)]
                                                                          for v in result.balanced_controls),
                             "joint_frontier_vectors_missing_from_simple_control_frontier": tuple(sorted({v.static_vector for v in missing})),
                             "joint_frontier_vectors_missing_from_refined_control_frontier": tuple(sorted({v.static_vector for v in result.frontier
                                                                                                         if v.static_vector not in refined_vectors})),
                             "refinement_s": refinement_s, "refinement_evaluations": sum(e for _, e, _ in refinements),
                             "refinement_steps": sum(steps for _, _, steps in refinements),
                             "minimum_joint_online_bytes_model": min(v.static_vector[0] for v in result.plans),
                             "minimum_control_online_bytes_model": min(v.static_vector[0] for v in controls)})
    result = metadata([Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "support_planner", "representation_oracle", "representation_planner", "representation_contract",
        "affine_dictionary", "crt_query_space", "dyadic_crt", "decryption_support", "rank_partition",
        "field_frontier", "reduction_oracles"))])
    result.update(kind="support_aware_static_grammar_oracle", cases=cases, exact_full_score_query_checks=score_checks,
                  random_seed=args.seed, additional_random_cases=random_cases,
                  scope="Finite fixed-tree raw/affine, contiguous-map CRT cover, all capacity-valid canonical row allocations; no arbitrary layout optimum. "
                        "Static projected-body objective keeps full index/answer/verifier/state charges; no lifecycle base/age/exposure/seed/budget optimization. "
                        "Known greedy balancing/global/single-row-refinement controls mandatory; refinement added after initial bounded screen. "
                        "Counts/search cost, not held-out native timing, assurance or established originality.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cases": len(cases), "score_checks": score_checks,
                      "cases_better_than_best_balancing": sum(c["minimum_joint_projected_online_bytes_model"] < c["minimum_balanced_projected_online_bytes_model"] for c in cases),
                      "fixed_geometries_balancing_not_optimal": sum(c["fixed_geometry_balancing_not_optimal_count"] for c in cases),
                      "random_cases": len(random_cases),
                      "random_cases_with_frontier_missing_from_controls": sum(bool(c["joint_frontier_vectors_missing_from_simple_control_frontier"]) for c in random_cases),
                      "random_cases_with_frontier_missing_from_refined_controls": sum(bool(c["joint_frontier_vectors_missing_from_refined_control_frontier"]) for c in random_cases)}))


if __name__ == "__main__":
    main()
