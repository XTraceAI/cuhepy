#!/usr/bin/env python3
"""Q71 sufficient paid replay models and frozen counter audit addendum."""

# ruff: noqa: E402 -- standalone research runner.

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks.dictionary_layout_lab import metadata
from benchmarks.noise_cut_fusion_lab import pin_file
from benchmarks.noise_cut_lowering_lab import plan_from_dict
from benchmarks.noise_cut_relation_lab import opaque, public_context
from benchmarks.propagated_gadget_encrypted_lab import write_new
from experiments.bfv_search_lab import noise_cut_fusion as fusion
from experiments.bfv_search_lab import noise_cut_reference as reference
from experiments.bfv_search_lab import noise_cut_shape as shape


def source_widths(plan, widths):
    if plan.mode == "zero":
        return []
    if plan.level == -1:
        return [30]
    return [
        *source_widths(plan.left, widths),
        *source_widths(plan.right, widths),
        *([widths[plan.level]] if plan.mode == "canonical" else []),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fusion-dir", type=Path, required=True)
    parser.add_argument("--planner-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    if any(args.out_dir.iterdir()):
        parser.error("New immutable output directory required")
    registration = ROOT / "docs/research/gadget-cut-controls-registration-20261004.json"
    paths = [Path(__file__), registration]
    paths.append(
        ROOT / "docs/research/gadget-cut-controls-retry-registration-20261004.json"
    )
    paths.extend(
        ROOT / f"experiments/bfv_search_lab/{name}.py"
        for name in (
            "noise_cut_fusion",
            "noise_cut_shape",
            "noise_cut_reference",
            "noise_cut_relation",
            "noise_cut_planner",
            "noise_cut_lowering",
            "noise_cut_oracle",
            "tensor_gadget_factorization",
            "tensor_gadget_seed",
            "propagated_gadget_bgv",
            "shallow_bgv",
            "trace_bgv",
            "butterfly_bgv",
            "compact_bgv",
        )
    )
    paths.extend(
        ROOT / f"benchmarks/{name}.py"
        for name in (
            "dictionary_layout_lab",
            "noise_cut_fusion_lab",
            "noise_cut_relation_lab",
            "noise_cut_lowering_lab",
            "noise_cut_planner_lab",
            "propagated_gadget_encrypted_lab",
        )
    )
    paths.extend((ROOT / "src/cuhepy/bfv/scheme.py", ROOT / "src/cuhepy/types.py"))
    result = metadata(paths)
    inputs = []
    screens = {}
    for mode in ("public", "local-public", "paired-model"):
        path = args.fusion_dir / mode / "fusion-screen.json"
        inputs.append(pin_file(path))
        screens[mode] = json.loads(path.read_text())
    parent = json.loads(
        (args.planner_dir / "large-refined/planner-screen.json").read_text()
    )
    cards = {}
    for entry in parent["cases"]:
        path = ROOT / entry["card"]
        raw = json.loads(path.read_text())
        if raw["status"] == "complete_declared_grammar":
            cards[raw["tiles"], raw["radix_bits"], raw["allow_seed"]] = raw
    encrypted = args.planner_dir / "encrypted/correctness.json"
    inputs.append(pin_file(encrypted))
    receipt = json.loads(encrypted.read_text())
    contexts = {}
    import gzip

    for c in receipt["contexts"]:
        path = args.planner_dir / f"encrypted/context-{c['context']}-public.json.gz"
        entry = next(f for f in receipt["files"] if f["file"] == path.name)
        inputs.append(pin_file(path, entry["sha256"]))
        contexts[c["context"]] = public_context(
            json.loads(gzip.decompress(path.read_bytes()))
        )
    write_new(
        args.out_dir / "started.json",
        json.dumps(
            {
                "utc": datetime.now(UTC).isoformat(),
                "source_sha256": result["source_sha256"],
                "inputs_before_models_and_audit": inputs,
                "new_HE_keys_private_diagnostics_or_timing": False,
            },
            indent=2,
        ).encode()
        + b"\n",
    )
    with tarfile.open(args.out_dir / "executed-source.tar.gz", "x:gz") as archive:
        for path in paths:
            archive.add(path, arcname=str(path.relative_to(ROOT)))
    models = []
    for model in screens["paired-model"]["cases"]:
        if model["matched_geometry_control_repeat"]:
            continue
        n, d, q_bits = model["N"], model["D"], 120
        canonical = model["kind"] == "matched_canonical30"
        plan = (
            opaque(d.bit_length() - 2, model["tiles"])
            if canonical
            else plan_from_dict(
                cards[model["tiles"], model["radix_bits"], model["allow_seed"]]["plan"]
            )
        )
        widths = tuple(model["body_and_keys"]["rotation_radix_bits_by_level"])
        cuts = source_widths(plan, widths)
        digits = sum((q_bits + bits - 1) // bits for bits in cuts)
        recomposition_scales = digits - len(cuts)
        direct = model["direct"]["online"]
        assert len(cuts) == model["source_layout_polynomials"]
        names = direct["distinct_bound_input_polynomials"]
        assert names >= digits + 4
        known_query_inputs = names - digits - 2
        qpoly = n * 15
        stock = model["body_and_keys"]
        checker = {
            "input_forward_prime_NTTs": direct["input_forward_prime_NTTs"],
            "residual_inverse_prime_NTTs": 0,
            "fresh_challenge_rows": 0,
            "DAG_word_products": direct["DAG_word_product_count"],
            "complete_zero_comparison_field_coordinates": 2 * n * (len(cuts) + 2),
            "whole_source_and_terminal_Q_wire_bytes": stock[
                "source_and_terminal_Q_body_bytes"
            ],
            "trusted_terminal_inverse_prime_NTTs_after_success": 4,
        }
        replay = {
            "source_witness_bytes": 0,
            "claimed_full_Q_output_bytes": 0,
            "forward_prime_NTTs": 2 * (known_query_inputs + digits),
            "canonical_source_inverse_prime_NTTs": 2 * len(cuts),
            "terminal_inverse_prime_NTTs": 4,
            "source_common_Q_CRT_coordinates": n * len(cuts),
            "terminal_common_Q_CRT_and_exact_round_coordinates": 2 * n,
            "DAG_word_products_after_removing_source_recomposition": direct[
                "DAG_word_product_count"
            ]
            - 2 * n * recomposition_scales,
            "DAG_add_sub_passes_after_removing_source_constraint_and_recomposition": direct[
                "polynomial_add_sub_passes"
            ]
            - digits
            - 2,
            "scope": "Sufficient same-direct-DAG prepared replay schedule; canonical sources are derived locally by inverse NTT/CRT and digit extraction. Actual performance, lifetimes/roots/scratch and backend schedules are unmeasured.",
        }
        models.append(
            {
                "vectors": model["vectors"],
                "tiles": model["tiles"],
                "kind": model["kind"],
                "bits": model["radix_bits"],
                "seeded": model["allow_seed"],
                "deterministic_exact_checker": checker,
                "prepared_full_replay": replay,
                "enrollment": {
                    "original_encrypted_index_Q_body_bytes": 2 * model["tiles"] * qpoly,
                    "original_query_Q_body_bytes": 2 * qpoly,
                    "canonical_relin_Q_body_bytes": 8 * qpoly,
                    "selected_rotation_key_Q_body_bytes": stock[
                        "rotation_key_Q_body_bytes"
                    ],
                    "alternate_rotation_keys_vs30_bytes": stock[
                        "additional_rotation_key_Q_body_bytes_vs30"
                    ],
                    "allowed_plaintext_binary_index_bytes": (model["vectors"] * d + 7)
                    // 8,
                },
                "cached_direct_public_multipliers_RNS_bytes": model["direct"][
                    "cached_preparation"
                ]["cached_public_multiplier_RNS_word_bytes"],
                "cached_fused_public_multipliers_RNS_bytes": model["fused"][
                    "cached_preparation"
                ]["cached_public_multiplier_RNS_word_bytes"],
                "client_reply_not_reduced_by_changing_this_source_tape": True,
            }
        )
    variant_plans = {
        (c["context"], c["query"], c["vectors"], c["radix_bits"], c["allow_seed"]): c[
            "plans"
        ]
        for c in receipt["cases"]
    }
    corrections, checked = [], 0
    for mode in ("public", "local-public"):
        for old in screens[mode]["cases"]:
            at, qa, count, bits, seeded = (
                old[k]
                for k in ("context", "query", "vectors", "radix_bits", "allow_seed")
            )
            pk, keys, queries, indexed = contexts[at]
            d, n = keys[30].padded, pk.n
            chosen = indexed[: (count + n // d - 1) // (n // d)]
            dimension = receipt["contexts"][at]["geometry"]["dimension"]
            if old["kind"] == "matched_canonical30":
                plans = tuple(
                    opaque(d.bit_length() - 2, min(d, len(chosen) - start))
                    for start in range(0, len(chosen), d)
                )
            else:
                plans = tuple(
                    plan_from_dict(v)
                    for v in variant_plans[at, qa, count, bits, seeded]
                )
            profiles = reference.profiles(
                queries[qa], chosen, count, dimension, pk, keys[30], keys[bits]
            )
            template = shape.compile_shape(
                profiles, plans, local_boundaries=mode == "local-public"
            )
            limits = (
                fusion.Limits()
                if mode == "public"
                else fusion.Limits(64, 4096, 3, 400_000, 12_000_000)
            )
            graphs = {
                "direct": shape.direct_graph(template.graph),
                "fused": fusion.fuse(template.graph, limits).graph,
            }
            for name, graph in graphs.items():
                current = fusion.resource_ledger(graph)
                assert {
                    k: v
                    for k, v in current.items()
                    if k != "fixed_position_index_update"
                } == {
                    k: v
                    for k, v in old[name].items()
                    if k != "fixed_position_index_update"
                }
                if (
                    current["fixed_position_index_update"]
                    != old[name]["fixed_position_index_update"]
                ):
                    corrections.append(
                        {
                            "mode": mode,
                            "context": at,
                            "query": qa,
                            "vectors": count,
                            "bits": bits,
                            "seeded": seeded,
                            "graph": name,
                            "corrected_index_update_counters": current[
                                "fixed_position_index_update"
                            ],
                        }
                    )
                checked += 1
    result.update(
        kind="Q71_paid_replay_control_and_counter_audit",
        distinct_models=models,
        distinct_model_count=len(models),
        earlier_resource_graphs_audited=checked,
        index_sum_counter_addenda=corrections,
        corrected_counter_panels=len(corrections),
        all_other_earlier_resource_fields_exact=True,
        new_HE_or_latency_cohort=False,
        future_native_and_release_usefulness_unresolved=True,
    )
    write_new(
        args.out_dir / "controls-screen.json",
        json.dumps(result, indent=2).encode() + b"\n",
    )
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "distinct_model_count",
                    "earlier_resource_graphs_audited",
                    "corrected_counter_panels",
                    "all_other_earlier_resource_fields_exact",
                )
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
