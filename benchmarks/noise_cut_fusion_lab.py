#!/usr/bin/env python3
"""Registered Q71 complete generic fusion and paid resource screen."""

# ruff: noqa: E402 -- standalone research runner.

from dataclasses import replace
from collections import Counter
from datetime import UTC, datetime
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks.dictionary_layout_lab import metadata
from benchmarks.noise_cut_lowering_lab import plan_from_dict
from benchmarks.noise_cut_planner_lab import profile
from benchmarks.noise_cut_relation_lab import opaque, public_context
from benchmarks.propagated_gadget_encrypted_lab import write_new
from experiments.bfv_search_lab import noise_cut_fusion as fusion
from experiments.bfv_search_lab import noise_cut_lowering as lowering
from experiments.bfv_search_lab import noise_cut_reference as reference
from experiments.bfv_search_lab import noise_cut_relation as relation
from experiments.bfv_search_lab import noise_cut_shape as shape


def pin_file(path, expected=None):
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if expected is not None and actual != expected:
        raise ValueError("Frozen input SHA mismatch: " + str(path))
    return {"file": str(path), "bytes": len(raw), "sha256": actual}


def json_gz(path):
    return json.loads(gzip.decompress(path.read_bytes()))


def prepare(args):
    args.out_dir.mkdir(parents=True, exist_ok=True)
    if any(args.out_dir.iterdir()):
        raise ValueError("Fresh immutable output directory required")
    registrations = [
        ROOT / "docs/research/gadget-cut-fusion-registration-20261004.json",
        ROOT / "docs/research/gadget-cut-fusion-refinement-20261004.json",
    ]
    paths = [Path(__file__), *registrations]
    paths.append(
        ROOT / "docs/research/gadget-cut-local-fusion-registration-20261004.json"
    )
    paths.append(
        ROOT / "docs/research/gadget-cut-paired-fusion-registration-20261004.json"
    )
    paths.append(ROOT / "docs/research/gadget-cut-planner-registration-20261003.json")
    paths.extend(
        ROOT / f"experiments/bfv_search_lab/{name}.py"
        for name in (
            "noise_cut_fusion",
            "noise_cut_shape",
            "noise_cut_relation",
            "noise_cut_lowering",
            "noise_cut_reference",
            "noise_cut_planner",
            "noise_cut_oracle",
            "tensor_gadget_factorization",
            "tensor_gadget_seed",
            "propagated_gadget_bgv",
            "shallow_bgv",
            "trace_bgv",
            "butterfly_bgv",
            "compact_bgv",
            "native_boundary_oracle",
            "support_bounds_bgv",
            "test_support_bounds_bgv",
        )
    )
    paths.extend(
        ROOT / f"benchmarks/{name}.py"
        for name in (
            "noise_cut_lowering_lab",
            "noise_cut_planner_lab",
            "noise_cut_relation_lab",
            "propagated_gadget_encrypted_lab",
            "dictionary_layout_lab",
        )
    )
    paths.extend([ROOT / "src/cuhepy/bfv/scheme.py", ROOT / "src/cuhepy/types.py"])
    result = metadata(paths)
    with tarfile.open(args.out_dir / "executed-source.tar.gz", "x:gz") as archive:
        for path in paths:
            archive.add(path, arcname=str(path.relative_to(ROOT)))
    return result


def start(args, result, inputs):
    write_new(
        args.out_dir / "started.json",
        json.dumps(
            {
                "utc": datetime.now(UTC).isoformat(),
                "mode": args.mode,
                "source_sha256": result["source_sha256"],
                "inputs_before_checks": inputs,
                "new_HE_keys_private_diagnostics_or_latency": False,
            },
            indent=2,
        ).encode()
        + b"\n",
    )


def public_cases(args, result):
    local = args.mode in ("local-public", "paired-public")
    paired = args.mode == "paired-public"
    limits = (
        fusion.Limits(64, 4096, 3, 400_000, 12_000_000) if local else fusion.Limits()
    )
    encrypted = args.input_dir / "encrypted"
    control = args.input_dir / "relation-retry"
    receipt = json.loads((encrypted / "correctness.json").read_text())
    controls = json.loads((control / "relation-screen.json").read_text())
    inputs = [
        pin_file(encrypted / "correctness.json"),
        pin_file(control / "relation-screen.json"),
    ]
    inputs.extend(
        pin_file(encrypted / v["file"], v["sha256"]) for v in receipt["files"]
    )
    inputs.extend(pin_file(control / v["file"], v["sha256"]) for v in controls["files"])
    start(args, result, inputs)
    contexts = {
        v["context"]: public_context(
            json_gz(encrypted / f"context-{v['context']}-public.json.gz")
        )
        for v in receipt["contexts"]
    }
    cards = [
        *receipt["cases"],
        *(
            v
            for v in controls["cases"]
            if v["status"] == "complete_matched_canonical_public_relation"
        ),
    ]
    cases = []
    for card in cards:
        at, qa, count, bits, seeded = (
            card[k] for k in ("context", "query", "vectors", "radix_bits", "allow_seed")
        )
        pk, keys, queries, indexed = contexts[at]
        n, q, d = pk.n, int(pk.q), keys[30].padded
        index = indexed[: (count + n // d - 1) // (n // d)]
        dimension = receipt["contexts"][at]["geometry"]["dimension"]
        stem = f"context-{at}-query-{qa}-count-{count}"
        canonical = "plans" not in card
        if canonical:
            plans = tuple(
                opaque(d.bit_length() - 2, min(d, len(index) - start))
                for start in range(0, len(index), d)
            )
            body = json_gz(control / f"{stem}-canonical-trace.json.gz")
        else:
            plans = tuple(plan_from_dict(p) for p in card["plans"])
            body = json_gz(encrypted / f"{stem}-b{bits}-s{int(seeded)}-trace.json.gz")
        compiled = relation.compile_relation(
            queries[qa], index, count, dimension, pk, keys[30], keys[bits], plans
        )
        by_identity = {
            (v["group"], v["level"], v["node"]): v
            for v in body["cuts"]
            if v["kind"].startswith("canonical")
        }
        if len(by_identity) != len(compiled.source_layout):
            raise ValueError("Complete canonical identity coverage required")
        sources = tuple(
            relation.Source(
                g, level, node, tuple(by_identity[g, level, node]["source"])
            )
            for g, level, node, _bits in compiled.source_layout
        )
        outputs = tuple(
            tuple(tuple(row) for row in pair) for pair in body["full_output"]
        )
        profiles = reference.profiles(
            queries[qa], index, count, dimension, pk, keys[30], keys[bits]
        )
        template = shape.compile_shape(
            profiles, plans, local_boundaries=local, paired_kernels=paired
        )
        assert template.source_layout == compiled.source_layout
        public = shape.concrete_constants(template, index, keys[30], keys, q)
        direct = shape.direct_graph(template.graph)
        fused = fusion.fuse(template.graph, limits)
        prepared = fusion.coefficients(fused.graph, public)
        original_constants = fusion.coefficients(direct, public)
        z = sources[0].polynomial
        bad_source = (
            replace(sources[0], polynomial=((z[0] + 1) % q, *z[1:])),
            *sources[1:],
        )
        pair = outputs[-1]
        bad_output = (*outputs[:-1], ((*pair[0][:-1], (pair[0][-1] + 1) % q), pair[1]))
        for mutation, source, terminal in (
            ("honest", sources, outputs),
            ("product_source", bad_source, outputs),
            ("last_output", sources, bad_output),
        ):
            bound = fusion.bindings(compiled, source, terminal)
            expected = relation.residuals(compiled, source, terminal)
            direct_vectors = fusion.evaluate(direct, bound, original_constants)
            actual = fusion.evaluate(fused.graph, bound, prepared)
            assert expected == direct_vectors == actual
            assert any(any(v) for v in actual) == (mutation != "honest")
        # Full resource ledgers are retained for all public cases. They price
        # the graph, not the variable-time toy Python execution.
        current = {
            **{
                k: card[k]
                for k in ("context", "query", "vectors", "radix_bits", "allow_seed")
            },
            "kind": "matched_canonical30" if canonical else "retained_variant",
            "complete_vectors_equal_on_honest_and_two_mutations": True,
            "residuals": len(compiled.residuals),
            "direct": fusion.resource_ledger(direct),
            "fused": fusion.resource_ledger(fused.graph),
            "boundaries_by_reason": dict(
                Counter(reason for _i, reason in fused.boundaries)
            ),
        }
        cases.append(current)
        write_new(
            args.out_dir
            / f"{stem}-b{bits}-s{int(seeded)}-{'canonical' if canonical else 'variant'}.json",
            json.dumps(current, indent=2).encode() + b"\n",
        )
        print(
            json.dumps(
                {
                    "case": len(cases),
                    "context": at,
                    "vectors": count,
                    "bits": bits,
                    "seeded": seeded,
                    "complete": True,
                }
            ),
            flush=True,
        )
    result.update(
        kind="Q71_complete_local_fusion_public_correctness"
        if local
        else "Q71_complete_bounded_fusion_public_correctness",
        cases=cases,
        complete_cases=len(cases),
        targeted_changed_tapes=2 * len(cases),
        retained_key_contexts=2,
        new_HE_key_contexts=0,
        independent_new_encrypted_cohort=False,
        input_receipts=inputs,
    )


def models(args, result):
    local = args.mode in ("local-model", "paired-model")
    paired = args.mode == "paired-model"
    limits = (
        fusion.Limits(64, 4096, 3, 400_000, 12_000_000) if local else fusion.Limits()
    )
    path = args.input_dir / "large-refined/planner-screen.json"
    source = json.loads(path.read_text())
    wanted = {(256, 14, False), (257, 14, False), (512, 18, True)}
    if local:
        wanted.update(((256, 30, False), (257, 30, False)))
    selected, inputs = [], [pin_file(path)]
    for entry in source["cases"]:
        card = ROOT / entry["card"]
        raw = json.loads(card.read_text())
        if (raw["tiles"], raw["radix_bits"], raw["allow_seed"]) in wanted:
            if raw["status"] != "complete_declared_grammar":
                raise ValueError("Selected parent planner case is incomplete")
            inputs.append(pin_file(card, entry["sha256"]))
            selected.append(raw)
    if len(selected) != len(wanted):
        raise ValueError("Exactly all registered selected cards required")
    start(args, result, inputs)
    spec = json.loads(
        (
            ROOT / "docs/research/gadget-cut-planner-registration-20261003.json"
        ).read_text()
    )["large"]
    cases = []
    seen_controls = set()
    for raw in selected:
        p = profile(
            raw["N"],
            raw["D"],
            raw["radix_bits"],
            int(spec["Q_hex"], 16),
            spec["t"],
            spec["eta"],
            spec["P"],
        )
        for kind, context, plan in (
            (
                "matched_canonical30",
                replace(p, bits=30),
                opaque(p.d.bit_length() - 2, raw["tiles"]),
            ),
            ("selected_lowered", p, plan_from_dict(raw["plan"])),
        ):
            label, body, _rows = lowering.lower(context, plan)
            current = {
                "N": p.n,
                "D": p.d,
                "tiles": raw["tiles"],
                "vectors": raw["tiles"] * (p.n // p.d),
                "radix_bits": context.bits,
                "allow_seed": raw["allow_seed"]
                if kind == "selected_lowered"
                else False,
                "kind": kind,
                "parent_profile_bits": raw["radix_bits"],
                "matched_geometry_control_repeat": kind == "matched_canonical30"
                and raw["tiles"] in seen_controls,
                "body_and_keys": body,
                "public_phase_bound_bits": label.peak.bit_length(),
            }
            try:
                template = shape.compile_shape(
                    (context,),
                    (plan,),
                    lowered=True,
                    local_boundaries=local,
                    paired_kernels=paired,
                )
                direct = shape.direct_graph(template.graph)
                fused = fusion.fuse(template.graph, limits)
                current.update(
                    status="complete_declared_shape_and_fusion_model",
                    direct=fusion.resource_ledger(direct),
                    fused=fusion.resource_ledger(fused.graph),
                    source_layout_polynomials=len(template.source_layout),
                    complete_terminal_Q_polynomials=2,
                    boundaries_by_reason=dict(
                        Counter(reason for _i, reason in fused.boundaries)
                    ),
                )
            except fusion.LimitReached as error:
                current.update(
                    status="explicit_compiler_resource_limit_no_complete_fused_model",
                    reason=str(error),
                )
            cases.append(current)
            if kind == "matched_canonical30":
                seen_controls.add(raw["tiles"])
            write_new(
                args.out_dir
                / f"m{raw['tiles']}-b{context.bits}-s{int(current['allow_seed'])}-{kind}{'-parent-b' + str(raw['radix_bits']) if local else ''}.json",
                json.dumps(current, indent=2).encode() + b"\n",
            )
            print(
                json.dumps(
                    {
                        "tiles": raw["tiles"],
                        "bits": context.bits,
                        "kind": kind,
                        "status": current["status"],
                    }
                ),
                flush=True,
            )
    result.update(
        kind="Q71_complete_local_fusion_resource_models"
        if local
        else "Q71_complete_bounded_fusion_resource_models",
        cases=cases,
        input_receipts=inputs,
        complete_models=sum(
            c["status"] == "complete_declared_shape_and_fusion_model" for c in cases
        ),
        explicit_model_limits=sum(
            c["status"] != "complete_declared_shape_and_fusion_model" for c in cases
        ),
        new_HE_keys_private_diagnostics_or_latency=False,
        repeated_identical_canonical_control_models=sum(
            c["matched_geometry_control_repeat"] for c in cases
        ),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=(
            "public",
            "model",
            "local-public",
            "local-model",
            "paired-public",
            "paired-model",
        ),
        required=True,
    )
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args)
    try:
        (
            public_cases
            if args.mode in ("public", "local-public", "paired-public")
            else models
        )(args, result)
        write_new(
            args.out_dir / "fusion-screen.json",
            json.dumps(result, indent=2).encode() + b"\n",
        )
    except Exception as error:
        write_new(
            args.out_dir / "failed.json",
            json.dumps(
                {"error_type": type(error).__name__, "reason": str(error)}, indent=2
            ).encode()
            + b"\n",
        )
        raise
    print(
        json.dumps(
            {
                k: v
                for k, v in result.items()
                if k
                in (
                    "complete_cases",
                    "targeted_changed_tapes",
                    "complete_models",
                    "explicit_model_limits",
                    "new_HE_key_contexts",
                )
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
