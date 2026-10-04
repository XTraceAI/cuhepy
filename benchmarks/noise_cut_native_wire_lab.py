#!/usr/bin/env python3
"""Q71 native common-Q wire checks on retained fresh RNS cohort fixtures."""

# ruff: noqa: E402 -- standalone research runner.

import argparse
from dataclasses import replace
from datetime import UTC, datetime
import gzip
import json
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks.dictionary_layout_lab import metadata
from benchmarks.noise_cut_fusion_lab import pin_file
from benchmarks.noise_cut_lowering_lab import plan_from_dict
from benchmarks.noise_cut_relation_lab import public_context
from benchmarks.propagated_gadget_encrypted_lab import write_new
from experiments.bfv_search_lab import native_noise_cut_kernel as native
from experiments.bfv_search_lab import noise_cut_fusion as fusion
from experiments.bfv_search_lab import noise_cut_reference as reference
from experiments.bfv_search_lab import noise_cut_relation as relation
from experiments.bfv_search_lab import noise_cut_shape as shape


def read(path):
    return json.loads(gzip.decompress(path.read_bytes()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--reference-backend", type=Path, required=True)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    if any(args.out_dir.iterdir()):
        parser.error("New immutable output directory required")
    receipt = json.loads((args.input_dir / "native-screen.json").read_text())
    inputs = [
        pin_file(args.input_dir / "native-screen.json"),
        pin_file(args.backend),
        pin_file(args.reference_backend),
    ]
    inputs.extend(
        pin_file(args.input_dir / item["file"], item["sha256"])
        for item in receipt["files"]
    )
    parent_start = json.loads((args.input_dir / "started.json").read_text())
    assert inputs[2]["sha256"] == parent_start["binary_sha256"]
    paths = [
        Path(__file__),
        ROOT / "docs/research/gadget-cut-native-wire-registration-20261004.json",
        ROOT / "experiments/bfv_search_lab/_gadget/noise_cut_kernel.cpp",
    ]
    paths.extend(
        ROOT / f"src/cuhepy/bfv/_cpu_ext/{name}" for name in ("rns_ntt.h", "profile.h")
    )
    paths.extend(
        ROOT / f"experiments/bfv_search_lab/{name}.py"
        for name in (
            "native_noise_cut_kernel",
            "noise_cut_fusion",
            "noise_cut_shape",
            "noise_cut_relation",
            "noise_cut_reference",
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
            "native_boundary_oracle",
        )
    )
    paths.extend(
        ROOT / f"benchmarks/{name}.py"
        for name in (
            "dictionary_layout_lab",
            "noise_cut_fusion_lab",
            "noise_cut_relation_lab",
            "noise_cut_lowering_lab",
            "propagated_gadget_encrypted_lab",
            "noise_cut_planner_lab",
        )
    )
    paths.extend((ROOT / "src/cuhepy/bfv/scheme.py", ROOT / "src/cuhepy/types.py"))
    result = metadata(paths)
    write_new(
        args.out_dir / "started.json",
        json.dumps(
            {
                "utc": datetime.now(UTC).isoformat(),
                "source_sha256": result["source_sha256"],
                "inputs_before_checks": inputs,
                "new_HE_keys_private_diagnostics_or_timing": False,
            },
            indent=2,
        ).encode()
        + b"\n",
    )
    with tarfile.open(args.out_dir / "executed-source.tar.gz", "x:gz") as archive:
        for path in paths:
            archive.add(path, arcname=str(path.relative_to(ROOT)))
    backend, previous = (
        native.load_backend(args.backend),
        native.load_backend(args.reference_backend),
    )
    contexts = {}
    for entry in receipt["contexts"]:
        at = entry["context"]
        raw = read(args.input_dir / f"context-{at}-public.json.gz")
        contexts[at] = public_context(
            {**raw, "diagnostic_full_key_sets": {"30": raw["keys"]}}
        )
    cases, files = [], []
    for card in receipt["cases"]:
        at, qa, count, kind = (card[k] for k in ("context", "query", "vectors", "kind"))
        stem = f"c{at}-q{qa}-m{count}-{kind}"
        raw = read(args.input_dir / f"{stem}-trace.json.gz")
        pk, keys, queries, indexed = contexts[at]
        d, n = keys[30].padded, pk.n
        dimension = receipt["contexts"][at]["geometry"]["dimension"]
        index, query = indexed[: (count + n // d - 1) // (n // d)], queries[qa]
        plans = tuple(plan_from_dict(p) for p in raw["plans"])
        pp = reference.profiles(query, index, count, dimension, pk, keys[30], keys[30])
        statement = relation.compile_relation(
            query, index, count, dimension, pk, keys[30], keys[30], plans
        )
        template = shape.compile_shape(
            pp, plans, local_boundaries=True, paired_kernels=True
        )
        public = shape.concrete_constants(template, index, keys[30], keys, int(pk.q))
        graphs = (
            shape.direct_graph(template.graph),
            fusion.fuse(
                template.graph, fusion.Limits(64, 4096, 3, 400_000, 12_000_000)
            ).graph,
        )
        kernels = tuple(
            native.WireKernel.prepare(statement, graph, public, backend)
            for graph in graphs
        )
        old = native.Kernel.prepare(statement, graphs[0], public, previous)
        sources = tuple(
            relation.Source(v["group"], v["level"], v["node"], tuple(v["source"]))
            for v in raw["cuts"]
            if v["kind"].startswith("canonical")
        )
        outputs = tuple(
            tuple(tuple(row) for row in pair) for pair in raw["full_output"]
        )
        q, z = int(pk.q), sources[0].polynomial
        bad_source = (
            replace(sources[0], polynomial=((z[0] + 1) % q, *z[1:])),
            *sources[1:],
        )
        pair = outputs[-1]
        bad_output = (*outputs[:-1], ((*pair[0][:-1], (pair[0][-1] + 1) % q), pair[1]))
        for mutation, cuts, terminal in (
            ("honest", sources, outputs),
            ("product_source", bad_source, outputs),
            ("last_output", sources, bad_output),
        ):
            vectors = old.residuals(cuts, terminal)
            for kernel in kernels:
                body = kernel.body(cuts, terminal)
                assert kernel.holds_bytes(body) == (mutation == "honest")
                assert kernel.residuals_bytes(body) == vectors
        body = kernels[0].body(sources, outputs)
        assert len(body) == 15 * n * (len(sources) + 2 * len(outputs))
        for kernel in kernels:
            assert not kernel.holds_bytes(body[:-1])
            assert not kernel.holds_bytes(body + b"\0")
            assert not kernel.holds_bytes(body[:-15] + q.to_bytes(15, "little"))
        files.append(write_new(args.out_dir / f"{stem}-body.bin", body))
        cases.append(
            {
                **card,
                "whole_wire_direct_fused_previous_native_vectors_exact": True,
                "malformed_length_and_last_common_Q_range_rejected": True,
                "whole_common_Q_wire_bytes": len(body),
            }
        )
        print(
            json.dumps(
                {
                    "case": len(cases),
                    "context": at,
                    "vectors": count,
                    "kind": kind,
                    "whole_wire": True,
                }
            ),
            flush=True,
        )
    result.update(
        kind="Q71_native_common_Q_wire_component",
        cases=cases,
        files=files,
        input_receipts=inputs,
        complete_retained_relations=32,
        targeted_changed_tapes=64,
        malformed_wire_bodies=96,
        new_HE_key_contexts=0,
        earlier_native_key_contexts_reused=2,
        complete_release_controller=False,
        large_preparation_or_timing=False,
    )
    write_new(
        args.out_dir / "wire-screen.json", json.dumps(result, indent=2).encode() + b"\n"
    )
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "complete_retained_relations",
                    "targeted_changed_tapes",
                    "malformed_wire_bodies",
                    "new_HE_key_contexts",
                )
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
