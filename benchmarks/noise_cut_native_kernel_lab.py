#!/usr/bin/env python3
"""Q71 registered fresh small RNS contexts for complete native residuals."""

# ruff: noqa: E402 -- standalone research runner.

import argparse
from dataclasses import asdict, replace
from datetime import UTC, datetime
import gzip
import hashlib
import json
from pathlib import Path
import random
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks.dictionary_layout_lab import metadata
from benchmarks.noise_cut_relation_lab import opaque
from benchmarks.propagated_gadget_encrypted_lab import (
    frame_decrypt,
    physical_decrypt,
    plain_values,
    write_new,
)
from experiments.bfv_search_lab import native_noise_cut_kernel as native
from experiments.bfv_search_lab import noise_cut_fusion as fusion
from experiments.bfv_search_lab import noise_cut_planner as planner
from experiments.bfv_search_lab import noise_cut_reference as reference
from experiments.bfv_search_lab import noise_cut_relation as relation
from experiments.bfv_search_lab import noise_cut_shape as shape
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    if any(args.out_dir.iterdir()):
        parser.error("New immutable evidence directory required")
    registration = (
        ROOT / "docs/research/gadget-cut-native-kernel-registration-20261004.json"
    )
    spec = json.loads(registration.read_text())
    sources = [
        Path(__file__),
        registration,
        ROOT / "experiments/bfv_search_lab/_gadget/noise_cut_kernel.cpp",
    ]
    sources.extend(
        ROOT / f"src/cuhepy/bfv/_cpu_ext/{p}" for p in ("rns_ntt.h", "profile.h")
    )
    sources.extend(
        ROOT / f"experiments/bfv_search_lab/{p}.py"
        for p in (
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
    sources.extend(
        ROOT / f"benchmarks/{p}.py"
        for p in (
            "dictionary_layout_lab",
            "noise_cut_relation_lab",
            "noise_cut_lowering_lab",
            "propagated_gadget_encrypted_lab",
            "noise_cut_planner_lab",
        )
    )
    sources.extend((ROOT / "src/cuhepy/bfv/scheme.py", ROOT / "src/cuhepy/types.py"))
    result = metadata(sources)
    rng = random.Random(640714)
    inputs = []
    for geometry in spec["contexts"]:
        d = geometry["dimension"]
        inputs.append(
            {
                "geometry": geometry,
                "rows": [
                    [rng.randrange(2) for _ in range(d)]
                    for _ in range(max(geometry["vectors"]))
                ],
                "queries": [
                    [rng.randrange(2) for _ in range(d)]
                    for _ in range(spec["queries_per_context"])
                ],
            }
        )
    write_new(
        args.out_dir / "started.json",
        json.dumps(
            {
                "utc": datetime.now(UTC).isoformat(),
                "source_sha256": result["source_sha256"],
                "binary_sha256": hashlib.sha256(args.backend.read_bytes()).hexdigest(),
                "backend": str(args.backend),
                "plaintext_inputs_before_key_creation": inputs,
                "before_key_creation": True,
                "no_service_timing": True,
            },
            indent=2,
        ).encode()
        + b"\n",
    )
    with tarfile.open(args.out_dir / "executed-source.tar.gz", "x:gz") as archive:
        for p in sources:
            archive.add(p, arcname=str(p.relative_to(ROOT)))
    backend = native.load_backend(args.backend)
    cases, contexts, files = [], [], []
    for at, entry in enumerate(inputs):
        geometry, rows = entry["geometry"], entry["rows"]
        n, d = geometry["N"], geometry["D"]
        pk, sk = bgv.key_gen(n, geometry["t"], 120, geometry["eta"], rns_modulus=True)
        keys = trace.evaluation_keys(pk, sk, d, 30)
        _, tiles = bgv.coefficient_inputs(entry["queries"][0], rows, n)
        index = [bgv.encrypt(p, pk) for p in tiles]
        queries = [
            bgv.encrypt(bgv.coefficient_inputs(p, [], n)[0], pk)
            for p in entry["queries"]
        ]
        files.append(
            write_new(
                args.out_dir / f"context-{at}-public.json.gz",
                gzip.compress(
                    json.dumps(
                        plain_values(
                            {
                                "pk": asdict(pk),
                                "keys": asdict(keys),
                                "index": [asdict(v) for v in index],
                                "queries": [asdict(v) for v in queries],
                            }
                        ),
                        sort_keys=True,
                    ).encode(),
                    mtime=0,
                ),
            )
        )
        contexts.append(
            {
                "context": at,
                "key_id": pk.key_id,
                "Q_hex": format(int(pk.q), "x"),
                "actual_primes": list(map(int, native._rns_coefficient_primes(n, 120))),
                "geometry": geometry,
            }
        )
        for qa, query in enumerate(queries):
            for count in geometry["vectors"]:
                chosen = index[: (count + n // d - 1) // (n // d)]
                pp = reference.profiles(
                    query, chosen, count, geometry["dimension"], pk, keys, keys
                )
                selected = tuple(
                    planner.select(
                        planner.frontier(p, min(d, len(chosen) - g * d), False)[0]
                    ).plan
                    for g, p in enumerate(pp)
                )
                canonical = tuple(
                    opaque(d.bit_length() - 2, min(d, len(chosen) - g * d))
                    for g in range(len(pp))
                )
                plaintext_baseline = None
                for kind, plans in (
                    ("canonical30", canonical),
                    ("selected_no_seed30", selected),
                ):
                    supplied = reference.make_trace(
                        query,
                        chosen,
                        count,
                        geometry["dimension"],
                        pk,
                        keys,
                        keys,
                        plans,
                    )
                    compiled = relation.compile_relation(
                        query,
                        chosen,
                        count,
                        geometry["dimension"],
                        pk,
                        keys,
                        keys,
                        plans,
                    )
                    template = shape.compile_shape(
                        pp, plans, local_boundaries=True, paired_kernels=True
                    )
                    public = shape.concrete_constants(
                        template, chosen, keys, {30: keys}, int(pk.q)
                    )
                    direct, fused = (
                        shape.direct_graph(template.graph),
                        fusion.fuse(
                            template.graph,
                            fusion.Limits(64, 4096, 3, 400_000, 12_000_000),
                        ).graph,
                    )
                    kernels = tuple(
                        native.Kernel.prepare(compiled, graph, public, backend)
                        for graph in (direct, fused)
                    )
                    sources = tuple(
                        relation.Source(c.group, c.level, c.node, c.source)
                        for c in supplied.cuts
                        if c.kind.startswith("canonical")
                    )
                    outputs, q = supplied.full_output, int(pk.q)
                    first = sources[0].polynomial
                    bad_source = (
                        replace(
                            sources[0], polynomial=((first[0] + 1) % q, *first[1:])
                        ),
                        *sources[1:],
                    )
                    pair = outputs[-1]
                    bad_output = (
                        *outputs[:-1],
                        ((*pair[0][:-1], (pair[0][-1] + 1) % q), pair[1]),
                    )
                    for mutation, cut, terminal in (
                        ("honest", sources, outputs),
                        ("product_source", bad_source, outputs),
                        ("last_output", sources, bad_output),
                    ):
                        expected = relation.residuals(compiled, cut, terminal)
                        for kernel in kernels:
                            assert kernel.holds(cut, terminal) == (mutation == "honest")
                            assert kernel.residuals(cut, terminal) == tuple(
                                tuple(tuple(x % p for x in row) for p in kernel.primes)
                                for row in expected
                            )
                    # Private operations occur only after public checks and only
                    # in this local correctness diagnostic; never drive a guard.
                    plain = physical_decrypt(supplied, pk, sk)
                    assert frame_decrypt(supplied, pk, sk) == plain
                    if plaintext_baseline is None:
                        plaintext_baseline = plain
                    assert plain == plaintext_baseline
                    truth = [
                        sum(
                            x != y
                            for x, y in zip(entry["queries"][qa], row, strict=True)
                        )
                        for row in rows[:count]
                    ]
                    scores = trace.decode(plain, count, geometry["dimension"], pk)
                    assert scores == truth
                    top = sorted(zip(scores, range(count), strict=True))[:3]
                    assert top == sorted(zip(truth, range(count), strict=True))[:3]
                    stem = f"c{at}-q{qa}-m{count}-{kind}"
                    raw = asdict(supplied)
                    raw.pop("response")
                    raw["plans"] = [asdict(v) for v in plans]
                    files.append(
                        write_new(
                            args.out_dir / f"{stem}-trace.json.gz",
                            gzip.compress(
                                json.dumps(raw, sort_keys=True).encode(), mtime=0
                            ),
                        )
                    )
                    files.append(
                        write_new(args.out_dir / f"{stem}.bin", supplied.response)
                    )
                    cases.append(
                        {
                            "context": at,
                            "query": qa,
                            "vectors": count,
                            "kind": kind,
                            "status": "complete_small_RNS_native_residual_correctness",
                            "full_Q_P_coordinates_scores_IDs_top3_exact": True,
                            "native_direct_fused_schoolbook_both_limbs_exact_on_three_tapes": True,
                            "canonical_sources": len(sources),
                            "residuals": len(compiled.residuals),
                            "selected_removed_sources": sum(
                                planner.replay(p, plan).removed
                                for p, plan in zip(pp, plans, strict=True)
                            ),
                            "client_frame_bytes": len(supplied.response),
                            "top3": top,
                        }
                    )
                    print(
                        json.dumps(
                            {
                                "case": len(cases),
                                "context": at,
                                "vectors": count,
                                "kind": kind,
                                "complete": True,
                            }
                        ),
                        flush=True,
                    )
    result.update(
        kind="Q71_first_native_complete_vector_residual_component",
        contexts=contexts,
        cases=cases,
        files=files,
        fresh_key_contexts=2,
        base_geometry_query_pairs=16,
        complete_canonical_and_variant_relations=32,
        targeted_changed_tapes=64,
        native_and_reference_comparisons_overlap=True,
        complete_native_wire_release_controller=False,
        service_timing=False,
    )
    write_new(
        args.out_dir / "native-screen.json",
        json.dumps(result, indent=2).encode() + b"\n",
    )
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "fresh_key_contexts",
                    "base_geometry_query_pairs",
                    "complete_canonical_and_variant_relations",
                    "targeted_changed_tapes",
                )
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
