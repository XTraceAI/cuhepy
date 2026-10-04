#!/usr/bin/env python3
"""Q70 per-node correctness screen; complete public replay before diagnostics."""

# ruff: noqa: E402 -- standalone research runner.

import argparse
from dataclasses import asdict
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
from benchmarks.propagated_gadget_encrypted_lab import (
    frame_decrypt,
    physical_decrypt,
    plain_values,
    write_new,
)
from experiments.bfv_search_lab import noise_cut_planner as planner
from experiments.bfv_search_lab import noise_cut_reference as reference
from experiments.bfv_search_lab import propagated_gadget_bgv as gadget
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    marker, out = args.out_dir / "started.json", args.out_dir / "correctness.json"
    if marker.exists() or out.exists():
        parser.error("New immutable output directory required")
    registration = (
        ROOT / "docs/research/gadget-cut-planner-encrypted-registration-20261003.json"
    )
    reg = json.loads(registration.read_text())
    paths = [
        Path(__file__),
        registration,
        ROOT / "benchmarks/dictionary_layout_lab.py",
        ROOT / "benchmarks/propagated_gadget_encrypted_lab.py",
        ROOT / "src/cuhepy/bfv/scheme.py",
        ROOT / "src/cuhepy/types.py",
    ]
    paths.extend(
        ROOT / f"experiments/bfv_search_lab/{name}.py"
        for name in (
            "noise_cut_reference",
            "noise_cut_planner",
            "tensor_gadget_seed",
            "propagated_gadget_bgv",
            "shallow_bgv",
            "trace_bgv",
            "butterfly_bgv",
            "compact_bgv",
            "native_boundary_oracle",
        )
    )
    result = metadata(paths)
    rng, inputs = random.Random(reg["public_seed"]), []
    for geometry in reg["contexts"]:
        dimension, maximum = geometry["dimension"], max(geometry["counts"])
        inputs.append(
            {
                "geometry": geometry,
                "rows": [
                    [rng.randrange(2) for _ in range(dimension)] for _ in range(maximum)
                ],
                "queries": [
                    [rng.randrange(2) for _ in range(dimension)]
                    for _ in range(reg["queries_per_context"])
                ],
                "ids": [3000 + 13 * i for i in range(maximum)],
            }
        )
    files = [
        write_new(
            args.out_dir / "inputs-before-keygen.json",
            json.dumps(inputs, indent=2).encode() + b"\n",
        )
    ]
    write_new(
        marker,
        json.dumps(
            {
                "utc": datetime.now(UTC).isoformat(),
                "source_sha256": result["source_sha256"],
                "registration_sha256": hashlib.sha256(
                    registration.read_bytes()
                ).hexdigest(),
                "input_receipt": files[0],
                "before_key_generation": True,
            },
            indent=2,
        ).encode()
        + b"\n",
    )
    with tarfile.open(args.out_dir / "executed-source.tar.gz", "x:gz") as archive:
        for path in paths:
            archive.add(path, arcname=str(path.relative_to(ROOT)))
    records, contexts, base_cases = [], [], []
    for context_at, entry in enumerate(inputs):
        g = entry["geometry"]
        pk, sk = bgv.key_gen(g["N"], t=g["t"], q_bits=g["q_bits"], eta=g["eta"])
        padded = 1 << (g["dimension"] - 1).bit_length()
        keys = {
            bits: trace.evaluation_keys(pk, sk, padded, bits) for bits in reg["radices"]
        }
        _, tiles = bgv.coefficient_inputs(entry["queries"][0], entry["rows"], pk.n)
        index = [bgv.encrypt(p, pk) for p in tiles]
        queries = []
        for plain in entry["queries"]:
            qp, _ = bgv.coefficient_inputs(plain, [], pk.n)
            queries.append(bgv.encrypt(qp, pk))
        public = plain_values(
            {
                "pk": asdict(pk),
                "diagnostic_full_key_sets": {
                    bits: asdict(k) for bits, k in keys.items()
                },
                "index": [asdict(c) for c in index],
                "queries": [asdict(c) for c in queries],
            }
        )
        files.append(
            write_new(
                args.out_dir / f"context-{context_at}-public.json.gz",
                gzip.compress(json.dumps(public, sort_keys=True).encode(), mtime=0),
            )
        )
        contexts.append(
            {
                "context": context_at,
                "geometry": g,
                "key_id": pk.key_id,
                "unused_diagnostic_keys_preserved": True,
            }
        )
        for query_at, (query, qp) in enumerate(
            zip(queries, entry["queries"], strict=True)
        ):
            for count in g["counts"]:
                chosen = index[: (count + pk.n // padded - 1) // (pk.n // padded)]
                canonical = gadget.make_trace(
                    query, chosen, count, g["dimension"], pk, keys[30], propagate=False
                )
                assert gadget.check_trace(
                    query,
                    chosen,
                    count,
                    g["dimension"],
                    pk,
                    keys[30],
                    canonical,
                    propagate=False,
                )
                plain_base = physical_decrypt(canonical, pk, sk)
                assert frame_decrypt(canonical, pk, sk) == plain_base
                truth = [
                    sum(a != b for a, b in zip(qp, row, strict=True))
                    for row in entry["rows"][:count]
                ]
                assert trace.decode(plain_base, count, g["dimension"], pk) == truth
                stem = f"context-{context_at}-query-{query_at}-count-{count}"
                files.append(
                    write_new(
                        args.out_dir / f"{stem}-canonical.bin", canonical.response
                    )
                )
                base_cases.append(
                    {
                        "context": context_at,
                        "query": query_at,
                        "vectors": count,
                        "canonical_public_replay": True,
                        "canonical_all_coordinates_and_distances_exact": True,
                    }
                )
                for bits in reg["radices"]:
                    pp = reference.profiles(
                        query, chosen, count, g["dimension"], pk, keys[30], keys[bits]
                    )
                    for seeded in reg["seed_modes"]:
                        card = {
                            "context": context_at,
                            "query": query_at,
                            "vectors": count,
                            "radix_bits": bits,
                            "allow_seed": seeded,
                        }
                        case_stem = f"{stem}-b{bits}-s{int(seeded)}"
                        try:
                            selected, stats = [], []
                            for group, p in enumerate(pp):
                                frontier, stat = planner.frontier(
                                    p, min(padded, len(chosen) - group * padded), seeded
                                )
                                selected.append(planner.select(frontier))
                                stats.append(stat)
                        except planner.PlannerLimit as error:
                            card.update(
                                status="registered_limit_no_exact_optimum",
                                reason=str(error),
                            )
                            records.append(card)
                            files.append(
                                write_new(
                                    args.out_dir / f"{case_stem}-limit.json",
                                    json.dumps(card, indent=2).encode() + b"\n",
                                )
                            )
                            continue
                        plans = tuple(v.plan for v in selected)
                        try:
                            supplied = reference.make_trace(
                                query,
                                chosen,
                                count,
                                g["dimension"],
                                pk,
                                keys[30],
                                keys[bits],
                                plans,
                            )
                            assert reference.check_trace(
                                query,
                                chosen,
                                count,
                                g["dimension"],
                                pk,
                                keys[30],
                                keys[bits],
                                plans,
                                supplied,
                            )
                            plain = physical_decrypt(supplied, pk, sk)
                            assert (
                                frame_decrypt(supplied, pk, sk) == plain == plain_base
                            )
                            distances = trace.decode(plain, count, g["dimension"], pk)
                            assert distances == truth
                            top = sorted(
                                zip(distances, entry["ids"][:count], strict=True)
                            )[:3]
                            assert (
                                top
                                == sorted(
                                    zip(truth, entry["ids"][:count], strict=True)
                                )[:3]
                            )
                            removed = sum(
                                c.kind.startswith("derived") for c in supplied.cuts
                            )
                            assert removed == sum(v.removed for v in selected)
                        except Exception as error:
                            failure = dict(
                                card,
                                status="failed_preserved",
                                error_type=type(error).__name__,
                                reason=str(error),
                            )
                            write_new(
                                args.out_dir / f"{case_stem}-failure.json",
                                json.dumps(failure, indent=2).encode() + b"\n",
                            )
                            raise
                        trace_body = asdict(supplied)
                        trace_body.pop("response")
                        files.append(
                            write_new(
                                args.out_dir / f"{case_stem}.bin", supplied.response
                            )
                        )
                        files.append(
                            write_new(
                                args.out_dir / f"{case_stem}-trace.json.gz",
                                gzip.compress(
                                    json.dumps(trace_body, sort_keys=True).encode(),
                                    mtime=0,
                                ),
                            )
                        )
                        card.update(
                            status="complete_toy_correctness",
                            whole_public_replay_before_private=True,
                            all_Q_P_coordinates_distances_IDs_top3_exact=True,
                            physical_coordinates=len(plain) * pk.n,
                            distances=count,
                            removed_source_cuts=removed,
                            whole_Q_bytes_differ=supplied.full_output
                            != canonical.full_output,
                            compact_frame_bytes=len(supplied.response),
                            canonical_frame_bytes=len(canonical.response),
                            top3=top,
                            profiles=[asdict(p) for p in pp],
                            plans=[asdict(p) for p in plans],
                            modeled_group_ledgers=[
                                planner.ledger(p, v)
                                for p, v in zip(pp, selected, strict=True)
                            ],
                            planner_stats=stats,
                        )
                        records.append(card)
                        print(
                            json.dumps(
                                {
                                    k: card[k]
                                    for k in (
                                        "context",
                                        "query",
                                        "vectors",
                                        "radix_bits",
                                        "allow_seed",
                                        "status",
                                        "removed_source_cuts",
                                    )
                                }
                            ),
                            flush=True,
                        )
        del sk
    completed = [r for r in records if r["status"] == "complete_toy_correctness"]
    result.update(
        kind="Q70_registered_per_node_homemade_encrypted_correctness",
        contexts=contexts,
        base_cases=base_cases,
        cases=records,
        files=files,
        distinct_fresh_key_contexts=len(contexts),
        distinct_query_contexts=len(contexts) * reg["queries_per_context"],
        base_geometry_query_cases=len(base_cases),
        variant_comparisons_completed=len(completed),
        variant_case_distance_checks_with_nested_overlap=sum(
            r["distances"] for r in completed
        ),
        distinct_max_prefix_distances=reg["queries_per_context"]
        * sum(max(g["counts"]) for g in reg["contexts"]),
        variant_case_physical_coordinates_with_overlap=sum(
            r["physical_coordinates"] for r in completed
        ),
        scope=reg["scope"],
    )
    write_new(out, json.dumps(result, indent=2).encode() + b"\n")
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "distinct_fresh_key_contexts",
                    "distinct_query_contexts",
                    "base_geometry_query_cases",
                    "variant_comparisons_completed",
                    "distinct_max_prefix_distances",
                )
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
