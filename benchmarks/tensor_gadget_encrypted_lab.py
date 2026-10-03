#!/usr/bin/env python3
"""Q70 bounded small-key public replay for mixed14/tensor18, no timing."""

# ruff: noqa: E402 -- standalone research runner.

from dataclasses import asdict
from datetime import UTC, datetime
import argparse
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
from experiments.bfv_search_lab import propagated_gadget_bgv as gadget
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import tensor_gadget_reference as candidate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out, marker = (
        args.out_dir / "Q70-small-correctness.json",
        args.out_dir / "Q70-started.json",
    )
    if out.exists() or marker.exists():
        parser.error("New immutable output directory required")
    registration = (
        ROOT / "docs/research/gadget-cut-small-followup-registration-20261003.json"
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
            "tensor_gadget_reference",
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
    for g in reg["contexts"]:
        n, d = g["N"], g["dimension"]
        inputs.append(
            {
                "geometry": g,
                "rows": [[rng.randrange(2) for _ in range(d)] for _ in range(n + 1)],
                "queries": [
                    [rng.randrange(2) for _ in range(d)]
                    for _ in range(reg["queries_per_context"])
                ],
                "ids": [2000 + 11 * i for i in range(n + 1)],
                "counts": [n // 2, n, n + 1],
            }
        )
    files = [
        write_new(
            args.out_dir / "inputs-before-keygen.json",
            json.dumps(inputs, indent=2).encode() + b"\n",
        )
    ]
    marker.write_text(
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
        )
        + "\n"
    )
    with tarfile.open(args.out_dir / "Q70-executed-source.tar.gz", "x:gz") as archive:
        for p in paths:
            archive.add(p, arcname=str(p.relative_to(ROOT)))
    records, contexts = [], []
    for context, entry in enumerate(inputs):
        g = entry["geometry"]
        pk, sk = bgv.key_gen(g["N"], t=g["t"], q_bits=g["q_bits"], eta=g["eta"])
        padded = 1 << (g["dimension"] - 1).bit_length()
        keys = {
            b: trace.evaluation_keys(pk, sk, padded, digit_bits=b) for b in (30, 14, 18)
        }
        _, tiles = bgv.coefficient_inputs(entry["queries"][0], entry["rows"], pk.n)
        index = [bgv.encrypt(p, pk) for p in tiles]
        queries = []
        for query in entry["queries"]:
            plain, _ = bgv.coefficient_inputs(query, [], pk.n)
            queries.append(bgv.encrypt(plain, pk))
        public = plain_values(
            {
                "pk": asdict(pk),
                "diagnostic_full_key_sets": {b: asdict(k) for b, k in keys.items()},
                "index": [asdict(c) for c in index],
                "queries": [asdict(c) for c in queries],
            }
        )
        files.append(
            write_new(
                args.out_dir / f"context-{context}-public.json.gz",
                gzip.compress(json.dumps(public, sort_keys=True).encode(), mtime=0),
            )
        )
        contexts.append(
            {
                "context": context,
                "key_id": pk.key_id,
                "geometry": g,
                "full_diagnostic_key_sets_generated": [30, 14, 18],
                "unused_keys_present_in_fixture": True,
            }
        )
        for query_at, (query, plain_query) in enumerate(
            zip(queries, entry["queries"], strict=True)
        ):
            for count in entry["counts"]:
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
                base_plain = physical_decrypt(canonical, pk, sk)
                assert frame_decrypt(canonical, pk, sk) == base_plain
                truth = [
                    sum(a != b for a, b in zip(plain_query, row, strict=True))
                    for row in entry["rows"][:count]
                ]
                for rule, width in (("mixed14", 14), ("tensor18", 18)):
                    supplied = candidate.make_trace(
                        query,
                        chosen,
                        count,
                        g["dimension"],
                        pk,
                        keys[30],
                        keys[width],
                        rule,
                    )
                    assert candidate.check_trace(
                        query,
                        chosen,
                        count,
                        g["dimension"],
                        pk,
                        keys[30],
                        keys[width],
                        rule,
                        supplied,
                    )
                    plain = physical_decrypt(supplied, pk, sk)
                    assert frame_decrypt(supplied, pk, sk) == plain == base_plain
                    distances = trace.decode(plain, count, g["dimension"], pk)
                    assert distances == truth
                    top = sorted(zip(distances, entry["ids"][:count], strict=True))[:3]
                    assert (
                        top == sorted(zip(truth, entry["ids"][:count], strict=True))[:3]
                    )
                    stem = f"context-{context}-query-{query_at}-count-{count}-{rule}"
                    files.append(
                        write_new(args.out_dir / f"{stem}.bin", supplied.response)
                    )
                    trace_body = asdict(supplied)
                    trace_body.pop("response")
                    files.append(
                        write_new(
                            args.out_dir / f"{stem}-trace.json.gz",
                            gzip.compress(
                                json.dumps(trace_body, sort_keys=True).encode(), mtime=0
                            ),
                        )
                    )
                    records.append(
                        {
                            "context": context,
                            "query": query_at,
                            "vectors": count,
                            "rule": rule,
                            "whole_public_replay_before_private": True,
                            "all_physical_plaintexts_scores_IDs_exact": True,
                            "physical_coordinates": len(plain) * pk.n,
                            "distances": count,
                            "noncanonical_cuts": sum(
                                c.kind == rule for c in supplied.cuts
                            ),
                            "whole_Q_bytes_differ": supplied.full_output
                            != canonical.full_output,
                            "compact_frame_bytes": len(supplied.response),
                            "canonical_frame_bytes": len(canonical.response),
                            "top3": top,
                        }
                    )
                stem = f"context-{context}-query-{query_at}-count-{count}-canonical"
                files.append(
                    write_new(args.out_dir / f"{stem}.bin", canonical.response)
                )
        del sk
    result.update(
        kind="Q70_bounded_small_homemade_mixed_and_tensor_seed_encrypted_correctness",
        contexts=contexts,
        cases=records,
        files=files,
        distinct_contexts=2,
        distinct_query_contexts=4,
        base_geometry_query_cases=12,
        variant_case_comparisons=len(records),
        scope="Two fresh toy keys, nested half/full/tail prefixes, known-method public full replay; actual complete plaintext/ID checks. Unused full diagnostic key columns are retained and not claimed as optimized setup. No native implementation/admission, timings, parameter/private-side-channel assurance or accepted originality for these follow-ups.",
    )
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                "contexts": 2,
                "base_cases": 12,
                "variant_comparisons": len(records),
                "all_exact": all(
                    r["all_physical_plaintexts_scores_IDs_exact"] for r in records
                ),
                "distinct_rule_counts": {
                    rule: sum(
                        r["noncanonical_cuts"] for r in records if r["rule"] == rule
                    )
                    for rule in ("mixed14", "tensor18")
                },
            }
        )
    )


if __name__ == "__main__":
    main()
