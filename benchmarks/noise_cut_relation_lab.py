#!/usr/bin/env python3
"""Q71 complete generic residual adapter on retained toy public HE fixtures."""

# ruff: noqa: E402 -- standalone research runner.

import argparse
from dataclasses import asdict, replace
from datetime import UTC, datetime
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tarfile

from gmpy2 import mpz

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks.dictionary_layout_lab import metadata
from benchmarks.noise_cut_lowering_lab import plan_from_dict
from benchmarks.propagated_gadget_encrypted_lab import write_new
from experiments.bfv_search_lab import noise_cut_planner as planner
from experiments.bfv_search_lab import noise_cut_relation as relation
from experiments.bfv_search_lab import propagated_gadget_bgv as gadget
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


def public_context(body):
    p = body["pk"]
    pk = bgv.PublicKey(
        p["n"],
        p["t"],
        mpz(p["q"]),
        p["eta"],
        tuple(map(mpz, p["a"])),
        tuple(map(mpz, p["b"])),
        p["key_id"],
    )

    def switch_key(value):
        return tuple(tuple(tuple(map(mpz, row)) for row in pair) for pair in value)

    keys = {}
    for bits, value in body["diagnostic_full_key_sets"].items():
        keys[int(bits)] = trace.EvaluationKeys(
            value["key_id"],
            value["padded"],
            value["digit_bits"],
            switch_key(value["relin"]),
            tuple((g, switch_key(key)) for g, key in value["rotations"]),
            value["switch_error_bound"],
        )

    def cipher(value):
        return bgv.Ciphertext(
            tuple(tuple(map(mpz, row)) for row in value["components"]),
            value["key_id"],
            value["phase_bound"],
        )

    return (
        pk,
        keys,
        [cipher(v) for v in body["queries"]],
        [cipher(v) for v in body["index"]],
    )


def opaque(level, count):
    if not count:
        return planner.Plan(level, 0, "zero", False)
    if level == -1:
        return planner.Plan(-1, 1, "plain", False)
    return planner.Plan(
        level,
        count,
        "canonical",
        False,
        opaque(level - 1, (count + 1) // 2),
        opaque(level - 1, count // 2),
    )


def check_case(compiled, sources, outputs):
    assert relation.holds(compiled, sources, outputs)
    poly = sources[0].polynomial
    bad = (
        replace(sources[0], polynomial=((poly[0] + 1) % compiled.q, *poly[1:])),
        *sources[1:],
    )
    assert not relation.holds(compiled, bad, outputs)
    pair = outputs[-1]
    bad_output = (
        *outputs[:-1],
        ((*pair[0][:-1], (pair[0][-1] + 1) % compiled.q), pair[1]),
    )
    assert not relation.holds(compiled, sources, bad_output)
    return dict(
        relation.statistics(compiled),
        whole_polynomial_relation_exact=True,
        canonical_product_source_mutation_rejected=True,
        last_physical_Q_coordinate_mutation_rejected=True,
        no_private_or_HE_oracle_during_relation_check=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    marker, out = args.out_dir / "started.json", args.out_dir / "relation-screen.json"
    if marker.exists() or out.exists():
        parser.error("New immutable output directory required")
    registration = ROOT / "docs/research/gadget-cut-relation-registration-20261003.json"
    paths = [
        Path(__file__),
        registration,
        ROOT / "docs/research/gadget-cut-relation-retry-registration-20261003.json",
        ROOT / "benchmarks/dictionary_layout_lab.py",
        ROOT / "benchmarks/noise_cut_lowering_lab.py",
        ROOT / "benchmarks/propagated_gadget_encrypted_lab.py",
        ROOT / "src/cuhepy/bfv/scheme.py",
        ROOT / "src/cuhepy/types.py",
    ]
    paths.extend(
        ROOT / f"experiments/bfv_search_lab/{name}.py"
        for name in (
            "noise_cut_relation",
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
    receipt_path = args.input_dir / "correctness.json"
    receipt = json.loads(receipt_path.read_text())
    inputs = [
        {
            "file": str(receipt_path),
            "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        }
    ]
    for entry in receipt["files"]:
        path = args.input_dir / entry["file"]
        assert (
            path.stat().st_size == entry["bytes"]
            and hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"]
        )
        inputs.append({"file": str(path), "sha256": entry["sha256"]})
    write_new(
        marker,
        json.dumps(
            {
                "utc": datetime.now(UTC).isoformat(),
                "source_sha256": result["source_sha256"],
                "registration_sha256": hashlib.sha256(
                    registration.read_bytes()
                ).hexdigest(),
                "input_receipts_before_relation_checks": inputs,
                "new_HE_keys_private_diagnostics_and_timing": False,
            },
            indent=2,
        ).encode()
        + b"\n",
    )
    with tarfile.open(args.out_dir / "executed-source.tar.gz", "x:gz") as archive:
        for path in paths:
            archive.add(path, arcname=str(path.relative_to(ROOT)))
    contexts = {}
    for c in receipt["contexts"]:
        number = c["context"]
        raw = json.loads(
            gzip.decompress(
                (args.input_dir / f"context-{number}-public.json.gz").read_bytes()
            )
        )
        contexts[number] = public_context(raw)
    cases, files, baselines = [], [], set()
    for card in receipt["cases"]:
        assert card["status"] == "complete_toy_correctness"
        at, query_at, count, bits, seeded = (
            card[k] for k in ("context", "query", "vectors", "radix_bits", "allow_seed")
        )
        pk, keys, queries, index = contexts[at]
        dimension = receipt["contexts"][at]["geometry"]["dimension"]
        padded, query = keys[30].padded, queries[query_at]
        chosen = index[: (count + pk.n // padded - 1) // (pk.n // padded)]
        stem = f"context-{at}-query-{query_at}-count-{count}"
        case_stem = f"{stem}-b{bits}-s{int(seeded)}"
        body = json.loads(
            gzip.decompress(
                (args.input_dir / f"{case_stem}-trace.json.gz").read_bytes()
            )
        )
        plans = tuple(plan_from_dict(v) for v in card["plans"])
        sources = tuple(
            relation.Source(v["group"], v["level"], v["node"], tuple(v["source"]))
            for v in body["cuts"]
            if v["kind"].startswith("canonical")
        )
        outputs = tuple(
            tuple(tuple(row) for row in pair) for pair in body["full_output"]
        )
        current = {
            k: card[k]
            for k in ("context", "query", "vectors", "radix_bits", "allow_seed")
        }
        try:
            compiled = relation.compile_relation(
                query, chosen, count, dimension, pk, keys[30], keys[bits], plans
            )
            stats = check_case(compiled, sources, outputs)
            assert len(sources) == len(body["cuts"]) - card["removed_source_cuts"]
        except Exception as error:
            write_new(
                args.out_dir / f"{case_stem}-failure.json",
                json.dumps(
                    dict(current, error_type=type(error).__name__, reason=str(error)),
                    indent=2,
                ).encode()
                + b"\n",
            )
            raise
        current.update(
            status="complete_retained_variant_public_relation",
            removed_source_cuts=card["removed_source_cuts"],
            statistics=stats,
        )
        cases.append(current)
        baseline_id = at, query_at, count
        if baseline_id not in baselines:
            baselines.add(baseline_id)
            supplied = gadget.make_trace(
                query, chosen, count, dimension, pk, keys[30], propagate=False
            )
            assert (
                supplied.response
                == (args.input_dir / f"{stem}-canonical.bin").read_bytes()
            )
            canonical_plans = tuple(
                opaque(padded.bit_length() - 2, min(padded, len(chosen) - start))
                for start in range(0, len(chosen), padded)
            )
            generic = relation.compile_relation(
                query, chosen, count, dimension, pk, keys[30], keys[30], canonical_plans
            )
            by_identity = {(c.group, c.level, c.node): c for c in supplied.cuts}
            assert len(by_identity) == len(supplied.cuts)
            assert set(by_identity) == {
                (g, level, node) for g, level, node, _bits in generic.source_layout
            }
            canonical_sources = tuple(
                relation.Source(g, level, node, by_identity[g, level, node].source)
                for g, level, node, _bits in generic.source_layout
            )
            canonical_stats = check_case(
                generic, canonical_sources, supplied.full_output
            )
            cases.append(
                {
                    "context": at,
                    "query": query_at,
                    "vectors": count,
                    "radix_bits": 30,
                    "allow_seed": False,
                    "status": "complete_matched_canonical_public_relation",
                    "statistics": canonical_stats,
                }
            )
            trace_body = asdict(supplied)
            trace_body.pop("response")
            files.append(
                write_new(
                    args.out_dir / f"{stem}-canonical-trace.json.gz",
                    gzip.compress(
                        json.dumps(trace_body, sort_keys=True).encode(), mtime=0
                    ),
                )
            )
        print(
            json.dumps(
                {
                    **{
                        k: current[k]
                        for k in (
                            "context",
                            "query",
                            "vectors",
                            "radix_bits",
                            "allow_seed",
                        )
                    },
                    "complete_relation": True,
                    "canonical_cuts": len(sources),
                }
            ),
            flush=True,
        )
    result.update(
        kind="Q71_first_complete_generic_affine_polynomial_relation_component",
        cases=cases,
        files=files,
        retained_variant_relations=96,
        matched_canonical_relations=len(baselines),
        complete_public_relations=len(cases),
        targeted_source_and_output_mutations=2 * len(cases),
        new_HE_key_contexts=0,
        new_private_diagnostics=0,
        scope=json.loads(registration.read_text())["scope"],
    )
    write_new(out, json.dumps(result, indent=2).encode() + b"\n")
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "complete_public_relations",
                    "targeted_source_and_output_mutations",
                    "new_HE_key_contexts",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
