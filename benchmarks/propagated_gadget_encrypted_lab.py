#!/usr/bin/env python3
"""Q66 four fresh homemade key contexts; complete public replay before decode."""

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

import msgpack
from gmpy2 import mpz

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import native_boundary_oracle as oracle
from experiments.bfv_search_lab import propagated_gadget_bgv as propagated
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


def plain_values(value):
    if isinstance(value, dict):
        return {k: plain_values(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain_values(v) for v in value]
    return int(value) if isinstance(value, mpz) else value


def write_new(path, data):
    with path.open("xb") as f:
        f.write(data)
    return {
        "file": path.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def physical_decrypt(tr, pk, sk):
    """Private diagnostic only; caller must first require full public replay."""
    return [
        bgv.decrypt(
            bgv.Ciphertext(tuple(tuple(map(mpz, p)) for p in pair), pk.key_id, bound),
            pk,
            sk,
        )
        for pair, bound in zip(tr.full_output, tr.bounds, strict=True)
    ]


def frame_decrypt(tr, pk, sk):
    """Decode exact admitted frame; this is not a network-facing packet parser."""
    header, body = msgpack.unpackb(tr.response, raw=False)
    p = int.from_bytes(header[3], "little")
    assert header == [
        "cuhepy-lab-bgv-compact-v1",
        pk.n,
        pk.t,
        header[3],
        bytes.fromhex(pk.key_id),
        tr.count,
        tr.dimension,
    ]
    assert len(body) == len(tr.full_output)
    output = []
    for rows, bound in zip(body, tr.bounds, strict=True):
        assert len(rows) == 2
        pair = tuple(
            tuple(map(mpz, oracle.unpack_bits(row, pk.n, p.bit_length(), p)))
            for row in rows
        )
        cipher = compact.CompactCiphertext(
            pair, pk.key_id, mpz(p), compact.reduced_bound(bound, pk, mpz(p))
        )
        output.append(compact.decrypt(cipher, pk, sk))
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    marker, out = (
        args.out_dir / "Q66-started.json",
        args.out_dir / "Q66-correctness.json",
    )
    if marker.exists() or out.exists():
        parser.error("New immutable output directory required")
    registration = ROOT / "docs/research/gadget-cut-preregistration-20261003.json"
    paths = [
        Path(__file__),
        registration,
        ROOT / "benchmarks/dictionary_layout_lab.py",
        ROOT / "src/cuhepy/bfv/scheme.py",
        ROOT / "src/cuhepy/types.py",
    ]
    paths.extend(
        ROOT / f"experiments/bfv_search_lab/{name}.py"
        for name in (
            "propagated_gadget_bgv",
            "native_boundary_oracle",
            "shallow_bgv",
            "trace_bgv",
            "butterfly_bgv",
            "compact_bgv",
        )
    )
    result = metadata(paths)
    reg_hash = hashlib.sha256(registration.read_bytes()).hexdigest()
    reg = json.loads(registration.read_text())["Q66"]
    inputs = []
    rng = random.Random(reg["public_data_seed"])
    for g in reg["contexts"]:
        n, d = g["N"], g["dimension"]
        rows = [[rng.randrange(2) for _ in range(d)] for _ in range(n + 1)]
        queries = [
            [rng.randrange(2) for _ in range(d)]
            for _ in range(reg["queries_per_context"])
        ]
        ids = [1000 + 7 * i for i in range(len(rows))]
        inputs.append(
            {
                "geometry": g,
                "rows": rows,
                "queries": queries,
                "ids": ids,
                "counts": [n // 2, n, n + 1],
            }
        )
    inputs_bytes = json.dumps(inputs, sort_keys=True, indent=2).encode() + b"\n"
    inputs_receipt = write_new(
        args.out_dir / "Q66-inputs-before-keygen.json", inputs_bytes
    )
    marker.write_text(
        json.dumps(
            {
                "utc": datetime.now(UTC).isoformat(),
                "registration_sha256": reg_hash,
                "source_sha256": result["source_sha256"],
                "public_inputs": inputs_receipt,
                "before_any_cohort_HE_key_creation": True,
            },
            indent=2,
        )
        + "\n"
    )
    with tarfile.open(args.out_dir / "Q66-executed-source.tar.gz", "x:gz") as archive:
        for path in paths:
            archive.add(path, arcname=str(path.relative_to(ROOT)))
    files, records, contexts = [inputs_receipt], [], []
    for context, entry in enumerate(inputs):
        g = entry["geometry"]
        pk, sk = bgv.key_gen(g["N"], t=g["t"], q_bits=g["q_bits"], eta=g["eta"])
        padded = 1 << (g["dimension"] - 1).bit_length()
        keys = trace.evaluation_keys(pk, sk, padded, g["digit_bits"])
        _, tiles = bgv.coefficient_inputs(entry["queries"][0], entry["rows"], pk.n)
        index = [bgv.encrypt(tile, pk) for tile in tiles]
        queries = []
        for query in entry["queries"]:
            plain, _ = bgv.coefficient_inputs(query, [], pk.n)
            queries.append(bgv.encrypt(plain, pk))
        public = plain_values(
            {
                "pk": asdict(pk),
                "keys": asdict(keys),
                "index": [asdict(c) for c in index],
                "queries": [asdict(c) for c in queries],
                "input_record": entry,
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
                "q": int(pk.q),
                "p": int(compact.terminal_modulus(pk.q, pk.t, 16)),
                "key_and_index_generated_fresh": True,
                "secret_key_retained": False,
            }
        )
        for query_at, (query, query_plain) in enumerate(
            zip(queries, entry["queries"], strict=True)
        ):
            for count in entry["counts"]:
                capacity = pk.n // padded
                chosen = index[: (count + capacity - 1) // capacity]
                reference = propagated.make_trace(
                    query, chosen, count, g["dimension"], pk, keys, propagate=False
                )
                alternate = propagated.make_trace(
                    query, chosen, count, g["dimension"], pk, keys
                )
                assert propagated.check_trace(
                    query,
                    chosen,
                    count,
                    g["dimension"],
                    pk,
                    keys,
                    reference,
                    propagate=False,
                )
                assert propagated.check_trace(
                    query, chosen, count, g["dimension"], pk, keys, alternate
                )
                # The first private operation occurs only after both whole traces
                # and exact compact frames pass their public relations.
                ref_plain, alt_plain = (
                    physical_decrypt(reference, pk, sk),
                    physical_decrypt(alternate, pk, sk),
                )
                ref_terminal, alt_terminal = (
                    frame_decrypt(reference, pk, sk),
                    frame_decrypt(alternate, pk, sk),
                )
                assert ref_plain == alt_plain == ref_terminal == alt_terminal
                scores = trace.decode(alt_terminal, count, g["dimension"], pk)
                truth = [
                    sum(a != b for a, b in zip(query_plain, row, strict=True))
                    for row in entry["rows"][:count]
                ]
                assert scores == truth
                top3 = sorted(zip(scores, entry["ids"][:count], strict=True))[:3]
                assert top3 == sorted(zip(truth, entry["ids"][:count], strict=True))[:3]
                stem = f"context-{context}-query-{query_at}-count-{count}"
                for tag, tr in (("canonical", reference), ("propagated", alternate)):
                    files.append(
                        write_new(args.out_dir / f"{stem}-{tag}.bin", tr.response)
                    )
                    public_tr = asdict(tr)
                    public_tr.pop("response")
                    files.append(
                        write_new(
                            args.out_dir / f"{stem}-{tag}-trace.json.gz",
                            gzip.compress(
                                json.dumps(public_tr, sort_keys=True).encode(), mtime=0
                            ),
                        )
                    )
                records.append(
                    {
                        "context": context,
                        "query": query_at,
                        "vectors": count,
                        "response_groups": len(alt_plain),
                        "all_physical_coefficients": len(alt_plain) * pk.n,
                        "exact_distances": count,
                        "top3": top3,
                        "propagated_cuts": sum(
                            c.kind == "propagated" for c in alternate.cuts
                        ),
                        "full_Q_bytes_differ": alternate.full_output
                        != reference.full_output,
                        "full_compact_bytes_differ": alternate.response
                        != reference.response,
                        "canonical_frame_bytes": len(reference.response),
                        "alternate_frame_bytes": len(alternate.response),
                        "public_replay_before_private_diagnostics": True,
                        "all_physical_plaintexts_and_scores_exact": True,
                        "public_bound": alternate.bounds,
                    }
                )
        del sk
    result.update(
        kind="Q66_four_fresh_homemade_context_complete_propagated_trace_correctness",
        registration_sha256=reg_hash,
        contexts=contexts,
        cases=records,
        files=files,
        distinct_contexts=len(contexts),
        distinct_query_contexts=len(contexts) * reg["queries_per_context"],
        encrypted_case_pairs=len(records),
        distinct_case_distance_checks=sum(r["exact_distances"] for r in records),
        distinct_case_physical_plaintext_checks=sum(
            r["all_physical_coefficients"] for r in records
        ),
        all_complete_physical_plaintexts_distances_and_IDs_exact=True,
        scope="Synthetic small-ring correctness under public worst-case guards; all ciphertext bytes retained, fresh HE entropy, no HE secret or error coins retained. Cases share their context/query and nested dataset prefixes. Not independent latency samples, parameter assurance, efficient proof or protected deployment. Known propagation/fusion algebra; systems originality unaccepted.",
    )
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "distinct_contexts",
                    "distinct_query_contexts",
                    "encrypted_case_pairs",
                    "distinct_case_distance_checks",
                    "distinct_case_physical_plaintext_checks",
                    "all_complete_physical_plaintexts_distances_and_IDs_exact",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
