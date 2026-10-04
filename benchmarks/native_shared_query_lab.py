#!/usr/bin/env python3
"""Q76.1 retained public native gate: no new keys, private work or timing panel."""

# ruff: noqa: E402 -- standalone research runner.
from __future__ import annotations

import argparse
from dataclasses import asdict, replace
from datetime import datetime, UTC
import gzip
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

from gmpy2 import mpz

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab import noise_cut_relation as relation
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_bgv as shared
from experiments.bfv_search_lab.shared_query_bounds import Profile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pin(path):
    return {"file": str(path), "bytes": path.stat().st_size, "sha256": sha(path.read_bytes())}


def tuples(value):
    return tuple(tuples(x) for x in value) if isinstance(value, list) else value


def public_cases(directory):
    report = json.loads((directory / "Q74-correctness.json").read_text())
    selected = [
        row
        for row in report["results"]
        if row["profile"]["index_mode"] == "owner" and row["profile"]["policy"] == "canonical30"
    ]
    if len(selected) != 16:
        raise ValueError("The registered 16 retained owner-canonical fixtures are required")
    return report, selected


def load_case(directory, entry, fixtures):
    path = directory / entry["fixture"]["file"]
    data = path.read_bytes()
    if sha(data) != entry["fixture"]["sha256"] or len(data) != entry["fixture"]["bytes"]:
        raise ValueError("Retained fixture hash changed")
    raw = json.loads(gzip.decompress(data))
    c, t = raw["context"], raw["transcript"]
    ctx = shared.Context(
        Profile(**c["profile"]),
        c["key_id"],
        tuples(c["query"]),
        tuples(c["index"]),
        tuples(c["ids"]),
        tuples(c["relin"]),
        tuples(c["rotations"]),
    )
    tape = shared.Transcript(
        t["statement_digest"],
        tuple(
            relation.Source(x["group"], x["level"], x["node"], tuple(x["polynomial"]))
            for x in t["sources"]
        ),
        tuples(t["full_output"]),
        bytes.fromhex(t["response"]),
    )
    selected = [x for x in fixtures if x["public_key"]["key_id"] == ctx.key_id]
    if len(selected) != 1 or ctx.digest != tape.statement_digest:
        raise ValueError("Wrong retained key or statement context")
    pub = selected[0]["public_key"]
    pk = bgv.PublicKey(
        pub["n"],
        pub["t"],
        mpz(pub["q"]),
        pub["eta"],
        tuple(map(mpz, pub["a"])),
        tuple(map(mpz, pub["b"])),
        pub["key_id"],
    )
    primes = tuple(selected[0]["ordered_primes"])
    return ctx, tape, pk, primes, pin(path)


def public_fixtures(directory, report):
    path = directory / report["public_fixtures"]["file"]
    data = path.read_bytes()
    if sha(data) != report["public_fixtures"]["sha256"]:
        raise ValueError("Retained public-key fixture hash changed")
    return json.loads(gzip.decompress(data))


def body(ctx, tape):
    rows = tuple(x.polynomial for x in tape.sources) + tuple(
        row for pair in tape.full_output for row in pair
    )
    return native.pack_common(rows, ctx.profile.n, ctx.profile.q)


def changed_coordinate(ctx, tape, slot, amount):
    """Last physical coordinate, including coordinates with no selected record."""
    n, q = ctx.profile.n, ctx.profile.q
    if slot < len(tape.sources):
        source = tape.sources[slot]
        row = (*source.polynomial[:-1], (source.polynomial[n - 1] + amount) % q)
        sources = (*tape.sources[:slot], replace(source, polynomial=row), *tape.sources[slot + 1 :])
        return replace(tape, sources=sources)
    g, c = divmod(slot - len(tape.sources), 2)
    pair = tape.full_output[g]
    row = (*pair[c][:-1], (pair[c][n - 1] + amount) % q)
    updated = (row, pair[1]) if c == 0 else (pair[0], row)
    outputs = (*tape.full_output[:g], updated, *tape.full_output[g + 1 :])
    return replace(tape, full_output=outputs, response=shared.expected_frame(ctx, outputs))


def limb_residuals(ctx, tape, primes):
    # This path uses the independently implemented schoolbook convolution,
    # not the C++ NTT, HE producer or its tensor-product implementation.
    rel = shared.compile_relation(ctx)
    whole = relation.residuals(rel, tape.sources, tape.full_output)
    return tuple(tuple(tuple(x % p for x in row) for p in primes) for row in whole)


def write_new(path, data):
    with path.open("xb") as output:
        output.write(data)
    return pin(path)


def json_new(path, value):
    return write_new(path, (json.dumps(value, indent=2) + "\n").encode())


def source_files():
    return sorted(
        {
            Path(__file__),
            ROOT / "experiments/bfv_search_lab/native_shared_query.py",
            ROOT / "experiments/bfv_search_lab/test_native_shared_query.py",
            ROOT / "experiments/bfv_search_lab/shared_query_bgv.py",
            ROOT / "experiments/bfv_search_lab/shared_query_bounds.py",
            ROOT / "experiments/bfv_search_lab/noise_cut_relation.py",
            ROOT / "experiments/bfv_search_lab/native_boundary_oracle.py",
            ROOT / "experiments/bfv_search_lab/_shared_query/shared_query.cpp",
            ROOT / "experiments/bfv_search_lab/_shared_query/Makefile",
            ROOT / "docs/research/native-shared-query-registration-20261004.json",
            *ROOT.glob("src/cuhepy/bfv/_cpu_ext/*.h"),
            *ROOT.glob("src/**/*.py"),
            *ROOT.glob("experiments/bfv_search_lab/*.py"),
        }
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=False)
    frozen = [pin(path) for path in source_files()]
    library = native.NativeLibrary(args.library)
    report, entries = public_cases(args.fixtures)
    fixtures = public_fixtures(args.fixtures, report)
    started = {
        "task": "Q76.1",
        "utc": datetime.now(UTC).isoformat(),
        "git_HEAD": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "source": frozen,
        "library": pin(args.library),
        "ABI": native.ABI,
        "python": sys.version,
        "platform": platform.platform(),
        "retained_report": pin(args.fixtures / "Q74-correctness.json"),
        "new_HE_key_contexts": 0,
        "private_work": 0,
        "timing_panels": 0,
    }
    json_new(args.out_dir / "started.json", started)
    results = []
    try:
        for entry in entries:
            ctx, tape, pk, primes, fixture_pin = load_case(args.fixtures, entry, fixtures)
            expected_body = body(ctx, tape)
            reference, _ = shared.produce(ctx, pk)
            assert body(ctx, reference) == expected_body and reference.response == tape.response
            with (
                library.from_reference(ctx, primes) as enrollment,
                enrollment.query(
                    native.pack_common(ctx.query, ctx.profile.n, ctx.profile.q)
                ) as query,
            ):
                assert query.produce() == expected_body
                expected_residuals = limb_residuals(ctx, tape, primes)
                assert query.residuals(expected_body) == expected_residuals
                assert all(not any(row) for pair in expected_residuals for row in pair)
                assert query.verifies(expected_body, tape.response)
                faults = []
                for slot in range(len(tape.sources) + 2 * ctx.groups):
                    for amount in (1, primes[0]):
                        changed = changed_coordinate(ctx, tape, slot, amount)
                        changed_body = body(ctx, changed)
                        residuals = query.residuals(changed_body)
                        assert residuals == limb_residuals(ctx, changed, primes)
                        assert any(any(row) for pair in residuals for row in pair)
                        assert not query.verifies(changed_body, changed.response)
                        if slot >= len(tape.sources) and amount == primes[0]:
                            assert all(not any(pair[0]) for pair in residuals)
                            assert any(any(pair[1]) for pair in residuals)
                        faults.append(
                            {
                                "slot": slot,
                                "delta": amount,
                                "both_actual_limb_vectors_equal_schoolbook": True,
                                "rejected": True,
                                "residual_vectors_sha256": sha(json.dumps(residuals).encode()),
                            }
                        )
                payload = json_new(args.out_dir / (entry["id"] + "-faults.json"), faults)
                result = {
                    "id": entry["id"],
                    "fixture": fixture_pin,
                    "key_context": ctx.key_id,
                    "primes": primes,
                    "body": write_new(args.out_dir / (entry["id"] + ".body"), expected_body),
                    "frame": write_new(args.out_dir / (entry["id"] + ".frame"), tape.response),
                    "stats": asdict(enrollment.stats),
                    "faults": payload,
                    "mutated_source_coordinates": 2 * len(tape.sources),
                    "mutated_output_coordinates": 4 * ctx.groups,
                    "exact_GMP_producer_tape_and_retained_frame": True,
                    "all_actual_limb_schoolbook_residuals_equal": True,
                    "complete_public_verification": True,
                }
                results.append(result)
                print(entry["id"], flush=True)
        assert [pin(Path(x["file"])) for x in frozen] == frozen
    except BaseException as error:
        json_new(
            args.out_dir / "failed.json",
            {
                "type": type(error).__name__,
                "error": str(error),
                "completed_retained_cases": len(results),
                "results": results,
                "completed": False,
            },
        )
        raise
    complete = {
        **started,
        "utc_completed": datetime.now(UTC).isoformat(),
        "complete": True,
        "retained_key_contexts": len({x["key_context"] for x in results}),
        "retained_complete_cases": len(results),
        "source_coordinate_faults": sum(x["mutated_source_coordinates"] for x in results),
        "output_coordinate_faults": sum(x["mutated_output_coordinates"] for x in results),
        "results": results,
        "scope": "Small public native core only; not authenticated enrollment/release, lifecycle, large native correctness, attestation, originality or parameter/security approval",
    }
    json_new(args.out_dir / "Q76.1-retained-core.json", complete)
    print(
        json.dumps(
            {
                k: complete[k]
                for k in [
                    "retained_complete_cases",
                    "source_coordinate_faults",
                    "output_coordinate_faults",
                    "new_HE_key_contexts",
                    "private_work",
                    "timing_panels",
                ]
            }
        )
    )


if __name__ == "__main__":
    main()
