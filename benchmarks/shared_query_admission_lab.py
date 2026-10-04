#!/usr/bin/env python3
"""Q74 registered small homemade contexts: complete public checks before decode.

No timing panel or production parameter assertion. Public fixtures and source
receipts are retained, private keys are not serialized. Random seeds generate
only synthetic data; key/encryption randomness remains OS-backed.
"""

# ruff: noqa: E402 -- standalone research runner.

import argparse
from dataclasses import asdict, replace
from datetime import datetime, timezone, UTC
import gzip
import hashlib
import io
import json
from math import prod
from pathlib import Path
import platform
import random
import subprocess
import sys
import tarfile

from gmpy2 import mpz
import msgpack

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cuhepy.bfv.scheme import _rns_coefficient_primes
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import native_boundary_oracle as oracle
from experiments.bfv_search_lab import noise_cut_fusion as fusion
from experiments.bfv_search_lab import noise_cut_relation as relation
from experiments.bfv_search_lab import seeded_bgv as seeded
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_bgv as shared
from experiments.bfv_search_lab.shared_query_bounds import Profile


def plain(value):
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    return int(value) if isinstance(value, mpz) else value


def write_new(path, data):
    with path.open("xb") as f:
        f.write(data)
    return {"file": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def json_new(path, value):
    return write_new(path, (json.dumps(value, indent=2) + "\n").encode())


def source_snapshot(out):
    paths = sorted(
        set(ROOT.glob("experiments/bfv_search_lab/*.py"))
        | set(ROOT.glob("src/**/*.py"))
        | {Path(__file__), ROOT / "docs/research/shared-query-admission-registration-20261004.json"}
    )
    stream, inventory = io.BytesIO(), []
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for path in paths:
            body = path.read_bytes()
            name = str(path.relative_to(ROOT))
            inventory.append(
                {"file": name, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
            )
            member = tarfile.TarInfo(name)
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
    receipt = write_new(out / "executed-source.tar.gz", gzip.compress(stream.getvalue(), mtime=0))
    return {"archive": receipt, "files": inventory}


def private_diagnostic(ctx, tape, expanded, pk, sk, bits, rows):
    """Only called after whole public acceptance; no private noise-based guard."""
    p = ctx.profile
    output_bound = p.envelope()["output_phase_bound"]
    full = [
        bgv.decrypt(
            bgv.Ciphertext(tuple(tuple(map(mpz, row)) for row in pair), pk.key_id, output_bound),
            pk,
            sk,
        )
        for pair in tape.full_output
    ]
    expected = [
        (p.dimension - 2 * sum(a != b for a, b in zip(bits, row, strict=True))) % p.t
        for row in rows
    ]
    assert [x for poly in full for x in poly] == expected + [0] * (ctx.groups * p.n - len(rows))
    expanded_bound = p.envelope()["expanded_phase_bound"]
    for j, pair in enumerate(expanded):
        actual = bgv.decrypt(
            bgv.Ciphertext(tuple(tuple(map(mpz, row)) for row in pair), pk.key_id, expanded_bound),
            pk,
            sk,
        )
        value = (1 - 2 * bits[j]) % p.t if j < p.dimension else 0
        assert actual == [value] + [0] * (p.n - 1)
    header, body = msgpack.unpackb(tape.response, raw=False)
    assert int.from_bytes(header[3], "little") == p.p
    compact_plain = []
    for pair in body:
        components = tuple(
            tuple(map(mpz, oracle.unpack_bits(row, p.n, p.p.bit_length(), p.p))) for row in pair
        )
        compact_plain.extend(
            compact.decrypt(
                compact.CompactCiphertext(
                    components, pk.key_id, mpz(p.p), p.envelope()["terminal_phase_bound"]
                ),
                pk,
                sk,
            )
        )
    assert compact_plain == [x for poly in full for x in poly]
    centered = [x if x <= p.t // 2 else x - p.t for x in compact_plain[: len(rows)]]
    decoded = [(p.dimension - x) // 2 for x in centered]
    direct = [sum(a != b for a, b in zip(bits, row, strict=True)) for row in rows]
    assert decoded == direct
    assert (
        sorted(zip(decoded, ctx.ids, strict=True))[:3]
        == sorted(zip(direct, ctx.ids, strict=True))[:3]
    )
    return {
        "expanded_leaves_including_zero_features_exact": True,
        "whole_Q_and_P_plaintext_including_zero_records_exact": True,
        "Hamming_and_stable_ID_top3_exact": True,
    }


def mutations(ctx, rel, tape):
    changed_sources = changed_outputs = 0
    for slot, source in enumerate(tape.sources):
        row = (*source.polynomial[:-1], (source.polynomial[-1] + 1) % ctx.profile.q)
        sources = (*tape.sources[:slot], replace(source, polynomial=row), *tape.sources[slot + 1 :])
        assert not shared.accepts(ctx, rel, replace(tape, sources=sources))
        changed_sources += 1
    for group, pair in enumerate(tape.full_output):
        for c in range(2):
            row = (*pair[c][:-1], (pair[c][-1] + 1) % ctx.profile.q)
            changed = (row, pair[1]) if c == 0 else (pair[0], row)
            outputs = (*tape.full_output[:group], changed, *tape.full_output[group + 1 :])
            assert not shared.accepts(
                ctx,
                rel,
                replace(tape, full_output=outputs, response=shared.expected_frame(ctx, outputs)),
            )
            changed_outputs += 1
    return {
        "canonical_source_slots_mutated_and_rejected": changed_sources,
        "full_terminal_components_last_coordinate_mutated_and_rejected": changed_outputs,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    registration_path = ROOT / "docs/research/shared-query-admission-registration-20261004.json"
    reg = json.loads(registration_path.read_text())
    source = source_snapshot(args.out_dir)
    json_new(
        args.out_dir / "started.json",
        {
            "utc": datetime.now(UTC).isoformat(),
            "registration_sha256": hashlib.sha256(registration_path.read_bytes()).hexdigest(),
            "source": source,
            "parent_HEAD": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip(),
            "platform": platform.platform(),
            "python": sys.version,
            "timing_panels": 0,
        },
    )
    rng, results, fixtures = random.Random(reg["data_seed"]), [], []
    for context_number, geometry in enumerate(reg["small_geometries"]):
        n, d, t, eta = (geometry[k] for k in ("N", "dimension", "t", "eta"))
        q = prod(map(int, _rns_coefficient_primes(n, geometry["Q_bits"])))
        p = int(compact.terminal_modulus(mpz(q), t, reg["terminal_bits"]))
        # Public guard happens before any keys or ciphertexts for this context.
        for mode in reg["index_modes"]:
            for policy in reg["policies"]:
                Profile(n, d, q, p, t, eta, mode, policy).require_safe()
        pk, sk = bgv.key_gen(n, t=t, q_bits=geometry["Q_bits"], eta=eta, rns_modulus=True)
        assert int(pk.q) == q
        keys = shared.evaluation_keys(pk, sk, d)
        rows = tuple(tuple(rng.randrange(2) for _ in range(d)) for _ in range(2 * n - 1))
        rows = (rows[0], rows[0], *rows[2:])  # Exact ties exercise stable IDs.
        all_queries = [
            tuple(rng.randrange(2) for _ in range(d)) for _ in range(reg["queries_per_context"])
        ]
        fixtures.append(
            {
                "geometry": geometry,
                "ordered_primes": tuple(map(int, _rns_coefficient_primes(n, geometry["Q_bits"]))),
                "public_key": plain(asdict(pk)),
                "evaluation_keys": plain(asdict(keys)),
                "synthetic_rows": rows,
                "synthetic_query_bits": all_queries,
            }
        )
        for query_number, bits in enumerate(all_queries):
            query_packet = seeded.encrypt(shared.encode_query(bits, n, t), pk, sk)
            query = seeded.expand(query_packet, pk)
            for count in (n - 1, n, n + 1, 2 * n - 1):
                selected = rows[:count]
                for mode in reg["index_modes"]:
                    packets, index = [], []
                    for poly in shared.encode_index(selected, n, d):
                        if mode == "owner":
                            packet = seeded.encrypt(poly, pk, sk)
                            packets.append(packet.hex())
                            index.append(seeded.expand(packet, pk))
                        else:
                            index.append(bgv.encrypt(poly, pk))
                    for policy in reg["policies"]:
                        profile = Profile(n, d, q, p, t, eta, mode, policy)
                        ctx = shared.enroll(
                            profile,
                            pk,
                            query,
                            tuple(index),
                            tuple(100 + 3 * i for i in range(count)),
                            keys,
                        )
                        rel = shared.compile_relation(ctx)
                        tape, expanded = shared.produce(ctx, pk)
                        assert shared.accepts(ctx, rel, tape)
                        residuals = relation.residuals(rel, tape.sources, tape.full_output)
                        assert all(not any(row) for row in residuals)
                        primes = tuple(map(int, _rns_coefficient_primes(n, geometry["Q_bits"])))
                        # Evaluate the complete graph per actual limb, using the
                        # SAME common-Q digits. Do not decompose independently.
                        graph, constants = fusion.from_relation(rel)
                        bindings = fusion.bindings(rel, tape.sources, tape.full_output)
                        for prime in primes:
                            limb = fusion.evaluate(
                                replace(graph, q=prime),
                                {
                                    name: tuple(x % prime for x in row)
                                    for name, row in bindings.items()
                                },
                                {
                                    name: tuple(x % prime for x in row)
                                    for name, row in constants.items()
                                },
                            )
                            assert limb == tuple(tuple(x % prime for x in row) for row in residuals)
                        diagnostics = private_diagnostic(
                            ctx, tape, expanded, pk, sk, bits, selected
                        )
                        faults = mutations(ctx, rel, tape)
                        case = {
                            "context": asdict(ctx),
                            "transcript": {**asdict(tape), "response": tape.response.hex()},
                            "query_seeded_packet": query_packet.hex(),
                            "owner_index_packets": packets,
                            "expected_scores": [
                                (d - 2 * sum(a != b for a, b in zip(bits, row, strict=True))) % t
                                for row in selected
                            ],
                        }
                        case_id = f"c{context_number}-q{query_number}-m{count}-{mode}-{policy}"
                        receipt = write_new(
                            args.out_dir / f"{case_id}.json.gz",
                            gzip.compress(json.dumps(case).encode(), mtime=0),
                        )
                        results.append(
                            {
                                "id": case_id,
                                "key_context": pk.key_id,
                                "records": count,
                                "profile": asdict(profile),
                                "envelope": profile.envelope(),
                                "graph": relation.statistics(rel),
                                "inventory": profile.inventory(count, len(primes)),
                                "actual_seeded_query_packet_bytes": len(query_packet),
                                "actual_complete_compact_packet_bytes": len(tape.response),
                                "all_physical_Q_residuals_exact": True,
                                "each_actual_limb_same_common_Q_digit_residuals_exact": True,
                                **diagnostics,
                                **faults,
                                "fixture": receipt,
                            }
                        )
                        print(case_id, flush=True)
    fixture_receipt = write_new(
        args.out_dir / "public-fixtures.json.gz",
        gzip.compress(json.dumps(fixtures).encode(), mtime=0),
    )
    assert len(results) == reg["honest_complete_relations"]
    report = {
        "task": "Q74",
        "scope": "Small independent exact-semantic/public-box gate. Known composition; no measured latency, native admission, protected release, security/parameter approval or originality result.",
        "fresh_experiment_key_contexts": len(fixtures),
        "honest_complete_relations": len(results),
        "source_slot_mutations": sum(
            r["canonical_source_slots_mutated_and_rejected"] for r in results
        ),
        "full_output_component_mutations": sum(
            r["full_terminal_components_last_coordinate_mutated_and_rejected"] for r in results
        ),
        "timing_panels": 0,
        "source": source,
        "public_fixtures": fixture_receipt,
        "results": results,
    }
    json_new(args.out_dir / "Q74-correctness.json", report)
    print(
        json.dumps(
            {
                k: report[k]
                for k in (
                    "fresh_experiment_key_contexts",
                    "honest_complete_relations",
                    "source_slot_mutations",
                    "full_output_component_mutations",
                    "timing_panels",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
