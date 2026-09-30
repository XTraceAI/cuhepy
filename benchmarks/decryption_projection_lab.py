#!/usr/bin/env python3
"""E62 direct-coefficient projection: actual bodies/exact native encrypted queries.

Separate research-only checked relation and dedicated decoder. A Python/GMP
fingerprint oracle is used; this is no native performance win or assurance
claim. Every kept C0 and all C1 is checked before selected secret arithmetic.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import heapq
import json
from pathlib import Path
import secrets
from statistics import mean
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import coordinate_factory as coordinates
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import decryption_projection as projection
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import native_linear_check as checks
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import score_layout
from experiments.bfv_search_lab import verification_lifetime as lifetime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=("semeion", "mushroom"), required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--n", type=int, nargs="+", default=(2048, 16384))
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 8 or any(n not in (2048, 16384) for n in args.n):
        parser.error("Bounded full-ring candidates and1..8 samples required")
    data = fixtures.load(args.dataset, args.cache_dir / fixtures.SOURCES[args.dataset]["member"])
    ids, heldout = fixtures.split(data, 3001)
    rows, words = [data.rows[i] for i in ids], [data.rows[i] for i in heldout[64:64 + args.repeats + 1]]
    t = 257 if data.name == "semeion" else 193
    discover_s, mapping = timed(affine.prepare, rows, data.dimension, t)
    bitmap = affine.compile_bits(mapping)
    groups = [affine.index_features(mapping, rows)]
    cases = []
    for n in args.n:
        s = space.space(score_layout.layout(tree.context(n, ("",), t), (mapping.features,), (len(rows),)), (0,))
        key_s, (pk, sk) = timed(masked.key_gen, s, q_bits=32, eta=21)
        epoch = secrets.token_bytes(32)
        with closing(owner.OwnerClient(pk, sk)) as client:
            enroll_s, (index, upload) = timed(masked.enroll, s, groups, epoch, client)
            producer_s, producer = timed(coordinates.Factory, s, groups, epoch, client)
            native_s, server = timed(native.NativeIndex, index, pk)
            budget = lifetime.AttemptBudget(1024)
            gate_s, checker = timed(projection.ProjectedCheck, index, pk, rounds=fields.rounds(int(pk.q)), budget=1024)
            bind_s, gate = timed(budget.bind, checker)
            gate_s += bind_s
            # Separate full relation reference before diagnostics/full decrypt;
            # not part of prototype timings or an untrusted deployment step.
            reference = checks.NativeVectorCheck(index, pk, rounds=fields.rounds(int(pk.q)), budget=1024)
            phase = audit.Audit(index, pk, sk)
            samples = []
            for ordinal, word in enumerate(words):
                token_s, (ticket, answer, _) = timed(producer.prepare, ordinal.to_bytes(16, "little"))
                hint_s, _ = timed(gate.prepare_answer, answer)
                reference.prepare_answer(answer)
                weights, offset = affine.bit_query_features(bitmap, word)
                request = ticket.consume(tuple(x % t for x in weights), epoch)
                server_s, output = timed(server.evaluate, answer, request)
                assert output == masked.evaluate(index, answer, request, pk) and reference.verify_once(request, output)
                measured_phase = phase.measure(request, answer, output)
                project_s, reply = timed(projection.project, output, s, pk)
                serialize_s, body = timed(codec.pack, reply.coefficients, int(pk.q))
                open_s, dots = timed(projection.open_body_once, gate, request, body, pk, sk, reply.phase_bounds)
                assert dots is not None
                def decode(dots, offset):
                    scores = tuple(affine.bit_decode(bitmap, [x for poly in dots for x in poly], offset))
                    return scores, tuple(heapq.nsmallest(3, zip(scores, ids, strict=True)))
                decode_s, (scores, top) = timed(decode, dots, offset)
                expected = tuple((word ^ row).bit_count() for row in rows)
                assert scores == expected and top == tuple(sorted(zip(expected, ids, strict=True))[:3])
                full_body = codec.pack(tuple(int(x) for c in output for p in c.components for x in p), int(pk.q))
                samples.append({"ordinal": ordinal, "warmup": ordinal == 0,
                                "prototype_stages_s": {"server_s": server_s, "project_s": project_s, "serialize_s": serialize_s,
                                                       "projected_parse_python_gate_selected_decrypt_s": open_s, "decode_stable_top3_s": decode_s},
                                "offline_token_and_projected_hint_s": token_s + hint_s,
                                "full_response_body_bytes": len(full_body), "projected_response_body_bytes": len(body),
                                "body_reduction_fraction": 1 - len(body) / len(full_body),
                                "all_scores_and_stable_top3_exact": True, "all_native_GMP_full_coefficients_equal": True,
                                "full_reference_gate_passed_before_diagnostics": True, "projected_gate_before_selected_SK": True,
                                "original_full_integer_phase": measured_phase,
                                "scores_sha256": hashlib.sha256(b"".join(x.to_bytes(2, "little") for x in expected)).hexdigest()})
            cases.append({"n": n, "q": int(pk.q), "count": len(rows), "dimension": data.dimension, "rank": mapping.rank,
                          "active_c0_counts": projection.active_counts(s), "global_attempts": budget.used,
                          "index_upload_packet_bytes": upload, "key_s": key_s, "enroll_s": enroll_s,
                          "coordinate_factory_s": producer_s, "native_server_prepare_s": native_s,
                          "projected_python_checker_prepare_s": gate_s, "samples": samples,
                          "mean_timed_prototype_stage_sum_s": mean(sum(s["prototype_stages_s"].values()) for s in samples if not s["warmup"])})
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.with_suffix(".partial.json").write_text(json.dumps({"kind": "incomplete_projection", "cases": cases}, indent=2) + "\n")
            print(data.name, n, "full/projected B", len(full_body), len(body), file=sys.stderr, flush=True)
    paths = [Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "decryption_projection", "affine_dictionary", "binary_fixtures", "coefficient_body", "coordinate_factory",
        "crt_masked_bgv", "crt_native_bgv", "crt_query_space", "crt_linear_check", "native_linear_check",
        "dyadic_crt", "score_layout", "owner_bgv", "integer_phase_audit", "shallow_bgv", "verification_lifetime")),
        ROOT / "src/cuhepy/bfv/scheme.py"]
    paths.extend(p for folder in ("_subring", "_fingerprint") for p in (ROOT / "experiments/bfv_search_lab" / folder).glob("*.so"))
    result = metadata(paths)
    result.update(kind="dedicated_decryption_coefficient_projection", dataset=data.name, fixture_sha256=data.sha256,
                  split_seed=3001, query_source_ids=heldout[64:64 + args.repeats + 1], map_discovery_s=discover_s, cases=cases,
                  counterexamples={"mod_t_projection": projection.plaintext_field_projection_counterexample(),
                                   "C1_deletion_structural_witnesses_checked": sum(1 for i in range(32) for j in (0, 31) if projection.c1_dependency_witness(32, i, j))},
                  scope="Separate research profile and changed checked relation. Authenticate every supplied C0 and ALL C1 before dedicated selected decryption. "
                        "Only one full-ring score-only leaf accepted; legacy/split contexts rejected. No generic padded-cipher decrypt. "
                        "Actual lossless coefficient bodies and exact native/GMP/full-reference gates/integer phases; no network/service timing. "
                        "Python/GMP projection checker is not the stronger native full-vector backend; stage sums omit reference checks/diagnostics. "
                        "No native/end-to-end speedup, novel primitive, reviewed projection protocol, seeded privacy, private timing or parameter assurance claim.")
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cases": len(cases)}))


if __name__ == "__main__":
    main()
