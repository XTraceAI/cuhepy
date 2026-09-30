#!/usr/bin/env python3
"""E59 insert/delete/edit lifecycles with an allowed authenticated full cache.

Frozen-base HE and local private changes are a known control, not a new HE
primitive. Every original token is consumed once. The full-cache arm pays for
AEAD acquisition, then applies the same trusted private updates in memory.
Owner/client transport and durable epochs are premises, not implemented here.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import heapq
import json
from pathlib import Path
import random
from statistics import mean
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata
from benchmarks.verification_frontier_lab import parse_bits
from experiments.bfv_search_lab import cache_snapshot as cache
from experiments.bfv_search_lab import client_buffer as buffer
from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import native_linear_check as checks
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import representation_updates as updates
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import verification_lifetime as lifetime
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def signature(ids, scores):
    return hashlib.sha256(b"".join(i.to_bytes(8, "little") + s.to_bytes(2, "little")
                                  for i, s in sorted(zip(ids, scores, strict=True)))).hexdigest()


def apply(current, transaction):
    for i in transaction["delete_ids"]:
        del current[i]
    current.update(transaction["edits"])
    current.update(transaction["inserts"])


def run(plan, discovery, compile_cost, trace, args, repetition, encrypted):
    stages, records, queries, reference = [], [], [], dict(zip(plan.ids, plan.workload.rows, strict=True))
    word, cursor, initial_packet = random.Random(61010 + repetition).randrange(1 << plan.dimension), 0, 0
    client = None
    if encrypted:
        key_s, (pk, sk) = timed(masked.key_gen, plan.query_space, q_bits=args.q_bits, eta=21)
        owner_s, client = timed(owner.OwnerClient, pk, sk)
        enroll_s, pool = timed(updates.RepairPool, plan, client, arithmetic="numpy")
        token_s, tokens = timed(lambda: [pool.prepare(i.to_bytes(16, "little")) for i in range(args.pool)])
        ledger_s, ledger = timed(buffer.Ledger, plan, pool.index.epoch)
        budget_s, attempts = timed(lifetime.AttemptBudget, plan.profile.attempt_budget)
        checker_s, gate = timed(lambda: attempts.bind(checks.NativeVectorCheck(
            pool.index, pk, rounds=fields.rounds(int(pk.q)), budget=plan.profile.attempt_budget)))
        hint_s, _ = timed(lambda: [gate.prepare_answer(t.answer) for t in tokens])
        native_s, server = timed(native.NativeIndex, pool.index, pk)
        phase_s, phase = timed(audit.Audit, pool.index, pk, sk)
        setup = {"discovery_s": discovery, "compile_s": compile_cost, "key_s": key_s, "owner_native_prepare_s": owner_s,
                 "encrypted_enroll_s": enroll_s, "entire_original_pool_s": token_s, "private_ledger_s": ledger_s,
                 "global_budget_s": budget_s, "complete_checker_s": checker_s, "entire_answer_hints_s": hint_s,
                 "server_native_prepare_s": native_s}
    else:
        key_s, key = timed(cache.secrets.token_bytes, 32)
        seal_s, (manifest, packet) = timed(cache.seal, plan.workload.rows, plan.ids, plan.dimension, key, compressed=False)
        open_s, acquired = timed(cache.open_snapshot, packet, key, manifest)
        # Authorized-client research adapter copies its authenticated raw cache.
        state_s, current = timed(lambda: dict(zip(acquired._ids, acquired._rows, strict=True)))
        del acquired  # Accounted row state is the mutable dictionary, not two retained caches.
        initial_packet = len(packet)
        setup = {"AEAD_key_s": key_s, "owner_seal_s": seal_s, "client_acquire_s": open_s, "mutable_cache_prepare_s": state_s}
        phase_s = 0
    try:
        for revision in range(len(trace) + 1):
            if revision:
                transaction = trace[revision - 1]
                stage_s, report = (timed(ledger.transact, **transaction) if encrypted else (timed(apply, current, transaction)[0], {}))
                apply(reference, transaction)  # Offline current-plaintext oracle, excluded from cost.
                width = (plan.dimension + 7) // 8
                update_bytes = 76 + (8 + width) * (len(transaction["edits"]) + len(transaction["inserts"])) + 8 * len(transaction["delete_ids"])
                assert not encrypted or report["private_update_body_bytes_model"] == update_bytes
                records.append({"revision": revision, "owner_client_update_s": stage_s, "private_update_body_bytes_model": update_bytes,
                                "server_update_body_bytes": 0, "report": report, "current_rows": len(reference)})
                stages.append(stage_s)
            count = args.queries_per_update if revision < len(trace) else args.pool - cursor
            for ordinal in range(count):
                start = time.perf_counter()
                if encrypted:
                    token = tokens[cursor + ordinal]
                    values, offsets = oracle.query(ledger.snapshot.base, word)
                    request = token.consume(values, pool.index.epoch)
                    output = server.evaluate(token.answer, request)
                    body = codec.pack(tuple(int(x) for c in output for p in c.components for x in p), int(pk.q))
                    parsed = parse_bits(body, pk, tuple(c.phase_bound for c in output))
                    if not gate.verify_once(request, parsed):
                        raise AssertionError("Complete frozen-base pre-decryption gate failed")
                    base = oracle.decode(ledger.snapshot.base, [bgv.decrypt(c, pk, sk) for c in parsed], offsets)
                    correction_start = time.perf_counter()
                    result = ledger.snapshot.correct(base, word, epoch=ledger.snapshot.epoch, verified_base_epoch=server.epoch)
                    correction_s = time.perf_counter() - correction_start
                    ids, scores, top = result.ids, result.scores, result.top3
                    response_bytes = len(body)
                else:
                    ids = tuple(current)
                    scores = tuple((row ^ word).bit_count() for row in current.values())
                    top = tuple(heapq.nsmallest(3, zip(scores, ids, strict=True)))
                    correction_s, response_bytes = 0, 0
                query_s = time.perf_counter() - start
                expected = {i: (row ^ word).bit_count() for i, row in reference.items()}
                assert dict(zip(ids, scores, strict=True)) == expected
                assert top == tuple(sorted((score, i) for i, score in expected.items())[:3])
                sample = {"revision": revision, "ordinal": cursor + ordinal, "online_elapsed_s": query_s,
                          "private_buffer_score_and_assembly_s": correction_s, "response_body_bytes": response_bytes,
                          "current_rows": len(ids), "all_current_scores_and_stable_top3_exact": True,
                          "scores_by_stable_id_sha256": signature(ids, scores), "top3": top}
                if encrypted:
                    sample["complete_base_gate_before_secret_decryption"] = True
                    if ordinal == 0:
                        gmp_s, gmp = timed(masked.evaluate, pool.index, token.answer, request, pk)
                        assert gmp == parsed
                        phase_check_s, measured = timed(phase.measure, request, token.answer, parsed)
                        sample.update(all_native_GMP_coefficients_equal=True, phase=measured,
                                      gmp_reference_s_outside_cost=gmp_s, phase_s_outside_cost=phase_check_s)
                queries.append(sample)
                word = int.from_bytes(hashlib.sha512(f"{top[0][1]}:{cursor + ordinal}".encode()).digest(), "little") % (1 << plan.dimension)
            cursor += count
            print("buffer" if encrypted else "cache", repetition, revision, "rows", len(reference), file=sys.stderr, flush=True)
        assert cursor == args.pool
        if encrypted:
            assert all(t._pad is None for t in tokens) and attempts.used == args.pool
            close_s, _ = timed(client.close)
            setup["owner_native_close_s"] = close_s
        else:
            close_s = 0
        complete = sum(setup.values()) + sum(stages) + sum(s["online_elapsed_s"] for s in queries)
        return {"method": "encrypted_base_private_buffer" if encrypted else "authenticated_full_cache", "repetition": repetition,
                "setup_stages_s": setup, "updates": records, "online": queries, "complete_lifecycle_compute_s": complete,
                "initial_AEAD_download_packet_bytes": initial_packet,
                "full_current_cache_body_bytes_model": len(reference) * (8 + (plan.dimension + 7) // 8) if not encrypted else 0,
                "peak_additional_private_buffer_body_bytes_model": max((r["report"]["private_snapshot_body_bytes_model"] for r in records), default=82) if encrypted else 0,
                "HE_base_resources_model_separately_charged": asdict(plan.resources) if encrypted else None,
                "owner_historical_ID_body_bytes_model": ledger.owner_historical_id_body_bytes_model if encrypted else 8 * (len(plan.ids) + args.inserts * args.updates),
                "private_owner_client_update_body_bytes_model": sum(r["private_update_body_bytes_model"] for r in records),
                "phase_oracle_setup_s_outside_cost": phase_s, "global_verification_attempts": attempts.used if encrypted else 0,
                "all_original_tokens_consumed_once": True if encrypted else None}
    finally:
        if client is not None:
            client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=8192)
    parser.add_argument("--dimension", type=int, default=128)
    parser.add_argument("--rank", type=int, default=32)
    parser.add_argument("--n", type=int, default=2048)
    parser.add_argument("--prime", type=int, default=1153)
    parser.add_argument("--q-bits", type=int, default=40)
    parser.add_argument("--pool", type=int, default=24)
    parser.add_argument("--updates", type=int, default=4)
    parser.add_argument("--edits", type=int, default=64)
    parser.add_argument("--inserts", type=int, default=128)
    parser.add_argument("--deletes", type=int, default=64)
    parser.add_argument("--queries-per-update", type=int, default=2)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if (not 64 <= args.count <= 16384 or not 1 <= args.rank <= args.dimension <= 512 or args.dimension % args.rank
            or not 1 <= args.updates <= 8 or not 1 <= args.edits <= 128 or not 1 <= args.inserts <= 256 or not 1 <= args.deletes <= 128
            or args.updates * args.deletes + args.edits >= args.count or not 2 <= args.pool <= 64
            or args.queries_per_update < 1 or args.queries_per_update * (args.updates + 1) > args.pool
            or not 1 <= args.repeats <= 4):
        parser.error("Invalid bounded private-buffer experiment")
    rng = random.Random(61001)
    def lift(x):
        return sum(x << j for j in range(0, args.dimension, args.rank))
    rows = tuple(lift(rng.randrange(1 << args.rank)) for _ in range(args.count))
    w = Workload(rows, tuple(range(args.count)), args.dimension)
    profile = Profile(args.n, args.prime, q_bits=args.q_bits, eta=21)
    profile.validate(args.dimension)
    discovery, choices = timed(oracle.choices, w, oracle.median_tree(w, 0), args.prime)
    compile_cost, plan = timed(oracle.compile_choice, w, choices[1], profile, (1,))
    current, trace = dict(zip(w.ids, w.rows, strict=True)), []
    for revision in range(args.updates):
        deleted = tuple(rng.sample(list(current), args.deletes))
        removed = set(deleted)
        edited = rng.sample([i for i in current if i not in removed], args.edits)
        transaction = {"edits": {i: rng.randrange(1 << args.dimension) for i in edited},
                       "inserts": {args.count + revision * args.inserts + offset: rng.randrange(1 << args.dimension) for offset in range(args.inserts)},
                       "delete_ids": deleted}
        apply(current, transaction)
        trace.append(transaction)
    cases = []
    for repetition in range(args.repeats):
        for encrypted in ((True, False) if repetition % 2 == 0 else (False, True)):
            cases.append(run(plan, discovery, compile_cost, trace, args, repetition, encrypted))
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.with_suffix(".partial.json").write_text(json.dumps({"kind": "incomplete_private_buffer", "cases": cases}, indent=2) + "\n")
    for repetition in range(args.repeats):
        paired = [c for c in cases if c["repetition"] == repetition]
        assert [(s["scores_by_stable_id_sha256"], s["top3"]) for s in paired[0]["online"]] == [(s["scores_by_stable_id_sha256"], s["top3"]) for s in paired[1]["online"]]
    paths = [Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "client_buffer", "client_delta", "cache_snapshot", "coordinate_cache", "representation_updates", "coordinate_factory",
        "representation_oracle", "affine_dictionary", "representation_contract", "crt_query_space", "crt_masked_bgv",
        "crt_native_bgv", "crt_linear_check", "native_linear_check", "owner_bgv", "integer_phase_audit", "shallow_bgv",
        "coefficient_body", "verification_lifetime")), ROOT / "src/cuhepy/bfv/scheme.py"]
    paths.extend(p for folder in ("_subring", "_fingerprint") for p in (ROOT / "experiments/bfv_search_lab" / folder).glob("*.so"))
    report = metadata(paths)
    report.update(kind="private_buffer_dynamic_lifecycle", arguments={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items() if k != "json_out"},
                  fixture_seed=61001, initial_count=args.count, final_count=len(current), initial_affine_rank=plan.maps[0].rank,
                  arbitrary_out_of_span_new_rows=True, profile=asdict(profile), cases=cases,
                  mean_complete_compute_s_by_method={method: mean(c["complete_lifecycle_compute_s"] for c in cases if c["method"] == method)
                                                     for method in ("encrypted_base_private_buffer", "authenticated_full_cache")},
                  scope="Research-only CPU lifecycle; trusted owner/client updates and current snapshot authorization. "
                        "Insert/delete/edit entirely private; complete old base relation checked before every HE decrypt. "
                        "HE discovery, compile, keys, owner preparation/close, all original tokens, every update/query charged. "
                        "Cache arm pays AEAD acquisition then uses its permitted full private cache with identical updates/query feedback. "
                        "No erase, remote private update transport, rollback protection, parameter assurance, GPU or network timing. "
                        "Rows/IDs/body models exclude Python RSS/allocator objects; old deleted rows remain encrypted at server.")
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "means": report["mean_complete_compute_s_by_method"]}))


if __name__ == "__main__":
    main()
