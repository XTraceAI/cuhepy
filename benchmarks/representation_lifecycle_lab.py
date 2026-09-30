#!/usr/bin/env python3
"""E43 repeated encrypted edits, complete pool use and strong matched control.

Every prepared token is consumed exactly once, queries adapt to prior results,
and all update/checker/native/online work is charged. Independent integer-phase
and GMP diagnostics run outside the measured stage sums, once per revision.
This is a bounded synthetic CPU lifecycle, not a service or security proof.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from contextlib import closing
from dataclasses import asdict
import hashlib
import heapq
import json
from pathlib import Path
import random
from statistics import median
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata, summary
from benchmarks.verification_frontier_lab import parse_bits
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
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=16384)
    parser.add_argument("--pool", type=int, default=32)
    parser.add_argument("--updates", type=int, default=4)
    parser.add_argument("--queries-per-update", type=int, default=2)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--rank", type=int, default=128)
    parser.add_argument("--dimension", type=int, default=512)
    parser.add_argument("--prime", type=int, default=1153)
    parser.add_argument("--q-bits", type=int, default=40)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if (not 64 <= args.count <= 16384 or not 2 <= args.pool <= 64 or not 1 <= args.updates <= 8
            or not 1 <= args.repeats <= 8 or not 1 <= args.queries_per_update <= args.pool
            or args.updates * args.queries_per_update > args.pool
            or not 1 <= args.rank <= 128 or not args.rank <= args.dimension <= 512 or args.dimension % args.rank):
        parser.error("Invalid bounded lifecycle workload")
    rng = random.Random(4301)
    def lift(x):
        return sum(x << j for j in range(0, args.dimension, args.rank))
    rows = tuple(lift(rng.randrange(1 << args.rank)) for _ in range(args.count))
    workload = Workload(rows, tuple(range(args.count)), args.dimension)
    profile = Profile(16384, args.prime, q_bits=args.q_bits, eta=21)
    profile.validate(args.dimension)
    discovery_s, choices = timed(oracle.choices, workload, oracle.median_tree(workload, 0), args.prime)
    choice = choices[1]
    compile_s, plan = timed(oracle.compile_choice, workload, choice, profile, (1,))
    # Both arms see the exact same fixed row-edit trace. No future query or
    # private mask determines public update positions, counts or geometry.
    current = list(rows)
    edits = []
    for revision in range(args.updates):
        identifier = revision % args.count
        current[identifier] = lift((current[identifier] & ((1 << args.rank) - 1)) ^ ((1 << min(3, args.rank)) - 1))
        edits.append({identifier: current[identifier]})
    cases = []
    for repetition in range(args.repeats):
        methods = ("sparse_delta", "full_reencrypt") if repetition % 2 == 0 else ("full_reencrypt", "sparse_delta")
        for method in methods:
            key_s, (pk, sk) = timed(masked.key_gen, plan.query_space, q_bits=args.q_bits, eta=21)
            with closing(owner.OwnerClient(pk, sk)) as client:
                enroll_s, pool = timed(updates.RepairPool, plan, client)
                pool_s, tokens = timed(lambda: [pool.prepare(i.to_bytes(16, "little")) for i in range(args.pool)])
                epochs, online, cursor = [], [], 0
                word = random.Random(43010 + repetition).randrange(1 << args.dimension)
                for revision, changes in enumerate(edits):
                    edit_s, report = timed(pool.edit, changes, method=method)
                    gate_s, gate = timed(checks.NativeVectorCheck, pool.index, pk,
                                         rounds=fields.rounds(int(pk.q)), budget=profile.attempt_budget)
                    pending = tokens[cursor:]
                    answer_check_s, _ = timed(lambda: [gate.prepare_answer(t.answer) for t in pending])
                    native_s, evaluator = timed(native.NativeIndex, pool.index, pk)
                    view = pool.plan.client_view()
                    diagnostic_setup_s, phase_oracle = timed(audit.Audit, pool.index, pk, sk,
                        maximum_answer_bound=max(c.phase_bound for token in pending for c in token.answer.ciphertexts))
                    count = args.queries_per_update if revision + 1 < args.updates else len(pending)
                    epoch_online = []
                    for ordinal, token in enumerate(pending[:count]):
                        start = time.perf_counter()
                        values, offsets = oracle.query(view, word)
                        request = token.consume(values, pool.index.epoch)
                        result = evaluator.evaluate(token.answer, request)
                        body = codec.pack(tuple(int(x) for c in result for poly in c.components for x in poly), int(pk.q))
                        parsed = parse_bits(body, pk, tuple(c.phase_bound for c in result))
                        if not gate.verify_once(request, parsed):
                            raise AssertionError("Honest lifecycle ciphertext failed its complete gate")
                        actual = oracle.decode(view, [bgv.decrypt(c, pk, sk) for c in parsed], offsets)
                        ranked = tuple(heapq.nsmallest(3, zip(actual, view.ids, strict=True)))
                        elapsed = time.perf_counter() - start
                        # The current owner plaintext is an offline reference,
                        # never an input to online query/verification/decoding.
                        cache_s, expected = timed(lambda: tuple((row ^ word).bit_count() for row in pool.plan.workload.rows))
                        cache_select_s, expected_top = timed(lambda: tuple(heapq.nsmallest(3, zip(expected, view.ids, strict=True))))
                        assert actual == expected and ranked == expected_top
                        sample = {"revision": revision + 1, "token_ordinal": cursor + ordinal,
                                  "online_elapsed_s": elapsed, "response_body_bytes": len(body),
                                  "all_scores_and_stable_top3_exact": True,
                                  "gate_passed_before_secret_decryption": True,
                                  "plaintext_cache_scan_and_select_s_control": cache_s + cache_select_s,
                                  "scores_sha256": hashlib.sha256(b"".join(x.to_bytes(2, "little") for x in actual)).hexdigest(),
                                  "top3": ranked}
                        if ordinal == 0:
                            gmp_s, gmp_result = timed(masked.evaluate, pool.index, token.answer, request, pk)
                            assert parsed == gmp_result
                            phase_s, phase = timed(phase_oracle.measure, request, token.answer, parsed)
                            sample.update(all_gmp_native_coefficients_equal=True,
                                          gmp_reference_s_outside_online=gmp_s,
                                          integer_phase_audit_s_outside_online=phase_s, phase=phase)
                        epoch_online.append(sample)
                        word = int.from_bytes(hashlib.sha512(f"{ranked[0][1]}:{cursor + ordinal}".encode()).digest(), "little") % (1 << args.dimension)
                    cursor += count
                    online.extend(epoch_online)
                    epoch = {"revision": revision + 1, "report": report, "owner_edit_s": edit_s,
                             "full_checker_prepare_s": gate_s, "pending_answer_checker_prepare_s": answer_check_s,
                             "native_prepare_s": native_s, "integer_phase_audit_setup_s_outside_cost": diagnostic_setup_s,
                             "complete_update_stage_sum_s": edit_s + gate_s + answer_check_s + native_s,
                             "queries_completed": count, "pending_after_queries": args.pool - cursor}
                    epochs.append(epoch)
                    print(method, repetition, "revision", revision + 1, "complete update ms",
                          round(epoch["complete_update_stage_sum_s"] * 1000, 3), "pending", args.pool - cursor,
                          file=sys.stderr, flush=True)
                    args.json_out.parent.mkdir(parents=True, exist_ok=True)
                    args.json_out.with_suffix(".partial.json").write_text(json.dumps({
                        "kind": "incomplete_pending_lifecycle_run", "profile": asdict(profile), "cases": cases,
                        "active_case": {"method": method, "repetition": repetition, "epochs": epochs,
                                        "online": online}}, indent=2) + "\n")
                assert cursor == args.pool and all(t._pad is None for t in tokens)
                for token in tokens:
                    try:
                        token.consume((0,) * plan.query_space.dimension, pool.index.epoch)
                    except RuntimeError:
                        pass
                    else:
                        raise AssertionError("A consumed pad returned after lifecycle completion")
                total_update = sum(epoch["complete_update_stage_sum_s"] for epoch in epochs)
                total_online = sum(sample["online_elapsed_s"] for sample in online)
                cases.append({"method": method, "repetition": repetition, "key_gen_s": key_s,
                              "owner_compile_s_common": compile_s, "initial_enroll_s": enroll_s,
                              "owner_discovery_s_common": discovery_s,
                              "initial_pool_s": pool_s, "epochs": epochs, "online": online,
                              "total_updates_stage_sum_s": total_update, "all_online_elapsed_s": total_online,
                              "full_lifetime_stage_sum_s": discovery_s + compile_s + key_s + enroll_s + pool_s + total_update + total_online,
                              "all_prepared_tokens_consumed_once": True, "unused_final": 0,
                              "query_count": cursor,
                              "update_seeded_packet_bytes_total": sum(e["report"]["seeded_patch_packet_bytes"] for e in epochs),
                              "response_body_bytes_total": sum(s["response_body_bytes"] for s in online)})
    for repetition in range(args.repeats):
        a, b = [c for c in cases if c["repetition"] == repetition]
        assert [(s["scores_sha256"], s["top3"]) for s in a["online"]] == [(s["scores_sha256"], s["top3"]) for s in b["online"]]
    paths = [Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "representation_updates", "representation_oracle", "representation_contract", "crt_query_space",
        "crt_masked_bgv", "crt_native_bgv", "crt_linear_check", "native_linear_check", "owner_bgv",
        "integer_phase_audit", "shallow_bgv", "coefficient_body")), ROOT / "src/cuhepy/bfv/scheme.py"]
    paths.extend(p for folder in ("_subring", "_fingerprint")
                 for p in (ROOT / "experiments/bfv_search_lab" / folder).glob("*.so"))
    result = metadata(paths)
    paired = []
    for repetition in range(args.repeats):
        pair = {c["method"]: c for c in cases if c["repetition"] == repetition}
        full, sparse = (pair[name]["full_lifetime_stage_sum_s"] for name in ("full_reencrypt", "sparse_delta"))
        paired.append({"repetition": repetition, "full_s": full, "sparse_s": sparse, "reduction_fraction": 1 - sparse / full})
    result.update(kind="pending_mask_complete_lifecycle", count=args.count, dimension=args.dimension,
                  rank=plan.maps[0].rank, profile=asdict(profile), pool_size=args.pool, update_count=args.updates,
                  queries_per_nonfinal_update=args.queries_per_update, cases=cases, paired=paired,
                  workload_digest_owner_local=workload.digest, resources_model=asdict(plan.resources),
                  synthetic_lifetime_reduction_fraction_paired_median=median(p["reduction_fraction"] for p in paired),
                  publication_gate_C_passed=False,
                  summary={method: summary([{axis: c[axis] for axis in (
                      "full_lifetime_stage_sum_s", "total_updates_stage_sum_s", "all_online_elapsed_s")}
                      for c in cases if c["method"] == method]) for method in ("sparse_delta", "full_reencrypt")},
                  scope="Bounded synthetic known-affine frozen-map CPU lifecycle; owner affine discovery/compilation, all unused-pool costs and queries included; "
                        "same trace, IDs, parameters, packet counts and same-unused-pad strong full-reencryption control. "
                        "Each query passes the complete full-vector gate before secret decryption. Independent native/GMP and "
                        "unreduced phase diagnostics on the first query of every revision, outside measured stage sums. "
                        "All prepared tokens consumed once; totals are measured CPU stage sums, not service/network timings. "
                        "Private randomness is fresh; the synthetic row seed is reproducible. Small serial paired sample, "
                        "not real-data/uncertainty Gate C, novel incremental-crypto claim, durability or production assurance.")
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cases": len(cases), "queries": sum(c["query_count"] for c in cases)}))


if __name__ == "__main__":
    main()
