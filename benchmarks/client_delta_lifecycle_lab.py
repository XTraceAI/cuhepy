#!/usr/bin/env python3
"""E54 matched native lifecycles: fresh rebuild versus private client deltas.

Charge discovery, keys, initial index/pool/checker/native preparation, all edits
and every token/query. The delta control adds private owner-to-client correction
state/traffic. This is a local trusted-channel experiment, not a deployed
authenticated update service, novelty claim, network timing or parameter audit.
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
from benchmarks.dictionary_layout_lab import metadata
from benchmarks.verification_frontier_lab import parse_bits
from experiments.bfv_search_lab import client_delta as delta
from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import lifetime_prices as prices
from experiments.bfv_search_lab import native_linear_check as checks
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import representation_updates as updates
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import verification_lifetime as lifetime
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def run(plan, args, method, repetition, edits, common):
    key_s, (pk, sk) = timed(masked.key_gen, plan.query_space, q_bits=args.q_bits, eta=21)
    with closing(owner.OwnerClient(pk, sk)) as client:
        enroll_s, pool = timed(updates.RepairPool, plan, client, arithmetic="numpy")
        pool_s, tokens = timed(lambda: [pool.prepare(i.to_bytes(16, "little")) for i in range(args.pool)])
        ledger_s, ledger = timed(delta.Ledger, plan, pool.index.epoch) if method in ("private_client_delta", "priced_policy") else (0, None)
        budget_s, attempt_budget = timed(lifetime.AttemptBudget, plan.profile.attempt_budget)
        price_load_s, price_data = timed(lambda: json.loads(args.price_file.read_text())) if method == "priced_policy" else (0, {})
        model = prices.Models.load(price_data["models"]) if price_data else None
        training_cost = price_data.get("calibration_fit_s", 0) + price_data.get("training_acquisition_s", 0)
        cursor, word = 0, random.Random(54010 + args.trace_seed + repetition).randrange(1 << plan.dimension)
        epochs, samples = [], []
        gate = evaluator = phase = None
        for revision in range(len(edits) + 1):
            report, edit_s = {}, 0
            refreshed = revision == 0 or ledger is None
            if revision:
                edit_s, report = (timed(ledger.edit, edits[revision - 1]) if ledger is not None
                                  else timed(pool.edit, edits[revision - 1], method=method))
                if model is not None:
                    start = time.perf_counter()
                    dirty = {pool._locations[p.position][1] // plan.query_space.layout.context.leaves[pool._locations[p.position][0]].degree
                             for p in ledger.snapshot.patches}
                    action, predicted = model.choose(geometry(plan, args), pending=args.pool - cursor,
                                                     exceptions=len(ledger.snapshot.patches), dirty_tiles=len(dirty), horizon=1)
                    report.update(policy_action=action, predicted_next_query_action_cost_s=predicted)
                    if action != "private_client_delta":
                        target = {plan.ids[p.position]: ledger.workload.rows[p.position] for p in ledger.snapshot.patches}
                        report.update(pool.edit(target, method=action))
                        report.update(ledger.rebase(pool.plan, pool.index.epoch))
                        refreshed = True
                    # Price selection, residual snapshot and encryption work
                    # all belong to the measured update stage.
                    edit_s += time.perf_counter() - start
            gate_s = answer_s = native_s = phase_setup_s = 0
            pending = tokens[cursor:]
            if refreshed:
                gate_s, gate = timed(lambda: attempt_budget.bind(checks.NativeVectorCheck(
                    pool.index, pk, rounds=fields.rounds(int(pk.q)), budget=plan.profile.attempt_budget)))
                answer_s, _ = timed(lambda gate=gate, pending=pending: [gate.prepare_answer(t.answer) for t in pending])
                native_s, evaluator = timed(native.NativeIndex, pool.index, pk)
                phase_setup_s, phase = timed(audit.Audit, pool.index, pk, sk)
            view = ledger.snapshot.base if ledger is not None else pool.plan.client_view()
            current = ledger.workload if ledger is not None else pool.plan.workload
            count = args.queries_per_update if revision < len(edits) else len(pending)
            for ordinal, token in enumerate(pending[:count]):
                start = time.perf_counter()
                values, offsets = oracle.query(view, word)
                request = token.consume(values, pool.index.epoch)
                output = evaluator.evaluate(token.answer, request)
                body = codec.pack(tuple(int(x) for c in output for p in c.components for x in p), int(pk.q))
                parsed = parse_bits(body, pk, tuple(c.phase_bound for c in output))
                if not gate.verify_once(request, parsed):
                    raise AssertionError("Complete response gate failed")
                base = oracle.decode(view, [bgv.decrypt(c, pk, sk) for c in parsed], offsets)
                correction_start = time.perf_counter()
                actual = ledger.snapshot.correct(base, word, epoch=ledger.snapshot.epoch) if ledger is not None else base
                correction_s = time.perf_counter() - correction_start
                top = tuple(heapq.nsmallest(3, zip(actual, view.ids, strict=True)))
                elapsed = time.perf_counter() - start
                expected = current.expected(word)
                assert actual == expected and top == current.top_k(expected)
                sample = {"revision": revision, "token": cursor + ordinal, "online_elapsed_s": elapsed,
                          "private_delta_correction_s": correction_s, "response_body_bytes": len(body),
                          "all_scores_and_stable_top3_exact": True, "gate_passed_before_secret_decryption": True,
                          "scores_sha256": hashlib.sha256(b"".join(x.to_bytes(2, "little") for x in actual)).hexdigest(),
                          "top3": top}
                if ordinal == 0:
                    gmp_s, reference = timed(masked.evaluate, pool.index, token.answer, request, pk)
                    assert reference == parsed
                    phase_s, measured = timed(phase.measure, request, token.answer, parsed)
                    sample.update(all_native_GMP_coefficients_equal=True, phase=measured,
                                  gmp_reference_s_outside_cost=gmp_s, integer_phase_s_outside_cost=phase_s)
                samples.append(sample)
                word = int.from_bytes(hashlib.sha512(f"{top[0][1]}:{cursor + ordinal}".encode()).digest(), "little") % (1 << plan.dimension)
            cursor += count
            stage = edit_s + gate_s + answer_s + native_s
            epochs.append({"revision": revision, "report": report, "owner_edit_s": edit_s,
                           "checker_prepare_s": gate_s, "pending_checker_prepare_s": answer_s,
                           "native_prepare_s": native_s, "complete_update_or_initial_prepare_s": stage,
                           "phase_setup_s_outside_cost": phase_setup_s, "queries_completed": count})
            print(method, repetition, revision, "stage ms", round(stage * 1000, 3), file=sys.stderr, flush=True)
        assert cursor == args.pool and all(t._pad is None for t in tokens)
        for token in tokens:
            try:
                token.consume((0,) * plan.query_space.dimension, pool.index.epoch)
            except RuntimeError:
                pass
            else:
                raise AssertionError("Consumed base pad reappeared")
        execution_cost = (sum(common.values()) + key_s + enroll_s + pool_s + ledger_s + budget_s + price_load_s
                          + sum(e["complete_update_or_initial_prepare_s"] for e in epochs)
                          + sum(s["online_elapsed_s"] for s in samples))
        return {"method": method, "repetition": repetition, "key_s": key_s, "enroll_s": enroll_s,
                "pool_s": pool_s, "ledger_setup_s": ledger_s, "common": common, "epochs": epochs, "online": samples,
                "lifetime_attempt_budget_prepare_s": budget_s, "global_verification_attempts": attempt_budget.used,
                "volatile_global_attempt_budget_enforced": True,
                "price_model_load_s": price_load_s, "full_training_acquisition_and_fit_s_charged_once": training_cost,
                "native_execution_lifetime_s_without_training": execution_cost,
                "complete_lifetime_s": execution_cost + training_cost,
                "coordinate_array_bytes": pool.coordinate_array_bytes,
                "peak_additional_private_client_body_bytes": max((e["report"].get("private_snapshot_body_bytes", 64)
                                                                  for e in epochs), default=64) if ledger is not None else 0,
                "private_owner_client_update_bytes_model": sum(e["report"].get("private_delta_update_body_bytes_model", 0) for e in epochs),
                "server_seeded_update_packet_bytes": sum(e["report"].get("seeded_patch_packet_bytes", 0) for e in epochs),
                "all_original_tokens_consumed_once": True}


def geometry(plan, args):
    return (len(plan.ids), plan.dimension, args.rank, args.n, args.prime, args.q_bits, 21,
            plan.resources.columns, plan.resources.replies, args.edit_rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=4096)
    parser.add_argument("--rank", type=int, default=32)
    parser.add_argument("--dimension", type=int, default=128)
    parser.add_argument("--n", type=int, default=2048)
    parser.add_argument("--prime", type=int, default=1153)
    parser.add_argument("--q-bits", type=int, default=40)
    parser.add_argument("--pool", type=int, default=16)
    parser.add_argument("--updates", type=int, default=4)
    parser.add_argument("--edit-rows", type=int, default=1)
    parser.add_argument("--queries-per-update", type=int, default=2)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--methods", nargs="+", choices=("full_reencrypt", "tile_reencrypt", "private_client_delta", "priced_policy"),
                        default=("full_reencrypt", "private_client_delta"))
    parser.add_argument("--edit-layout", choices=("contiguous", "spread", "random"), default="contiguous")
    parser.add_argument("--trace-seed", type=int, default=0)
    parser.add_argument("--price-file", type=Path)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if (not 64 <= args.count <= 16384 or not 1 <= args.rank <= 128
            or not args.rank <= args.dimension <= 512 or args.dimension % args.rank
            or not 2 <= args.pool <= 64 or not 1 <= args.updates <= 8 or not 1 <= args.repeats <= 8
            or not 1 <= args.edit_rows <= args.count or args.queries_per_update < 1
            or args.queries_per_update * (args.updates + 1) > args.pool
            or len(set(args.methods)) != len(args.methods) or len(args.methods) < 2
            or args.methods[0] != "full_reencrypt" or ("priced_policy" in args.methods and args.price_file is None)):
        parser.error("Invalid bounded matched delta workload")
    profile = Profile(args.n, args.prime, q_bits=args.q_bits, eta=21)
    profile.validate(args.dimension)
    rng = random.Random(4301)
    def lift(x):
        return sum(x << j for j in range(0, args.dimension, args.rank))
    rows = tuple(lift(rng.randrange(1 << args.rank)) for _ in range(args.count))
    w = Workload(rows, tuple(range(args.count)), args.dimension)
    discovery_s, choices = timed(oracle.choices, w, oracle.median_tree(w, 0), args.prime)
    compile_s, plan = timed(oracle.compile_choice, w, choices[1], profile, (1,))
    current, edits = list(rows), []
    trace_rng = random.Random(args.trace_seed)
    for revision in range(args.updates):
        batch = {}
        random_ids = trace_rng.sample(range(args.count), args.edit_rows) if args.edit_layout == "random" else None
        for offset in range(args.edit_rows):
            identifier = (random_ids[offset] if random_ids is not None else
                          (revision * args.edit_rows + offset) % args.count if args.edit_layout == "contiguous"
                          else ((revision * args.edit_rows + offset) * 7919) % args.count)
            current[identifier] = lift((current[identifier] & ((1 << args.rank) - 1)) ^ ((1 << min(3, args.rank)) - 1))
            batch[identifier] = current[identifier]
        edits.append(batch)
    cases = []
    methods = tuple(args.methods)
    for repetition in range(args.repeats):
        for method in methods[::1 if repetition % 2 == 0 else -1]:
            cases.append(run(plan, args, method, repetition, edits, {"discovery_s": discovery_s, "compile_s": compile_s}))
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.with_suffix(".partial.json").write_text(json.dumps({"kind": "incomplete_client_delta_lifecycle", "cases": cases}, indent=2) + "\n")
    paired = []
    for repetition in range(args.repeats):
        full = next(c for c in cases if c["method"] == methods[0] and c["repetition"] == repetition)
        for method in methods[1:]:
            patched = next(c for c in cases if c["method"] == method and c["repetition"] == repetition)
            assert [(s["scores_sha256"], s["top3"]) for s in full["online"]] == [(s["scores_sha256"], s["top3"]) for s in patched["online"]]
            paired.append({"repetition": repetition, "method": method, "fresh_s": full["complete_lifetime_s"],
                           "alternative_s": patched["complete_lifetime_s"],
                           "reduction_fraction": 1 - patched["complete_lifetime_s"] / full["complete_lifetime_s"]})
    paths = [Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "client_delta", "representation_updates", "coordinate_factory", "representation_oracle", "affine_dictionary",
        "representation_contract", "crt_query_space", "crt_masked_bgv", "crt_native_bgv", "crt_linear_check",
        "native_linear_check", "owner_bgv", "integer_phase_audit", "shallow_bgv", "coefficient_body",
        "lifetime_prices", "verification_lifetime")),
        ROOT / "src/cuhepy/bfv/scheme.py"]
    paths.extend(p for folder in ("_subring", "_fingerprint") for p in (ROOT / "experiments/bfv_search_lab" / folder).glob("*.so"))
    if args.price_file is not None:
        paths.append(args.price_file)
    result = metadata(paths)
    result.update(kind="private_client_delta_complete_lifecycle", profile=asdict(profile), workload={
        "count": args.count, "rank": plan.maps[0].rank, "dimension": args.dimension, "digest_owner_local": w.digest},
        arguments={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items() if k != "json_out"},
        resources_model=asdict(plan.resources),
        cases=cases, paired=paired, paired_median_reduction_fraction_by_method={
            method: median(p["reduction_fraction"] for p in paired if p["method"] == method) for method in methods[1:]},
        publication_gate_C_passed=False,
        scope="Measured local CPU complete stage sums; independent GMP/phase diagnostics excluded. "
              "Same fixed synthetic rows/edits/adaptive-query policy and all original tokens. "
              "Delta changes private owner/client state and traffic while the full encrypted base and checker remain fixed. "
              "Added private state/body sizes are models, not RSS or authenticated network bytes. "
              "Owner and client are the same confidentiality domain; ordinary delta caching, not novelty or production assurance.")
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "paired": paired}))


if __name__ == "__main__":
    main()
