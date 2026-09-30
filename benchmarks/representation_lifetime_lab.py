#!/usr/bin/env python3
"""E43 paired owner-update experiment, including encryption and full checks.

Same fixed maps, keys/parameters, padding and retained unused pads in both
arms. The strong control reencrypts full new M*r instead of discarding tokens
or refitting maps. Sparse repair pays additive noise and full fresh encryption;
old unused-answer preparation is charged equally. No GPU or wire service.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random
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
from experiments.bfv_search_lab import native_linear_check as checks
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import representation_updates as updates
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=8192)
    parser.add_argument("--pool", type=int, default=12)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--rank", type=int, default=8)
    parser.add_argument("--dimension", type=int, default=32)
    parser.add_argument("--prime", type=int, default=193)
    parser.add_argument("--q-bits", type=int, default=32)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if (not 64 <= args.count <= 16384 or not 2 <= args.pool <= 32 or not 1 <= args.repeats <= 8
            or not 1 <= args.rank <= 128 or not args.rank <= args.dimension <= 512 or args.dimension % args.rank):
        parser.error("Bounded research count/pool/repeat workload required")
    rng = random.Random(4301)
    def lift(x):
        return sum(x << j for j in range(0, args.dimension, args.rank))
    rows = tuple(lift(rng.randrange(1 << args.rank)) for _ in range(args.count))
    w = Workload(rows, tuple(range(args.count)), args.dimension)
    profile = Profile(16384, args.prime, q_bits=args.q_bits, eta=21)
    profile.validate(args.dimension)
    choice = oracle.choices(w, oracle.median_tree(w, 0), args.prime)[1]
    compile_s, plan = timed(oracle.compile_choice, w, choice, profile, (1,))
    cases = []
    for repetition in range(args.repeats):
        methods = ("sparse_delta", "full_reencrypt") if repetition % 2 == 0 else ("full_reencrypt", "sparse_delta")
        for method in methods:
            key_s, (pk, sk) = timed(masked.key_gen, plan.query_space, q_bits=args.q_bits, eta=21)
            with closing(owner.OwnerClient(pk, sk)) as client:
                enroll_s, pool = timed(updates.RepairPool, plan, client)
                prepare_s, tokens = timed(lambda: [pool.prepare(i.to_bytes(16, "little")) for i in range(args.pool)])
                edit_s, report = timed(pool.edit, {0: lift((rows[0] & ((1 << args.rank) - 1)) ^ ((1 << min(3, args.rank)) - 1))}, method=method)
                gate_s, gate = timed(checks.NativeVectorCheck, pool.index, pk, rounds=fields.rounds(int(pk.q)), budget=1024)
                answer_check_s, _ = timed(lambda: [gate.prepare_answer(t.answer) for t in tokens])
                native_s, evaluator = timed(native.NativeIndex, pool.index, pk)
                view = pool.plan.client_view()
                expected_workload = pool.plan.workload
                # Owner plaintext is kept only for offline checking, outside the
                # actual online request path and its elapsed measurement.
                online = []
                word = random.Random(43010 + repetition).randrange(1 << args.dimension)
                for i, token in enumerate(tokens[:3]):
                    start = time.perf_counter()
                    values, offsets = oracle.query(view, word)
                    request = token.consume(values, pool.index.epoch)
                    result = evaluator.evaluate(token.answer, request)
                    body = codec.pack(tuple(int(x) for c in result for poly in c.components for x in poly), int(pk.q))
                    result = parse_bits(body, pk, tuple(c.phase_bound for c in result))
                    accepted = gate.verify_once(request, result)
                    if not accepted:
                        raise AssertionError("Honest repaired ciphertext was rejected before decryption")
                    actual = oracle.decode(view, [bgv.decrypt(c, pk, sk) for c in result], offsets)
                    ranked = tuple(sorted(zip(actual, view.ids, strict=True))[:3])
                    elapsed = time.perf_counter() - start
                    assert actual == expected_workload.expected(word)
                    assert result == masked.evaluate(pool.index, token.answer, request, pk)
                    online.append({"warmup": i == 0, "elapsed_s": elapsed, "all_scores_and_stable_top3_exact": True,
                                   "response_body_bytes": len(body), "top3": ranked,
                                   "all_gmp_native_coefficients_equal": True})
                    word = (ranked[0][1] * 4301 + i) % (1 << args.dimension)
                total_update = edit_s + gate_s + answer_check_s + native_s
                cases.append({"method": method, "repetition": repetition, "key_gen_s": key_s,
                              "initial_enroll_s": enroll_s, "initial_unused_answer_pool_s": prepare_s,
                              "owner_update_and_all_answer_repair_s": edit_s,
                              "full_new_checker_prepare_s": gate_s, "answer_checker_pool_s": answer_check_s,
                              "public_native_prepare_s": native_s, "total_update_stage_sum_s": total_update,
                              "report": report, "online": online,
                              "unused_after_validation": args.pool - len(online),
                              "epoch_initial_and_update_work_stage_sum_s": key_s + enroll_s + prepare_s + total_update})
                print(method, repetition, "complete update ms", round(total_update * 1000, 3), file=sys.stderr, flush=True)
                # Preserve completed expensive runs even if later reporting or
                # another repetition fails. This partial file is not a final result.
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.with_suffix(".partial.json").write_text(json.dumps(
                    {"kind": "incomplete_pending_repair_run", "profile": asdict(profile), "cases": cases}, indent=2) + "\n")
    paths = [Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{n}.py" for n in (
        "representation_contract", "representation_oracle", "representation_updates", "crt_query_space",
        "crt_masked_bgv", "crt_native_bgv", "crt_linear_check", "native_linear_check", "owner_bgv", "shallow_bgv"))]
    result = metadata(paths)
    result.update(kind="pending_mask_frozen_representation_update", count=args.count, dimension=args.dimension,
                  rank=plan.maps[0].rank, pool_size=args.pool, profile=asdict(profile), owner_compile_s=compile_s,
                  workload_digest_owner_local=w.digest, resources_model=asdict(plan.resources), cases=cases,
                  summary={method: summary([{axis: c[axis] for axis in (
                      "owner_update_and_all_answer_repair_s", "total_update_stage_sum_s", "epoch_initial_and_update_work_stage_sum_s")}
                      for c in cases if c["method"] == method])
                           for method in ("sparse_delta", "full_reencrypt")},
                  scope="Research-only full N=16384 homogeneous known-affine synthetic fixture; constant padded packet counts. "
                        "Independent fresh OS encryption randomness and private mask seed per initial token. All reused pads were "
                        "NEVER exposed. Same-pending-pad full-reencryption is the matched strong control. Native full-vector checking "
                        "before secret GMP decryption; full checker and native index re-preparation charged. Local measured update "
                        "stage sums are CPU work, not network latency. Small serial sample, no production, security reduction, "
                        "private timing, durable migration, insertion/deletion or general update support.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cases": len(cases)}))


if __name__ == "__main__":
    main()
