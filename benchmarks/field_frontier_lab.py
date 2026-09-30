#!/usr/bin/env python3
"""E34 ideal transcripts and E35 index-only fields, then adaptive HE searches.

The ideal-mask model is not a proof for encrypted preprocessing. Full-size
searches use the EXISTING absolute phase API; no CBD independence is needed for
adaptive correctness. All query choices occur after enrollment/pool creation.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import importlib
import json
from pathlib import Path
import random
import sys
import zlib

from gmpy2 import mpz

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata, summary
from experiments.bfv_search_lab import adaptive_masking_oracles as masks
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import rank_partition as partition
from experiments.bfv_search_lab import shallow_bgv as bgv


def public_space(candidate):
    maps = tuple(dict.fromkeys(b.mapping for b in candidate.blocks))
    return maps, space.space(candidate.layout, tuple(maps.index(b.mapping) for b in candidate.blocks))


def allocations(groups, rows):
    choices = []
    for slots in (1, 2, 4, 8, 16, 32, 64):
        try:
            seconds, candidate = timed(fields.allocate, groups, rows, slots)
            choices.append((slots, candidate, seconds))
        except ValueError:
            continue
    return choices


def parse_response_body(body, pk, bounds):
    """Local lossless body timing helper; no new authenticated wire format."""
    width = (pk.q.bit_length() + 7) // 8
    if len(body) != 2 * pk.n * width * len(bounds):
        raise ValueError("Unexpected local body length")
    words = tuple(mpz(int.from_bytes(body[i:i + width], "little")) for i in range(0, len(body), width))
    return tuple(bgv.Ciphertext((words[2 * i * pk.n:(2 * i + 1) * pk.n],
                                  words[(2 * i + 1) * pk.n:(2 * i + 2) * pk.n]), pk.key_id, bound)
                 for i, bound in enumerate(bounds))


def plan(rows, data, order):
    records, objects, rejected, fit_times = [], {}, [], {}
    primes = (127, 193, 257, 1153) if data.name == "mushroom" else (251, 257, 769, 1153)
    for t in primes:
        for target in (16, 32, 64):
            try:
                seconds, groups = timed(fields.fit, rows, data.dimension, order, prime=t, target=target)
            except ValueError as error:
                rejected.append({"t": t, "target": target, "stage": "fit", "reason": str(error)})
                continue
            fit_times[t, target] = seconds
            objects[t, target] = groups
            print("curve", data.name, "t/rank", t, target, "groups", len(groups.blocks), file=sys.stderr, flush=True)
            for slots in (1, 2, 4, 8, 16, 32, 64):
                try:
                    seconds, candidate = timed(fields.allocate, groups, rows, slots)
                    description = fields.describe(candidate)
                except ValueError as error:
                    rejected.append({"t": t, "target": target, "slots": slots, "stage": "allocate", "reason": str(error)})
                    continue
                records.append({"label": f"local_t{t}_rank{target}_slots{slots}", "allocation_s": seconds,
                                "discovery_depth": max(len(b.path) for b in groups.blocks), "groups": len(groups.blocks),
                                **description})
        # A global private affine control has no CRT split/root requirement.
        try:
            seconds, groups = timed(fields.fit, rows, data.dimension, order, prime=t,
                                    target=1 << (data.dimension - 1).bit_length(), initial_parts=1)
            candidate = fields.allocate(groups, rows, 1)
            records.append({"label": f"global_t{t}", "fit_s": seconds, "allocation_s": 0.0,
                            "discovery_depth": 0, "groups": 1, **fields.describe(candidate)})
        except ValueError as error:
            rejected.append({"t": t, "stage": "global", "reason": str(error)})
    baseline_groups = objects[1153, 32]
    baseline_choices = allocations(baseline_groups, rows)
    baseline_slots, baseline, _ = min(baseline_choices, key=lambda c: (c[1].layout.cost.response_ciphertexts, c[0]))
    _, baseline_space = public_space(baseline)
    index_cap = space.cost(baseline_space, q_bits=40)["expanded_index_body_bytes"]
    eligible = [r for r in records if r["label"].startswith("local_")
                and r["profiles"]["deterministic"]["cost"]["expanded_index_body_bytes"] <= index_cap]
    selected = min(eligible, key=lambda r: (
        r["profiles"]["deterministic"]["cost"]["online_response_body_bytes"]
        + r["profiles"]["deterministic"]["cost"]["online_query_body_bytes"],
        r["profiles"]["deterministic"]["cost"]["expanded_index_body_bytes"],
        r["private_map_body_bytes"], r["W"], r["t"], r["target"], r["slots"]))
    candidate = fields.allocate(objects[selected["t"], selected["target"]], rows, selected["slots"])
    controls = {"fixed_membership_refit_scope": "New maps fitted and certified in the selected field; original source memberships."}
    refit_s, refit_groups = timed(fields.refit, baseline_groups, rows, selected["t"])
    refit_choices = allocations(refit_groups, rows)
    _, refit, _ = min(refit_choices, key=lambda c: (c[1].layout.cost.response_ciphertexts, c[0]))
    match = (refit.layout, refit.blocks) == (candidate.layout, candidate.blocks)
    controls.update(refit_s=refit_s, refit=fields.describe(refit), refit_matches_selected_layout_and_maps=match)
    # Preserve the earlier rejected coupling rather than silently fixing its
    # root/discovery-depth constraint and presenting the result as unchanged.
    try:
        _, legacy = timed(partition.prepare, rows, data.dimension, order, prime=selected["t"],
                          target=selected["target"], policy="hybrid",
                          max_depth=fields.max_slots(selected["t"]).bit_length() - 1)
        controls["legacy_root_limited_fit"] = {"succeeded": True, "groups": len(legacy.blocks)}
    except ValueError as error:
        controls["legacy_root_limited_fit"] = {"succeeded": False, "reason": str(error)}
    encrypted = [("baseline_t1153_q40", baseline, 40),
                 ("selected_deterministic", candidate, selected["profiles"]["deterministic"]["implemented_api_minimum_q_bits"])]
    if not match:
        encrypted.append(("fixed_membership_refit", refit,
                          controls["refit"]["profiles"]["deterministic"]["implemented_api_minimum_q_bits"]))
    return {"rows": records, "rejected": rejected, "selected": selected, "controls": controls,
            "baseline_slots": baseline_slots, "index_cap_bytes": index_cap,
            "selection_scope": "Index-only finite candidate set; minimize response+query bodies under baseline canonical index cap, "
                               "then index bytes/map bytes/W. Not a global optimum or latency selector.",
            "successful_fit_stage_sum_s": sum(fit_times.values()),
            "baseline_fit_and_allocation_stage_sum_s": fit_times[1153, 32] + sum(c[2] for c in baseline_choices)}, encrypted


def prepare(args):
    data = fixtures.load(args.dataset, args.cache_dir / fixtures.SOURCES[args.dataset]["member"])
    ids, holdout = fixtures.split(data, args.seed)
    rows = [data.rows[i] for i in ids]
    common = {}
    common["metric_order_s"], order = timed(dictionary.metric_order, rows, data.dimension, 32)
    frontier_s, (frontier, encrypted) = timed(plan, rows, data, order)
    # This is a held-out candidate list, NOT a predeclared query schedule.
    # Each next candidate is chosen using the previous authenticated winner.
    candidates = holdout[64:64 + 2 * (args.repeats + 1)]
    raw = b"".join(x.to_bytes((data.dimension + 7) // 8, "little") for x in rows)
    cache_model = {"raw_row_body_bytes": len(raw), "zlib_row_body_bytes": len(zlib.compress(raw, 9)),
                   "scope": "Separate full-plaintext owner cache, in RAM for timing. No encrypted outsourced search/privacy contract."}
    cases = []
    for label, candidate, bits in encrypted if args.seed % 2 else list(reversed(encrypted)):
        setup = dict(common)
        if label == "baseline_t1153_q40":
            setup["candidate_prepare_stage_sum_s"] = frontier["baseline_fit_and_allocation_stage_sum_s"]
        else:
            setup["complete_frontier_selection_s"] = frontier_s
        maps, s = public_space(candidate)
        setup["coordinate_enroll_s"], groups = timed(lambda candidate=candidate: [
            affine.index_features(b.mapping, [rows[i] for i in b.positions]) for b in candidate.blocks])
        setup["query_compile_s"], compiled = timed(lambda maps=maps: [affine.compile_bits(p) for p in maps])
        setup["key_gen_s"], (pk, sk) = timed(masked.key_gen, s, q_bits=bits)
        epoch = hashlib.sha256(bytes.fromhex(candidate.source_digest) + s.binding + bytes.fromhex(pk.key_id)).digest()
        with closing(owner.OwnerClient(pk, sk)) as client:
            setup["transposed_index_s"], (index, upload) = timed(masked.enroll, s, groups, epoch, client)
            setup["seeded_index_packet_bytes"] = upload
            setup["native_prepare_s"], evaluator = timed(native.NativeIndex, index, pk)
            count = fields.rounds(int(pk.q), budget=args.query_budget)
            setup["checker_prepare_s"], gate = timed(check.EpochCheck, index, pk, rounds=count, budget=args.query_budget)
            rng = random.Random(35000 + args.seed)  # Public mask fixtures; fresh OS HE errors/checking secrets.
            seeds = tuple(rng.randbytes(32) for _ in range(args.repeats + 1))
            setup["offline_answer_pool_s"], pool = timed(lambda s=s, groups=groups, epoch=epoch, client=client, seeds=seeds: [
                masked.prepare(s, groups, epoch, i.to_bytes(16, "little"), seed, client) for i, seed in enumerate(seeds)])
            setup["offline_answer_check_pool_s"], _ = timed(lambda gate=gate, pool=pool: [gate.prepare_answer(a) for _, a, _ in pool])
            setup["integer_phase_audit_prepare_s"], phase_audit = timed(audit.Audit, index, pk, sk)
            print(label, args.dataset, args.seed, "t/Qbits/F/h/W", pk.t, bits, s.columns, s.dimension,
                  sum(s.column_degrees), file=sys.stderr, flush=True)
            samples, previous_winner = [], 0
            for i, (ticket, answer, _) in enumerate(pool):
                query_id = candidates[2 * i + (previous_winner & 1)]
                query = data.rows[query_id]
                cache_s, expected = timed(lambda query=query: sorted(((query ^ x).bit_count(), stable)
                                                                     for x, stable in zip(rows, ids, strict=True)))
                def make_request(ticket=ticket, query=query, compiled=compiled, epoch=epoch):
                    transformed = [affine.bit_query_features(p, query) for p in compiled]
                    weights = tuple(x for values, _ in transformed for x in values)
                    return ticket.consume(weights, epoch), [off for _, off in transformed]
                query_s, (request, offsets) = timed(make_request)
                query_pack_s, query_body = timed(request.body)
                def parse_request(query_body=query_body, request=request, s=s, epoch=epoch):
                    width = (s.layout.context.prime.bit_length() + 7) // 8
                    return masked.Request(s, epoch, request.token_id,
                                          tuple(int.from_bytes(query_body[j:j + width], "little")
                                                for j in range(0, len(query_body), width)))
                query_parse_s, parsed_request = timed(parse_request)
                assert parsed_request == request
                request = parsed_request
                if (i + args.seed) % 2:
                    native_s, output = timed(evaluator.evaluate, answer, request)
                    gmp_s, reference = timed(masked.evaluate, index, answer, request, pk)
                else:
                    gmp_s, reference = timed(masked.evaluate, index, answer, request, pk)
                    native_s, output = timed(evaluator.evaluate, answer, request)
                assert output == reference
                pack_s, body = timed(lambda output=output, bits=bits: b"".join(
                    int(x).to_bytes((bits + 7) // 8, "little") for c in output for poly in c.components for x in poly))
                parse_s, parsed = timed(parse_response_body, body, pk, tuple(c.phase_bound for c in output))
                assert parsed == output
                verify_s, accepted = timed(gate.verify_once, request, parsed)
                assert accepted
                decrypt_s, plaintexts = timed(lambda parsed=parsed, pk=pk, sk=sk: [bgv.decrypt(c, pk, sk) for c in parsed])
                def finish(plaintexts=plaintexts, candidate=candidate, s=s, offsets=offsets, compiled=compiled):
                    dots = tree.unpack(candidate.layout, plaintexts)
                    actual = []
                    for block, values, group in zip(candidate.blocks, dots, s.map_ids, strict=True):
                        actual.extend(zip(affine.bit_decode(compiled[group], values, offsets[group]),
                                          (ids[j] for j in block.positions), strict=True))
                    return sorted(actual)
                finish_s, actual = timed(finish)
                assert actual == expected
                previous_winner = actual[0][1]
                audit_s, phase = timed(phase_audit.measure, request, answer, parsed)
                samples.append({"query_id": query_id, "next_policy_authenticated_winner_id": previous_winner,
                                "owner_transform_and_request_s": query_s, "gmp_server_s": gmp_s, "native_server_s": native_s,
                                "verification_s": verify_s, "decrypt_s": decrypt_s, "decode_select_s": finish_s,
                                "query_pack_s": query_pack_s, "public_query_parse_s": query_parse_s,
                                "response_pack_s": pack_s, "public_response_parse_s": parse_s, "full_plaintext_cache_s_control": cache_s,
                                "native_local_online_s": query_s + query_pack_s + query_parse_s + native_s + verify_s + decrypt_s + finish_s + pack_s + parse_s,
                                "gmp_local_online_s": query_s + query_pack_s + query_parse_s + gmp_s + verify_s + decrypt_s + finish_s + pack_s + parse_s,
                                "integer_phase_audit_s_outside_online": audit_s,
                                "query_body_bytes": len(query_body), "response_coefficient_body_bytes": len(body),
                                "score_digest": hashlib.sha256(json.dumps(actual).encode()).hexdigest(), "phase": phase,
                                "all_distances_and_stable_top3_exact": True, "all_gmp_native_coefficients_equal": True,
                                "all_request_and_response_body_coefficients_roundtrip": True})
                print("query", query_id, "native", round(samples[-1]["native_local_online_s"] * 1000, 2),
                      "phase", phase["maximum_unreduced_integer_phase"], file=sys.stderr, flush=True)
            model = space.cost(s, q_bits=bits, rounds=count)
            cases.append({"layout": label, "t": pk.t, "q": str(pk.q), "n": pk.n, "eta": pk.eta, "rounds": count,
                          "setup": setup, "cost_model": model, "private_map_body_bytes": candidate.map_bytes,
                          "owner_plaintext_coordinate_2bit_body_model":
                          (2 * sum(len(group) * f for group, f in zip(groups, s.layout.features, strict=True)) + 7) // 8,
                          "seeded_answer_packet_bytes": [packet for _, _, packet in pool], "warmup": samples[0], "samples": samples[1:],
                          "queries_chosen_after_index_and_entire_answer_pool": True,
                          "correctness_uses_absolute_phase_bound_not_fixed_cbd": True,
                          "setup_scope": "Baseline uses recorded same-field fit/allocation stage sum; new cases pay complete frontier search. "
                                         "Frontier was run once for the paired experiment. These are standalone recorded-stage models, not elapsed benchmarks.",
                          "summary": summary([{k: v for k, v in sample.items() if k.endswith("_s") or k.endswith("_bytes")}
                                               for sample in samples[1:]])})
    return {"dataset": args.dataset, "split_seed": args.seed, "fixture_sha256": data.sha256,
            "count": len(rows), "dimension": data.dimension, "heldout_candidate_ids": candidates,
            "adaptive_policy": "query_i = heldout[64+2*i+(previous_authenticated_winner_source_id mod 2)]; initial winner=0",
            "frontier": frontier, "full_plaintext_cache_control": cache_model, "cases": cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--dataset", choices=tuple(fixtures.SOURCES), default="mushroom")
    parser.add_argument("--seed", type=int, default=3001)
    parser.add_argument("--repeats", type=int, default=8)
    parser.add_argument("--query-budget", type=int, default=1024)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 15 or args.query_budget < args.repeats + 1:
        parser.error("Expected 1..15 samples fitting the declared query budget")
    paths = [Path(__file__), ROOT / "benchmarks/certified_filter_lab.py", ROOT / "benchmarks/dictionary_layout_lab.py",
             ROOT / "src/cuhepy/bfv/scheme.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "adaptive_masking_oracles", "field_frontier", "integer_phase_audit", "test_adaptive_masking_oracles", "test_field_frontier",
        "crt_noise_budget", "crt_query_space", "crt_masked_bgv", "crt_native_bgv", "crt_linear_check", "rank_partition",
        "affine_dictionary", "folded_dictionary", "folded_filter", "binary_fixtures", "dyadic_crt", "linear_packing",
        "owner_bgv", "seeded_bgv", "shallow_bgv"))
    paths.extend([ROOT / "experiments/bfv_search_lab/_subring/bindings.cpp", ROOT / "experiments/bfv_search_lab/_subring/Makefile",
                  Path(importlib.import_module("experiments.bfv_search_lab._subring._crt_subring").__file__)])
    report = metadata(paths)
    report.update({"kind": "adaptive_masking_and_joint_field_frontier",
                   "ideal_masks": [masks.describe(masks.joint(mode=m, requests=1 if m == "select" else 2))
                                   for m in ("fresh", "reuse", "early_linear", "select")],
                   "result": prepare(args),
                   "scope": "Research full-ring homemade symmetric BGV/GMP/existing single-thread C++ NTT. No GPU/SEAL. "
                            "Existing deterministic ciphertext and key gates, query choices after enrollment and offline answers. "
                            "Conditional hidden exact fingerprint gate from trusted inputs precedes secret decryption. "
                            "No RLWE/private-side-channel/production or complete adaptive privacy proof. Ideal pads are a separate toy model. "
                            "Integer phase diagnostics outside online timing. Field selection includes full recorded frontier work. "
                            "Body counts exclude transport/authentication; owner coordinate cache/full-cache alternatives are charged separately."})
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "searches": len(report["result"]["cases"]) * (args.repeats + 1)}))


if __name__ == "__main__":
    main()
