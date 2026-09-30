#!/usr/bin/env python3
"""E37 paired complete-checker and lossless precision ablations.

Full-size encrypted searches, including negative algorithmic alternatives.
The four private gates verify the SAME response independently before a single
secret decryption. Deployment totals are sums of shared measured stages, not
four independently elapsed requests. No private key enters the new C++ code.
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

from gmpy2 import mpz

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata, summary
from benchmarks.field_frontier_lab import parse_response_body, public_space
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import native_linear_check as alternatives
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import polynomial_fingerprint as polynomial
from experiments.bfv_search_lab import shallow_bgv as bgv


def parse_bits(body, pk, bounds):
    words = codec.unpack(body, 2 * pk.n * len(bounds), int(pk.q))
    return tuple(bgv.Ciphertext((words[2 * i * pk.n:(2 * i + 1) * pk.n],
                                words[(2 * i + 1) * pk.n:(2 * i + 2) * pk.n]), pk.key_id, bound)
                 for i, bound in enumerate(bounds))


def run(args):
    data = fixtures.load(args.dataset, args.cache_dir / fixtures.SOURCES[args.dataset]["member"])
    ids, holdout = fixtures.split(data, args.seed)
    rows = [data.rows[i] for i in ids]
    order_s, order = timed(dictionary.metric_order, rows, data.dimension, 32)
    selected_t = 193 if data.name == "mushroom" else 257
    slots = 32 if data.name == "mushroom" else 64
    narrow_bits = 35 if data.name == "mushroom" else 36
    geometry = {}
    for t in (1153, selected_t):
        fit_s, groups = timed(fields.fit, rows, data.dimension, order, prime=t, target=32)
        allocation_s, candidate = timed(fields.allocate, groups, rows, slots)
        geometry[t] = candidate, {"metric_order_s": order_s, "fit_s": fit_s, "allocation_s": allocation_s}
    profiles = [("baseline_t1153_q40", 1153, 40), ("same_field_narrow_lossless", 1153, narrow_bits),
                ("selected_field_q32", selected_t, 32)]
    if args.seed % 2 == 0:
        profiles.reverse()
    cases = []
    candidates = holdout[64:64 + 2 * (args.repeats + 1)]
    for label, t, bits in profiles:
        candidate, setup = geometry[t]
        setup = dict(setup)
        maps, s = public_space(candidate)
        assert 2 * space.cost(s)["worst_case_phase_bound"] < fields.modulus(s.layout.context.n, bits)
        setup["coordinate_enroll_s"], groups = timed(lambda candidate=candidate: [
            affine.index_features(b.mapping, [rows[i] for i in b.positions]) for b in candidate.blocks])
        setup["query_compile_s"], compiled = timed(lambda maps=maps: [affine.compile_bits(p) for p in maps])
        setup["key_gen_s"], (pk, sk) = timed(masked.key_gen, s, q_bits=bits)
        epoch = hashlib.sha256(bytes.fromhex(candidate.source_digest) + s.binding + bytes.fromhex(pk.key_id)).digest()
        with closing(owner.OwnerClient(pk, sk)) as client:
            setup["transposed_index_s"], (index, upload) = timed(masked.enroll, s, groups, epoch, client)
            setup["seeded_index_packet_bytes"] = upload
            setup["native_prepare_s"], evaluator = timed(native.NativeIndex, index, pk)
            rounds = fields.rounds(int(pk.q), budget=args.query_budget)
            constructors = {
                "vector_gmp": lambda index=index, pk=pk, rounds=rounds: check.EpochCheck(index, pk, rounds=rounds, budget=args.query_budget),
                "vector_native": lambda index=index, pk=pk, rounds=rounds: alternatives.NativeVectorCheck(index, pk, rounds=rounds, budget=args.query_budget),
                "polynomial_gmp": lambda index=index, pk=pk: alternatives.PolynomialCheck(index, pk, budget=args.query_budget),
                "polynomial_native": lambda index=index, pk=pk: alternatives.PolynomialCheck(index, pk, budget=args.query_budget, native_backend=True),
            }
            gates, gate_setup = {}, {}
            for name, constructor in constructors.items():
                seconds, gate = timed(constructor)
                gates[name] = gate
                gate_setup[name] = {"checker_prepare_s": seconds}
            rng = random.Random(35000 + args.seed)  # Public fixtures; HE errors and all secret checking keys use OS randomness.
            seeds = tuple(rng.randbytes(32) for _ in range(args.repeats + 1))
            setup["offline_answer_pool_s"], pool = timed(lambda s=s, groups=groups, epoch=epoch, seeds=seeds, client=client: [
                masked.prepare(s, groups, epoch, i.to_bytes(16, "little"), seed, client) for i, seed in enumerate(seeds)])
            for name, gate in gates.items():
                seconds, _ = timed(lambda gate=gate, pool=pool: [gate.prepare_answer(a) for _, a, _ in pool])
                gate_setup[name]["offline_answer_check_pool_s"] = seconds
            setup["integer_phase_audit_prepare_s"], phase_audit = timed(audit.Audit, index, pk, sk)
            print(label, args.dataset, args.seed, "t/Qbits/F/h/W", t, bits, s.columns, s.dimension,
                  sum(s.column_degrees), file=sys.stderr, flush=True)
            samples, previous_winner = [], 0
            for i, (ticket, answer, _) in enumerate(pool):
                query_id = candidates[2 * i + (previous_winner & 1)]
                query = data.rows[query_id]
                cache_s, expected = timed(lambda query=query: sorted(((query ^ row).bit_count(), stable)
                                                        for row, stable in zip(rows, ids, strict=True)))

                def make_request(ticket=ticket, query=query, compiled=compiled, epoch=epoch):
                    transformed = [affine.bit_query_features(p, query) for p in compiled]
                    weights = tuple(x for values, _ in transformed for x in values)
                    return ticket.consume(weights, epoch), [off for _, off in transformed]

                query_s, (request, offsets) = timed(make_request)
                query_pack_s, query_body = timed(request.body)

                def parse_request(query_body=query_body, request=request, s=s, epoch=epoch, t=t):
                    width = (t.bit_length() + 7) // 8
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
                byte_pack_s, byte_body = timed(lambda output=output, bits=bits: b"".join(
                    int(x).to_bytes((bits + 7) // 8, "little") for c in output for row in c.components for x in row))
                bounds = tuple(c.phase_bound for c in output)
                byte_parse_s, byte_parsed = timed(parse_response_body, byte_body, pk, bounds)
                bit_pack_s, bit_body = timed(lambda output=output, pk=pk: codec.pack(tuple(x for c in output for row in c.components for x in row), int(pk.q)))
                bit_parse_s, bit_parsed = timed(parse_bits, bit_body, pk, bounds)
                assert byte_parsed == bit_parsed == output
                words = tuple(x for c in output for row in c.components for x in row)
                assert bit_body == codec.reference_pack(words, int(pk.q))
                assert codec.reference_unpack(bit_body, len(words), int(pk.q)) == words
                native_gate = gates["vector_native"]
                assert native_gate._hash(output) == check.EpochCheck._hash(native_gate, output)
                poly_gate = gates["polynomial_native"]
                assert poly_gate._hash(output) == polynomial.digest(words, poly_gate._polynomial, int(pk.q))
                verification = {}
                names = tuple(gates)
                for name in names[i % len(names):] + names[:i % len(names)]:
                    seconds, accepted = timed(gates[name].verify_once, request, bit_parsed)
                    assert accepted
                    verification[name] = seconds
                decrypt_s, plaintexts = timed(lambda bit_parsed=bit_parsed, pk=pk, sk=sk: [bgv.decrypt(c, pk, sk) for c in bit_parsed])

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
                audit_s, phase = timed(phase_audit.measure, request, answer, bit_parsed)
                common = query_s + query_pack_s + query_parse_s + native_s + decrypt_s + finish_s
                variants = {}
                for name, seconds in verification.items():
                    for transport, pack_s, parse_s, body in (("byte", byte_pack_s, byte_parse_s, byte_body),
                                                            ("bit", bit_pack_s, bit_parse_s, bit_body)):
                        variants[f"{name}_{transport}"] = {
                            "local_online_s_stage_sum": common + seconds + pack_s + parse_s,
                            "verification_s": seconds, "response_pack_s": pack_s, "response_parse_s": parse_s,
                            "response_body_bytes": len(body), "query_body_bytes": len(query_body)}
                sample = {"query_id": query_id, "next_policy_authenticated_winner_id": previous_winner,
                          "owner_transform_and_request_s": query_s, "query_pack_s": query_pack_s,
                          "public_query_parse_s": query_parse_s, "native_server_s": native_s, "gmp_server_s": gmp_s,
                          "decrypt_s": decrypt_s, "decode_select_s": finish_s,
                          "full_plaintext_cache_s_control": cache_s, "integer_phase_audit_s_outside_online": audit_s,
                          "phase": phase, "variants": variants,
                          "score_digest": hashlib.sha256(json.dumps(actual).encode()).hexdigest(),
                          "all_four_gates_accept_before_secret_decryption": True,
                          "all_distances_and_stable_top3_exact": True, "all_gmp_native_coefficients_equal": True,
                          "both_lossless_body_roundtrips_and_gmp_reference_equal": True,
                          "both_native_hashes_and_gmp_references_equal": True}
                samples.append(sample)
                print("query", query_id, "local GMP/native checker", round(variants["vector_gmp_byte"]["local_online_s_stage_sum"] * 1000, 2),
                      round(variants["vector_native_bit"]["local_online_s_stage_sum"] * 1000, 2),
                      "polynomial", round(variants["polynomial_native_bit"]["local_online_s_stage_sum"] * 1000, 2),
                      file=sys.stderr, flush=True)
            degree = gates["polynomial_native"].degree
            bound = gates["polynomial_native"].collision_bound
            cases.append({"layout": label, "t": t, "q": str(pk.q), "q_bits": bits, "n": pk.n, "eta": pk.eta,
                          "rounds": rounds, "polynomial_degree": degree,
                          "polynomial_collision_bound": {"numerator": str(bound.numerator), "denominator": str(bound.denominator)},
                          "setup": setup, "gate_setup": gate_setup, "cost_model": space.cost(s, q_bits=bits, rounds=rounds),
                          "private_map_body_bytes": candidate.map_bytes,
                          "owner_plaintext_coordinate_2bit_body_model":
                          (2 * sum(len(group) * f for group, f in zip(groups, s.layout.features, strict=True)) + 7) // 8,
                          "seeded_answer_packet_bytes": [packet for _, _, packet in pool],
                          "private_check_fingerprint_coefficient_counts": {name: len(gate._fingerprints) * sum(s.column_degrees)
                                                                            for name, gate in gates.items()},
                          "private_check_key_body_model_bytes": {"vector_gmp": 32 * rounds, "vector_native": 32 * rounds,
                                                                 "polynomial_gmp": degree * ((bits + 7) // 8),
                                                                 "polynomial_native": degree * ((bits + 7) // 8)},
                          "warmup": samples[0], "samples": samples[1:],
                          "summary": summary([{key: value for key, value in sample.items() if key.endswith("_s")}
                                               for sample in samples[1:]]),
                          "variant_summary": {name: summary([sample["variants"][name] for sample in samples[1:]])
                                              for name in samples[0]["variants"]},
                          "setup_scope": "Each profile charges its same-field fit/allocation, enrollment, actual nine-token pool "
                                         "and ONLY the chosen checker. Prior E35 full grid-selection cost is separate; not rerun here.",
                          "queries_chosen_after_index_and_entire_answer_pool": True,
                          "correctness_uses_absolute_phase_bound_not_fixed_cbd": True})
    return {"dataset": data.name, "split_seed": args.seed, "fixture_sha256": data.sha256, "count": len(rows),
            "dimension": data.dimension, "heldout_candidate_ids": candidates,
            "adaptive_policy": "query_i = heldout[64+2*i+(previous_authenticated_winner_source_id mod 2)]; initial winner=0",
            "cases": cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--dataset", choices=tuple(fixtures.SOURCES), required=True)
    parser.add_argument("--seed", type=int, default=3001)
    parser.add_argument("--repeats", type=int, default=8)
    parser.add_argument("--query-budget", type=int, default=1024)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 15 or not args.repeats + 1 <= args.query_budget <= 65536:
        parser.error("Expected 1..15 measured queries within the declared lifetime budget")
    paths = [Path(__file__), ROOT / "benchmarks/field_frontier_lab.py", ROOT / "benchmarks/certified_filter_lab.py",
             ROOT / "benchmarks/dictionary_layout_lab.py", ROOT / "src/cuhepy/bfv/scheme.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "polynomial_fingerprint", "native_linear_check", "coefficient_body", "test_polynomial_fingerprint",
        "field_frontier", "integer_phase_audit", "crt_noise_budget", "crt_query_space", "crt_masked_bgv", "crt_native_bgv",
        "crt_linear_check", "rank_partition", "affine_dictionary", "folded_dictionary", "folded_filter", "binary_fixtures",
        "dyadic_crt", "linear_packing", "owner_bgv", "seeded_bgv", "shallow_bgv"))
    for name in ("_fingerprint", "_subring"):
        paths.extend([ROOT / f"experiments/bfv_search_lab/{name}/bindings.cpp", ROOT / f"experiments/bfv_search_lab/{name}/Makefile",
                      Path(importlib.import_module(f"experiments.bfv_search_lab.{name}." +
                                                   ("_fingerprint" if name == "_fingerprint" else "_crt_subring")).__file__)])
    report = metadata(paths)
    report.update(kind="complete_verifier_lossless_precision_frontier", result=run(args),
                  scope="Research full-ring homemade BGV/GMP/existing single-thread public C++ NTT plus isolated private-check C++. "
                        "No SEAL/GPU. Private checking before secret decryption, trusted index/offline answers, pinned requests, "
                        "one-use local tokens and bounded verification transcript. Existing HE absolute phase/key gates unchanged. "
                        "All four gates verify the same canonical response; totals are paired measured stage-sum ablations. "
                        "No production, private-timing, RLWE assurance, malicious-preprocessing or full adaptive privacy proof. "
                        "Coefficient bodies exclude framing/authentication; all diagnostics/reference comparisons outside timing. "
                        "Polynomial hashing is a known family, not a novelty claim; vector native control preserves the exact old family.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "searches": 3 * (args.repeats + 1)}))


if __name__ == "__main__":
    main()
