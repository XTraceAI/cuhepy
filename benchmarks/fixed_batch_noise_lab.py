#!/usr/bin/env python3
"""E32 paired q40 deterministic and q32 fixed-CBD full encrypted search.

All queries/corrections are fixed before index errors are sampled. No adaptive
query claim. An independent larger-modulus phase oracle reconstructs integer
phases from fresh input phases, so a wrapped result cannot masquerade as a
small observed phase. Diagnostic work is outside measured online timings.
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
from cuhepy.bfv.scheme import _ring_product
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata, summary
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_noise_budget as noise
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import fixed_batch_bgv as fixed
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import rank_partition as partition
from experiments.bfv_search_lab import shallow_bgv as bgv


class PhaseOracle:
    """Owner-only diagnostics, using a separate modulus above the L1 maximum."""
    def __init__(self, batch):
        self.batch = batch
        self.pk = batch.pk
        self.product = owner.TernaryProduct(batch.sk.s, self.pk.q)
        self.product.prepare(self.pk.q)
        worst = space.cost(batch.profile.space, eta=self.pk.eta)["worst_case_phase_bound"]
        self.modulus = mpz(2 * worst + 1)  # primality is not needed by the GMP ring oracle.
        self.columns = [[tuple(x % self.modulus for x in self.fresh(cipher)) for cipher in column]
                        for column in batch.index.columns]

    def fresh(self, cipher):
        product = self.product.multiply(cipher.components[1], self.pk.q)
        phase = [(a + b) % self.pk.q for a, b in zip(cipher.components[0], product, strict=True)]
        result = [int(x if x <= self.pk.q // 2 else x - self.pk.q) for x in phase]
        assert max(map(abs, result), default=0) <= cipher.phase_bound
        return result

    def measure(self, request, answer, output):
        short = space.corrections(self.batch.profile.space, request.delta)
        coefficients = [tuple(mpz(x) % self.modulus for x in space.expand(self.batch.profile.space, row)) for row in short]
        maximum = 0
        digest = hashlib.sha256()
        for i, (saved, cipher) in enumerate(zip(answer.ciphertexts, output, strict=True)):
            phase = [mpz(x) % self.modulus for x in self.fresh(saved)]
            for column, poly in zip(self.columns, coefficients, strict=True):
                product = _ring_product(column[i], poly, self.modulus)
                phase = [(a + b) % self.modulus for a, b in zip(phase, product, strict=True)]
            true_phase = [int(x if x <= self.modulus // 2 else x - self.modulus) for x in phase]
            maximum = max(maximum, max(map(abs, true_phase), default=0))
            actual_product = self.product.multiply(cipher.components[1], self.pk.q)
            actual = [(a + b) % self.pk.q for a, b in zip(cipher.components[0], actual_product, strict=True)]
            assert all(a == b % self.pk.q for a, b in zip(actual, true_phase, strict=True))
            assert all(abs(x) * 2 < self.pk.q for x in true_phase)
            digest.update(b"".join(x.to_bytes(8, "little", signed=True) for x in true_phase))
        cert = noise.certificate(self.batch.profile, short)
        assert maximum <= cert.total
        return {"maximum_unreduced_integer_phase": maximum, "statistical_certificate_total": cert.total,
                "message_carry_bound": cert.message_bound, "cbd_tail_bound": cert.tail_bound,
                "phase_margin_fraction_of_half_q": 2 * maximum / int(self.pk.q),
                "all_integer_phase_coefficients_match_ciphertext": True,
                "private_phase_digest_diagnostic_only": digest.hexdigest()}


def prepare(args):
    data = fixtures.load(args.dataset, args.cache_dir / fixtures.SOURCES[args.dataset]["member"])
    ids, holdout = fixtures.split(data, args.seed)
    rows = [data.rows[i] for i in ids]
    setup = {}
    setup["metric_order_s"], order = timed(dictionary.metric_order, rows, data.dimension, 32)
    setup["rank_fit_s"], original = timed(partition.prepare, rows, data.dimension, order, target=32, policy="hybrid")
    alternatives, allocation_s = [], 0.0
    for slots in (1, 2, 4, 8, 16, 32, 64):
        if slots >= len(set(b.mapping for b in original.blocks)):
            seconds, c = timed(partition.reallocate, original, rows, slots)
            allocation_s += seconds
            alternatives.append((slots, c))
    _, candidate = min(alternatives, key=lambda item: (item[1].layout.cost.response_ciphertexts, item[0]))
    setup["allocation_s"] = allocation_s
    maps = tuple(dict.fromkeys(b.mapping for b in candidate.blocks))
    map_ids = tuple(maps.index(b.mapping) for b in candidate.blocks)
    s = space.space(candidate.layout, map_ids)
    setup["coordinate_enroll_s"], groups = timed(lambda: [affine.index_features(b.mapping, [rows[i] for i in b.positions])
                                                       for b in candidate.blocks])
    setup["query_compile_s"], compiled = timed(lambda: [affine.compile_bits(p) for p in maps])
    # Predeclare queries BEFORE either encrypted index exists. Use a new slice
    # of the holdout relative to E29/E30/E31. No future latency chooses a query.
    query_ids = holdout[32:32 + args.repeats + 1]
    setup["fixed_query_transform_s"], transforms = timed(
        lambda: [[affine.bit_query_features(p, data.rows[i]) for p in compiled] for i in query_ids])
    weights = tuple(tuple(x for row, _ in per_map for x in row) for per_map in transforms)
    offsets = [[off for _, off in per_map] for per_map in transforms]
    rng = random.Random(32000 + args.seed)
    seeds = tuple(rng.randbytes(32) for _ in weights)  # Public fixtures only, HE errors remain fresh OS samples.
    cases = []
    for bits in (40, 32) if args.seed % 2 else (32, 40):
        label = "deterministic_q40" if bits == 40 else "fixed_cbd_q32"
        case_setup = dict(setup)
        case_setup["fixed_batch_construct_s"], batch = timed(
            fixed.Batch, s, groups, weights, q_bits=bits, seeds=seeds,
            correctness_bits=args.correctness_bits, query_budget=args.query_budget)
        with closing(batch):
            case_setup["fixed_batch_construct_body_bytes"] = 2 * s.dimension * len(weights) * 2 + 32 * len(weights)
            # Above: weights + deltas (u16), private mask seeds. Token IDs,
            # pinned context and verifier state are priced separately.
            case_setup["key_and_mask_fix_s"], _ = timed(batch.keygen)
            case_setup["transposed_index_s"], (index, upload) = timed(batch.enroll)
            case_setup["seeded_index_packet_bytes"] = upload
            rounds = 4 if bits == 40 else 5
            if bits == 40:
                case_setup["native_prepare_s"], evaluator = timed(native.NativeIndex, index, batch.pk)
                case_setup["checker_prepare_s"], gate = timed(check.EpochCheck, index, batch.pk,
                                                             rounds=rounds, budget=args.query_budget)
            else:
                case_setup["native_prepare_s"], evaluator = timed(fixed.NativeIndex, batch.context, index)
                case_setup["checker_prepare_s"], gate = timed(batch.verifier, rounds=rounds)
            case_setup["offline_answer_pool_s"], pool = timed(batch.prepare_answers)
            case_setup["offline_answer_check_pool_s"], _ = timed(
                lambda gate=gate, pool=pool: [gate.prepare_answer(a) for a, _ in pool])
            case_setup["integer_phase_oracle_prepare_s"], oracle = timed(PhaseOracle, batch)
            print(label, args.dataset, args.seed, "F/h/W", s.columns, s.dimension, sum(s.column_degrees), file=sys.stderr, flush=True)
            samples = []
            for i, query_id in enumerate(query_ids):
                q = data.rows[query_id]
                expected = sorted(((q ^ x).bit_count(), stable) for x, stable in zip(rows, ids, strict=True))
                request_s, (request, answer) = timed(batch.release, i)
                if (i + args.seed) % 2:
                    native_s, output_native = timed(evaluator.evaluate, answer, request)
                    gmp_s, output_gmp = timed(masked.evaluate if bits == 40 else fixed.evaluate,
                                             *([index, answer, request, batch.pk] if bits == 40 else [batch.context, index, answer, request]))
                else:
                    gmp_s, output_gmp = timed(masked.evaluate if bits == 40 else fixed.evaluate,
                                             *([index, answer, request, batch.pk] if bits == 40 else [batch.context, index, answer, request]))
                    native_s, output_native = timed(evaluator.evaluate, answer, request)
                assert output_native == output_gmp
                if bits == 40:
                    verify_s, accepted = timed(gate.verify_once, request, output_native)
                    assert accepted
                    decrypt_s, plaintexts = timed(
                        lambda output_native=output_native, batch=batch: [bgv.decrypt(c, batch.pk, batch.sk) for c in output_native])
                else:
                    verify_s, receipt = timed(gate.accept_once, request, output_native)
                    assert receipt is not None
                    decrypt_s, plaintexts = timed(gate.decrypt_once, receipt, batch.sk)

                def finish(plaintexts=plaintexts, i=i):
                    dots = tree.unpack(s.layout, plaintexts)
                    actual = []
                    for block, values, group in zip(candidate.blocks, dots, map_ids, strict=True):
                        actual.extend(zip(affine.bit_decode(compiled[group], values, offsets[i][group]),
                                          (ids[j] for j in block.positions), strict=True))
                    return sorted(actual)

                finish_s, actual = timed(finish)
                assert actual == expected
                pack_s, coefficient_body = timed(lambda output_native=output_native, bits=bits: b"".join(
                    int(x).to_bytes((bits + 7) // 8, "little") for c in output_native for poly in c.components for x in poly))
                oracle_s, phase = timed(oracle.measure, request, answer, output_native)
                samples.append({"query_id": query_id, "request_release_s": request_s, "gmp_server_s": gmp_s,
                                "native_server_s": native_s, "verification_s": verify_s, "decrypt_s": decrypt_s,
                                "decode_select_s": finish_s, "response_pack_s": pack_s,
                                "native_local_online_s": request_s + native_s + verify_s + decrypt_s + finish_s + pack_s,
                                "gmp_local_online_s": request_s + gmp_s + verify_s + decrypt_s + finish_s + pack_s,
                                "integer_phase_oracle_s_outside_online": oracle_s,
                                "query_body_bytes": len(request.body()), "response_coefficient_body_bytes": len(coefficient_body),
                                "score_digest": hashlib.sha256(json.dumps(actual).encode()).hexdigest(), "phase": phase,
                                "all_distances_and_stable_top3_exact": True, "all_gmp_native_coefficients_equal": True})
                print("query", query_id, "native", round(samples[-1]["native_local_online_s"] * 1000, 2),
                      "phase", phase["maximum_unreduced_integer_phase"], file=sys.stderr, flush=True)
            model = space.cost(s, q_bits=bits, rounds=rounds)
            cases.append({"layout": label, "n": batch.pk.n, "t": batch.pk.t, "q": str(batch.pk.q), "eta": batch.pk.eta,
                          "rounds": rounds, "setup": case_setup, "cost_model": model, "fixed_profile": noise.describe(batch.profile),
                          "additional_statistical_certificate_body_bytes": 56 if bits == 32 else 0,
                          "seeded_answer_packet_bytes": [packet for _, packet in pool],
                          "warmup": samples[0], "samples": samples[1:],
                          "summary": summary([{k: v for k, v in sample.items() if k.endswith("_s") or k.endswith("_bytes")} for sample in samples[1:]]),
                          "fixed_request_count": len(weights), "queries_and_corrections_fixed_before_enrollment": True})
    return {"dataset": args.dataset, "split_seed": args.seed, "fixture_sha256": data.sha256,
            "count": len(rows), "dimension": data.dimension, "query_ids_with_warmup": query_ids, "cases": cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--dataset", choices=tuple(fixtures.SOURCES), default="mushroom")
    parser.add_argument("--seed", type=int, default=3001)
    parser.add_argument("--repeats", type=int, default=8)
    parser.add_argument("--correctness-bits", type=int, default=128)
    parser.add_argument("--query-budget", type=int, default=1024)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 32 or args.query_budget < args.repeats + 1:
        parser.error("Expected 1..32 samples fitting the declared query budget")
    paths = [Path(__file__), ROOT / "benchmarks/certified_filter_lab.py", ROOT / "benchmarks/dictionary_layout_lab.py",
             ROOT / "src/cuhepy/bfv/scheme.py"]
    paths.extend(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "crt_noise_budget", "fixed_batch_bgv", "test_crt_noise_budget", "test_fixed_batch_bgv", "crt_query_space",
        "crt_masked_bgv", "crt_native_bgv", "crt_linear_check", "rank_partition", "affine_dictionary", "folded_dictionary",
        "folded_filter", "binary_fixtures", "dyadic_crt", "linear_packing", "owner_bgv", "seeded_bgv", "shallow_bgv"))
    paths.extend([ROOT / "experiments/bfv_search_lab/_subring/bindings.cpp", ROOT / "experiments/bfv_search_lab/_subring/Makefile",
                  Path(importlib.import_module("experiments.bfv_search_lab._subring._crt_subring").__file__)])
    report = metadata(paths)
    report.update({"kind": "fixed_cbd_linear_correctness_profile", "result": prepare(args),
                   "scope": "Research fixed-batch scheduling only. Queries/corrections fixed before index encryption. "
                            "Homemade full-ring symmetric BGV and existing single-thread C++ public NTT; no GPU/SEAL. "
                            "Trusted index/answer preparation and hidden conditional exact fingerprint gate. "
                            "New statistical output/certificate type; old deterministic phase APIs unchanged. "
                            "Correctness bits are not lattice security. No adaptive/noise-side-channel/production assurance. "
                            "Independent unreduced integer-phase audit is outside timing. Body bytes omit transport/auth framing. "
                            "Fixed schedule owner state is additional and charged separately. Public reproducible mask seeds, fresh OS HE errors."})
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "searches": 2 * (args.repeats + 1)}))


if __name__ == "__main__":
    main()
