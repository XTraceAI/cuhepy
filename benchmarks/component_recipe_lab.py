#!/usr/bin/env python3
"""E48 paired full-reply/public-C1-recipe wire/work/state tradeoff pilot.

Same request, complete ciphertext, keys, verifier family and all-score output.
Totals are paired timed-stage sums; bandwidth sweeps are explicit models,
not actual network latency. Public caching and streaming scratch are charged.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from contextlib import closing
import json
from pathlib import Path
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata, summary
from benchmarks.field_frontier_lab import public_space
from benchmarks.verification_frontier_lab import parse_bits
from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import binary_fixtures as fixtures
from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import component_recipe as recipe
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import native_linear_check as checks
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--dataset", choices=tuple(fixtures.SOURCES), required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 10:
        parser.error("Expected 1..10 measured pilot queries")
    data = fixtures.load(args.dataset, args.cache_dir / fixtures.SOURCES[args.dataset]["member"])
    ids, heldout = fixtures.split(data, 3001)
    rows = [data.rows[i] for i in ids]
    order = dictionary.metric_order(rows, data.dimension, 32)
    t, slots = (193, 32) if data.name == "mushroom" else (257, 64)
    groups_plan = fields.fit(rows, data.dimension, order, prime=t, target=32)
    candidate = fields.allocate(groups_plan, rows, slots)
    maps, s = public_space(candidate)
    bitmaps = [affine.compile_bits(p) for p in maps]
    groups = [affine.index_features(b.mapping, [rows[i] for i in b.positions]) for b in candidate.blocks]
    pk, sk = masked.key_gen(s, q_bits=32)
    setup, samples = {}, []
    epoch = secrets.token_bytes(32)
    with closing(owner.OwnerClient(pk, sk)) as client:
        setup["enroll_s"], (index, manifest, upload) = timed(recipe.enroll, s, groups, epoch, client)
        setup["seeded_index_upload_bytes"] = upload
        setup["server_prepare_s"], server = timed(native.NativeIndex, index, pk)
        setup["public_cached_recipe_prepare_s"], cached = timed(recipe.Reconstructor, manifest, pk, mode="cached")
        setup["public_streaming_recipe_prepare_s"], streaming = timed(recipe.Reconstructor, manifest, pk, mode="streaming")
        gates = {name: checks.NativeVectorCheck(index, pk, rounds=fields.rounds(int(pk.q)), budget=1024)
                 for name in ("full", "cached", "streaming")}
        setup["offline_pool_s"], pool = timed(lambda: [recipe.prepare(s, groups, epoch, i.to_bytes(16, "little"),
                                                                     secrets.token_bytes(32), client)
                                                     for i in range(args.repeats + 1)])
        for gate in gates.values():
            for _, answer, _ in pool:
                gate.prepare_answer(answer)
        previous = 0
        for i, (ticket, answer, answer_seeds) in enumerate(pool):
            word = data.rows[heldout[64 + 2 * i + (previous & 1)]]
            def request():
                transformed = [affine.bit_query_features(p, word) for p in bitmaps]
                weights = tuple(x for values, _ in transformed for x in values)
                return ticket.consume(weights, epoch), tuple(off for _, off in transformed)
            transform_s, (req, offsets) = timed(request)
            server_s, output = timed(server.evaluate, answer, req)
            full_pack_s, full_body = timed(codec.pack, tuple(int(x) for c in output for p in c.components for x in p), int(pk.q))
            full_parse_s, full = timed(parse_bits, full_body, pk, tuple(c.phase_bound for c in output))
            full_check_s, accepted = timed(gates["full"].verify_once, req, full)
            assert accepted
            short_pack_s, short_body = timed(recipe.c0_body, output, pk)
            variants = {"full": {"response_pack_s": full_pack_s, "public_restore_s": full_parse_s,
                                 "full_check_s": full_check_s, "response_body_bytes": len(full_body)}}
            for label, helper in (("cached", cached), ("streaming", streaming)):
                restore_s, reconstructed = timed(helper.restore, req, short_body, answer_seeds)
                gate_s, accepted = timed(gates[label].verify_once, req, reconstructed)
                assert accepted and reconstructed == output
                variants[label] = {"response_pack_s": short_pack_s, "public_restore_s": restore_s,
                                   "full_check_s": gate_s, "response_body_bytes": len(short_body)}
            assert output == masked.evaluate(index, answer, req, pk)
            decrypt_s, plaintexts = timed(lambda: [bgv.decrypt(c, pk, sk) for c in full])
            def decode():
                dots = tree.unpack(candidate.layout, plaintexts)
                actual = [None] * len(rows)
                for block, scores, map_id in zip(candidate.blocks, dots, s.map_ids, strict=True):
                    for position, score in zip(block.positions, affine.bit_decode(bitmaps[map_id], scores, offsets[map_id]), strict=True):
                        actual[position] = score
                return tuple(actual), sorted(zip(actual, ids, strict=True))[:3]
            decode_s, (scores, winners) = timed(decode)
            assert scores == tuple((word ^ row).bit_count() for row in rows)
            for v in variants.values():
                v["local_online_s_stage_sum"] = transform_s + server_s + decrypt_s + decode_s + v["response_pack_s"] + v["public_restore_s"] + v["full_check_s"]
                v["directional_link_models_s"] = {str(mbps): v["local_online_s_stage_sum"] + 8 * v["response_body_bytes"] / (mbps * 1000000)
                                                  for mbps in (1, 10, 40, 100, 1000)}
            samples.append({"warmup": i == 0, "query_policy_previous_winner": previous, "next_winner": winners[0][1],
                            "transform_s": transform_s, "native_server_s": server_s, "decrypt_s": decrypt_s,
                            "decode_select_s": decode_s, "all_full_ciphertext_coefficients_identical": True,
                            "all_gates_pass_before_secret_decryption": True, "all_scores_and_stable_top3_exact": True,
                            "variants": variants})
            previous = winners[0][1]
    result = metadata([Path(__file__), ROOT / "experiments/bfv_search_lab/component_recipe.py"])
    result.update(kind="public_component_seed_recipe", dataset=data.name, fixture_sha256=data.sha256,
                  count=len(rows), dimension=data.dimension, n=pk.n, q=int(pk.q), t=t, setup=setup, samples=samples,
                  summary={name: summary([{k: sample["variants"][name][k] for k in (
                      "response_pack_s", "public_restore_s", "full_check_s", "local_online_s_stage_sum", "response_body_bytes")}
                                         for sample in samples[1:]]) for name in ("full", "cached", "streaming")},
                  added_public_seed_body_bytes_model=s.columns * s.layout.cost.response_ciphertexts * 32,
                  added_public_answer_seed_body_bytes_per_token_model=s.layout.cost.response_ciphertexts * 32,
                  cached_public_native_index_word_bytes_model=2 * s.columns * s.layout.cost.response_ciphertexts * pk.n * 8,
                  streaming_native_one_column_word_scratch_bytes_model=2 * s.layout.cost.response_ciphertexts * pk.n * 8,
                  private_map_body_bytes=candidate.map_bytes, id_permutation_body_bytes_model=12 * len(rows),
                  scope="Fresh fixed index only; trusted owner seed manifest/answer preprocessing. Known public-seed recomputation "
                        "tradeoff, not a new compression primitive. Same full-vector verifier, complete ciphertext and secret decryption. "
                        "Cached mode holds a charged public native index; streaming scratch excludes Python/GMP and transient buffers. "
                        "Small CPU pilot, paired stage sums; bandwidth is a directional no-overlap model with common RTT/upload omitted "
                        "from both variants. Not a service/network latency measurement, production assurance or low-RSS claim.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "queries": len(samples)}))


if __name__ == "__main__":
    main()
