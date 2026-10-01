#!/usr/bin/env python3
"""E66 exact combined-release controls on seven toy layouts and two modes.

Actual serialized coefficient bodies; toy stage measurements are diagnostics,
not representative company performance. No token/preparation cost is removed.
"""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.certified_filter_lab import timed
from benchmarks.dictionary_layout_lab import metadata, summary
from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import component_recipe as recipe
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import score_layout
from experiments.bfv_search_lab import supported_decoder as supported
from experiments.bfv_search_lab import terminal_release as release
from experiments.bfv_search_lab import verification_lifetime as lifetime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new output path")
    descriptors = ((32, ("",), (19,), tree.layout),
                   (32, ("0", "1"), (12, 4), tree.layout),
                   (32, ("0", "10", "11"), (6, 3, 1), tree.layout),
                   (32, ("0", "1"), (35, 9), tree.layout),
                   (32, ("0", "1"), (12, 4), score_layout.layout),
                   (32, ("0", "1"), (16, 16), score_layout.layout),
                   (32, ("0", "1"), (0, 4), score_layout.layout))
    cases = []
    for n, paths, counts, constructor in descriptors:
        s = space.space(constructor(tree.context(n, paths, 17), (4,) * len(paths), counts), tuple(range(len(paths))))
        words = tuple(tuple((3*i + group) % 16 for i in range(count)) for group, count in enumerate(counts))
        groups = [[[int(word >> j & 1) for j in range(4)] for word in row] for row in words]
        ids, cursor = [], 0
        for count in counts:
            ids.append(tuple(1000 - cursor - i for i in range(count)))
            cursor += count
        ids = tuple(ids)
        binding = hashlib.sha256(repr((words, ids)).encode()).hexdigest()
        pk, sk = masked.key_gen(s, q_bits=32, eta=1)
        epoch = secrets.token_bytes(32)
        with closing(owner.OwnerClient(pk, sk)) as client:
            enroll_s, (index, material, upload) = timed(recipe.enroll, s, groups, epoch, client)
            server_s, server = timed(native.NativeIndex, index, pk)
            for mode in ("cached", "streaming"):
                attempts = lifetime.AttemptBudget(16)
                setup_s, gate = timed(release.Gate, index, material, pk, ids, binding, attempts, mode=mode)
                samples, result_hash = [], hashlib.sha256()
                for word in range(16):
                    prepare_s, (ticket, answer, seeds) = timed(recipe.prepare, s, groups, epoch, word.to_bytes(16, "little"), secrets.token_bytes(32), client)
                    check_prepare_s, _ = timed(gate.prepare_answer, answer, seeds)
                    weights = tuple((1 - 2 * (word >> j & 1)) % 17 for _ in paths for j in range(4))
                    request = ticket.consume(weights, epoch)
                    evaluate_s, output = timed(server.evaluate, answer, request)
                    assert output == masked.evaluate(index, answer, request, pk)
                    pack_s, body = timed(release.pack, output, s, pk, epoch)
                    open_s, dots = timed(gate.open_body_once, request, body, sk)
                    assert dots == tuple(tuple(row) for row in space.scores(s, groups, weights))
                    scores = tuple((x + word.bit_count()) % 17 for row in dots for x in row)
                    expected = tuple((old ^ word).bit_count() for row in words for old in row)
                    flat_ids = tuple(i for row in ids for i in row)
                    assert scores == expected and sorted(zip(scores, flat_ids, strict=True))[:3] == sorted(zip(expected, flat_ids, strict=True))[:3]
                    bodies = {"full_body_bytes": len(codec.pack(tuple(x for c in output for poly in c.components for x in poly), int(pk.q))),
                              "recipe_only_body_bytes": len(recipe.c0_body(output, pk)),
                              "support_only_body_bytes": len(supported.pack(supported.project(output, s, pk, epoch), pk)),
                              "combined_body_bytes": len(body)}
                    counts_model = release.cost(s, pk)
                    assert all(bodies[k] == counts_model[k] for k in bodies)
                    result_hash.update(bytes(scores))
                    samples.append({"prepare_answer_s": prepare_s, "register_answer_s": check_prepare_s,
                                    "server_evaluate_s": evaluate_s, "combined_pack_s": pack_s,
                                    "combined_public_restore_check_secret_decode_s": open_s,
                                    "every_score_and_stable_top3_exact": True})
                cases.append({"n": n, "paths": paths, "row_counts": counts, "layout_module": constructor.__module__,
                              "mode": mode, "q": int(pk.q), "eta": pk.eta, "rounds": 4,
                              "index_upload_packet_bytes": upload, "index_enroll_s": enroll_s,
                              "server_setup_s": server_s, "combined_owner_pinned_setup_s": setup_s,
                              "counts": release.cost(s, pk), "samples": samples,
                              "summary_toy_diagnostics_only": summary([{k: v for k, v in sample.items() if k.endswith("_s")} for sample in samples]),
                              "all_binary_queries": 16, "scores_sha256": result_hash.hexdigest(),
                              "attempts_used": attempts.used, "dedicated_decoder_after_supported_relation": True})
    paths = [Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "terminal_release", "supported_decoder", "component_recipe", "decryption_support", "coefficient_body",
        "crt_linear_check", "crt_query_space", "crt_masked_bgv", "crt_native_bgv", "dyadic_crt", "score_layout",
        "owner_bgv", "seeded_bgv", "shallow_bgv", "verification_lifetime")),
        ROOT / "src/cuhepy/bfv/scheme.py", ROOT / "benchmarks/dictionary_layout_lab.py", ROOT / "benchmarks/certified_filter_lab.py"]
    paths.extend((ROOT / "experiments/bfv_search_lab/_subring").glob("*.so"))
    result = metadata(paths)
    result.update(kind="combined_terminal_release_control", cases=cases,
                  scope="Known public C1 recipe plus supported C0 projection, separately gated. "
                        "224 toy encrypted searches, N32/t17/eta1; timings diagnose plumbing only. "
                        "No preparation elimination, complete service/transport, durability, security proof, parameter approval or new compression primitive.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "encrypted_queries": sum(c["all_binary_queries"] for c in cases),
                      "minimum_combined_to_full_body_ratio": min(c["counts"]["combined_body_bytes"] / c["counts"]["full_body_bytes"] for c in cases)}))


if __name__ == "__main__":
    main()
