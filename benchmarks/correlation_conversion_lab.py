#!/usr/bin/env python3
"""E69 ideal random-triple conversion: exact algebra and encrypted controls.

No real PCG, distributed authentication, timing win or fixed-M programming is
implemented here. Every ideal triple and intermediate stays inside the owner.
"""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
from contextlib import closing
import itertools
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import correlation_conversion_oracle as conversion
from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new result path; retained runs are immutable")
    rng, tiny = random.Random(69001), 0
    for flat in itertools.product(range(3), repeat=4):
        matrix = (flat[:2], flat[2:])
        for _ in range(3):
            triple = conversion.ideal_triple(2, 2, 3, rng)
            conversion.audit_ideal_triple(triple)
            assert conversion.convert(matrix, triple) == conversion.product(matrix, triple.mask, 3)
            tiny += 1

    s = space.space(tree.layout(tree.context(32, ("0", "1"), 17), (2, 2), (4, 3)), (0, 1))
    groups = [[[1, 0], [0, 1], [1, 1], [0, 0]], [[1, 0], [0, 1], [1, 1]]]
    matrix = tuple(tuple(row[j] if group == leaf else 0 for group in range(2) for j in range(2))
                   for leaf, rows in enumerate(groups) for row in rows)
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    epoch, rng, queries, seen = b"i" * 32, random.Random(69003), 0, set()
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, epoch, client)
        server, gate = native.NativeIndex(index, pk), check.EpochCheck(index, pk, budget=16)
        for i, values in enumerate(itertools.product((0, 1), repeat=4)):
            triple = conversion.ideal_triple(7, 4, 17, rng)
            conversion.audit_ideal_triple(triple)
            output = conversion.convert(matrix, triple)
            assert output == conversion.product(matrix, triple.mask, 17)
            packets = tuple(client.encrypt(p) for p in space.outputs(s.layout, [list(output[:4]), list(output[4:])]))
            answer = masked.Answer(s, epoch, i.to_bytes(16, "little"), tuple(owner.expand(p, pk) for p in packets))
            c1 = tuple(c.components[1] for c in answer.ciphertexts)
            assert c1 not in seen
            seen.add(c1)
            gate.prepare_answer(answer)
            request = masked.Request(s, epoch, answer.token_id,
                                     tuple((a-b) % 17 for a, b in zip(values, triple.mask, strict=True)))
            result = server.evaluate(answer, request)
            assert result == masked.evaluate(index, answer, request, pk)
            assert gate.verify_once(request, result)
            assert tree.unpack(s.layout, [bgv.decrypt(c, pk, sk) for c in result]) == space.scores(s, groups, values)
            try:
                gate.verify_once(request, result)
            except RuntimeError:
                pass
            else:
                raise AssertionError("One-use gate accepted a replay")
            queries += 1

    paths = [Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "correlation_conversion_oracle", "crt_linear_check", "crt_masked_bgv", "crt_native_bgv",
        "crt_query_space", "dyadic_crt", "owner_bgv", "shallow_bgv")),
        ROOT / "benchmarks/dictionary_layout_lab.py"]
    result = metadata(paths)
    result.update(kind="ideal_random_triple_fixed_private_matrix_conversion_control",
                  tiny_fixed_matrices=81, tiny_exact_conversions=tiny,
                  encrypted_exact_queries=queries, unique_fresh_C1_packets=len(seen),
                  encrypted_profile={"n": pk.n, "t": pk.t, "q": int(pk.q), "eta": pk.eta,
                                     "leaf_degrees": [16, 16], "rows": 7, "query_coordinates": 4},
                  per_token_cost=conversion.cost(7, 4, field_bits=pk.t.bit_length()),
                  scope="Ideal private random triples only, not a PCG/MAC or distributed protocol. "
                        "Dense (M-B)r costs the same field product count as Mr, plus correction and triple handling. "
                        "Fresh answer encryption and full-Q gate preparation remain on every query. "
                        "Native/GMP evaluation, exact score/ID order and one-use replay control checked on toys. "
                        "No parameter assurance, side-channel assurance, durable state, latency or novel mechanism claim.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "tiny_conversions": tiny, "encrypted_queries": queries}))


if __name__ == "__main__":
    main()
