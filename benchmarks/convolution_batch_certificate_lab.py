#!/usr/bin/env python3
"""E70 post-output batching, challenge-order and additional-round count screen."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import convolution_batch_certificate as batching
from experiments.bfv_search_lab import convolution_certificate_oracle as primitive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new result path")
    rng = random.Random(70021)
    groups = tuple(tuple((tuple(rng.randrange(97) for _ in range(8)), tuple(rng.randrange(97) for _ in range(8)))
                         for _ in range(3)) for _ in range(6))
    frozen = batching.freeze(tuple(primitive.certify(g, 97).output for g in groups), 97)
    beta = batching.challenge(frozen, 97, 4, rng)
    witnesses = batching.quotients(groups, beta, 97)
    assert batching.verify_at_points(groups, frozen, beta, witnesses, (0, 1, 2, 96), 97)

    q, accepts, attempts = 17, 0, 0
    groups = ((((1, 2), (3, 4)),), (((2, 3), (4, 5)),))
    outputs = tuple(primitive.certify(g, q).output for g in groups)
    frozen = batching.freeze((((outputs[0][0]+1) % q, outputs[0][1]), outputs[1]), q)
    for a, b in itertools.product(range(q), repeat=2):
        weights = ((a, b),)
        h = batching.quotients(groups, weights, q)
        for point in range(q):
            decision = batching.verify_at_points(groups, frozen, weights, h, (point,), q)
            assert decision == (a == 0)
            accepts += decision
            attempts += 1

    original = ROOT / "benchmarks/results/publication-structured-operator-screen-20260930.json"
    screens = []
    for profile in json.loads(original.read_text())["recorded_geometry_count_screens"]:
        n = 2048 if profile["dataset"] == "connect4" else 16384
        outputs = profile["rows"]//n
        count = batching.cost(n=n, q=profile["inner_q"], outputs=outputs)
        saved = count["net_body_bytes_saved_before_compute_RTT_framing"]
        screens.append({"dataset": profile["dataset"], "profile": profile["profile"],
                        "n": n, "q": profile["inner_q"], "outputs": outputs, "cost": count,
                        "max_added_RTT_s_payload_only_model": {str(rate): max(0, saved)*8/rate for rate in (20000000, 100000000, 1000000000)},
                        "positive_body_saving_not_service_win": saved > 0})
    paths = [Path(__file__), ROOT / "experiments/bfv_search_lab/convolution_batch_certificate.py",
             ROOT / "experiments/bfv_search_lab/convolution_certificate_oracle.py",
             ROOT / "benchmarks/dictionary_layout_lab.py", original]
    result = metadata(paths)
    result.update(kind="post_output_quotient_batching_algebra_and_RTT_count_control",
                  honest_profile={"n": 8, "q": 97, "outputs": 6, "factor_pairs_per_output": 3, "rounds": 4, "exact": True},
                  cancellation_control={"q": q, "attempts": attempts, "accepts": accepts, "exact_probability_numerator": 1, "exact_probability_denominator": q},
                  geometry_count_screens=screens,
                  scope="Known random output batching after immutable statement in pure local oracle. "
                        "No durable receiver, actual transfer/RTT, HE query/privacy/release integration, security proof or novel result. "
                        "Payload-only RTT thresholds exclude generation/check/CPU/framing and are optimistic models. "
                        "Batched certificates still retain owner factory in the masked-stage comparison.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cancellation_control_attempts": attempts,
                      "accepts": accepts, "geometry_screens": len(screens)}))


if __name__ == "__main__":
    main()
