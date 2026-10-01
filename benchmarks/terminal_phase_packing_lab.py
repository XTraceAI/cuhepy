#!/usr/bin/env python3
"""E66 exact integer terminal packing correctness and additive-HE counts."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import reduction_oracles as integer
from experiments.bfv_search_lab import terminal_phase_packing as packing


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new result path")
    count, bound = 0, packing.integer_bound(2, 17, 1)
    for c0, c1, secret in itertools.product(tuple(itertools.product((-8, 0, 8), repeat=2)),
                                          tuple(itertools.product((-8, 0, 8), repeat=2)),
                                          tuple(itertools.product((-1, 0, 1), repeat=2))):
        product = integer.ring_product(c1, secret)
        phases = tuple(a+b for a, b in zip(c0, product, strict=True))
        packets = packing.pack(phases, bound, 31)
        assert packing.unpack(packets, 2, bound, 31) == phases
        count += 1
    original = ROOT / "benchmarks/results/publication-structured-operator-screen-20260930.json"
    screens = []
    for profile in json.loads(original.read_text())["recorded_geometry_count_screens"]:
        n = 2048 if profile["dataset"] == "connect4" else 16384
        phases = profile["rows"]//2
        screens.append({"dataset": profile["dataset"], "profile": profile["profile"],
                        "n": n, "q": profile["inner_q"], "phases": phases,
                        "secret_coefficient_bound": 1, "paillier_key_bits_count_only": 2048,
                        "cost": packing.cost(n=n, q=profile["inner_q"], phases=phases)})
    paths = [Path(__file__), ROOT / "experiments/bfv_search_lab/terminal_phase_packing.py",
             ROOT / "experiments/bfv_search_lab/reduction_oracles.py",
             ROOT / "benchmarks/dictionary_layout_lab.py", original]
    result = metadata(paths)
    result.update(kind="exact_unrescaled_terminal_integer_packing_control", exact_toy_phase_cases=count,
                  geometry_count_screens=screens,
                  scope="Plain integer correctness oracle plus known coefficient-method additive-HE byte/work model. "
                        "No additive encryption, latency, compression/proof/key assurance or malicious release protocol. "
                        "Naive exact integer phases lose this body comparison; optimized rescaling, terminal contexts and rate-1 controls remain distinct.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "exact_cases": count, "profiles": len(screens)}))


if __name__ == "__main__":
    main()
