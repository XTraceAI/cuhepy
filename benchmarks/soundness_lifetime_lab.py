#!/usr/bin/env python3
"""P07 exact ideal-field rejection-path and epoch-reset controls, not HE timing."""

# ruff: noqa: E402 -- standalone exact oracle.

from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import soundness_lifetime_oracle as oracle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    cases = [{"q": q, "rounds": rounds, "attempts": attempts, **oracle.enumerate_first_failure(q, rounds, attempts)}
             for q in (3, 5) for rounds in (1, 2) for attempts in (1, 2, 3)]
    result = metadata([Path(__file__), ROOT / "experiments/bfv_search_lab/soundness_lifetime_oracle.py"])
    result.update(kind="ideal_vector_check_lifetime_oracle", cases=cases, counterexamples=oracle.conditional_and_reset_counterexamples(),
                  scope="Exact two-dimensional small-prime exhaustive all-reject paths with hidden uniform independent vector challenges. "
                        "Models first false acceptance only; not concrete PRG/HE privacy, a service proof, timing assurance or new checker.")
    args.json_out.write_text(json.dumps(result, indent=2, default=lambda x: {"numerator": x.numerator, "denominator": x.denominator} if isinstance(x, Fraction) else None) + "\n")
    print(json.dumps({"output": str(args.json_out), "policies_checked": sum(c["policies_checked"] for c in cases)}))


if __name__ == "__main__":
    main()
