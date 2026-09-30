#!/usr/bin/env python3
"""E63 complete tiny decoder matrix supports and equal-old-cost counterexample."""

# ruff: noqa: E402 -- standalone algebra/count oracle.

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import decryption_support as support
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import score_layout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    cases = []
    for n, paths, counts in ((32, ("",), (19,)), (32, ("0", "1"), (12, 4)),
                             (64, ("0", "10", "11"), (9, 5, 1)), (32, ("0", "1"), (35, 9))):
        ctx = tree.context(n, paths, 17)
        for constructor in (tree.layout, score_layout.layout):
            layout = constructor(ctx, (2,) * len(paths), counts)
            certificate = support.certify(layout)
            assert certificate == support.matrix_oracle(layout)
            cases.append({"layout": asdict(layout), "support": asdict(certificate),
                          "full_coefficient_count": certificate.full_coefficient_count,
                          "projected_coefficient_count": certificate.projected_coefficient_count,
                          "all_decoder_basis_columns_checked": True})
    result = metadata([Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "decryption_support", "dyadic_crt", "score_layout", "crt_query_space"))])
    result.update(kind="decoder_support_algebra_oracle", cases=cases, counterexample=support.equal_old_cost_counterexample(),
                  scope="Exact public field-decoder support and coefficient-deletion body model; no multi-leaf projected ciphertext gate/decoder implementation. "
                        "Independent linear decoder basis-column agreement; same old resource vector differs in new projected cost. "
                        "Known sample extraction/support ingredients; not an arbitrary-ciphertext compression lower bound, originality, timing or assurance claim.")
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cases": len(cases)}))


if __name__ == "__main__":
    main()
