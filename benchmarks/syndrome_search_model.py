#!/usr/bin/env python3
"""Reproducible E19 plaintext selectivity fixtures; not an encrypted benchmark."""

# ruff: noqa: E402 -- standalone benchmark adds the repository root before imports.

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.bfv_search_lab import syndrome_oracle as oracle


def balanced_word(rng, dimension):
    result = 0
    for offset in range(0, dimension, 8):
        result |= sum(1 << j for j in rng.sample(range(8), 4)) << offset
    return result


def balanced_neighbor(query, pairs, dimension, rng):
    # Preserve weight four in every block, while changing exactly 2*pairs bits.
    swaps = []
    for offset in range(0, dimension, 8):
        ones = [offset + j for j in range(8) if (query >> (offset + j)) & 1]
        zeros = [offset + j for j in range(8) if not (query >> (offset + j)) & 1]
        rng.shuffle(ones)
        rng.shuffle(zeros)
        swaps.extend(zip(ones, zeros, strict=True))
    selected = rng.sample(swaps, pairs)
    return query ^ sum((1 << a) + (1 << b) for a, b in selected)


def fixtures(count, dimension, seed):
    rng = random.Random(seed)
    query = rng.getrandbits(dimension)
    yield "uniform", query, [rng.getrandbits(dimension) for _ in range(count)]
    rows = [rng.getrandbits(dimension) for _ in range(count - 3)]
    rows.extend(query ^ sum(1 << j for j in rng.sample(range(dimension), distance))
                for distance in (2, 4, 6))
    rng.shuffle(rows)
    yield "planted-close", query, rows
    yield "all-identical", query, [query] * count
    query = balanced_word(rng, dimension)
    rows = [balanced_word(rng, dimension) for _ in range(count - 3)]
    # A deliberately favorable distribution for the coupled bound, not a
    # representative production dataset. Also test uniform data above.
    pairs = dimension // 8
    rows.extend(balanced_neighbor(query, p, dimension, rng) for p in (pairs - 4, pairs - 3, pairs - 2))
    rng.shuffle(rows)
    yield "balanced-with-planted-neighbors", query, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=8192)
    parser.add_argument("--dimension", type=int, default=512)
    parser.add_argument("--seeds", type=int, nargs="+", default=[2701, 2702, 2703])
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.count < 3 or args.dimension < 64 or args.dimension % 8:
        parser.error("Require count >= 3 and dimension >= 64 divisible by eight")
    rows = []
    for seed in args.seeds:
        codes = [oracle.make_code(8, 4, 20260927 + i) for i in range(args.dimension // 8)]
        for name, query, vectors in fixtures(args.count, args.dimension, seed):
            result = oracle.selectivity(query, vectors, codes)
            result.update({"fixture": name, "seed": seed})
            rows.append(result)
            print(f"{name} seed={seed}: kth={result['oracle_kth_radius']}, "
                  f"survivors={ {key: value['survivors'] for key, value in result['filters'].items()} }",
                  file=sys.stderr, flush=True)
    sources = [Path(__file__), ROOT / "experiments/bfv_search_lab/syndrome_oracle.py"]
    output = {"kind": "plaintext_syndrome_weight_selectivity_model", "utc": datetime.now(UTC).isoformat(),
              "command": sys.argv,
              "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in sources},
              "notes": "Exact plaintext oracle, no encrypted speedup or novel coding-theory claim. "
                       "Oracle kth radius is not free; fixed-radius results include insufficient coverage. "
                       "All derived features are scanned. Encrypted lookup is only a cost model here; "
                       "a separate small encrypted regression checks its algebra. Private routing, omitted-result "
                       "certificates, threshold discovery, traffic and server/client timings are unimplemented. "
                       "Data are synthetic, including deliberately favorable and adverse fixtures.",
              "code_columns": [list(code.columns) for code in codes],
              "onehot_lookup_cost_model": oracle.lookup_expansion(codes, args.count), "results": rows}
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
