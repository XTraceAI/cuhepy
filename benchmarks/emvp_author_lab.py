#!/usr/bin/env python3
"""Pinned original EMVP Go/C++ artifact on exact public binary full scans.

The original crypto artifact is unchanged. An isolated adapter adds input/output
mapping and an optional own complete pre-decode field gate. Native code dimensions,
author heuristic parameters, all setup, state and word bodies are reported.
No imported artifact is our deliverable implementation or production assurance.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import math
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import binary_fixtures as fixtures

AUTHOR = ROOT.parent / "research-data/reference-artifacts-20260930/emvp-author"
PIN = "856762f5925fe873bb5cbc0401ceb5a44568efa9"
EXECUTABLE = AUTHOR.parent / "emvp-author-adapter"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=tuple(fixtures.SOURCES), required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--queries", type=int, default=8)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 4 or not 1 <= args.queries <= 128:
        parser.error("Invalid bounded public reference run")
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=AUTHOR, text=True).strip() == PIN
    assert not subprocess.check_output(["git", "diff", "--name-only"], cwd=AUTHOR, text=True).strip()
    data = fixtures.load(args.dataset, args.cache / fixtures.SOURCES[args.dataset]["member"])
    index_ids, query_ids = fixtures.split(data, 3001)
    rows = tuple(data.rows[i] for i in index_ids)
    query_ids = query_ids[:args.queries]
    words = tuple(data.rows[i] for i in query_ids)
    modes = ((False, False), (False, True), (True, False), (True, True))
    cases = []
    for repetition in range(args.repeats):
        for key_only, verified in modes[::1 if repetition % 2 == 0 else -1]:
            payload = {"rows": [format(x, "x") for x in rows], "ids": index_ids,
                       "queries": [format(x, "x") for x in words], "dimension": data.dimension,
                       "key_only": key_only, "verified": verified}
            env = dict(os.environ, GOMAXPROCS="1")
            process = subprocess.run([str(EXECUTABLE)], input=json.dumps(payload), text=True,
                                     capture_output=True, timeout=180, env=env)
            if process.returncode:
                raise RuntimeError(process.stderr[:4000])
            case = json.loads(process.stdout)
            for word, sample in zip(words, case["samples"], strict=True):
                expected = tuple((row ^ word).bit_count() for row in rows)
                assert tuple(sample.pop("scores")) == expected
                assert tuple(tuple(x) for x in sample["top3"]) == tuple(heapq.nsmallest(3, zip(expected, index_ids, strict=True)))
                sample.update(all_exact_scores_and_stable_top3=True,
                              scores_sha256=hashlib.sha256(b"".join(x.to_bytes(2, "little") for x in expected)).hexdigest())
            profile = case["profile"]
            n, k, b = (profile[name] for name in ("n", "k", "b"))
            degree = math.ceil(k / (b - 1))
            case.update(repetition=repetition, degree=degree,
                        two_author_algebraic_screen_inequalities_met=(b ** (degree - 1) * min(b, degree) >= 1 << 128
                                                                     and (n // b + 1) * k > n + 128),
                        complete_setup_plus_all_queries_s=sum(case["setup"].values()) + sum(s["online_s"] for s in case["samples"]))
            cases.append(case)
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.with_suffix(".partial.json").write_text(json.dumps({"kind": "incomplete_original_emvp_reference", "cases": cases}, indent=2) + "\n")
            print(args.dataset, repetition, key_only, verified, "online mean ms",
                  round(sum(s["online_s"] for s in case["samples"]) * 1000 / args.queries, 3), file=sys.stderr, flush=True)
    paths = [Path(__file__), ROOT / "experiments/bfv_search_lab/binary_fixtures.py",
             ROOT / "experiments/bfv_search_lab/references/emvp_author_adapter/main.go",
             ROOT / "experiments/bfv_search_lab/references/emvp_author_adapter/go.mod"]
    result = metadata(paths)
    external_files = [AUTHOR / name for name in subprocess.check_output(["git", "ls-files"], cwd=AUTHOR, text=True).splitlines()
                      if name.endswith((".go", ".cpp", ".h", ".mod", ".sh"))]
    external_files += [EXECUTABLE, *(AUTHOR / f"{name}/lib{library}.a" for name, library in (
        ("tdm", "NTT"), ("dataobjects", "dataobjects"), ("ecc", "ReedSolomon"), ("mvp", "MVP"), ("utils", "utils")))]
    result["source_sha256"].update({os.path.relpath(p, ROOT): hashlib.sha256(p.read_bytes()).hexdigest() for p in external_files})
    result.update(kind="original_emvp_author_exact_binary_reference", author_revision=PIN,
                  author_repository="https://github.com/SecretKeyCrypto/Encrypted-Matrix-Vector-Products",
                  dataset=args.dataset, dataset_sha256=data.sha256, split_seed=3001, dimension=data.dimension,
                  index_count=len(rows), query_source_ids=query_ids, cases=cases,
                  compiler="go1.23.12 linux/amd64; author run.sh C++ -O3 -march=native; adapter -buildvcs=false; GOMAXPROCS=1",
                  gate_soundness_scope="Own conditional complete public encoded-response check before author private decoding; "
                      "1024/65537^9 plus hidden AES-CTR challenge hybrid, trusted epoch/index/pinned requests and no private side channels. "
                      "Not a proof of author transcript/privacy or reviewed composition.",
                  scope="Partial original artifact adaptation, not complete published reproduction or security/parameter assurance. "
                      "Exact binary signed queries, stable full-score output checked independently outside timing. "
                      "Artifact uses seeded/64-bit math/rand sampling; measurements do not certify cryptographic key entropy. "
                      "Key-only clears the cached code matrix and charges regeneration to each query. "
                      "Word body models and private hints exclude RSS, framing and network transport. "
                      "Owner encoding/setup is charged and never required by the online decode API. "
                      "Nine-round gate and its setup/state/time are additions by this adapter, not the authors' malicious-integrity claim.")
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "cases": len(cases)}))


if __name__ == "__main__":
    main()
