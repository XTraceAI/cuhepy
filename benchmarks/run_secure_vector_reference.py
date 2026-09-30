#!/usr/bin/env python3
"""Pinned author EMVP/BNTM baseline on the exact own-anchor inputs.

This adapter invokes external Rust implementations for comparison only. The
deliverable BGV/BFV arithmetic stays homemade. Public fixture rows are encoded
as signs, so all scores and stable-ID top-3 are exact without row-norm leakage.
Bytes come from the author count models; no network timing is measured.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.bfv_search_lab import binary_fixtures as fixtures

PIN = "519148cf3fddc11277a111774ca8cb92d891e0e3"
ADAPTER = ROOT / "experiments/bfv_search_lab/references/secure_vector_search_adapter"
REFERENCE = ROOT.parent / "research-data/reference-artifacts-20260930"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--anchor", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    checkout = REFERENCE / "secure-vector-search"
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip()
    if actual != PIN:
        raise RuntimeError("External baseline checkout differs from the reviewed source pin")
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--", "Cargo.toml", "scorer-core",
                    "scorer-emvp", "scorer-bntm", "ivf-index"], cwd=checkout, check=True)
    raw_anchor = args.anchor.read_bytes()
    result = json.loads(raw_anchor)["result"]
    data = fixtures.load(result["dataset"], args.cache_dir / fixtures.SOURCES[result["dataset"]]["member"])
    ids, _ = fixtures.split(data, result["split_seed"])
    if data.sha256 != result["fixture_sha256"] or len(ids) != result["count"]:
        raise RuntimeError("Anchor and reference workload mismatch")
    rows = [data.rows[i] for i in ids]
    samples = [result["cases"][0]["warmup"], *result["cases"][0]["samples"]]
    if any([c["warmup"]["query_id"], *[x["query_id"] for x in c["samples"]]]
           != [x["query_id"] for x in samples] for c in result["cases"]):
        raise RuntimeError("Anchor profiles used different adaptive query sequences")

    def signs(word):
        return [1 - 2 * ((word >> j) & 1) for j in range(data.dimension)]

    public = {"dataset": data.name, "dimension": data.dimension, "ids": list(ids),
              "rows": [signs(row) for row in rows], "fixture_sha256": data.sha256,
              "queries": [{"source_id": x["query_id"], "signs": signs(data.rows[x["query_id"]]),
                           "expected": [(row ^ data.rows[x["query_id"]]).bit_count() for row in rows]}
                          for x in samples]}
    body = (json.dumps(public, separators=(",", ":")) + "\n").encode()
    input_path = REFERENCE / f"exact-input-{data.name}-{result['split_seed']}.json"
    input_path.write_bytes(body)
    env = dict(os.environ, CARGO_HOME=str(REFERENCE / "cargo-cache"),
               CARGO_TARGET_DIR=str(REFERENCE / "cargo-target"), RAYON_NUM_THREADS="1")
    command = ["cargo", "+1.98.1", "build", "--manifest-path", str(ADAPTER / "Cargo.toml"),
               "--release", "--locked", "--offline"]
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    binary = REFERENCE / "cargo-target/release/cuhepy-exact-search-reference"
    completed = subprocess.run([str(binary), str(input_path)], env=env, capture_output=True, text=True)
    log = REFERENCE / f"adapter-{data.name}-{result['split_seed']}.stderr.log"
    with log.open("a") as stream:
        stream.write(f"\nadapter source sha256 {hashlib.sha256((ADAPTER / 'src/main.rs').read_bytes()).hexdigest()}\n")
        stream.write(completed.stderr)
    if completed.returncode:
        raise RuntimeError(f"Reference adapter failed ({completed.returncode}); retained {log}: "
                           + completed.stderr[:1600])
    report = json.loads(completed.stdout)
    assert report["rayon_threads"] == 1 and report["full_scores_and_stable_id_top3"]
    for case in report["cases"]:
        for sample, expected_query in zip(case["samples"], public["queries"], strict=True):
            assert sample["query_id"] == expected_query["source_id"] and sample["all_scores_exact"]
            expected_top = sorted(zip(expected_query["expected"], ids, strict=True))[:3]
            assert [tuple(x) for x in sample["top3"]] == expected_top
    files = [Path(__file__), ADAPTER / "Cargo.toml", ADAPTER / "Cargo.lock", ADAPTER / "src/main.rs",
             checkout / "Cargo.lock"]
    report.update(anchor_path=str(args.anchor), anchor_sha256=hashlib.sha256(raw_anchor).hexdigest(),
                  input_sha256=hashlib.sha256(body).hexdigest(), input_path=str(input_path),
                  platform=platform.platform(), compiler=subprocess.check_output(
                      ["rustc", "+1.98.1", "--version", "--verbose"], text=True),
                  compiler_override="Artifact requests 1.95.0; explicit installed 1.98.1 used",
                  source_hashes={str(p.relative_to(ROOT) if p.is_relative_to(ROOT) else p):
                                 hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
                  binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  reproduction_command=command,
                  scope="Local CPU serial preliminary matched-input execution, not a paper-size latency sample. "
                        "All score adaptation/select costs included in elapsed time; OS/task scheduling is included. "
                        "Author bytes are models, and integrity/parameter assumptions differ. BNTM verified mode "
                        "retains the complete encrypted matrix on the client and reruns full Freivalds reductions.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "count": len(rows), "searches": 3 * len(samples)}))


if __name__ == "__main__":
    main()
