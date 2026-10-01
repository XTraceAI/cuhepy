#!/usr/bin/env python3
"""Retain raw hashes and locate exact historical sources for publication pilots.

Git HEAD recorded by a run may precede its uncommitted source. Match the source
SHA to committed content rather than assuming HEAD alone reproduces it. Runtime
binaries/external locks remain explicitly separate workspace-cache dependencies.
This validates artifact identity, not cryptographic correctness or assurances.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from functools import cache
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def digest(body):
    return hashlib.sha256(body).hexdigest()


@cache
def locate(name, expected):
    path = (ROOT / name).resolve()
    if not path.is_relative_to(WORKSPACE):
        return {"path": name, "sha256": expected, "location": "outside-workspace/not-read"}
    if path.is_relative_to(ROOT):
        relative = str(path.relative_to(ROOT))
        revisions = git("log", "--all", "--follow", "--format=%H", "--", relative).decode().splitlines()
        for revision in revisions:
            process = subprocess.run(["git", "show", f"{revision}:{relative}"], cwd=ROOT, capture_output=True)
            if process.returncode == 0 and digest(process.stdout) == expected:
                return {"path": relative, "sha256": expected, "location": "git", "revision": revision}
    if path.is_file() and digest(path.read_bytes()) == expected:
        return {"path": str(path.relative_to(WORKSPACE)), "sha256": expected, "location": "workspace-cache"}
    # External adapters can be rebuilt at the same requested cache path. Keep
    # their old binary by content hash instead of rewriting a historical run.
    history = WORKSPACE / "research-data/reference-artifacts-20260930/runtime-history" / expected / path.name
    if history.is_file() and digest(history.read_bytes()) == expected:
        return {"path": str(history.relative_to(WORKSPACE)), "requested_path": name,
                "sha256": expected, "location": "workspace-cache"}
    return {"path": name, "sha256": expected, "location": "unresolved"}


def create(dependency_receipts=()):
    raw_paths = git("ls-files", "benchmarks/results/publication-*.json").decode().splitlines()
    runs, sources = [], {}
    for name in raw_paths:
        body = (ROOT / name).read_bytes()
        data = json.loads(body)
        pairs = dict(data.get("source_hashes", {}))
        pairs.update(data.get("source_sha256", {}))
        if "runner_sha256" in data:
            pairs[data["command"][0]] = data["runner_sha256"]
        for path, sha in pairs.items():
            sources[(path, sha)] = locate(path, sha)
        runs.append({"path": name, "sha256": digest(body), "bytes": len(body),
                     "kind": data.get("kind", "parameter-estimate" if "estimator_revision" in data else "reference"),
                     "recorded_head": data.get("git_head", data.get("sdk_revision")),
                     "command": data.get("command"), "source_versions": len(pairs)})
    receipts = []
    for receipt in dependency_receipts:
        path = receipt.resolve()
        if not path.is_relative_to(ROOT):
            raise ValueError("Dependency receipt must be retained in the repository")
        body = path.read_bytes()
        data = json.loads(body)
        pairs = dict(data.get("source_hashes", {}))
        pairs.update(data.get("source_sha256", {}))
        for name, sha in pairs.items():
            sources[(name, sha)] = locate(name, sha)
        receipts.append({"path": str(path.relative_to(ROOT)), "sha256": digest(body),
                         "bytes": len(body), "source_versions": len(pairs)})
    return {"schema": 1, "generated_utc": datetime.now(UTC).isoformat(),
            "retention_head": git("rev-parse", "HEAD").decode().strip(),
            "baseline": "02e06c0f5636def284ed6864b3e208538fcb10a6", "raw_runs": runs,
            "source_versions": list(sources.values()), "dependency_receipts": receipts,
            "external_pins": {"secure-vector-search": "519148cf3fddc11277a111774ca8cb92d891e0e3",
                              "original-emvp-author": "856762f5925fe873bb5cbc0401ceb5a44568efa9",
                              "lattice-estimator": "53da5982597709ba0fdf94ea37a84d822310fd84"},
            "scope": "Identity/retention manifest of TRACKED completed publication pilots. "
                     "Ignored partial/preliminary duplicates are excluded. Exact historical Git blobs are located by SHA. "
                     "Workspace binaries and external generated locks are not claimed to be in the Git bundle. "
                     "Public fixture/external clone/compiler metadata remains in each raw run and baseline report. "
                     "No complete paper evaluation, protocol proof, parameter or GPU assurance is inferred."}


def verify(data):
    errors = []
    for run in [*data["raw_runs"], *data.get("dependency_receipts", ())]:
        path = ROOT / run["path"]
        if not path.is_file() or digest(path.read_bytes()) != run["sha256"]:
            errors.append("raw run mismatch: " + run["path"])
    for source in data["source_versions"]:
        if source["location"] == "git":
            process = subprocess.run(["git", "show", f"{source['revision']}:{source['path']}"], cwd=ROOT, capture_output=True)
            if process.returncode or digest(process.stdout) != source["sha256"]:
                errors.append("historical source mismatch: " + source["path"])
        elif source["location"] == "workspace-cache":
            path = WORKSPACE / source["path"]
            if not path.is_file() or digest(path.read_bytes()) != source["sha256"]:
                errors.append("runtime/external cache mismatch: " + source["path"])
        else:
            errors.append("unresolved source identity: " + source["path"])
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--dependency-receipt", type=Path, action="append", default=[],
                        help="Additional immutable source/runtime identities; not benchmark runs")
    args = parser.parse_args()
    if (args.json_out is None) == (args.verify is None):
        parser.error("Choose --json-out or --verify")
    if args.verify and args.dependency_receipt:
        parser.error("Dependency receipts are selected only when creating a manifest")
    data = json.loads(args.verify.read_text()) if args.verify else create(args.dependency_receipt)
    errors = verify(data)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"runs": len(data["raw_runs"]), "source_versions": len(data["source_versions"]), "errors": errors}))
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
