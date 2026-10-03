"""E110 bounded integer correctness/count runner; no timing measurements."""
# Standalone bootstrap precedes repository imports.
# ruff: noqa: E402

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import traceback

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from experiments.bfv_search_lab import functional_orbit as lab

DEFAULT_FIXTURE = REPO.parent/"research-data/native-boundary-20261003/frozen-fixture.json"
SOURCES = ("experiments/bfv_search_lab/functional_orbit.py",
           "experiments/bfv_search_lab/functional_orbit_test.py",
           "experiments/bfv_search_lab/native_boundary_oracle.py",
           "benchmarks/functional_orbit_lab.py", "docs/research/functional-orbit-preregistration.md")


def identities():
    return {name: hashlib.sha256((REPO/name).read_bytes()).hexdigest() for name in SOURCES}


def write_fresh(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        stream.write(json.dumps(value, indent=2)+"\n")


def main(argv=None):
    if sys.flags.optimize:
        raise RuntimeError("Assertions must remain enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--keys", type=Path, required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--freeze-keys", action="store_true")
    action.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)
    source_hashes = identities()
    fixture, ctx, secret = lab.load_fixture(args.fixture)
    if args.freeze_keys:
        if args.keys.exists():
            raise ValueError("Never overwrite a frozen toy enrollment")
        enrollment = lab.prepare(ctx, secret)
        record = {"kind": "deterministic_disclosed_N8_toy_raw_Q_gadget_keys_not_security_assurance",
                  "utc_before_main_run": datetime.now(UTC).isoformat(), "fixture_sha256": lab.FIXTURE_SHA256,
                  "source_hashes": source_hashes, "sampler": "SHAKE labeled biased modular masks and mod3 errors; deliberately not cryptographic randomness",
                  "enrollment": asdict(enrollment), "public_enrollment_digest": enrollment.public_digest()}
        write_fresh(args.keys, record)
        print(json.dumps({"frozen_keys": str(args.keys), "public_digest": enrollment.public_digest()}))
        return
    if args.json_out.exists():
        raise ValueError("Never overwrite raw experiment evidence")
    record = json.loads(args.keys.read_text())
    if record["fixture_sha256"] != lab.FIXTURE_SHA256 or record["source_hashes"] != source_hashes:
        raise ValueError("Frozen enrollment source/fixture drift")
    enrollment = lab.enrollment_from_dict(record["enrollment"])
    lab.validate_enrollment(ctx, enrollment)
    if enrollment.public_digest() != record["public_enrollment_digest"]:
        raise ValueError("Frozen owner enrollment substitution")
    metadata = {"experiment": "Q36/E110", "utc": datetime.now(UTC).isoformat(), "command": sys.argv,
                "python": sys.executable, "python_version": platform.python_version(),
                "assertions_enabled": not sys.flags.optimize, "fixture_sha256": lab.FIXTURE_SHA256,
                "keys_sha256": hashlib.sha256(args.keys.read_bytes()).hexdigest(),
                "source_hashes": source_hashes, "timing_measurements": False,
                "native_cuda_or_external_HE_artifact_executed": False,
                "git_head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, check=True, capture_output=True, text=True).stdout.strip()}
    try:
        result = lab.run_fixture(fixture, ctx, secret, enrollment)
    except Exception:
        write_fresh(args.json_out, {**metadata, "status": "failed", "traceback": traceback.format_exc()})
        raise
    write_fresh(args.json_out, {**metadata, "status": "completed", "result": result})
    print(json.dumps({"json_out": str(args.json_out), "status": "completed", "costs": result["costs"],
                      "different_packets": result["different_complete_packets_vs_ordinary"]}))


if __name__ == "__main__":
    main()
