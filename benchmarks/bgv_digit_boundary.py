#!/usr/bin/env python3
"""E13 synthetic digit-conversion boundary, not a full search or verified service.

Measures exact Q120 CRT plus four 30-bit gadget digits, GPU/CPU round trips and
packing/unpacking, at the current joint circuit's actual stage batch sizes.
Uses pinned host buffers, one/eight CPU workers, serial stage boundaries, and
repeated synthetic public residues. Excludes linear checks, commitments,
preprocessing, Nitro/vsock copies, receipts and all HE private arithmetic.
Its host/GPU paths agree completely; that is correctness testing, not attestation.
"""

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from experiments.bfv_search_lab.verification_oracles import digit_boundary_counts  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("/tmp/cuhepy-bgv-digit-boundary"))
    parser.add_argument("--num-vectors", type=int, default=8192)
    parser.add_argument("--ring-degree", type=int, default=16384)
    parser.add_argument("--padded", type=int, default=512)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    model = digit_boundary_counts(args.ring_degree, args.padded, args.num_vectors)
    if args.num_vectors > 65536 or not 1 <= args.repeats <= 100:
        parser.error("Invalid bounded boundary workload")
    sources = [Path(__file__), REPO/"experiments/bfv_search_lab/verification_oracles.py"]
    for directory in (REPO/"experiments/bfv_search_lab/_native", REPO/"src/cuhepy/bfv/_cpu_ext", REPO/"src/cuhepy/bfv/_gpu_ext"):
        sources.extend(p for p in sorted(directory.iterdir()) if p.suffix in (".h", ".cuh", ".cu", ".cpp") or p.name == "Makefile")
    hashes = {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    binary_hash = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    command = [str(args.binary.resolve()), str(args.ring_degree), str(args.num_vectors), str(args.padded), str(args.repeats)]
    environment = dict(os.environ, OMP_WAIT_POLICY="PASSIVE")
    process = subprocess.run(command, cwd=REPO, env=environment, check=True, capture_output=True, text=True)
    measured = json.loads(process.stdout)
    for field, predicted in (("switch_coefficients", "switch_input_coefficients"),
        ("native_roundtrip_bytes", "native_layout_roundtrip_bytes"),
        ("shared_roundtrip_bytes", "shared_uint64_digits_roundtrip_bytes"),
        ("word_packed_roundtrip_bytes", "aligned_words_roundtrip_bytes"),
        ("packed_roundtrip_bytes", "ideally_packed_roundtrip_bytes")):
        if measured[field] != model[predicted]:
            raise AssertionError("Measured schedule differs from the independent boundary model")
    if not measured["complete_cpu_gpu_digits_equal"] or not measured["gmp_oracle_and_rejections_passed"]:
        raise AssertionError("Digit oracle checks were not completed")
    report = dict(kind="bgv_digit_boundary", scope=__doc__, command=sys.argv, executable_command=command,
        utc=datetime.now(UTC).isoformat(), git_head=head,
        platform=platform.platform(), gpu=subprocess.check_output(["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"], text=True).strip(),
        documented_build_flags="nvcc -O3 -std=c++17 -ccbin g++-12 -Xcompiler=-fopenmp -gencode arch=compute_86,code=sm_86",
        omp_wait_policy="PASSIVE", synthetic_public_seed=20260927, repeats=args.repeats,
        measured=measured, model=model, source_sha256=hashes, binary_sha256=binary_hash,
        medians={name: {k: statistics.median(s[k] for s in values) for k in values[0]}
                 for name, values in measured["samples"].items()})
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2)+"\n")
    print(args.json_out)


if __name__ == "__main__":
    main()
