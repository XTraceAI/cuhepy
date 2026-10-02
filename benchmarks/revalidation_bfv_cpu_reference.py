#!/usr/bin/env python3
"""Repeated CPU-reference study supplementing the old BFV CUDA scaling artifact.

The old artifact has one warm-plan CPU sample per size. This separate study uses
the same synthetic fixture, BFV geometry, residue backend and search call, with
one excluded first sample followed by at least five measured calls. Setup,
decryption, correctness checks, optional GPU preparation and network are outside
the CPU timer. Fresh encryption randomness prevents exact historical replay.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

from bfv_client_matrix import REPO_ROOT, make_data
from cuhepy.hamming.bfv import BFVClient


def timed(function):
    # Match bfv_cuda_scaling.timed: no collection, codec or decryption in timer.
    start = time.perf_counter()
    result = function()
    return time.perf_counter() - start, result


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def probe(argv):
    try:
        process = subprocess.run(argv, cwd=REPO_ROOT, capture_output=True,
                                 text=True, timeout=10, check=False)
        return {"argv": argv, "returncode": process.returncode,
                "stdout": process.stdout.strip(), "stderr": process.stderr.strip()}
    except (OSError, subprocess.SubprocessError) as error:
        return {"argv": argv, "error": str(error)}


def write_report(path, report):
    # The destination is reserved exclusively before any expensive operation.
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False,
                                     prefix=path.name + ".", suffix=".tmp") as stream:
        temporary = Path(stream.name)
        try:
            json.dump(report, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", default="1024,8192,32768")
    parser.add_argument("--poly-modulus-degree", type=int, default=16384)
    parser.add_argument("--embed-len", type=int, default=512)
    parser.add_argument("--seed", type=int, default=913)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--batch-tiles", type=int, default=32)
    parser.add_argument("--include-gpu-reference", action="store_true")
    parser.add_argument("--historical-artifact", type=Path,
                        default=REPO_ROOT / "benchmarks/results/bfv_cuda_fused_scaling.json")
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    try:
        sizes = sorted(set(int(value) for value in args.sizes.split(",")))
    except ValueError:
        parser.error("Sizes must be comma-separated integers")
    if (not sizes or sizes[0] < 1 or sizes[-1] > 65536
            or not 5 <= args.repeats <= 30 or not 1 <= args.batch_tiles <= 256):
        parser.error("Use bounded sizes, 5–30 repeats and 1–256 batch tiles")
    historical = json.loads(args.historical_artifact.read_text())
    historical_config = historical["config"]
    if (args.poly_modulus_degree != historical_config["poly_modulus_degree"]
            or args.embed_len != historical_config["embed_len"]
            or args.seed != historical["seed"]
            or args.batch_tiles != historical["batch_tiles"]
            or sizes != sorted(row["vectors"] for row in historical["sizes"])):
        parser.error("This confirmation must retain the artifact's sizes, geometry, seed and batch tiles")
    if (historical_config["plain_modulus"] != 65537
            or historical_config["coeff_modulus_bits"] != 180
            or historical_config["decomposition_bits"] != 30
            or historical_config["rns_modulus"] is not True):
        parser.error("Artifact does not describe the declared BFV scaling baseline")
    output = args.json_out.resolve()
    if output.is_relative_to(REPO_ROOT):
        parser.error("Use a new result path outside the source checkout")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("x") as stream:
            stream.write("{}\n")
    except FileExistsError:
        parser.error("Result already exists; use a new path")
    report = {
        "schema": "cuhepy.bfv_cpu_reference_repeated_confirmation.v1",
        "kind": "bfv_cpu_reference_repeated_confirmation",
        "start_utc": datetime.now(UTC).isoformat(), "command": sys.argv,
        "state": "started", "historical_artifact": str(args.historical_artifact.resolve()),
        "historical_artifact_sha256": sha(args.historical_artifact),
        "historical_CPU_scope": "One warm-plan sample per size; not a repeated distribution.",
        "new_study_scope": "One excluded first warm-plan call, then repeated CPU searches on one freshly encrypted context; optional paired GPU calls. Current-source confirmation, not historical-source replay or independent process blocks.",
        "CPU_timed_boundary": "owner.encode_hamming_server_packed(encrypted_query, index_prefix, count), identical call and perf_counter boundary to bfv_cuda_scaling.py; setup, owner decoding, correctness and optional GPU calls excluded.",
        "GPU_timed_boundary": "Raw search includes upload/conversion/validation/allocation; prepared search excludes separately measured index preparation. No network/attestation or owner crypto timed.",
        "seed": args.seed, "sizes_declared": sizes, "repeats": args.repeats,
        "batch_tiles": args.batch_tiles, "gpu_reference_requested": args.include_gpu_reference,
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "thread_environment": {name: os.environ.get(name) for name in
                                               ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "OMP_WAIT_POLICY")},
                        "git_head": probe(["git", "rev-parse", "HEAD"]),
                        "gpu": probe(["nvidia-smi", "--query-gpu=name,uuid,driver_version,memory.total", "--format=csv,noheader"])},
        "setup": {}, "sizes": [],
    }

    def progress(message):
        print(message, file=sys.stderr, flush=True)

    def save():
        write_report(output, report)

    save()
    try:
        sources = [Path(__file__).resolve(), REPO_ROOT / "benchmarks/bfv_cuda_scaling.py",
                   REPO_ROOT / "benchmarks/bfv_client_matrix.py"]
        for directory in ("src/cuhepy/bfv", "src/cuhepy/hamming"):
            sources.extend(path for path in (REPO_ROOT / directory).rglob("*")
                           if path.is_file() and path.suffix in (".py", ".cpp", ".h", ".cuh", ".cu", ".so"))
        report["source_and_library_sha256"] = {str(path.relative_to(REPO_ROOT)): sha(path)
                                               for path in sorted(set(sources))}
        setup = report["setup"]
        setup["fixture_generate_s"], (vectors, query, expected) = timed(
            lambda: make_data(sizes[-1], args.embed_len, args.seed))
        fixture_hash = hashlib.sha256(bytes(query))
        for vector in vectors:
            fixture_hash.update(bytes(vector))
        report["plaintext_fixture_sha256"] = fixture_hash.hexdigest()
        progress("Generating a fresh BFV context and maximum-sized index")
        setup["key_generation_s"], owner = timed(lambda: BFVClient(
            args.embed_len, args.poly_modulus_degree, 65537, 180, 30,
            rns_modulus=True, server_backend="residue"))
        report["config"] = json.loads(owner.stringify_config())
        if any(report["config"].get(key) != value for key, value in historical_config.items()):
            raise AssertionError("Current configuration differs from the declared historical geometry")
        capacity = owner.vectors_per_ciphertext
        index = []
        start = time.perf_counter()
        for at in range(0, len(vectors), capacity * 32):
            index.extend(owner.encrypt_vec_packed(vectors[at:at + capacity * 32]))
            progress(f"Encrypted {min(at + capacity * 32, len(vectors))}/{len(vectors)} vectors")
        setup["index_encrypt_s"] = time.perf_counter() - start
        setup["query_encrypt_s"], encrypted_query = timed(lambda: owner.encrypt_vec_one(query))
        setup["cpu_plan_s"], _ = timed(owner._native)
        plans = {}
        if args.include_gpu_reference:
            from cuhepy.bfv.cuda import BFVCudaServer
            from cuhepy.bfv.rns import BFVRNSArithmetic
            arithmetic = BFVRNSArithmetic(owner._pk(), fast=True, residue=True)
            for label, level in (("original_cuda", 0), ("fused_ntt", 1),
                                 ("gpu_decode", 2), ("shared_keys", 3)):
                setup[label + "_plan_s"], plans[label] = timed(partial(
                    BFVCudaServer, arithmetic, owner.padded_embed_len,
                    owner.response_modulus_bits, kernel_level=level,
                    batch_tiles=32 if level == 0 else args.batch_tiles))
        save()
        for count in sizes:
            tiles = index[:(count + capacity - 1) // capacity]
            cpu_call = partial(owner.encode_hamming_server_packed, encrypted_query, tiles, count)
            first_elapsed, reference = timed(cpu_call)
            if owner.decode_hamming_client_packed(reference, count) != expected[:count]:
                raise AssertionError(f"Incorrect first CPU distances at {count}")
            row = {"vectors": count, "response_ciphertexts": len(reference),
                   "first_warm_plan_sample_s_excluded": first_elapsed,
                   "samples_s": {"cpu_reference": []}, "identical_ciphertexts": True,
                   "all_distances_correct": True, "completed_repeats": 0}
            report["sizes"].append(row)
            calls = {"cpu_reference": cpu_call}
            prepared = None
            if plans:
                row["index_prepare_s"], prepared = timed(partial(plans["shared_keys"].prepare_index, tiles, count))
                row["resident_index_bytes"] = prepared.device_bytes
                calls.update({label: partial(plan.search, encrypted_query, tiles, count)
                              for label, plan in plans.items()})
                calls["prepared_index"] = partial(plans["shared_keys"].search_prepared, encrypted_query, prepared)
                for label in calls:
                    if label == "cpu_reference":
                        continue
                    elapsed, result = timed(calls[label])
                    if result != reference or owner.decode_hamming_client_packed(result, count) != expected[:count]:
                        raise AssertionError(f"Incorrect GPU warmup: {count}, {label}")
                    row.setdefault("GPU_warmups_s_excluded", {})[label] = elapsed
                    row["samples_s"][label] = []
            for repeat in range(args.repeats):
                order = list(calls) if repeat % 2 == 0 else list(reversed(calls))
                for label in order:
                    elapsed, result = timed(calls[label])
                    if result != reference:
                        raise AssertionError(f"Ciphertexts differ: {count}, {label}, {repeat}")
                    if owner.decode_hamming_client_packed(result, count) != expected[:count]:
                        raise AssertionError(f"Incorrect distances: {count}, {label}, {repeat}")
                    row["samples_s"][label].append(elapsed)
                    progress(f"{count}: {label}, repeat {repeat + 1}: {elapsed:.6f} s")
                row["completed_repeats"] = repeat + 1
                save()
            row["warm_medians_s"] = {label: statistics.median(samples)
                                     for label, samples in row["samples_s"].items()}
            row["sample_range_s"] = {label: [min(samples), max(samples)]
                                     for label, samples in row["samples_s"].items()}
            row["vectors_per_second"] = {label: count / median
                                          for label, median in row["warm_medians_s"].items()}
            if plans:
                row["paired_median_speedup_over_CPU"] = {
                    label: row["warm_medians_s"]["cpu_reference"] / median
                    for label, median in row["warm_medians_s"].items() if label != "cpu_reference"}
            del calls, prepared, reference
            save()
        report["state"] = "completed"
    except BaseException as error:
        report["state"] = "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        report["end_utc"] = datetime.now(UTC).isoformat()
        save()
    print(json.dumps({"output": str(output), "state": report["state"],
                      "output_sha256": sha(output), "repeated_CPU_samples_per_size": args.repeats}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
