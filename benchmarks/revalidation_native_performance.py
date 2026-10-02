#!/usr/bin/env python3
"""Plan, then explicitly build/run the deferred digit and NTT timing panels.

Default invocation prints a plan and runs no external command. --execute uses
an entirely fresh output directory, records actual compiler/source/binary
identities, and runs six digit workloads plus retained NTT/narrow configurations.
Run standalone correctness/sanitizers separately before this uninstrumented
timing phase. Existing extensions and original results are never rebuilt.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from revalidation_native_lab import invoke, source_closure

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "digit-boundary": "experiments/bfv_search_lab/_native/digit_boundary.cu",
    "ntt-schedule": "experiments/bfv_search_lab/_native/ntt_schedule.cu",
    "narrow-ntt": "experiments/bfv_search_lab/_native/narrow_ntt.cu",
}


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def utc():
    return datetime.now(UTC).isoformat()


def make_plan(args):
    source, output = args.source.resolve(), args.output.resolve()
    binaries = {name: output / "bin" / ("cuhepy-" + name) for name in SOURCES}
    builds = []
    for name, relative in SOURCES.items():
        command = [str(args.nvcc.resolve()), "-O3", "-std=c++17", "-UNDEBUG",
                   "-ccbin", str(args.cuda_host_cxx.resolve())]
        if name == "digit-boundary":
            command += ["-Xcompiler=-fopenmp"]
        command += ["-gencode", "arch=compute_" + args.cuda_arch + ",code=sm_" + args.cuda_arch,
                    "-I" + str(source / "src/cuhepy/bfv/_cpu_ext"), str(source / relative),
                    "-lgmpxx", "-lgmp", "-o", str(binaries[name])]
        builds.append({"name": name, "source": relative, "command": command,
                       "source_sha256": sha(source / relative), "binary": str(binaries[name]),
                       "assertions_enabled": True, "timeout_s": args.compile_timeout_s})
    jobs = []
    # These are the six retained final digit schedules. Old v1 rows are aliases
    # of current scope only; this does not claim reproduction of their old code.
    for count in (10923, 16384, 2731, 32768, 4096, 8192):
        name = "digit-boundary-" + str(count)
        original = ["benchmarks/results/bgv_digit_boundary_" + str(count) + ".json"]
        if count in (8192, 32768):
            original.append("benchmarks/results/bgv_digit_boundary_v1_" + str(count) + ".json")
        destination = output / "raw" / (name + ".json")
        jobs.append({"name": name, "family": "digit-boundary", "classification": "timing",
                     "command": [str(args.python.resolve()), str(source / "benchmarks/bgv_digit_boundary.py"),
                                 "--num-vectors", str(count), "--ring-degree", "16384", "--padded", "512",
                                 "--repeats", "10", "--binary", str(binaries["digit-boundary"]),
                                 "--json-out", str(destination)], "raw_output": str(destination),
                     "original_raws": original, "timeout_s": args.run_timeout_s,
                     "external_build_receipt_required": True,
                     "runner_note": "Runner still hardcodes historical documented_build_flags=g++-12. The actual build receipt here overrides that documentation; source was not edited."})
    old_ntt = json.loads((source / "benchmarks/results/bgv_ntt_schedule.json").read_text())
    for row in old_ntt["workloads"]:
        rounds = len(next(iter(row["roundtrip_gpu_ms"].values())))
        name = f'ntt-n{row["n"]}-p{row["polynomials"]}'
        jobs.append({"name": name, "family": "ntt-schedule",
                     "classification": "correctness_only" if row["correctness_only"] else "timing",
                     "command": [str(binaries["ntt-schedule"]), str(row["n"]), str(row["polynomials"]), str(rounds)],
                     "raw_output": str(output / "raw" / (name + ".json")),
                     "original_raws": ["benchmarks/results/bgv_ntt_schedule.json"], "timeout_s": args.run_timeout_s})
    for reverse in (False, True):
        name = "narrow-ntt-" + ("reverse" if reverse else "forward")
        jobs.append({"name": name, "family": "narrow-ntt", "classification": "timing",
                     "command": [str(binaries["narrow-ntt"]), "16384", "1024", "20"] + (["reverse"] if reverse else []),
                     "raw_output": str(output / "raw" / (name + ".json")),
                     "original_raws": ["benchmarks/results/bgv_narrow_ntt.json"], "timeout_s": args.run_timeout_s})
    for degree in (8, 32768):
        name = "narrow-ntt-n" + str(degree) + "-p3"
        jobs.append({"name": name, "family": "narrow-ntt", "classification": "correctness_only",
                     "command": [str(binaries["narrow-ntt"]), str(degree), "3", "1"],
                     "raw_output": str(output / "raw" / (name + ".json")),
                     "original_raws": ["benchmarks/results/bgv_narrow_ntt.json"], "timeout_s": args.run_timeout_s})
    return {"schema": "cuhepy.deferred_native_performance_plan.v1", "source": str(source),
            "output": str(output), "runner_sha256": sha(Path(__file__)),
            "command": sys.argv, "builds": builds, "jobs": jobs,
            "environment_overrides": {"OMP_NUM_THREADS": "8", "OPENBLAS_NUM_THREADS": "1", "OMP_WAIT_POLICY": "PASSIVE"},
            "execution_mode": "serial", "execution_requested": args.execute,
            "original_files_remain_unchanged": True,
            "scope": "Current-source, new CUDA/GCC common-toolchain confirmation. Compiler, driver and source identity can differ from old artifacts. Resident NTT timings exclude CRT/key-switch/transfer/full search; narrow variants use different Q bases. Digit runner is a synthetic public conversion boundary, not a verifier or full search.",
            "precondition": "Complete standalone correctness and instrumentation first, then let machine settle. No profiling/sanitizer flags enter these timing builds."}


def exact_flags(result, fields):
    # The result schemas differ, so validate each declared correctness field
    # explicitly rather than accepting an arbitrary success-looking JSON.
    for field in fields:
        if result.get(field) is not True:
            raise AssertionError("Missing/false correctness field: " + field)


def validate_result(job, result):
    if job["family"] == "digit-boundary":
        if result.get("kind") != "bgv_digit_boundary":
            raise AssertionError("Unexpected digit runner result")
        exact_flags(result["measured"], ("complete_cpu_gpu_digits_equal", "gmp_oracle_and_rejections_passed"))
        return
    if job["family"] == "ntt-schedule":
        exact_flags(result, ("forward_and_inverse_exact",))
    else:
        variants = result.get("variants", [])
        if len(variants) != 2:
            raise AssertionError("Expected wide and narrow variants")
        for variant in variants:
            exact_flags(variant, ("forward_and_inverse_exact",))


def execute(args, plan):
    source, output = Path(plan["source"]), Path(plan["output"])
    if output.exists() or output.is_relative_to(source):
        raise ValueError("Execution requires a new output directory outside source")
    for tool in (args.nvcc, args.cuda_host_cxx, args.python):
        if not tool.is_file() or not os.access(tool, os.X_OK):
            raise ValueError("Explicit executable tool is unavailable: " + str(tool))
    output.mkdir(parents=True)
    for name in ("bin", "logs", "raw"):
        (output / name).mkdir()
    receipt = {**plan, "schema": "cuhepy.deferred_native_performance_receipt.v1",
               "start_utc": utc(), "state": "started", "build_steps": [], "run_steps": [],
               "tool_checks": [], "tool_binary_sha256": {str(p.resolve()): sha(p.resolve())
                                                         for p in (args.nvcc, args.cuda_host_cxx, args.python)}}
    path = output / "receipt.json"

    def save():
        path.write_text(json.dumps(receipt, indent=2) + "\n")

    save()
    try:
        for name, command in (("nvcc-version", [args.nvcc, "--version"]),
                              ("host-cxx-version", [args.cuda_host_cxx, "--version"]),
                              ("host-cxx-numeric-version", [args.cuda_host_cxx, "-dumpfullversion", "-dumpversion"]),
                              ("device-driver", ["nvidia-smi", "--query-gpu=name,uuid,driver_version,memory.total", "--format=csv,noheader"])):
            row = invoke(command, output / "logs", name, source, 15, {})
            row["timing_classification"] = "setup_diagnostic"
            receipt["tool_checks"].append(row)
            save()
            if not row["passed"]:
                raise RuntimeError("Tool preflight failed: " + name)
        includes = [source / "src/cuhepy/bfv/_cpu_ext", source / "experiments/bfv_search_lab/_native"]
        for build in plan["builds"]:
            entry = dict(build)
            entry["source_closure"] = source_closure(source / build["source"], source, includes)
            if sha(source / build["source"]) != build["source_sha256"] or entry["source_closure"]["unresolved_quoted_includes"]:
                raise ValueError("Native source changed or include closure incomplete")
            row = invoke(build["command"], output / "logs", "compile-" + build["name"], source, build["timeout_s"], {})
            row["timing_classification"] = "build_setup"
            entry["step"] = row
            receipt["build_steps"].append(entry)
            if row["passed"]:
                entry["binary_sha256"] = sha(Path(build["binary"]))
            save()
            if not row["passed"]:
                raise RuntimeError("Native build failed: " + build["name"])
        receipt["actual_builds_complete"] = True
        save()
        for job in plan["jobs"]:
            print("Running " + job["name"], file=sys.stderr, flush=True)
            row = invoke(job["command"], output / "logs", job["name"], source, job["timeout_s"], plan["environment_overrides"])
            row.update(name=job["name"], family=job["family"], timing_classification=job["classification"],
                       raw_output=job["raw_output"], original_raws=job["original_raws"])
            receipt["run_steps"].append(row)
            save()
            if not row["passed"]:
                raise RuntimeError("Native workload failed: " + job["name"])
            raw = Path(job["raw_output"])
            if job["family"] != "digit-boundary":
                with raw.open("x") as stream:
                    stream.write(Path(row["stdout"]).read_text())
            result = json.loads(raw.read_text())
            validate_result(job, result)
            row.update(raw_output_sha256=sha(raw), correctness_fields_validated=True)
            save()
        receipt["state"] = "completed"
    except BaseException as error:
        receipt.update(state="failed", error={"type": type(error).__name__, "message": str(error)})
        raise
    finally:
        receipt["end_utc"] = utc()
        save()
    print(json.dumps({"receipt": str(path), "receipt_sha256": sha(path),
                      "state": receipt["state"], "completed_jobs": len(receipt["run_steps"])}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--nvcc", type=Path, required=True)
    parser.add_argument("--cuda-host-cxx", type=Path, default=Path("/usr/bin/g++"))
    parser.add_argument("--python", type=Path)
    parser.add_argument("--cuda-arch", default="86")
    parser.add_argument("--compile-timeout-s", type=int, default=900)
    parser.add_argument("--run-timeout-s", type=int, default=1800)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--plan", action="store_true", help="Explicit default: print proposal without external commands")
    args = parser.parse_args()
    if args.execute and args.plan:
        parser.error("Choose --execute or --plan")
    if (not re.fullmatch(r"[0-9]{2,3}", args.cuda_arch)
            or not 60 <= args.compile_timeout_s <= 3600 or not 60 <= args.run_timeout_s <= 7200):
        parser.error("Invalid bounded architecture/timeouts")
    args.python = args.python or args.source / ".venv/bin/python"
    plan = make_plan(args)
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return 0
    execute(args, plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
