#!/usr/bin/env python3
"""Build isolated standalone correctness targets after the timed queue finishes.

CPU targets use assertion-enabled GCC 13 ASan/UBSan executables. CUDA and
Valgrind checks require explicit tools; absent instrumentation stays visible.
No delivered extension is rebuilt. Instrumented elapsed times are diagnostic,
not latency measurements, parameter assurance or a constant-time proof.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sysconfig
import time

ROOT = Path(__file__).resolve().parents[1]
CPU = {
    "tests/unit/native/test_bfv_rns.cpp": "bfv-rns",
    "tests/unit/native/test_bfv_private.cpp": "bfv-private",
    "experiments/bfv_search_lab/_owner/test_private.cpp": "bgv-private",
    "experiments/bfv_search_lab/_native/test_digit_boundary.cpp": "bgv-digit-boundary",
}
CUDA = {
    "tests/unit/native/test_bfv_cuda.cu": "bfv-cuda",
    "experiments/bfv_search_lab/_native/sanitize_cuda.cu": "bgv-cuda",
    "experiments/bfv_search_lab/_native/sanitize_terminal.cu": "bgv-terminal",
    "experiments/bfv_search_lab/_native/sanitize_product.cu": "bgv-product",
    "experiments/bfv_search_lab/_native/ntt_schedule.cu": "ntt-schedule",
    "experiments/bfv_search_lab/_native/narrow_ntt.cu": "narrow-ntt",
}
TAINT = {"bfv-private": "CUHEPY_BFV_CTGRIND", "bgv-private": "CUHEPY_BGV_CTGRIND"}


def utc():
    return datetime.now(UTC).isoformat()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tool(path, candidate):
    requested = path.resolve() if path else None
    discovered = shutil.which(candidate)
    executable = bool(requested and requested.is_file() and os.access(requested, os.X_OK))
    return {"explicit_path": str(path) if path else None,
            "resolved_path": str(requested) if requested else None,
            "executable": executable,
            "executable_sha256": sha(requested) if executable else None,
            "discovered_path_not_automatically_used": discovered}


def stop_owned(process):
    """Terminate only the session created for this direct worker and its children."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


def invoke(command, folder, name, cwd, timeout, environment, expected=0):
    """Save bounded structured-argv execution, including unsuccessful attempts."""
    stdout, stderr = folder / (name + ".stdout.log"), folder / (name + ".stderr.log")
    row = {"command": [str(x) for x in command], "cwd": str(cwd),
           "timeout_s": timeout, "expected_returncode": expected, "start_utc": utc(),
           "environment_overrides": environment, "timing_classification": "instrumented_diagnostic"}
    start = time.monotonic()
    process = None
    with stdout.open("x") as out, stderr.open("x") as err:
        try:
            process = subprocess.Popen(row["command"], cwd=cwd, env=dict(os.environ, **environment),
                                       stdout=out, stderr=err, start_new_session=True)
            try:
                row["returncode"] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                stop_owned(process)
                row.update(returncode=124, timeout=True)
        except OSError as error:
            row.update(returncode=127, launch_error=str(error))
        except BaseException:
            if process is not None and process.poll() is None:
                stop_owned(process)
            raise
    row.update(end_utc=utc(), process_wall_s=time.monotonic() - start,
               stdout=str(stdout), stderr=str(stderr), stdout_sha256=sha(stdout), stderr_sha256=sha(stderr))
    row["passed"] = row["returncode"] == expected and not row.get("timeout", False)
    return row


def source_closure(path, source, includes):
    """Pin repository quoted includes; compiler/system headers remain external."""
    found, unresolved = {}, []
    pending = [path]
    while pending:
        current = pending.pop().resolve()
        if current in found:
            continue
        if not current.is_relative_to(source) or not current.is_file():
            raise ValueError("Target include escapes source copy: " + str(current))
        found[current] = sha(current)
        for name in re.findall(r'^\s*#include\s+"([^"]+)"', current.read_text(), re.MULTILINE):
            candidates = [current.parent / name, *(p / name for p in includes)]
            resolved = next((p.resolve() for p in candidates if p.is_file()), None)
            if resolved is None:
                unresolved.append({"including_source": str(current.relative_to(source)), "include": name})
            else:
                pending.append(resolved)
    return {"files": {str(p.relative_to(source)): value for p, value in sorted(found.items())},
            "unresolved_quoted_includes": unresolved,
            "system_header_and_library_versions_not_fully_pinned": True}


def extension_hashes(source):
    result = {}
    for parent in (source / "src", source / "experiments/bfv_search_lab"):
        for path in sorted(parent.rglob("*.so")):
            result[str(path.relative_to(source))] = sha(path)
    return result


def build_arguments(compiler, target, source, executable, includes, mode, host=None, arch=None):
    if mode == "cuda":
        command = [compiler, "-O2", "-lineinfo", "-std=c++17", "-UNDEBUG", "-ccbin", host,
                   "-gencode", "arch=compute_" + arch + ",code=sm_" + arch]
    else:
        command = [compiler, "-std=c++17", "-O3" if mode == "taint" else "-O1", "-g", "-UNDEBUG"]
        if mode == "asan_ubsan":
            command += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-sanitize-recover=all"]
        if target["source"].endswith("test_digit_boundary.cpp"):
            command.append("-fopenmp")
        if mode == "taint":
            command.append("-D" + TAINT[CPU[target["source"]]])
    command += ["-I" + str(p) for p in includes]
    command += [str(source / target["source"]), "-lgmpxx", "-lgmp", "-o", str(executable)]
    return command


def proposed_binding_actions(source, output, compiler):
    """Data only: dedicated C-API extensions, never automatic binding builds."""
    directory = output / "proposed-bindings"
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    python_include = sysconfig.get_paths()["include"]
    python = source / ".venv/bin/python"
    specs = {
        "_bfv_rns": "src/cuhepy/bfv/_cpu_ext/bindings.cpp",
        "_bfv_private": "src/cuhepy/bfv/_cpu_ext/private_bindings.cpp",
        "_bgv_checked": "experiments/bfv_search_lab/_verify/bindings.cpp",
        "_fingerprint": "experiments/bfv_search_lab/_fingerprint/bindings.cpp",
    }
    binaries = {name: directory / (name + suffix) for name in specs}
    builds = []
    for name, relative in specs.items():
        command = [str(compiler), "-std=c++17", "-O1", "-g", "-UNDEBUG", "-Wall", "-Wextra",
                   "-fPIC", "-shared", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                   "-fno-sanitize-recover=all", "-I" + python_include,
                   "-I" + str(source / "src/cuhepy/bfv/_cpu_ext")]
        if name == "_bfv_private":
            command += ["-fstack-protector-strong", "-D_FORTIFY_SOURCE=3"]
        command += [str(source / relative), "-lgmpxx", "-lgmp", "-o", str(binaries[name])]
        if name == "_bfv_private":
            command += ["-Wl,-z,relro,-z,now,-z,noexecstack"]
        builds.append({"name": name, "source": relative, "source_sha256": sha(source / relative),
                       "command": command, "new_library": str(binaries[name]), "timeout_s": 600,
                       "status": "proposed_not_built"})
    fingerprint_original = source.parent / "checkpoints/verification-frontier-2026-09-30/tools/cuhepy-fingerprint-sanitizer-20260930.py"
    environment = {"PYTHONPATH": str(source / "src") + ":" + str(source),
                   "PYCRYPTODOME_DISABLE_DEEPBIND": "1",
                   "LD_PRELOAD": "<verified compiler libasan.so absolute path>:<verified compiler libstdc++.so.6 absolute path>",
                   "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:strict_string_checks=1",
                   "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"}
    return {"status": "proposed_only_never_executed_by_this_runner", "directory": str(directory),
            "builds": builds, "bindings_use": "CPython C API; repository Makefiles require Python development headers, not pybind11.",
            "running_interpreter_extension_suffix": suffix, "running_interpreter_python_include": python_include,
            "required_venv_ABI_query": [str(python), "-c", "import json,sysconfig; print(json.dumps({'include':sysconfig.get_paths()['include'],'suffix':sysconfig.get_config_var('EXT_SUFFIX')}))"],
            "required_runtime_path_queries": [[str(compiler), "-print-file-name=libasan.so"],
                                              [str(compiler), "-print-file-name=libstdc++.so.6"]],
            "preflight": "Verify queried files exist and match the compiler and venv ABI before using commands. Create a fresh dedicated directory. Keep each build/test/log receipt and delivered .so hashes before/after. No sanitizer library installed over delivered extensions.",
            "environment": environment,
            "checks": [
                {"name": "BFV_binding_sanitizers", "command": [str(python), str(source / "tests/unit/native/run_binding_sanitizers.py"),
                                                               str(binaries["_bfv_rns"]), str(binaries["_bfv_private"])],
                 "timeout_s": 1800, "status": "proposed_not_run", "expected_returncode": 0},
                {"name": "BGV_checked_binding_sanitizers", "command": [str(python), str(source / "experiments/bfv_search_lab/_verify/run_sanitizers.py"),
                                                                      str(binaries["_bgv_checked"])],
                 "timeout_s": 1800, "status": "proposed_not_run", "expected_returncode": 0},
                {"name": "fingerprint_binding_sanitizers", "checkpoint_loader": str(fingerprint_original),
                 "checkpoint_loader_sha256": sha(fingerprint_original) if fingerprint_original.is_file() else None,
                 "fresh_loader": str(directory / "fingerprint-loader.py"),
                 "required_loader_adaptation": "Copy preserved checkpoint loader, replacing its hardcoded original repository and /tmp library paths with this source copy and dedicated _fingerprint library. Also set PYCRYPTODOME_DISABLE_DEEPBIND=1 before imports. Preserve exact adaptation diff and source hashes; do not edit checkpoint helper. Assert loaded module.__file__ equals the dedicated rebuilt library before pytest.",
                 "command_after_loader_adaptation": [str(python), str(directory / "fingerprint-loader.py")],
                 "timeout_s": 1800, "status": "proposed_not_run", "expected_returncode": 0}],
            "scope": "Binding proposals extend standalone sanitizer coverage into existing Python loaders/tests. Python/system libraries remain uninstrumented. Leak detection disabled only for proposed Python-hosted runs because interpreter shutdown allocations need separate attribution; standalone executables keep leak detection enabled. Normal pytest does not imply these proposed sanitizer checks ran."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True, help="Entirely new native receipt/build directory")
    parser.add_argument("--gxx", type=Path, default=Path("/usr/bin/g++-13"))
    parser.add_argument("--nvcc", type=Path)
    parser.add_argument("--compute-sanitizer", type=Path)
    parser.add_argument("--cuda-host-cxx", type=Path, help="Explicit compatible CUDA host compiler")
    parser.add_argument("--cuda-arch", default="86")
    parser.add_argument("--cuda-polynomials", type=int, default=16)
    parser.add_argument("--cuda-repeats", type=int, default=1)
    parser.add_argument("--valgrind", type=Path)
    parser.add_argument("--valgrind-include", type=Path, default=Path("/usr/include"))
    parser.add_argument("--compile-timeout-s", type=int, default=600)
    parser.add_argument("--run-timeout-s", type=int, default=600)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if output.exists() or output.is_relative_to(source):
        parser.error("Use an entirely new output directory outside source; never replace retained artifacts")
    if (not re.fullmatch(r"[0-9]{2,3}", args.cuda_arch)
            or not 1 <= args.cuda_polynomials <= 128 or not 1 <= args.cuda_repeats <= 4
            or not 1 <= args.compile_timeout_s <= 1800 or not 1 <= args.run_timeout_s <= 1800):
        parser.error("Invalid bounded native validation options")
    inventory = json.loads(args.inventory.read_text())
    targets = inventory["targets"]
    known = set(CPU) | set(CUDA)
    if len(targets) != len(known) or {t["source"] for t in targets} != known:
        parser.error("Inventory must contain exactly the four declared CPU and six CUDA targets")
    output.mkdir(parents=True)
    includes = [source / "src/cuhepy/bfv/_cpu_ext", source / "experiments/bfv_search_lab/_owner",
                source / "experiments/bfv_search_lab/_native"]
    tools = {"gxx": tool(args.gxx, "g++-13"), "nvcc": tool(args.nvcc, "nvcc"),
             "compute_sanitizer": tool(args.compute_sanitizer, "compute-sanitizer"),
             "cuda_host_cxx": tool(args.cuda_host_cxx, "g++-13"), "valgrind": tool(args.valgrind, "valgrind")}
    receipt = {"schema": 1, "start_utc": utc(), "kind": "isolated_standalone_native_correctness_instrumentation",
               "source": str(source), "inventory": str(args.inventory.resolve()), "inventory_sha256": sha(args.inventory),
               "runner_sha256": sha(Path(__file__)), "tools": tools, "compiler_checks": [], "targets": [],
               "proposed_binding_instrumentation": proposed_binding_actions(source, output, args.gxx),
               "delivered_extension_hashes_before": extension_hashes(source),
               "scope": "Standalone executables only, serial assertions/sanitizers. No extension rebuild, throughput/latency result, full security assurance, parameter approval or constant-time proof. System libraries are not instrumented by compiling these targets."}
    path = output / "receipt.json"

    def save():
        path.write_text(json.dumps(receipt, indent=2) + "\n")

    save()
    try:
        compiler_ready = tools["gxx"]["executable"]
        if compiler_ready:
            version = invoke([args.gxx, "--version"], output, "gxx-version", source, 10, {})
            numeric = invoke([args.gxx, "-dumpfullversion", "-dumpversion"], output, "gxx-numeric-version", source, 10, {})
            receipt["compiler_checks"] += [version, numeric]
            tools["gxx"]["version_text"] = Path(version["stdout"]).read_text()
            tools["gxx"]["numeric_version"] = Path(numeric["stdout"]).read_text().strip()
            compiler_ready = version["passed"] and numeric["passed"] and tools["gxx"]["numeric_version"].split(".")[0] == "13"
        tools["gxx"]["required_GCC_13_ready"] = compiler_ready
        cuda_requested = bool(args.nvcc or args.compute_sanitizer or args.cuda_host_cxx)
        cuda_ready = all(tools[k]["executable"] for k in ("nvcc", "compute_sanitizer", "cuda_host_cxx"))
        for key, flag in (("nvcc", "--version"), ("compute_sanitizer", "--version"), ("cuda_host_cxx", "--version"), ("valgrind", "--version")):
            if tools[key]["executable"]:
                row = invoke([tools[key]["resolved_path"], flag], output, key + "-version", source, 10, {})
                receipt["compiler_checks"].append(row)
                tools[key]["version_text"] = Path(row["stdout"]).read_text()
                if key in ("nvcc", "compute_sanitizer", "cuda_host_cxx") and not row["passed"]:
                    cuda_ready = False
                if key == "valgrind":
                    tools[key]["version_check_passed"] = row["passed"]
        for target in targets:
            relative = target["source"]
            cpu = relative in CPU
            name = (CPU if cpu else CUDA)[relative]
            folder = output / name
            folder.mkdir()
            entry = {"name": name, "source": relative, "inventory_source_sha256": target["source_sha256"],
                     "source_sha256": sha(source / relative), "device": "cpu" if cpu else "cuda", "scope": target["scope"],
                     "assertions_enabled": True, "steps": [], "status": "not_run", "passed": None}
            receipt["targets"].append(entry)
            if entry["source_sha256"] != entry["inventory_source_sha256"]:
                entry.update(status="source_hash_mismatch", passed=False)
                save()
                continue
            entry["source_closure"] = source_closure(source / relative, source, includes)
            if entry["source_closure"]["unresolved_quoted_includes"]:
                entry.update(status="missing_repository_include", passed=False)
                save()
                continue
            ready = compiler_ready if cpu else cuda_ready
            if not ready:
                entry.update(status="unavailable_required_compiler" if cpu else "unavailable_explicit_CUDA_tools" if cuda_requested else "not_requested_explicit_CUDA_tools_required",
                             passed=False if cpu or cuda_requested else None)
                save()
                continue
            executable = folder / "standalone"
            mode = "asan_ubsan" if cpu else "cuda"
            command = build_arguments(args.gxx if cpu else args.nvcc, target, source, executable, includes, mode,
                                      args.cuda_host_cxx, args.cuda_arch)
            build = invoke(command, folder, "compile", source, args.compile_timeout_s, {})
            entry["steps"].append(build)
            if not build["passed"]:
                entry.update(status="compile_failed", passed=False)
                save()
                continue
            entry["executable_sha256"] = sha(executable)
            environment = {"ASAN_OPTIONS": "abort_on_error=1:detect_leaks=1:strict_string_checks=1",
                           "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1", "OMP_WAIT_POLICY": "PASSIVE"} if cpu else {}
            invocations = [[]]
            if name in ("ntt-schedule", "narrow-ntt"):
                invocations = [[str(n), str(args.cuda_polynomials), str(args.cuda_repeats)] for n in (16, 2048, 16384)]
            for number, arguments in enumerate(invocations):
                command = [executable, *arguments]
                if not cpu:
                    command = [args.compute_sanitizer, "--tool", "memcheck", "--error-exitcode", "99",
                               "--leak-check", "full", "--target-processes", "all", *command]
                entry["steps"].append(invoke(command, folder, "run-" + str(number), source, args.run_timeout_s, environment))
            entry.update(status="completed", passed=all(s["passed"] for s in entry["steps"]))
            save()
        receipt["taint_checks"] = []
        for relative, name in CPU.items():
            if name not in TAINT:
                continue
            row = {"name": name, "macro": TAINT[name], "requested": bool(args.valgrind), "steps": [],
                   "passed": None,
                   "claim_limit": "Finite dynamic taint checks and deliberate negative control, not a constant-time proof."}
            receipt["taint_checks"].append(row)
            header = args.valgrind_include / "valgrind/memcheck.h"
            if not args.valgrind:
                row.update(status="not_requested_explicit_Valgrind_required", passed=None)
            elif not compiler_ready or not tools["valgrind"]["executable"] or not tools["valgrind"].get("version_check_passed") or not header.is_file():
                row.update(status="unavailable_requested_Valgrind_compiler_or_headers", passed=False,
                           header_path=str(header), header_present=header.is_file())
            else:
                folder = output / (name + "-taint")
                folder.mkdir()
                executable = folder / "standalone"
                target = next(t for t in targets if t["source"] == relative)
                if sha(source / relative) != target["source_sha256"]:
                    row.update(status="source_hash_mismatch", passed=False)
                    save()
                    continue
                row["valgrind_header_sha256"] = sha(header)
                command = build_arguments(args.gxx, target, source, executable, [*includes, args.valgrind_include], "taint")
                build = invoke(command, folder, "compile", source, args.compile_timeout_s, {})
                row["steps"].append(build)
                if build["passed"]:
                    row["executable_sha256"] = sha(executable)
                    base = [args.valgrind, "--tool=memcheck", "--error-exitcode=99", "--undef-value-errors=yes",
                            "--track-origins=yes", "--leak-check=full", "--show-leak-kinds=all", "--errors-for-leak-kinds=all", executable]
                    positive = invoke(base, folder, "positive", source, args.run_timeout_s, {})
                    negative = invoke([*base, "negative"], folder, "deliberate-negative", source, args.run_timeout_s, {}, expected=99)
                    negative["secret_branch_marker_observed"] = "Deliberate secret branch" in Path(negative["stdout"]).read_text()
                    negative["undefined_conditional_report_observed"] = "Conditional jump or move depends on uninitialised value" in Path(negative["stderr"]).read_text()
                    negative["passed"] = negative["passed"] and negative["secret_branch_marker_observed"] and negative["undefined_conditional_report_observed"]
                    row["steps"] += [positive, negative]
                row.update(status="completed" if build["passed"] else "compile_failed", passed=all(s["passed"] for s in row["steps"]))
            save()
    except BaseException as error:
        receipt["execution_exception"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        receipt["delivered_extension_hashes_after"] = extension_hashes(source)
        receipt["delivered_extensions_unchanged"] = receipt["delivered_extension_hashes_before"] == receipt["delivered_extension_hashes_after"]
        receipt["end_utc"] = utc()
        receipt["CPU_ASAN_UBSAN_targets_passed"] = sum(t["passed"] is True for t in receipt["targets"] if t["device"] == "cpu")
        receipt["CUDA_instrumented_targets_passed"] = sum(t["passed"] is True for t in receipt["targets"] if t["device"] == "cuda")
        receipt["all_ten_native_targets_instrumented_and_passed"] = len(receipt["targets"]) == 10 and all(t["passed"] is True for t in receipt["targets"])
        receipt["requested_work_passed"] = (not receipt.get("execution_exception") and len(receipt["targets"]) == 10 and receipt["delivered_extensions_unchanged"]
                                             and all(t["passed"] is not False for t in receipt["targets"])
                                             and all(t["passed"] is not False for t in receipt.get("taint_checks", [])))
        save()
    print(json.dumps({"receipt": str(path), "receipt_sha256": sha(path),
                      "CPU_ASAN_UBSAN_targets_passed": receipt["CPU_ASAN_UBSAN_targets_passed"],
                      "CUDA_instrumented_targets_passed": receipt["CUDA_instrumented_targets_passed"],
                      "requested_work_passed": receipt["requested_work_passed"]}))
    return 0 if receipt["requested_work_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
