#!/usr/bin/env python3
"""E123 one fixed continuation; resource diagnostics are not performance."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
from time import monotonic

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from experiments.bfv_search_lab import joint_root as old  # noqa: E402
from experiments.bfv_search_lab import joint_root_census as lab  # noqa: E402

WORK = REPO.parent / "research-data/joint-root-census-20261003"
PREVIOUS = REPO.parent / "research-data/joint-root-20261003"
RAW = REPO / "benchmarks/results/publication-joint-root-census-20261003.json"
OLD_RAW = REPO / "benchmarks/results/publication-joint-root-20261003.json"
PREREG = "docs/research/joint-root-census-preregistration-20261003.md"
PREREG_SHA = "0dff8993a9479624b4a563315a33b51f060b445be817e92b9194dffb23f51d55"
BASE = "be7067836cb57fae798ed44650ed690b29f804b9"
BRANCH = "experiment/joint-root-census-20261003"
OLD_SOURCE = "experiments/bfv_search_lab/joint_root.py"
OLD_SOURCE_SHA = "e2717193a441bb9cd63467036a8946c5b3fb0cd3deeaa3fb11588e6b2013160d"
OLD_PINS = {
    OLD_RAW: "9db6e36cbff3ddef95abd8ac5fca8efecd39d2e180f22713f123bf05fdd1cf3a",
    PREVIOUS / "main/complete-orbit-inventory.json": "f5a937d9b970b98fd22e05dbba465392e6c8f85e6df4aa8b971ed0948dd7a862",
    PREVIOUS / "main/mass-prefix.jsonl": "e68933d45e22112e9b2c017645a93ee6d1c045f005e0e77691009285ea813bb1",
    PREVIOUS / "source-argv-freeze.json": "f1b8f52227ac58b82fcbfdb2c81180077f4626a43d38775f5e9228bbce92cbc4",
    PREVIOUS / "execution-receipt.json": "b7f953b938ab3d80b2b69c671073fadd1c0944e7b65defd3a13a9ab8240446dc",
    REPO / OLD_SOURCE: OLD_SOURCE_SHA,
}
OWNED = ("experiments/bfv_search_lab/joint_root_census.py",
         "experiments/bfv_search_lab/test_joint_root_census.py", "benchmarks/joint_root_census_lab.py")


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def encode(value):
    if is_dataclass(value):
        return encode(asdict(value))
    if type(value) is dict:
        return {str(key): encode(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        return [encode(item) for item in value]
    return value


def write_json(path, value):
    path.write_text(json.dumps(encode(value), indent=2) + "\n")


def read_json(path):
    return lab.strict_json(path.read_text())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value):
    if type(value) is not int:
        raise ValueError("Expected an exact metadata integer")
    return value


def authenticate_inputs(freeze):
    """Validate recorded root/partition/counts; never select or recount them."""
    for name, expected in OLD_PINS.items():
        require(sha(name) == expected == freeze["source_sha256"][str(name)], "Frozen E122 input pin")
    previous_freeze = read_json(PREVIOUS / "source-argv-freeze.json")
    for name, expected in previous_freeze["source_sha256"].items():
        require(sha(Path(name)) == expected, "E122 original source closure")
    supervisor = read_json(PREVIOUS / "supervisor-receipt.json")
    require(integer(supervisor["scientific_child_attempts"]) == 1
            and integer(supervisor["child_exit_code"]) == 0
            and supervisor["timed_out"] is False and supervisor["main_retry_permitted"] is False,
            "E122 successful one-child supervisor")
    execution = read_json(PREVIOUS / "execution-receipt.json")
    require(integer(execution["main_execution_count"]) == 1
            and integer(execution["main_exit_code"]) == 0
            and integer(execution["main_retries"]) == 0
            and execution["all_pins_unchanged"] is True
            and integer(execution["final_distinct_tests"]) == 58, "E122 execution receipt")
    historical_tests = read_json(PREVIOUS / "final-tests-receipt.json")
    require(integer(historical_tests["distinct_tests"]) == 58
            and integer(historical_tests["test_exit"]) == 0
            and historical_tests["source_sha256"][str(REPO / OLD_SOURCE)] == OLD_SOURCE_SHA,
            "Historical tests refer to the unchanged counter")
    raw = read_json(OLD_RAW)
    require(raw["packet"] == "Q48/E122" and raw["status"] == "counterexample_found"
            and raw["source_sha256"][str(REPO / OLD_SOURCE)] == OLD_SOURCE_SHA,
            "Expected the successful frozen E122 prefix")
    ctx = lab.parse_context(raw["context"])
    require((ctx.n, ctx.q, ctx.root) == (16, 97, 19), "Frozen main context identity")
    selected = read_json(PREVIOUS / "main/selected-public-root.json")
    require(set(selected) == {"context", "selector_candidates", "powers"}
            and lab.parse_context(selected["context"]) == ctx
            and integer(selected["selector_candidates"]) == ctx.root - 1,
            "Recorded root identity")
    require(type(selected["powers"]) is list
            and all(type(value) is int for value in selected["powers"])
            and selected["powers"] == [pow(ctx.root, j, ctx.q) for j in range(2 * ctx.n)],
            "Recorded powers of the original root")
    inventory = lab.parse_inventory(read_json(PREVIOUS / "main/complete-orbit-inventory.json"))
    require(inventory.context == ctx and inventory.root_count == 4
            and len(inventory.assignments) == 1820 and len(inventory.orbits) == 120,
            "Frozen complete orbit inventory")
    lab.validate_zero_accounting(raw["zero_secret_included_per_count"], raw["zero_secret_added_again"])
    require(integer(raw["total_representatives"]) == 120
            and integer(raw["mass_representatives_visited"]) == 40
            and integer(raw["unvisited_representatives"]) == 80
            and integer(raw["raw_law_denominator"]) == 3 ** ctx.n,
            "Frozen prefix coverage and raw law")
    lines = tuple((PREVIOUS / "main/mass-prefix.jsonl").read_text().splitlines(keepends=True))
    reused = lab.reuse_prefix(inventory, raw["counts"], lines)
    require(len(reused) == 40 and reused[-1].count.total_count == 33
            and reused[-1].count.roots == (1, 3, 13, 31)
            and all(item.count.total_count == 1 for item in reused[:-1]),
            "Successful original first-counterexample order")
    require(raw["complete_orbit_inventory_sha256"] == sha(PREVIOUS / "main/complete-orbit-inventory.json")
            and raw["mass_prefix_sha256"] == sha(PREVIOUS / "main/mass-prefix.jsonl"),
            "Original raw references original exact bytes")
    return ctx, inventory, reused, historical_tests


def independent_horner(coefficients, point, q):
    value = 0
    for coefficient in coefficients[::-1]:
        value = (point * value + coefficient) % q
    return value


def main():
    start = monotonic()
    if not __debug__ or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE") != "0":
        raise ValueError("Registered main requires enabled assertions and PYTHONOPTIMIZE=0")
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (180, 180))

    def timeout(_signum, _frame):
        raise TimeoutError("Registered 180-second wall ceiling")

    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(180)
    phase, active_index, result = "source_closure", None, None
    output = WORK / "main"
    try:
        contract = read_json(WORK / "root-contract-freeze.json")
        require(sha(REPO / PREREG) == PREREG_SHA == contract["contract_sha256"], "Frozen root contract")
        require(contract["base_commit"] == BASE and contract["branch"] == BRANCH, "Root checkpoint contract")
        require(subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=REPO,
                                         text=True).strip() == BASE, "Census evidence parent")
        require(subprocess.check_output(["/usr/bin/git", "branch", "--show-current"], cwd=REPO,
                                         text=True).strip() == BRANCH, "Isolated census branch")
        require(subprocess.check_output(["/usr/bin/git", "rev-parse",
                                          "checkpoint/joint-root-discriminator-2026-10-03^{commit}"],
                                         cwd=REPO, text=True).strip() == BASE,
                "Authenticated original checkpoint tag")
        freeze = read_json(WORK / "source-argv-freeze.json")
        require(freeze["argv"] == [sys.executable, *sys.argv]
                and freeze["environment"].get("PYTHONOPTIMIZE") == "0", "Frozen argv/environment")
        for name, expected in freeze["source_sha256"].items():
            require(sha(Path(name)) == expected, "Frozen source/input closure")
        require(not output.exists() and not RAW.exists(), "Exactly one new output tree")
        output.mkdir()
        for name in (*OWNED, PREREG):
            target = output / "before-main-sources" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / name, target)
        phase = "authenticated_original_input_validation"
        ctx, inventory, reused, historical_tests = authenticate_inputs(freeze)
        bridge = lab.NormBridge(ctx, 4).validate()
        #The known nonzero determinant bound, separate from any mass oracle.
        require(ctx.n ** (ctx.n // 2) < ctx.q ** 5, "Independent public norm/prime-power inequality")
        write_json(output / "authenticated-inputs.json", {
            "context": ctx, "root_count": inventory.root_count,
            "representatives": len(inventory.orbits), "reused": len(reused),
            "fresh_worklist": [orbit.representative for orbit in inventory.orbits[len(reused):]],
            "new_root_selections": 0, "new_orbit_inventory_constructions": 0,
            "recomputed_reused_masses": 0, "historical_test_count_not_rerun": historical_tests["distinct_tests"],
            "norm_bridge": {"norm_bound": ctx.n ** (ctx.n // 2), "prime_power": ctx.q ** 5}})
        ledger = output / "complete-or-partial-ledger.jsonl"

        def append(item):
            with ledger.open("a") as file:
                file.write(json.dumps(encode(item), sort_keys=True) + "\n")
                file.flush()
                os.fsync(file.fileno())

        for item in reused:
            append(item)
        phase = "remaining_ascending_exact_masses"

        def evaluate(roots):
            nonlocal active_index
            active_index = next(index for index, orbit in enumerate(inventory.orbits, 1)
                                if orbit.representative == roots)
            count = old.count_roots(ctx, roots)
            lab.validate_count(ctx, 4, count)
            if count.witness is not None:
                require(all(independent_horner(count.witness, pow(ctx.root, exponent, ctx.q), ctx.q) == 0
                            for exponent in roots), "Independent fresh literal Horner witness")
                for target, representative, g in inventory.assignments:
                    if representative == roots:
                        transported = old.signed_action(count.witness, pow(g, -1, 2 * ctx.n))
                        require(all(independent_horner(transported, pow(ctx.root, exponent, ctx.q), ctx.q) == 0
                                    for exponent in target), "Independent fresh inverse orbit transport")
            return count

        result = lab.continue_census(inventory, reused, evaluate, on_complete=append)
        durable_rows = len(ledger.read_text().splitlines())
        write_json(output / "completed-coverage.json", {
            "status": result.status, "last_completed_index": len(result.entries),
            "reused_representatives": len(reused), "fresh_completed": len(result.entries) - len(reused),
            "remaining_worklist": [orbit.representative for orbit in inventory.orbits[len(result.entries):]],
            "active_index": active_index, "interrupted_mass_work_unknown": result.interrupted_mass_work_unknown,
            "durable_ledger_rows": durable_rows, "finalized_result_rows": len(result.entries),
            "durable_append_interruption_alignment_unknown": durable_rows != len(result.entries)})
        phase = "complete_or_partial_output_assembly"
        require(result.status != "completed" or durable_rows == len(result.entries),
                "Complete ledger and finalized result must agree")
        fresh_count = len(inventory.orbits) - len(reused)
        work = lab.work_counters(result)
        fresh = work["recorded"]["fresh_E123"]
        require(fresh["half_visits"] <= fresh_count * 2 * 3 ** 8
                and fresh["extraction_visits"] <= fresh_count * 3 ** 8
                and fresh["left_bucket_join_visits"] <= fresh_count * 3 ** 8
                and fresh["vector_updates"] <= fresh_count * 4 * 3 ** 8
                and fresh["extraction_vector_updates"] <= fresh_count * 2 * 3 ** 8,
                "Registered aggregate fresh work caps")
        summary = lab.complete_summary(inventory, result, norm_bridge=bridge) if result.status == "completed" else None
        for name, expected in freeze["source_sha256"].items():
            require(sha(Path(name)) == expected, "Post-main source/input closure")
        record = {"packet": "Q50/E123", "created_utc": datetime.now(UTC).isoformat(),
                  "evidence_parent": BASE, "status": result.status, "context": ctx,
                  "root_source": "authenticated recorded E122 root; no selector rerun",
                  "inventory_source": "authenticated recorded E122 assignments; no new partition",
                  "root_subsets": len(inventory.assignments), "total_representatives": len(inventory.orbits),
                  "reused_E122_representatives": len(reused), "fresh_E123_completed": len(result.entries) - len(reused),
                  "remaining_representatives": len(inventory.orbits) - len(result.entries),
                  "ledger_path": str(ledger), "ledger_sha256": sha(ledger),
                  "work_counters": work, "complete_summary": summary,
                  "registered_fresh_work_caps": {"half_visits": fresh_count * 2 * 3 ** 8,
                                                  "extraction_visits": fresh_count * 3 ** 8,
                                                  "left_bucket_join_visits": fresh_count * 3 ** 8},
                  "reused_historical_tests_not_executed": 58,
                  "source_argv_freeze_sha256": sha(WORK / "source-argv-freeze.json"),
                  "source_sha256": freeze["source_sha256"], "ordinary_control_ratio": 1,
                  "new_root_selections": 0, "new_orbit_inventory_constructions": 0,
                  "recomputed_E122_masses": 0, "full_secret_to_rootset_enumerations": 0,
                  "large_prime_or_HE_operations": 0, "timing_claims": False,
                  "scope": "Fixed tiny raw-law assurance census using known methods; no source-prime extrapolation, new algorithm, security, parameter or original-main claim"}
        write_json(RAW, record)
        usage = resource.getrusage(resource.RUSAGE_SELF)
        write_json(output / "resource-diagnostic.json", {
            "elapsed_wall_seconds": monotonic() - start, "CPU_user_seconds": usage.ru_utime,
            "CPU_system_seconds": usage.ru_stime, "max_RSS_KiB_Linux": usage.ru_maxrss,
            "kind": "resource guard diagnostic, not a performance benchmark",
            "wall_CPU_cap_seconds": 180, "address_space_cap_bytes": 256 * 1024 * 1024,
            "scientific_main_attempts": 1, "retry_permitted": False})
        signal.alarm(0)
        print(json.dumps({"status": result.status, "reused": len(reused),
                          "fresh_completed": len(result.entries) - len(reused), "raw_sha256": sha(RAW)}))
    except BaseException as error:
        if type(error) in (KeyboardInterrupt, SystemExit):
            raise
        write_json(WORK / "main-failure-or-stop.json", {
            "phase": phase, "active_index": active_index, "error_type": type(error).__name__,
            "message": str(error), "status": ("resource_bounded_inconclusive"
                                               if isinstance(error, (TimeoutError, MemoryError)) else "failed_validation"),
            "last_completed_index": len(result.entries) if result is not None else None,
            "partial_ledger_path": str(output / "complete-or-partial-ledger.jsonl"),
            "interrupted_mass_work_unknown": True, "retry_permitted": False})
        raise


if __name__ == "__main__":
    main()
