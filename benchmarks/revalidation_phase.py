#!/usr/bin/env python3
"""Run one declared follow-up phase serially, retaining resource evidence.

The plan is trusted local data containing argument arrays, never shell code.
Phase wall time includes builds and diagnostics and is not an algorithm timing.
The shared lock prevents overlap with the main revalidation queue. Historical
outputs and failed attempts must use different output directories.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from revalidation_lab import Telemetry, digest, utc


def finish_owned_group(group):
    """Bound cleanup to the session created for this task's worker."""
    try:
        os.killpg(group, signal.SIGTERM)
    except ProcessLookupError:
        return
    for _ in range(30):
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            return
        time.sleep(.1)
    try:
        os.killpg(group, signal.SIGKILL)
    except ProcessLookupError:
        pass


def main():
    def cancelled(signum, _frame):
        raise KeyboardInterrupt("Follow-up phase cancelled by signal " + str(signum))

    # The worker has its own session. Route termination through cleanup instead
    # of releasing the lock while that worker continues running.
    signal.signal(signal.SIGTERM, cancelled)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--preflight-s", type=float, default=30)
    args = parser.parse_args()
    if not 0 <= args.preflight_s <= 120:
        parser.error("Invalid bounded preflight")
    plan = json.loads(args.plan.read_text())
    jobs = [job for job in plan["jobs"] if job["id"] == args.id]
    if len(jobs) != 1:
        parser.error("Exactly one declared job must match")
    job = jobs[0]
    argv = job["command"]
    if not argv or not all(isinstance(value, str) and "\0" not in value for value in argv):
        parser.error("Command must be an argument array")
    executable = Path(argv[0])
    if not executable.is_absolute() or not executable.is_file():
        parser.error("An explicit existing executable is required")
    source = Path(job["cwd"]).resolve()
    output = args.output.resolve()
    if output.exists() or output.is_relative_to(source):
        parser.error("Use a fresh evidence directory outside source")
    required = [Path(value) for value in job.get("required_outputs", [])]
    if any(value.exists() for value in required):
        parser.error("A declared result already exists; use a fresh attempt")
    output.mkdir(parents=True)
    args.lock.parent.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ, **job.get("environment", {}))
    receipt = {
        "schema": "cuhepy.monitored_followup_phase.v1", "job": job,
        "start_utc": utc(), "state": "waiting_for_serial_lock",
        "plan_sha256": digest(args.plan), "runner_sha256": digest(Path(__file__)),
        "executable_sha256": digest(executable.resolve()),
        "affinity": sorted(os.sched_getaffinity(0)),
        "scope": "Whole-phase setup/diagnostic wall time is not an algorithm timing; "
                 "desktop GPU sharing remains. Resource conditions apply to the whole phase.",
    }
    path = output / "receipt.json"

    def save():
        path.write_text(json.dumps(receipt, indent=2) + "\n")

    save()
    with args.lock.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if any(value.exists() for value in required):
            receipt.update(state="failed", error={"type": "FileExistsError",
                                                  "message": "A result appeared while waiting for the serial lock"})
            save()
            raise FileExistsError(receipt["error"]["message"])
        telemetry = Telemetry(output / "telemetry.jsonl")
        telemetry.thread.start()
        try:
            receipt["state"] = "resource_preflight"
            receipt["preflight_windows"] = []
            save()
            for _ in range(4):
                begin = time.monotonic()
                time.sleep(args.preflight_s)
                conditions = telemetry.conditions(begin, time.monotonic())
                receipt["preflight_windows"].append(conditions)
                if not conditions["qualified_by_conditions"]:
                    break
            else:
                raise RuntimeError("Observed competing compute; phase postponed")
            receipt.update(state="running", worker_start_utc=utc())
            save()
            begin = time.monotonic()
            with (output / "stdout.log").open("x") as stdout, (output / "stderr.log").open("x") as stderr:
                worker = subprocess.Popen(argv, cwd=source, env=environment,
                                          stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    returncode = worker.wait(timeout=job.get("timeout_s", 7200))
                except BaseException:
                    # Only our worker's process group is signalled.
                    finish_owned_group(worker.pid)
                    try:
                        worker.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(worker.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        worker.wait()
                    raise
                finally:
                    # Adapters may finish after an inner timeout while their
                    # children remain in the task's group. Stop that group
                    # before releasing the serial lock, including normal exit.
                    # Tools that deliberately detach need explicit --batch or
                    # their own task-specific shutdown in the declared command.
                    finish_owned_group(worker.pid)
            end = time.monotonic()
            receipt.update(returncode=returncode, phase_wall_s=end - begin,
                           resource_conditions=telemetry.conditions(begin, end))
            receipt["required_outputs"] = {str(value): digest(value) if value.is_file() else None
                                           for value in required}
            receipt["state"] = "completed" if returncode == 0 and all(value.is_file() for value in required) else "failed"
        except BaseException as error:
            receipt.update(state="failed", error={"type": type(error).__name__, "message": str(error)})
            raise
        finally:
            telemetry.finish()
            receipt["end_utc"] = utc()
            receipt["telemetry_sha256"] = digest(output / "telemetry.jsonl")
            for name in ("stdout.log", "stderr.log"):
                if (output / name).is_file():
                    receipt[name + "_sha256"] = digest(output / name)
            save()
    print(json.dumps({"receipt": str(path), "state": receipt["state"],
                      "resource_conditions": receipt.get("resource_conditions")}))
    return 0 if receipt["state"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
