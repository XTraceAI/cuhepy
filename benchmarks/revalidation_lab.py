#!/usr/bin/env python3
"""Serial, monitored current-source confirmations; preserve original measurements.

The execution plan is data, not shell code. Telemetry is sampled every two
seconds and cannot prove absence of interference in individual short calls.
Historical source drift, complete costs and statistical conclusions need the
separate comparison report; a successful process alone establishes none of them.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time


def utc():
    return datetime.now(UTC).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=10)
    return {"returncode": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}


def descendants(processes, root):
    owned = {root}
    while True:
        extra = {pid for pid, row in processes.items() if row["parent"] in owned}
        if extra <= owned:
            return owned
        owned |= extra


def processes():
    result = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            body = (entry / "stat").read_text()
            left, right = body.index("("), body.rindex(")")
            fields = body[right + 2:].split()
            result[int(entry.name)] = {"name": body[left + 1:right], "parent": int(fields[1]),
                                       "ticks": int(fields[11]) + int(fields[12])}
        except (OSError, ValueError, IndexError):
            continue
    return result


def snapshot():
    ticks = list(map(int, Path("/proc/stat").read_text().splitlines()[0].split()[1:]))
    memory = {k: int(v.split()[0]) for k, v in
              (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())}
    vm = {k: int(v) for k, v in (line.split() for line in Path("/proc/vmstat").read_text().splitlines())
          if k in {"pswpin", "pswpout"}}
    gpu = command(["nvidia-smi", "--query-gpu=name,uuid,driver_version,utilization.gpu,utilization.memory,memory.used,memory.total,clocks.sm,clocks.mem,temperature.gpu,power.draw,pstate",
                   "--format=csv,noheader,nounits"])
    apps = command(["nvidia-smi", "--query-compute-apps=pid,process_name,used_memory",
                    "--format=csv,noheader,nounits"])
    pids = []
    if apps["returncode"] == 0:
        for line in apps["stdout"].splitlines():
            try:
                pids.append(int(line.split(",", 1)[0]))
            except ValueError:
                pass
    pressure = {}
    for kind in ["cpu", "memory", "io"]:
        p = Path("/proc/pressure") / kind
        pressure[kind] = p.read_text().strip() if p.is_file() else None
    return {"utc": utc(), "monotonic": time.monotonic(), "cpu_ticks": ticks,
            "loadavg": Path("/proc/loadavg").read_text().strip(),
            "memory_kib": {k: memory[k] for k in ["MemTotal", "MemAvailable", "SwapTotal", "SwapFree"]},
            "swap_pages": vm, "pressure": pressure, "gpu": gpu,
            "compute_apps": apps, "compute_pids": pids, "processes": processes()}


class Telemetry:
    def __init__(self, path, interval=2.0):
        self.path, self.interval = path, interval
        self.stop = threading.Event()
        self.samples = []
        self.errors = []
        self.thread = threading.Thread(target=self.collect, daemon=True)

    def collect(self):
        previous = None
        hz = os.sysconf("SC_CLK_TCK")
        with self.path.open("x") as stream:
            while not self.stop.is_set():
                start = time.monotonic()
                try:
                    row = snapshot()
                    owned = descendants(row["processes"], os.getpid())
                    row["foreign_compute_pids"] = [pid for pid in row["compute_pids"] if pid not in owned]
                    row["foreign_CPU_cores"] = None
                    row["foreign_top"] = []
                    if previous:
                        elapsed = row["monotonic"] - previous["monotonic"]
                        external = []
                        for pid, p in row["processes"].items():
                            before = previous["processes"].get(pid)
                            if before and pid not in owned:
                                cores = max(0, p["ticks"] - before["ticks"]) / hz / elapsed
                                if cores:
                                    external.append({"pid": pid, "name": p["name"], "CPU_cores": cores})
                        row["foreign_CPU_cores"] = sum(p["CPU_cores"] for p in external)
                        row["foreign_top"] = sorted(external, key=lambda p: p["CPU_cores"], reverse=True)[:12]
                        total = sum(row["cpu_ticks"]) - sum(previous["cpu_ticks"])
                        idle = sum(row["cpu_ticks"][3:5]) - sum(previous["cpu_ticks"][3:5])
                        row["aggregate_cpu_busy_fraction"] = (total - idle) / total if total else None
                    previous = row
                    saved = {k: v for k, v in row.items() if k != "processes"}
                    saved["collection_wall_s"] = time.monotonic() - start
                    self.samples.append(saved)
                    stream.write(json.dumps(saved) + "\n")
                    stream.flush()
                except (OSError, subprocess.SubprocessError, ValueError) as e:
                    self.errors.append(str(e))
                    stream.write(json.dumps({"utc": utc(), "telemetry_error": str(e)}) + "\n")
                    stream.flush()
                self.stop.wait(max(0, self.interval - (time.monotonic() - start)))

    def finish(self):
        self.stop.set()
        self.thread.join(timeout=20)

    def conditions(self, begin=None, end=None):
        rows = [s for s in self.samples if (begin is None or s["monotonic"] >= begin)
                and (end is None or s["monotonic"] <= end)]
        busy = [s for s in rows if s.get("foreign_CPU_cores", 0) is not None and s["foreign_CPU_cores"] > .75]
        swapping = bool(rows and any(s["swap_pages"] != rows[0]["swap_pages"] for s in rows[1:]))
        foreign_gpu = sorted({p for s in rows for p in s["foreign_compute_pids"]})
        missing_gpu = sum(s["gpu"]["returncode"] != 0 or s["compute_apps"]["returncode"] != 0 for s in rows)
        return {"sample_count": len(rows), "foreign_CPU_above_0_75_cores_samples": len(busy),
                "foreign_compute_pids": foreign_gpu, "new_swap_activity": swapping,
                "missing_gpu_counter_samples": missing_gpu,
                "telemetry_errors": list(self.errors),
                "qualified_by_conditions": bool(foreign_gpu or swapping or self.errors or missing_gpu or len(busy) >= 3),
                "short_panel_sampling_cannot_assure_exclusivity": len(rows) < 3}


def run_job(job, args):
    target = args.output / job["id"]
    target.mkdir(parents=True, exist_ok=True)
    receipt = target / "receipt.json"
    if receipt.exists():
        data = json.loads(receipt.read_text())
        raw = Path(data["job"]["new_raw"])
        if data["returncode"] == 0 and raw.is_file() and digest(raw) == data["new_raw_sha256"]:
            return data
        raise ValueError("Retained failed attempt needs a new job ID: " + job["id"])
    # A model must never silently fall back to copied historical measurements.
    for dependency in job.get("depends_on", []):
        prerequisite = args.output / dependency / "receipt.json"
        if not prerequisite.is_file():
            raise ValueError("Fresh prerequisite has not completed: " + dependency)
        recorded = json.loads(prerequisite.read_text())
        raw = Path(recorded["job"]["new_raw"])
        if (recorded["returncode"] != 0 or not raw.is_file()
                or digest(raw) != recorded["new_raw_sha256"]):
            raise ValueError("Fresh prerequisite failed or changed: " + dependency)
    telemetry = Telemetry(target / "telemetry.jsonl")
    telemetry.thread.start()
    # Four windows maximum. Never stop somebody else's program.
    windows = []
    for _ in range(4):
        start = time.monotonic()
        time.sleep(args.preflight_s)
        condition = telemetry.conditions(start, time.monotonic())
        windows.append(condition)
        if not condition["qualified_by_conditions"]:
            break
    else:
        telemetry.finish()
        raise RuntimeError("Observed host contention; retain preflight and postpone " + job["id"])
    cmd = list(job["command"])
    if not cmd or Path(cmd[0]).resolve() not in {Path(args.python).resolve(), Path("/opt/sage/bin/python").resolve()}:
        raise ValueError("Interpreter outside the declared allowlist")
    if len(cmd) < 2 or not Path(cmd[1]).resolve().is_relative_to(args.source.resolve()):
        raise ValueError("Runner outside the isolated source copy")
    output = Path(job["new_raw"])
    if output.exists():
        raise ValueError("Never overwrite a measured output")
    output.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONPATH=str(args.source / "src") + ":" + str(args.source),
               OMP_NUM_THREADS="8", OPENBLAS_NUM_THREADS="1", CUHEPY_REQUIRE_BGV_CUDA="1")
    start_utc, start = utc(), time.monotonic()
    with (target / "stdout.log").open("x") as stdout, (target / "stderr.log").open("x") as stderr:
        p = subprocess.Popen(cmd, cwd=args.source, env=env, stdout=stdout, stderr=stderr,
                             start_new_session=True)
        try:
            code = p.wait(timeout=job.get("timeout_s", 3600))
        except subprocess.TimeoutExpired:
            # This group contains only our directly created worker and its children.
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                p.wait()
            code = 124
    end = time.monotonic()
    conditions = telemetry.conditions(start, end)
    telemetry.finish()
    data = {"schema": 1, "job": job, "start_utc": start_utc, "end_utc": utc(),
            "returncode": code, "process_wall_s": end - start,
            "execution_mode": "current_source_confirmation_not_unqualified_historical_replication",
            "source_copy": str(args.source), "source_archive_head": args.archive_head,
            "driver_sha256": digest(Path(__file__)), "runner_sha256": digest(Path(cmd[1])),
            "environment": {k: env[k] for k in ["PYTHONPATH", "OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "CUHEPY_REQUIRE_BGV_CUDA"]},
            "affinity": sorted(os.sched_getaffinity(0)), "preflight_windows": windows,
            "resource_conditions": conditions, "telemetry_interval_s": telemetry.interval,
            "new_raw_sha256": digest(output) if output.is_file() else None,
            "stdout_sha256": digest(target / "stdout.log"), "stderr_sha256": digest(target / "stderr.log"),
            "telemetry_sha256": digest(target / "telemetry.jsonl"),
            "completed_successfully": code == 0 and output.is_file(),
            "scope": "Whole process serial confirmation, existing runner timed boundaries and assertions. "
                     "Desktop GPU baseline remains; no machine-exclusive, historical-source-identical, "
                     "tail-latency, parameter or security claim follows from execution success."}
    receipt.write_text(json.dumps(data, indent=2) + "\n")
    if code == 0 and output.is_file():
        # Redirect internal hard-coded dependencies in the isolated copy only.
        for original in job.get("original_raws", []):
            link = args.source / original
            if link.is_file() or link.is_symlink():
                link.unlink()
            link.symlink_to(output)
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python", required=True)
    parser.add_argument("--archive-head", required=True)
    parser.add_argument("--preflight-s", type=float, default=30)
    parser.add_argument("--ids", nargs="*")
    args = parser.parse_args()
    if not 5 <= args.preflight_s <= 60:
        parser.error("Preflight must be5–60 seconds")
    args.output.mkdir(parents=True, exist_ok=True)
    # Hold a process lock through the complete queue, including preflight gaps.
    lock = (args.output / "serial.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    plan = json.loads(args.plan.read_text())
    if args.ids is not None and set(args.ids) - {j["id"] for j in plan["jobs"]}:
        parser.error("Unknown job IDs")
    jobs = [j for j in plan["jobs"] if args.ids is None or j["id"] in args.ids]
    status_path = args.output / "status.json"
    results = []
    for job in jobs:
        status_path.write_text(json.dumps({"utc": utc(), "active": job["id"], "completed": len(results),
                                           "planned": len(jobs)}, indent=2) + "\n")
        try:
            result = run_job(job, args)
        except (ValueError, RuntimeError) as error:
            # Preserve failed/preflight attempts and continue independent jobs.
            results.append({"id": job["id"], "execution_error": str(error)})
            print(json.dumps(results[-1]), flush=True)
            continue
        results.append({"id": job["id"], "returncode": result["returncode"],
                        "resource_conditions": result["resource_conditions"]})
        print(json.dumps(results[-1]), flush=True)
    status_path.write_text(json.dumps({"utc": utc(), "active": None, "completed": len(results),
                                      "planned": len(jobs), "results": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
