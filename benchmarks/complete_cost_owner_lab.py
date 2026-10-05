"""Q77 measured role and public telemetry services for the owner coordinator.

Native clocks preserve the configured callables, including factory-cached
references. Their computational projection excludes Python framing, RPC waits
and admission/signing; it is not an independently executed bare evaluator.
Whole observed owner completion remains the primary metric.

Telemetry reads kernel counters, not process memory, arguments or environment.
Trusted local files supply PID/birth identities and finite sampling limits.
It can signal a cooperative resource failure, but cannot kill user processes.
These local services supply no attestation or rollback/private-key assurance.

The full owner cohort orchestrator and committed execution addendum are still
required. This entry currently exposes only fixed public worker services; it
does not generate HE keys or silently run an underspecified timing cohort.
"""

# ruff: noqa: E402 -- standalone research worker adds the repository root.
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks import complete_cost_shared_query_lab as roles
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_relay as relay
from experiments.bfv_search_lab import complete_cost_supervisor as supervisor
from experiments.bfv_search_lab import shared_query_certificate as cert

NATIVE_SYMBOLS = tuple(
    "cuhepy_shared_" + name
    for name in (
        "create",
        "query",
        "produce",
        "check",
        "residuals",
        "terminal",
        "destroy",
        "query_destroy",
    )
)
CACHED_SYMBOLS = {
    cert.MODES[0]: (),
    cert.MODES[1]: (("_run", "cuhepy_shared_replay"),),
    cert.MODES[2]: (
        ("_produce", "cuhepy_shared_aggregate_produce"),
        ("_finish", "cuhepy_shared_aggregate_finish"),
    ),
}
PHASES = frozenset(("initial-preparation", "refresh", "run", "descriptor", "stop", "close"))
CALL_CAP = 4096
SAMPLE_CAP = 172800
SAMPLE_BYTE_CAP = 128 << 20
PID_CAP = 32


class NativeCall:
    """Transparent fixed-call proxy; no arguments, return values or pointers logged."""

    def __init__(self, function, symbol, clocks):
        self._function, self._symbol, self._clocks = function, symbol, clocks

    def __call__(self, *args):
        with self._clocks.call(self._symbol):
            return self._function(*args)

    @property
    def argtypes(self):
        return self._function.argtypes

    @argtypes.setter
    def argtypes(self, value):
        self._function.argtypes = value

    @property
    def restype(self):
        return self._function.restype

    @restype.setter
    def restype(self, value):
        self._function.restype = value

    def __copy__(self):
        raise TypeError("Native call lifetime cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Native call lifetime cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Native call lifetime cannot be serialized")


class NativeClocks:
    """Actual bounded native intervals, separate from whole role/RPC intervals."""

    def __init__(self, role, mode):
        if role not in ("frontend", "protected") or mode not in cert.MODES:
            raise ValueError("Fixed trusted role/mode required")
        self.role, self.mode, self._pid = role, mode, os.getpid()
        self._lock, self._local = threading.Lock(), threading.local()
        self._calls, self._phases, self._installed = [], [], False

    def _process(self):
        if os.getpid() != self._pid:
            raise RuntimeError("Inherited native clock holder")

    @contextmanager
    def phase(self, label):
        self._process()
        if label not in PHASES:
            raise ValueError("Fixed native clock phase required")
        if getattr(self._local, "phase", None) is not None:
            raise RuntimeError("Native operation phase cannot nest")
        start, cpu = time.perf_counter_ns(), time.thread_time_ns()
        with self._lock:
            if len(self._phases) >= CALL_CAP:
                raise RuntimeError("Native phase recording cap exhausted")
            item = {
                "id": len(self._phases),
                "phase": label,
                "start_ns": start,
                "thread": threading.get_native_id(),
                "status": "active",
            }
            self._phases.append(item)
        self._local.phase = item["id"]
        status, error_class = "returned", None
        try:
            yield item["id"]
        except BaseException as error:
            status, error_class = "raised", type(error).__name__
            raise
        finally:
            with self._lock:
                item.update(
                    end_ns=time.perf_counter_ns(),
                    thread_cpu_ns=time.thread_time_ns() - cpu,
                    status=status,
                    error_class=error_class,
                )
            self._local.phase = None

    @contextmanager
    def call(self, symbol):
        self._process()
        phase_id = getattr(self._local, "phase", None)
        if phase_id is None:
            raise RuntimeError("Native work requires its explicit operation phase")
        start, cpu = time.perf_counter_ns(), time.thread_time_ns()
        with self._lock:
            if len(self._calls) >= CALL_CAP:
                raise RuntimeError("Native call recording cap exhausted")
            item = {
                "id": len(self._calls),
                "symbol": symbol,
                "phase_id": phase_id,
                "start_ns": start,
                "thread": threading.get_native_id(),
                "status": "active",
            }
            self._calls.append(item)
        status, error_class = "returned", None
        try:
            yield
        except BaseException as error:
            status, error_class = "raised", type(error).__name__
            raise
        finally:
            with self._lock:
                item.update(
                    end_ns=time.perf_counter_ns(),
                    thread_cpu_ns=time.thread_time_ns() - cpu,
                    status=status,
                    error_class=error_class,
                )

    def install(self, library, factory):
        """Install once after signature/factory configuration, before enrollment."""
        self._process()
        if self._installed:
            raise RuntimeError("Native call proxies already installed")
        dll = library._lib
        symbols = NATIVE_SYMBOLS + tuple(symbol for _, symbol in CACHED_SYMBOLS[self.mode])
        originals = {name: getattr(dll, name) for name in symbols}
        if any(isinstance(fn, NativeCall) or not callable(fn) for fn in originals.values()):
            raise ValueError("Fixed original configured native callables required")
        arithmetic = getattr(factory, "_arithmetic", None)
        for attr, symbol in CACHED_SYMBOLS[self.mode]:
            if arithmetic is None or getattr(arithmetic, attr) is not originals[symbol]:
                raise ValueError("Factory cached a foreign native callable")
        proxies = {name: NativeCall(fn, name, self) for name, fn in originals.items()}
        # Validate the whole set before replacing either DLL attributes or caches.
        for name, proxy in proxies.items():
            setattr(dll, name, proxy)
        for attr, symbol in CACHED_SYMBOLS[self.mode]:
            setattr(arithmetic, attr, proxies[symbol])
        self._installed = True

    def inventory(self):
        self._process()
        with self._lock:
            calls, phases = [dict(x) for x in self._calls], [dict(x) for x in self._phases]
        if self.mode == cert.MODES[1]:
            selected = (
                {"cuhepy_shared_query", "cuhepy_shared_replay"}
                if self.role == "protected"
                else set()
            )
        elif self.role == "frontend":
            selected = (
                {"cuhepy_shared_query", "cuhepy_shared_produce", "cuhepy_shared_terminal"}
                if self.mode == cert.MODES[0]
                else {"cuhepy_shared_query", "cuhepy_shared_aggregate_produce"}
            )
        else:
            selected = set()
        included = [
            c
            for c in calls
            if c["symbol"] in selected
            and phases[c["phase_id"]]["phase"] == "run"
            and c["status"] == "returned"
        ]
        return {
            "role": self.role,
            "mode": self.mode,
            "process": self._pid,
            "calls": calls,
            "phases": phases,
            "call_cap": CALL_CAP,
            "configured_native_calls_installed": self._installed,
            "return_status_does_not_assert_native_or_protocol_success": True,
            "computational_projection": {
                "included_symbols": sorted(selected),
                "included_call_ids": [c["id"] for c in included],
                "wall_ns": sum(c["end_ns"] - c["start_ns"] for c in included),
                "thread_cpu_ns": sum(c["thread_cpu_ns"] for c in included),
                "scope": "Actual per-query source construction/evaluation/witness or terminal native calls; selected symbols only",
                "excluded": "Python parsing/authentication/allocation/framing, RPC/verification wait, signing, initial preparation and cleanup",
                "not_independently_executed_unverified_evaluator": True,
                "not_whole_owner_completion_latency": True,
            },
        }

    def __copy__(self):
        raise TypeError("Native clock ownership cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Native clock ownership cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Native clock ownership cannot be serialized")


class TimedLocalRole(roles.LocalRole):
    """Existing actual role arithmetic and authority, with additive native clocks."""

    def __init__(self, config_path, freeze_path, **kwargs):
        cfg = json.loads(Path(config_path).read_text())
        self._native_clocks = NativeClocks(cfg["role"], cfg["mode"])
        super().__init__(config_path, freeze_path, **kwargs)

    def refresh(self, *, initial=False):
        if self.library is not None and not self._native_clocks._installed:
            self._native_clocks.install(self.library, self.factory)
        with self._native_clocks.phase("initial-preparation" if initial else "refresh"):
            return super().refresh(initial=initial)

    def execute(self, packet):
        # Fixed command tags become clock labels, never peer-supplied strings.
        fields = auth._unpack(packet, limit=roles.native.PACKET_CAP, array_cap=3)
        verb = fields[0] if type(fields) is list and fields else None
        if type(verb) is not bytes:
            raise ValueError("Fixed byte-valued public command required")
        if verb == b"refresh":
            return super().execute(packet)  # refresh owns its own explicit phase.
        label = {b"run": "run", b"descriptor": "descriptor", b"stop": "stop"}.get(verb)
        if label is None:
            raise ValueError("Fixed public role command required")
        with self._native_clocks.phase(label):
            return super().execute(packet)

    def inventory(self):
        value = super().inventory()
        value["actual_native_clocks"] = self._native_clocks.inventory()
        value["worker_close_after_inventory_not_in_native_clock_report"] = True
        return value

    def close(self):
        self._process()
        if self._closed:
            return
        with self._native_clocks.phase("close"):
            super().close()


def process_counters(pid):
    """Read only public kernel metadata; exclude argv/env/address lines."""
    if type(pid) is not int or not 1 <= pid < 1 << 31:
        raise ValueError("Explicit public process identity required")
    raw = Path(f"/proc/{pid}/stat").read_text()
    fields = raw[raw.rfind(")") + 2 :].split()
    return {
        "pid": pid,
        "birth_ticks": int(fields[19]),
        "parent": int(fields[1]),
        "state": fields[0],
        "user_ticks": int(fields[11]),
        "system_ticks": int(fields[12]),
        "threads": int(fields[17]),
        "last_cpu": int(fields[36]),
    }


def _number_fields(path, names):
    result = {}
    for line in Path(path).read_text().splitlines():
        fields = line.replace(":", "").split()
        if fields and fields[0] in names:
            value = int(fields[1])
            result[fields[0]] = value * 1024 if len(fields) > 2 and fields[2] == "kB" else value
    return result


def system_counters():
    cpu = {
        parts[0]: [int(x) for x in parts[1:]]
        for line in Path("/proc/stat").read_text().splitlines()
        if (parts := line.split())
        and (parts[0] == "cpu" or parts[0][3:].isdigit() and parts[0].startswith("cpu"))
    }
    sensors = {}
    paths = sorted(Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_cur_freq"))
    paths += sorted(Path("/sys/class/thermal").glob("thermal_zone*/temp"))
    paths += sorted(Path("/sys/class/hwmon").glob("hwmon*/temp*_input"))
    for path in paths[:128]:
        try:
            sensors[str(path)] = int(path.read_text())
        except (OSError, ValueError):
            sensors[str(path)] = None
    return {
        "CPU_ticks": cpu,
        "load": list(os.getloadavg()),
        "memory_bytes": _number_fields(
            "/proc/meminfo", {"MemAvailable", "MemFree", "SwapTotal", "SwapFree"}
        ),
        "VM_counters": _number_fields(
            "/proc/vmstat", {"pswpin", "pswpout", "pgfault", "pgmajfault"}
        ),
        "clock_kHz_temperature_milliC": sensors,
        "sensors_truncated": len(paths) > 128,
    }


class PublicTelemetry:
    """Fixed bounded sampler; its guard is cooperative, never a hard memory limit."""

    def __init__(self, config_path, freeze_path):
        roles.verify_freeze(freeze_path)
        self.config_path = Path(config_path).resolve(strict=True)
        cfg = json.loads(self.config_path.read_text())
        required = {
            "role",
            "service",
            "registry",
            "samples",
            "guard",
            "interval_ns",
            "max_samples",
            "max_bytes",
            "deadline_ns",
            "min_available_bytes",
        }
        if (
            type(cfg) is not dict
            or set(cfg) != required
            or cfg["role"] != "frontend"
            or cfg["service"] != "public-resource-telemetry"
            or any(
                type(cfg[k]) is not int
                for k in (
                    "interval_ns",
                    "max_samples",
                    "max_bytes",
                    "deadline_ns",
                    "min_available_bytes",
                )
            )
            or not 50_000_000 <= cfg["interval_ns"] <= 1_000_000_000
            or not 1 <= cfg["max_samples"] <= SAMPLE_CAP
            or not 1024 <= cfg["max_bytes"] <= SAMPLE_BYTE_CAP
            or not time.perf_counter_ns()
            < cfg["deadline_ns"]
            <= time.perf_counter_ns() + 86_400_000_000_000
            or not 0 <= cfg["min_available_bytes"] <= 1 << 40
        ):
            raise ValueError("Fixed bounded public telemetry configuration required")
        for name in ("registry", "samples", "guard"):
            if type(cfg[name]) is not str or not Path(cfg[name]).is_absolute():
                raise ValueError("Fixed trusted absolute telemetry paths required")
        targets = [Path(cfg[name]).resolve() for name in ("registry", "samples", "guard")]
        if len(set(targets)) != 3 or not targets[0].is_file():
            raise ValueError("Distinct telemetry paths and existing trusted registry required")
        for path in targets[1:]:
            path.parent.resolve(strict=True)
            if path.exists() or path.is_symlink():
                raise ValueError("Telemetry artifact already consumed")
        self._cfg, self._pid = cfg, os.getpid()
        self._lock, self._stop = threading.Lock(), threading.Event()
        self._closed, self.stopping, self._signer = False, False, None
        self.transfers, self._failure, self._guard_persisted = [], None, False
        self._count, self._bytes, self._sample_cpu_ns = 0, 0, 0
        self._last_start_ns, self._maximum_gap_ns = None, 0
        self._stream = targets[1].open("xb")
        self._thread = threading.Thread(
            target=self._sample_loop, name="Q77-public-telemetry", daemon=False
        )
        self._thread.start()

    def _process(self):
        if os.getpid() != self._pid:
            raise RuntimeError("Inherited telemetry worker")

    def _registry(self):
        if json.loads(self.config_path.read_text()) != self._cfg:
            raise ValueError("Trusted telemetry limits or paths changed")
        entries = json.loads(Path(self._cfg["registry"]).read_text())
        if type(entries) is not list or not 1 <= len(entries) <= PID_CAP:
            raise ValueError("Bounded trusted PID/birth registry required")
        labels, identities = set(), set()
        for entry in entries:
            if (
                type(entry) is not dict
                or set(entry) != {"label", "pid", "birth_ticks"}
                or type(entry["label"]) is not str
                or not 1 <= len(entry["label"]) <= 64
                or any(
                    c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                    for c in entry["label"]
                )
                or type(entry["pid"]) is not int
                or not 1 <= entry["pid"] < 1 << 31
                or type(entry["birth_ticks"]) is not int
                or entry["birth_ticks"] < 1
                or entry["label"] in labels
                or entry["pid"] in identities
            ):
                raise ValueError("Distinct trusted process identities required")
            labels.add(entry["label"])
            identities.add(entry["pid"])
        return entries

    def _fail(self, reason):
        if self._failure is not None:
            return
        self._failure = {
            "reason": reason,
            "monotonic_ns": time.perf_counter_ns(),
            "samples_consumed": self._count,
            "sample_bytes": self._bytes,
            "cooperative_guard_not_hard_limit": True,
            "no_processes_killed": True,
        }
        # Even a guard-file persistence failure must stop this owned worker.
        self.stopping = True
        self._stop.set()
        with Path(self._cfg["guard"]).open("x") as out:
            out.write(json.dumps(self._failure, sort_keys=True) + "\n")
            out.flush()
            os.fsync(out.fileno())
        directory = os.open(Path(self._cfg["guard"]).parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self._guard_persisted = True

    def sample(self):
        self._process()
        with self._lock:
            if self._closed or self._failure is not None:
                raise RuntimeError("Closed or failed public telemetry")
            start, cpu = time.perf_counter_ns(), time.thread_time_ns()
            if start >= self._cfg["deadline_ns"]:
                self._fail("absolute_lifetime_expired")
                raise RuntimeError("Telemetry lifetime exhausted")
            if self._count >= self._cfg["max_samples"]:
                self._fail("sample_attempt_cap_exhausted")
                raise RuntimeError("Telemetry sample budget exhausted")
            self._count += 1  # Failure is consumed too; no replacement sample.
            gap = None if self._last_start_ns is None else start - self._last_start_ns
            if gap is not None:
                self._maximum_gap_ns = max(self._maximum_gap_ns, gap)
            self._last_start_ns = start
            processes = []
            for entry in self._registry():
                row = dict(entry)
                try:
                    before = process_counters(entry["pid"])
                    if before["birth_ticks"] != entry["birth_ticks"]:
                        row["observation"] = "birth_mismatch_no_process_followed"
                    else:
                        root = Path(f"/proc/{entry['pid']}")
                        memory = _number_fields(root / "status", {"VmRSS", "VmHWM", "VmSwap"})
                        try:
                            proportional = _number_fields(
                                root / "smaps_rollup", {"Pss", "Rss", "Swap"}
                            )
                        except PermissionError:
                            proportional = {"unavailable_due_to_permissions": True}
                        after = process_counters(entry["pid"])
                        if after["birth_ticks"] != entry["birth_ticks"]:
                            row["observation"] = "birth_changed_during_sample_values_discarded"
                        else:
                            row.update(
                                observation="matched_birth",
                                counters=after,
                                memory_bytes=memory,
                                proportional_bytes=proportional,
                            )
                except (FileNotFoundError, ProcessLookupError):
                    row["observation"] = "process_disappeared"
                processes.append(row)
            system = system_counters()
            if system["memory_bytes"]["MemAvailable"] < self._cfg["min_available_bytes"]:
                self._fail("available_memory_below_frozen_minimum")
            used = time.thread_time_ns() - cpu
            item = {
                "sequence": self._count - 1,
                "start_ns": start,
                "end_ns": time.perf_counter_ns(),
                "observed_gap_ns": gap,
                "gap_exceeds_one_second": gap is not None and gap > 1_000_000_000,
                "sampler_thread_cpu_ns": used,
                "sampler_cpu_affinity": sorted(os.sched_getaffinity(0)),
                "processes": processes,
                "system": system,
            }
            body = (json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n").encode()
            if self._bytes + len(body) > self._cfg["max_bytes"]:
                self._fail("sample_byte_cap_exhausted")
                raise RuntimeError("Telemetry artifact budget exhausted")
            self._stream.write(body)
            self._stream.flush()
            self._bytes += len(body)
            self._sample_cpu_ns += used
            return item

    def _sample_loop(self):
        next_at = time.perf_counter_ns()
        try:
            while not self._stop.is_set():
                self.sample()
                next_at = max(next_at + self._cfg["interval_ns"], time.perf_counter_ns())
                # A delayed sample does not fabricate intermediate observations.
                delay = max(0, next_at - time.perf_counter_ns()) / 1e9
                if self._stop.wait(delay):
                    break
        except BaseException as error:
            with self._lock:
                if self._failure is not None and not self._guard_persisted:
                    self._failure["guard_persistence_error_class"] = type(error).__name__
                try:
                    self._fail(type(error).__name__)
                except BaseException as persistence_error:
                    self._failure["guard_persistence_error_class"] = type(
                        persistence_error
                    ).__name__

    def execute(self, packet):
        self._process()
        fields = auth._unpack(packet, limit=4096, array_cap=1)
        if fields != [b"stop"]:
            raise ValueError("Only fixed telemetry stop is remotely accepted")
        self.close()
        self.stopping = True
        return auth._pack([roles.OK_TAG])

    def inventory(self):
        self._process()
        with self._lock:
            return {
                "role": "public-resource-telemetry",
                "process": self._pid,
                "samples_consumed": self._count,
                "sample_bytes": self._bytes,
                "sample_thread_cpu_ns": self._sample_cpu_ns,
                "failure": self._failure,
                "guard_record_persistence_completed": self._guard_persisted,
                "maximum_observed_gap_ns": self._maximum_gap_ns,
                "observed_gap_exceeds_one_second": self._maximum_gap_ns > 1_000_000_000,
                "sampler_thread_alive": self._thread.is_alive(),
                "closed": self._closed,
                "samples": supervisor.pinned(self._cfg["samples"]),
                "transfers": [x.as_dict() for x in self.transfers],
                "process_memory_argv_environment_or_keys_read": False,
                "cooperative_guard_not_hard_memory_limit": True,
                "no_processes_killed": True,
                "whole_owner_cohort_actual_HE_custody_and_attestation_pending": True,
            }

    def close(self):
        self._process()
        if self._closed:
            return
        self._stop.set()
        self._thread.join(timeout=2)
        if self._thread.is_alive():
            with self._lock:
                self._fail("sampler_owned_join_timeout")
            raise RuntimeError("Owned telemetry sampler did not finish")
        with self._lock:
            self._stream.flush()
            os.fsync(self._stream.fileno())
            self._stream.close()
            self._closed = True

    def __copy__(self):
        raise TypeError("Telemetry ownership cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Telemetry ownership cannot be copied")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Telemetry ownership cannot be serialized")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("worker",))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu", type=int, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("Never replace a consumed public worker output")
    os.sched_setaffinity(0, {args.cpu})
    cfg = json.loads(args.config.read_text())
    role = (
        PublicTelemetry(args.config, args.freeze)
        if cfg.get("service") == "public-resource-telemetry"
        else TimedLocalRole(args.config, args.freeze)
    )
    roles.serve(
        role,
        args.output,
        cpu=args.cpu,
        link=relay.LOCAL_DISPATCH if cfg["role"] == "frontend" else roles.INTERNAL_LINK,
    )


if __name__ == "__main__":
    main()
