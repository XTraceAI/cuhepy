"""Actual owner trajectory orchestration for the Q77 complete-cost study.

The caller supplies already owned public workers and honest provisioning/update
operations. This module executes those operations; it does not accept measured
stage costs. Cache-only trajectories require no HE descriptor, key, certificate
or encrypted index. A fresh-device acquisition and a returning cache are
different initial states. Racing work stays charged until explicit settlement.

The full cohort launcher must create the clean supervisor before private keys,
freeze all source/event/budget inputs, and instantiate independent trajectories.
These local orchestration controls are not attestation or parameter assurance.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import time

from experiments.bfv_search_lab import authenticated_cache as cache
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_owner as owner
from experiments.bfv_search_lab import complete_cost_relay as relay
from experiments.bfv_search_lab import complete_cost_trace as trace

POLICIES = ("remote", "returning-cache", "fresh-cache", "prefetch")


def write_once(path, value):
    """Persist a consumed local result, never replace an earlier attempt."""
    path = Path(path)
    with path.open("x") as stream:
        stream.write(json.dumps(value, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class ResourceGuard:
    """Cooperative whole-artifact and available-memory guard, including failures.

    The sampler's fail file is sticky. Walking the explicitly owned artifact
    directory counts logical bytes, not RSS or filesystem allocation. A native
    call cannot be preempted by this guard; the supervisor owns process cleanup.
    """

    def __init__(self, root, guard_file, *, artifact_limit, min_available_bytes, deadline_ns):
        self.root, self.guard_file = Path(root).resolve(strict=True), Path(guard_file)
        if any(type(x) is not int for x in (artifact_limit, min_available_bytes, deadline_ns)):
            raise ValueError("Explicit integer resource limits required")
        if not 1 <= artifact_limit <= 8 << 30 or not 0 <= min_available_bytes <= 1 << 40:
            raise ValueError("Bounded artifact and available-memory limits required")
        self.artifact_limit, self.minimum, self.deadline_ns = (
            artifact_limit,
            min_available_bytes,
            deadline_ns,
        )
        self._pid, self._failure, self.observations = os.getpid(), None, []

    def check(self):
        if os.getpid() != self._pid:
            raise RuntimeError("Inherited owner resource guard")
        if self._failure is not None:
            raise RuntimeError("Consumed owner resource failure")
        try:
            if self.guard_file.exists():
                raise RuntimeError("Public telemetry guard reported a failure")
            now, total = time.perf_counter_ns(), 0
            if now >= self.deadline_ns:
                raise TimeoutError("Frozen trajectory deadline exhausted")
            for path in self.root.rglob("*"):
                if path.is_symlink():
                    raise ValueError("Owned artifact root cannot contain symlinks")
                if path.is_file():
                    total += path.stat().st_size
            available = next(
                int(line.split()[1]) * 1024
                for line in Path("/proc/meminfo").read_text().splitlines()
                if line.startswith("MemAvailable:")
            )
            self.observations.append(
                {
                    "monotonic_ns": now,
                    "logical_artifact_bytes": total,
                    "system_available_bytes": available,
                }
            )
            if total > self.artifact_limit or available < self.minimum:
                raise RuntimeError("Frozen memory or artifact ceiling failed")
            return now
        except BaseException as error:
            self._failure = type(error).__name__
            raise

    def inventory(self):
        return {
            "failure_class": self._failure,
            "checks": list(self.observations),
            "cooperative_not_hard_memory_or_preemption_limit": True,
        }


class CacheOwnerTrace(owner._Owned):
    """Direct authenticated plaintext-cache control without any HE dependency.

    Current context is honest-owner authority. AEAD plus the existing signed
    delivery binds the data and ordered IDs. Each answer maps ordinals to IDs
    authenticated inside that cache; a peer cannot install a current context.
    """

    def __init__(self, client, endpoint, log):
        if (
            type(client) is not cache.CacheClient
            or type(endpoint) is not relay.OwnerEndpoint
            or type(log) is not trace.EventLog
        ):
            raise ValueError("Fixed owner cache, shared endpoint and event log required")
        self._initialize()
        self.cache, self.endpoint, self.log = client, endpoint, log
        self._failed, self._acquired, self._queries, self._results = False, False, set(), []

    def _ready(self, deadline_ns):
        self._open()
        if self._failed:
            raise RuntimeError("Failed cache trajectory cannot be retried")
        if (
            type(deadline_ns) is not int
            or not 0 < deadline_ns - time.perf_counter_ns() <= self.endpoint.timeout_ns
        ):
            raise TimeoutError("Bounded absolute cache operation deadline required")

    def _failure(self):
        with self._lock:
            self._failed = True

    @contextmanager
    def operation(self, label, deadline_ns):
        self._process()
        self._ready(deadline_ns)
        try:
            with self.log.event(label):
                yield
                self._ready(deadline_ns)
        except BaseException:
            self._failure()
            raise

    def cache_ready(self):
        self._process()
        with self._lock:
            self._open()
            return not self._failed and self.cache.inventory()["active"]

    def _delivery(self, verb, deadline_ns):
        packet = self.endpoint.rpc(auth._pack([verb]), deadline_ns=deadline_ns)
        fields = auth._unpack(packet, limit=self.endpoint.cap, array_cap=2)
        if (
            type(fields) is not list
            or len(fields) != 2
            or any(type(x) is not bytes for x in fields)
        ):
            raise ValueError("Complete authenticated cache delivery required")
        return fields

    def acquire(self, *, deadline_ns):
        with self.operation("cache-acquisition", deadline_ns):
            with self._lock:
                if self._acquired or self.cache_ready():
                    raise ValueError("One declared absent-cache acquisition required")
                self._acquired = True
            with self.log.event("snapshot-shared-link"):
                packet, descriptor = self._delivery(b"snapshot", deadline_ns)
            with self.log.event("cache-authenticate-publish"):
                self.cache.acquire(packet, descriptor)

    def query(self, word, *, label, arrival_ns, deadline_ns, policy="cache"):
        self._process()
        trace._label(label)
        self._ready(deadline_ns)
        if policy != "cache":
            raise ValueError("Cache-only control has no remote policy")
        with self._lock:
            if label in self._queries or len(self._queries) >= trace.MAX_QUERIES:
                raise RuntimeError("Consumed or excess cache query")
            self._queries.add(label)
        try:
            with self.log.event(label, arrival_ns=arrival_ns):
                with self.log.event("cache-scan"):
                    answer = self.cache.query(word)
                self._ready(deadline_ns)
                if answer.context != self.cache.current_context:
                    raise ValueError("Cache answer differs from trusted current context")
                result = owner.SearchResult(
                    answer.scores,
                    tuple(
                        owner.Match(ordinal, pair[1], pair[0])
                        for ordinal, pair in zip(answer.top3_positions, answer.top3, strict=True)
                    ),
                )
                self._results.append(
                    {
                        "label": label,
                        "path": "cache",
                        "count": len(answer.scores),
                        "epoch": answer.context.epoch,
                        "snapshot_id": answer.context.snapshot_id.hex(),
                        "nearest": [asdict(m) for m in result.nearest],
                    }
                )
                return result
        except BaseException:
            self._failure()
            raise

    def advance(self, current, *, deadline_ns):
        with self.operation("owner-cache-current-update", deadline_ns):
            self.cache.pin_current(current)

    def patch(self, *, deadline_ns):
        with self.operation("cache-update", deadline_ns):
            if self.cache_ready():
                raise ValueError("An invalidated retained cache is required")
            with self.log.event("patch-shared-link"):
                packet, descriptor = self._delivery(b"patch", deadline_ns)
            with self.log.event("cache-authenticate-patch"):
                self.cache.apply_update(packet, descriptor)

    def inventory(self):
        self._process()
        return {
            "process": self._pid,
            "failed": self._failed,
            "closed": self._closed,
            "requires_HE_descriptor_key_index_or_certificate": False,
            "consumed_query_labels": sorted(self._queries),
            "results": list(self._results),
            "endpoint": self.endpoint.inventory(),
            "trace": self.log.inventory(),
        }

    def close(self):
        self._process()
        self._closed = True
        self.endpoint.close()
        # Caller owns the cache/native/key lifetimes, just as in OwnerTrace.


class TrajectoryRunner:
    """Execute a fixed eight-query trajectory, update and complete output checks.

    Public setup/refresh/warmup/stop callbacks are fixed trusted caller code,
    not response-selected operations or cost models. The caller must retain
    their source pins and independent role inventories in its execution freeze.
    """

    def __init__(
        self,
        owner_trace,
        *,
        policy,
        label,
        words,
        rows,
        ids,
        output,
        guard,
        operation_timeout_ns,
        setup,
        update,
        close_workers,
        cache_warmup=None,
        stop_remote=None,
        remote_cpu=4,
        background_cpu=6,
        log=None,
        dimension=None,
    ):
        if owner_trace is not None and type(owner_trace) not in (trace.OwnerTrace, CacheOwnerTrace):
            raise ValueError("Actual fixed owner trace and policy required")
        if policy not in POLICIES:
            raise ValueError("Fixed trusted owner policy required")
        if (
            type(words) is not tuple
            or len(words) != 8
            or type(rows) is not tuple
            or type(ids) is not tuple
        ):
            raise ValueError("Frozen eight words and complete immutable rows/IDs required")
        if owner_trace is None:
            if (
                type(log) is not trace.EventLog
                or type(dimension) is not int
                or not 1 <= dimension <= 512
            ):
                raise ValueError("Deferred preparation needs a fixed log and public dimension")
        else:
            dimension = (
                owner_trace.cache.current_context.dimension
                if owner_trace.cache is not None
                else owner_trace.descriptor.metadata().geometry.dimension
            )
            if log is not None and log is not owner_trace.log:
                raise ValueError("One owner event log required")
            log = owner_trace.log
        if not rows or len(rows) != len(ids) or len(set(ids)) != len(ids):
            raise ValueError("Complete unique row/ID coverage required")
        for word in (*words, *rows):
            trace._word(word, dimension)
        if any(type(x) is not int or not 0 <= x < 1 << 64 for x in ids):
            raise ValueError("Complete UInt64 IDs required")
        if (
            policy in ("returning-cache", "fresh-cache")
            and owner_trace is not None
            and type(owner_trace) is not CacheOwnerTrace
        ):
            raise ValueError("Raw-cache control cannot be forced through HE metadata")
        if (
            owner_trace is not None
            and policy in ("remote", "prefetch")
            and type(owner_trace) is not trace.OwnerTrace
        ):
            raise ValueError("An actual encrypted owner path is required")
        if policy == "prefetch" and (
            owner_trace is not None and owner_trace.cache is None or not callable(stop_remote)
        ):
            raise ValueError("Prefetch requires cache and explicit owned remote shutdown")
        if policy == "fresh-cache" and not callable(cache_warmup):
            raise ValueError("Fresh-cache code warmup without acquisition required")
        if not all(callable(x) for x in (setup, update, close_workers, guard)):
            raise ValueError("Fixed trusted setup/update/cleanup/resource operations required")
        if (
            type(operation_timeout_ns) is not int
            or not 1 <= operation_timeout_ns <= 900_000_000_000
            or owner_trace is not None
            and operation_timeout_ns > owner_trace.endpoint.timeout_ns
        ):
            raise ValueError("Bounded operation timeout required")
        trace._label(label)
        self.trace, self.policy, self.label = owner_trace, policy, label
        self.log, self.dimension = log, dimension
        self.words, self.rows, self.ids = words, rows, ids
        self.output, self.guard, self.timeout = Path(output), guard, operation_timeout_ns
        if self.output.exists():
            raise ValueError("Trajectory attempt output already consumed")
        self.setup, self.update, self.close_workers = setup, update, close_workers
        self.cache_warmup, self.stop_remote = cache_warmup, stop_remote
        self.remote_cpu, self.background_cpu = remote_cpu, background_cpu
        self._pid, self._consumed = os.getpid(), False
        self.observations, self.checks = [], []

    def deadline(self):
        self.guard()
        return time.perf_counter_ns() + self.timeout

    def _check_result(self, result, word, rows, label):
        # Complete independent plaintext oracle, outside owner completion.
        expected = tuple((row ^ word).bit_count() for row in rows)
        top = sorted(range(len(rows)), key=lambda i: (expected[i], i))[:3]
        nearest = tuple(owner.Match(i, self.ids[i], expected[i]) for i in top)
        if (
            type(result) is not owner.SearchResult
            or result.distances != expected
            or result.nearest != nearest
        ):
            raise ValueError("Complete distance or ordinal/ID oracle disagreement")
        self.checks.append(
            {
                "label": label,
                "count": len(rows),
                "complete": True,
                "distances_sha256": hashlib.sha256(
                    b"".join(x.to_bytes(2, "little") for x in expected)
                ).hexdigest(),
            }
        )

    def run(self):
        if os.getpid() != self._pid or self._consumed:
            raise RuntimeError("Inherited or consumed trajectory attempt")
        self._consumed = True
        result = {
            "label": self.label,
            "policy": self.policy,
            "status": "starting",
            "started_ns": time.perf_counter_ns(),
            "error_class": None,
            "primary": "Actual owner completion minus causal query arrival",
            "scope": "Local prototype, not attestation or a secure deployment",
        }
        # Persist before setup, including a partially failed attempt.
        attempt = self.output.with_suffix(self.output.suffix + ".attempt.json")
        write_once(attempt, result)
        cleanup_errors, job = [], None
        try:
            with self.log.event("trajectory-setup"):
                prepared = self.setup(self.deadline())
                if self.trace is None:
                    if type(prepared) not in (trace.OwnerTrace, CacheOwnerTrace):
                        raise ValueError("Preparation must return an actual owned trajectory")
                    self.trace = prepared
                elif prepared is not None and prepared is not self.trace:
                    raise ValueError("Preparation replaced an existing trajectory")
                if (
                    type(self.trace) not in (trace.OwnerTrace, CacheOwnerTrace)
                    or self.trace.log is not self.log
                ):
                    raise ValueError("Preparation must return the actual owned trajectory")
                if self.policy.endswith("cache") and type(self.trace) is not CacheOwnerTrace:
                    raise ValueError("Cache-only preparation cannot require HE metadata")
                if (
                    self.policy in ("remote", "prefetch")
                    and type(self.trace) is not trace.OwnerTrace
                ):
                    raise ValueError("Encrypted preparation must return an actual owner trace")
                if self.policy == "prefetch" and self.trace.cache is None:
                    raise ValueError("Prefetch preparation requires an absent cache handle")
                actual_dimension = (
                    self.trace.cache.current_context.dimension
                    if self.trace.cache is not None
                    else self.trace.descriptor.metadata().geometry.dimension
                )
                if (
                    actual_dimension != self.dimension
                    or self.timeout > self.trace.endpoint.timeout_ns
                ):
                    raise ValueError(
                        "Prepared shape or deadline differs from the frozen trajectory"
                    )
            if self.policy == "returning-cache":
                self.trace.acquire(deadline_ns=self.deadline())
            with self.trace.log.event("excluded-warmup"):
                if self.policy == "fresh-cache":
                    self.cache_warmup(self.deadline())
                else:
                    answer = self.trace.query(
                        self.words[0],
                        label="excluded-warmup-query",
                        policy="cache" if self.policy == "returning-cache" else "remote",
                        arrival_ns=time.perf_counter_ns(),
                        deadline_ns=self.deadline(),
                    )
                    self._check_result(answer, self.words[0], self.rows, "excluded-warmup")
            for i, word in enumerate(self.words):
                self.guard()
                arrival, deadline = time.perf_counter_ns(), self.deadline()
                label = f"measured-{i}"
                # The first fresh-cache arrival precedes acquisition. No
                # returning-cache query is relabelled as cold acquisition.
                with self.trace.log.event(label + "-completion", arrival_ns=arrival):
                    if i == 0 and self.policy == "fresh-cache":
                        self.trace.acquire(deadline_ns=deadline)
                    if i == 0 and self.policy == "prefetch":
                        job = self.trace.start_acquisition(
                            deadline_ns=deadline, cpu=self.background_cpu
                        )
                    if self.policy == "prefetch":
                        answer = self.trace.race_query(
                            word,
                            label=label,
                            arrival_ns=arrival,
                            deadline_ns=deadline,
                            remote_cpu=self.remote_cpu,
                        )
                    else:
                        answer = self.trace.query(
                            word,
                            label=label,
                            arrival_ns=arrival,
                            deadline_ns=deadline,
                            policy="remote" if self.policy == "remote" else "cache",
                        )
                    completion = time.perf_counter_ns()
                self.observations.append(
                    {
                        "query": i,
                        "arrival_ns": arrival,
                        "completion_ns": completion,
                        "owner_latency_ns": completion - arrival,
                    }
                )
                self._check_result(answer, word, self.rows, label)
                self.guard()
            if self.policy == "prefetch":
                with self.trace.log.event("paid-prefetch-settlement"):
                    job.join(deadline_ns=self.deadline())
                    self.trace.join_races(deadline_ns=self.deadline())
                    self.trace.stop_remote()
                    self.stop_remote(self.deadline())
            with self.trace.log.event("paid-owner-update"):
                new_trace, changed_rows = self.update(self.deadline())
                if (
                    type(new_trace) not in (trace.OwnerTrace, CacheOwnerTrace)
                    or type(changed_rows) is not tuple
                    or len(changed_rows) != len(self.rows)
                ):
                    raise ValueError(
                        "Actual refreshed trajectory and complete current rows required"
                    )
                if self.policy == "prefetch" and type(new_trace) is not CacheOwnerTrace:
                    raise ValueError("Settled prefetch update must use its cache-only path")
                expected_rows = tuple(
                    self.words[i % 2] ^ 1 if i < 32 else row for i, row in enumerate(self.rows)
                )
                if changed_rows != expected_rows:
                    raise ValueError("Update differs from the frozen first-32-row replacement law")
                if new_trace.log is not self.log:
                    raise ValueError("Update replaced the actual owner event history")
                self.trace = new_trace
            answer = self.trace.query(
                self.words[0],
                label="post-update-check",
                arrival_ns=time.perf_counter_ns(),
                deadline_ns=self.deadline(),
                policy="remote" if self.policy == "remote" else "cache",
            )
            self._check_result(answer, self.words[0], changed_rows, "post-update-check")
            self.guard()
            result["status"] = "complete"
        except BaseException as error:
            result.update(status="failed", error_class=type(error).__name__)
        finally:
            # Worker shutdown first unblocks owned RPC/native work. Do not
            # serialize exception messages or send private diagnostics back.
            closes = (
                (self.close_workers,)
                if self.trace is None
                else (self.close_workers, self.trace.close)
            )
            for close in closes:
                try:
                    close()
                except BaseException as error:
                    cleanup_errors.append(type(error).__name__)
            if cleanup_errors:
                result["status"] = "failed"
            try:
                inventory = (
                    self.trace.inventory()
                    if self.trace is not None
                    else {"owner_trace_preparation_unfinished": True, "trace": self.log.inventory()}
                )
            except BaseException as error:
                inventory = {"inventory_failure_class": type(error).__name__}
                result["status"] = "failed"
            result.update(
                finished_ns=time.perf_counter_ns(),
                cleanup_error_classes=cleanup_errors,
                observations=self.observations,
                complete_oracle_checks=self.checks,
                owner_inventory=inventory,
            )
            write_once(self.output, result)
        return result
