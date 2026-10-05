"""One frozen Q77 complete owner cohort, with no retries or resumed lifetimes.

This is the actual provisioning/transfer/preparation/query/update action. The
committed addendum pins inputs, code, libraries, order, budgets and guards.
Calibration freezes selectors before any held-out block. Clean public workers
are launched by a manager created before owner keys; all owner traffic shares
one upload lane and one relay download lane within each independent lifetime.

The local signer and shaped loopback experiment are not attestation, parameter
approval, a new cryptographic scheme or an independently timed bare evaluator.
"""

# ruff: noqa: E402 -- standalone entry sets thread policy before project imports.
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if __name__ == "__main__":
    for _name in (
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "MKL_NUM_THREADS",
        "NUMEXPR_NUM_THREADS",
    ):
        os.environ[_name] = "1"

from benchmarks import complete_cost_owner_cohort as assembly
from benchmarks import complete_cost_owner_lab as worker
from benchmarks import complete_cost_shared_query_lab as roles
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_cohort as cohort
from experiments.bfv_search_lab import complete_cost_cohort_relay as cohort_relay
from experiments.bfv_search_lab import complete_cost_coordinator as coordinator
from experiments.bfv_search_lab import complete_cost_network as network
from experiments.bfv_search_lab import complete_cost_owner as owner
from experiments.bfv_search_lab import complete_cost_relay as relay
from experiments.bfv_search_lab import complete_cost_supervisor as supervisor
from experiments.bfv_search_lab import complete_cost_tenant as tenant_module
from experiments.bfv_search_lab import complete_cost_trace as trace
from experiments.bfv_search_lab import authenticated_cache as cache
from experiments.bfv_search_lab import shared_query_certificate as cert
from experiments.bfv_search_lab import shared_query_client_context as context

SIZES = (8224, 16384, 32768)
TRAJECTORIES = ("m0", "m1", "m2", "returning", "fresh", "prefetch")
CPUS = {
    "owner": 4,
    "producer": 0,
    "protected": 2,
    "relay": 1,
    "cache_background": 6,
    "manager": 3,
    "assembler": 5,
    "telemetry": 7,
}
LIMITS = dict(cohort.HISTORICAL_LIMITS, query_encryptions=702, protected_signing_keys=72)
RETENTION = (
    "retain-inputs-receipts-and-recovery; "
    "retire-verified-successful-upload-and-assembly-scratch; "
    "retain-failures; no-full-witness-copy-v1"
)


def cohort_order():
    """Commit the entire order before timing: six calibration, twelve held-out."""
    result = []
    for block in range(3):
        for key in range(2):
            for size_index, count in enumerate(SIZES):
                offset = (3 * key + size_index + block) % len(TRAJECTORIES)
                order = TRAJECTORIES[offset:] + TRAJECTORIES[:offset]
                if (key + size_index + block) % 2:
                    order = tuple(reversed(order))
                result.append(
                    {
                        "key": key,
                        "count": count,
                        "block": block,
                        "phase": "calibration" if block == 0 else "held-out",
                        "trajectories": list(order),
                    }
                )
    return result


def query_bytes():
    return (
        bytes.fromhex("55" * 64),
        bytes.fromhex("a3" * 64),
        *(
            hashlib.shake_256(b"cuhepy/Q77/public-query/v1" + i.to_bytes(8, "little")).digest(64)
            for i in range(2, 8)
        ),
    )


def _git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def validate_execution(path):
    """Pure preflight. Reject before any manager, native library or owner key."""
    path = Path(path).resolve(strict=True)
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        raise ValueError(
            "Execution addendum must be committed in the research repository"
        ) from None
    committed = subprocess.check_output(["git", "show", "HEAD:" + str(relative)], cwd=ROOT)
    if committed != path.read_bytes() or _git("status", "--porcelain"):
        raise ValueError("Exact committed execution addendum and clean source tree required")
    freeze = roles.verify_freeze(path)
    required = {
        "schema_version",
        "task",
        "implementation_commit",
        "new_sources",
        "preserved_runtime_sources",
        "dependencies",
        "python",
        "native_library",
        "cache_library",
        "executed_public_libraries",
        "private_extension",
        "corpus",
        "profile",
        "order",
        "query_bytes_sha256",
        "limits",
        "cpus",
        "client_link",
        "internal_link",
        "guard",
        "retention",
        "prefetch_calibration_mode",
        "inactive_verifier_anchor_policy",
    }
    if type(freeze) is not dict or set(freeze) != required:
        raise ValueError("Complete exact Q77 execution grammar required")
    g = cert.geometry(2)
    expected_geometry = json.loads(json.dumps(asdict(g)))
    if (
        freeze["schema_version"] != 1
        or freeze["task"] != "Q77_reserved_owner_complete_cost"
        or freeze["profile"] != expected_geometry
        or freeze["order"] != cohort_order()
        or freeze["limits"] != LIMITS
        or freeze["cpus"] != CPUS
        or freeze["client_link"] != asdict(roles.CLIENT_LINK)
        or freeze["internal_link"] != asdict(roles.INTERNAL_LINK)
        or freeze["retention"] != RETENTION
        or freeze["prefetch_calibration_mode"] != cert.MODES[1]
        or freeze["query_bytes_sha256"] != hashlib.sha256(b"".join(query_bytes())).hexdigest()
        or freeze["inactive_verifier_anchor_policy"] != "honest-owner-anchor-no-cloud-receipts-v1"
    ):
        raise ValueError("Frozen profile/order/limits/links/retention law differs from reservation")
    sources = freeze["new_sources"] + freeze["preserved_runtime_sources"]
    for module in (
        sys.modules[__name__],
        assembly,
        tenant_module,
        coordinator,
        trace,
        supervisor,
        relay,
        cohort_relay,
        worker,
        roles,
    ):
        if supervisor.pinned(module.__file__) not in sources:
            raise ValueError("Complete owner/worker source missing from execution freeze")
    if freeze["python"] != supervisor.pinned(sys.executable):
        raise ValueError("Actual interpreter differs from execution freeze")
    supervisor.check_pin(freeze["python"])
    supervisor.check_pin(freeze["corpus"])
    supervisor.check_pin(freeze["private_extension"])
    if freeze["corpus"]["bytes"] != 32768 * 64:
        raise ValueError("Exact public 32768-row source corpus required")
    if {freeze["native_library"]["file"], freeze["cache_library"]["file"]} != {
        entry["file"] for entry in freeze["executed_public_libraries"]
    }:
        raise ValueError("Only the exact selected native and popcount libraries may execute")
    for entry in freeze["executed_public_libraries"]:
        supervisor.check_pin(entry)
    guard = freeze["guard"]
    if (
        type(guard) is not dict
        or set(guard)
        != {
            "artifact_limit",
            "min_available_bytes",
            "wall_budget_ns",
            "operation_timeout_ns",
            "telemetry_interval_ns",
        }
        or any(type(x) is not int for x in guard.values())
        or guard["artifact_limit"] != 10 << 30
        or not 1 <= guard["min_available_bytes"] <= 1 << 40
        or not 1 <= guard["wall_budget_ns"] <= 86_400_000_000_000
        or not 1 <= guard["operation_timeout_ns"] <= roles.TIMEOUT_NS
        or not 50_000_000 <= guard["telemetry_interval_ns"] <= 1_000_000_000
        or not set(CPUS.values()) <= os.sched_getaffinity(0)
    ):
        raise ValueError("Explicit frozen memory/deadline/telemetry/available CPU guards required")
    # The addendum must follow the implementation, not merely name any SHA.
    ancestor = _git("rev-parse", freeze["implementation_commit"] + "^{commit}")
    subprocess.check_call(["git", "merge-base", "--is-ancestor", ancestor, "HEAD"], cwd=ROOT)
    if shutil.disk_usage(ROOT).free < 20 << 30:
        raise RuntimeError("At least 20 GiB filesystem headroom required before Q77 execution")
    return freeze


def select_policies(results, path):
    """Use the complete six-block calibration once, with deterministic ties."""
    expected = {
        (key, count, label) for key in range(2) for count in SIZES for label in TRAJECTORIES
    }
    if type(results) is not list or len(results) != 36:
        raise ValueError("All six complete calibration blocks required before policy selection")
    identities = {(x["key"], x["count"], x["trajectory"]) for x in results}
    if identities != expected or any(
        x["block"] != 0 or x["status"] != "complete" or len(x["observations"]) != 8 for x in results
    ):
        raise ValueError("Missing, duplicate, failed or held-out calibration inputs")
    for result in results:
        supervisor.check_pin(result["result_pin"])
        retained = json.loads(Path(result["result_pin"]["file"]).read_text())
        supplied = json.loads(json.dumps({k: v for k, v in result.items() if k != "result_pin"}))
        if retained != supplied:
            raise ValueError("Supplied calibration rows differ from their retained inputs")
    client, evaluator, input_pins = {}, {}, []
    for count in SIZES:
        paid, projected = {}, {}
        for label in TRAJECTORIES[:3]:
            chosen = [x for x in results if x["count"] == count and x["trajectory"] == label]
            # Optimize the registered arithmetic-mean objective. Each key
            # supplies exactly eight requests, preserving equal key weights.
            paid[label] = statistics.fmean(
                o["owner_latency_ns"] for x in chosen for o in x["observations"]
            )
            if any(
                type(x.get("evaluator_projection_ns")) is not list
                or len(x["evaluator_projection_ns"]) != 8
                for x in chosen
            ):
                raise ValueError("Actual attributed measured-query native projection required")
            projected[label] = statistics.fmean(
                v for x in chosen for v in x["evaluator_projection_ns"]
            )
        client[str(count)] = min(paid, key=lambda x: (paid[x], x))
        evaluator[str(count)] = min(projected, key=lambda x: (projected[x], x))
    for result in results:
        supervisor.check_pin(result["result_pin"])
        input_pins.append(result["result_pin"])
    policy = {
        "schema_version": 1,
        "client_remote": client,
        "evaluator_projection_remote": evaluator,
        "generic_same_information_remote": dict(client),
        "calibration_inputs": input_pins,
        "selection_implementation": supervisor.pinned(__file__),
        "legal_choices": list(TRAJECTORIES[:3]),
        "weights": "equal key/size/query",
        "selection_metric": "arithmetic mean of actual owner completion minus arrival",
        "tie_rule": "lexical trajectory label",
        "held_out_inputs": 0,
        "evaluator_projection_is_not_bare_evaluator_measurement": True,
        "cache_initial_states_compared_separately": True,
        "prefetch_held_out_mode": {k: cert.MODES[int(v[1])] for k, v in client.items()},
    }
    coordinator.write_once(path, policy)
    return policy


def _atomic(path, value):
    """Trusted local mutable config/registry; peer messages cannot call this."""
    path = Path(path)
    temporary = path.with_name(path.name + ".pending")
    coordinator.write_once(temporary, value)
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _pin_fields(pin):
    return {
        key: value.hex() if type(value) is bytes else value for key, value in asdict(pin).items()
    }


def _projection(report):
    clocks = report["actual_native_clocks"]
    phases = [x["id"] for x in clocks["phases"] if x["phase"] == "run"]
    if len(phases) != 10:
        raise ValueError("Warmup, eight queries and post-update native runs required")
    symbols = set(clocks["computational_projection"]["included_symbols"])
    return [
        sum(
            x["end_ns"] - x["start_ns"]
            for x in clocks["calls"]
            if x["phase_id"] == phase and x["symbol"] in symbols and x["status"] == "returned"
        )
        for phase in phases[1:9]
    ]


class OwnerStudy:
    """One owned full-cohort action, never a proxy timing or resumed job."""

    def __init__(self, addendum, output):
        self.freeze = validate_execution(addendum)
        self.addendum = Path(addendum).resolve(strict=True)
        self.root = Path(output).resolve()
        if self.root.exists() or self.root.is_symlink():
            raise ValueError("Cohort output already consumed; no resume or replacement")
        self.root.mkdir()
        self._pid, self._consumed, self._seq = os.getpid(), False, 0
        self.manager = self.provisioner = self.ledger = self.native_cache = None
        self.active, self.history, self.results = {}, [], []
        limits = self.freeze["guard"]
        self.deadline = time.perf_counter_ns() + limits["wall_budget_ns"]
        self.guard = coordinator.ResourceGuard(
            self.root,
            self.root / "guard.json",
            artifact_limit=limits["artifact_limit"],
            min_available_bytes=limits["min_available_bytes"],
            deadline_ns=self.deadline,
        )
        self.registry = self.root / "owned-pids.json"
        self.telemetry_samples = self.root / "telemetry.jsonl"
        self.policy = None

    def _registry(self):
        records = [
            {"label": "owner", "pid": self._pid},
            {"label": "manager", "pid": self.manager.process_id},
        ]
        records.extend(
            {"label": label, "pid": item["process"]} for label, item in self.active.items()
        )
        for record in records:
            record["birth_ticks"] = worker.process_counters(record["pid"])["birth_ticks"]
        _atomic(self.registry, records)

    def _start(self, label, entry, config, cpu, directory):
        self.guard.check()
        path, output = directory / (label + ".config.json"), directory / (label + ".worker.json")
        coordinator.write_once(path, config)
        spec = supervisor.WorkerSpec(
            label, supervisor.pinned(entry), str(path), str(self.addendum), str(output), cpu
        )
        # Validation requires unconsumed output paths, so capture the public
        # specification before the supervisor creates any child artifacts.
        fields = spec.fields()
        ready = self.manager.start((spec,))[label]
        self.active[label] = ready
        self.history.append(
            {
                "label": label,
                "birth": worker.process_counters(ready["process"]),
                "spec": fields,
                "ready": ready,
            }
        )
        self._registry()
        self.guard.check()
        return ready, path, output

    def _stop(self, labels):
        labels = tuple(label for label in labels if label in self.active)
        if labels:
            removed = {label: self.active.pop(label) for label in labels}
            # Remove old births before stopping; never follow a reused PID.
            self._registry()
            self.manager.stop(labels)
            self.history.append({"stopped": list(removed), "monotonic_ns": time.perf_counter_ns()})

    def _ready(self):
        if (
            self.manager is None
            or self.manager._process.poll() is not None
            or "telemetry" not in self.active
        ):
            return False
        record = worker.process_counters(self.active["telemetry"]["process"])
        if record["birth_ticks"] != next(
            x["birth"]["birth_ticks"] for x in self.history if x.get("label") == "telemetry"
        ):
            return False
        return self.telemetry_samples.exists() and self.telemetry_samples.stat().st_size > 0

    def _bootstrap(self):
        limits = self.freeze["guard"]
        self.manager = supervisor.PublicSupervisor(
            self.root / "manager.json",
            source_pin=supervisor.pinned(supervisor.__file__),
            python_pin=self.freeze["python"],
            timeout_ns=limits["operation_timeout_ns"],
            manager_cpu=CPUS["manager"],
        )
        self._registry()
        cfg = {
            "role": "frontend",
            "service": "public-resource-telemetry",
            "registry": str(self.registry),
            "samples": str(self.telemetry_samples),
            "guard": str(self.root / "guard.json"),
            "interval_ns": limits["telemetry_interval_ns"],
            "max_samples": 172800,
            "max_bytes": 128 << 20,
            "deadline_ns": self.deadline,
            "min_available_bytes": limits["min_available_bytes"],
        }
        self._start("telemetry", worker.__file__, cfg, CPUS["telemetry"], self.root)
        ready_deadline = min(self.deadline, time.perf_counter_ns() + 5_000_000_000)
        while not self._ready():
            self.guard.check()
            if time.perf_counter_ns() > ready_deadline:
                raise TimeoutError("Actual telemetry sample readiness failed")
            time.sleep(0.01)
        os.sched_setaffinity(0, {CPUS["owner"]})
        self.ledger = cohort.ResourceLedger(self.root / "resources.jsonl", self.freeze["limits"])
        self.provisioner = tenant_module.TenantProvisioner(
            self.root / "tenants",
            self.ledger,
            geometry=cert.geometry(2),
            guard=self.guard.check,
            ready=self._ready,
            # Retained public inputs fit their historical 8 GiB archive cap.
            # The separately registered 10 GiB guard also covers live uploads,
            # assemblies, telemetry and diagnostics outside that archive.
            byte_limit=8 << 30,
        )
        self.library = roles.native.NativeLibrary(self.freeze["native_library"]["file"])
        self.native_cache = cache.NativePopcount(self.freeze["cache_library"]["file"])

    def _policies(self, anchor):
        return (
            tuple(factory(anchor, self.library).policy_digest for factory in roles.FACTORIES),
            bytes.fromhex(self.freeze["native_library"]["sha256"]),
        )

    def run(self):
        if os.getpid() != self._pid or self._consumed:
            raise RuntimeError("Inherited or consumed owner cohort")
        self._consumed = True
        coordinator.write_once(
            self.root / "attempt.json",
            {
                "started_ns": time.perf_counter_ns(),
                "addendum": supervisor.pinned(self.addendum),
                "order": cohort_order(),
                "retry": False,
            },
        )
        outcome = {"status": "failed", "error_class": None, "cleanup_error_classes": []}
        original_affinity = os.sched_getaffinity(0)
        try:
            self._bootstrap()
            raw = roles.pinned_bytes(self.freeze["corpus"])
            rows = tuple(int.from_bytes(raw[i : i + 64], "little") for i in range(0, len(raw), 64))
            ids = tuple((1 << 64) - 1 - i for i in range(len(rows)))
            words = tuple(int.from_bytes(x, "little") for x in query_bytes())
            tenants, views = {}, {}
            for slot in range(2):
                tenants[slot] = self.provisioner.create(slot, policy_builder=self._policies)
                for count in SIZES:
                    views[slot, count] = tenants[slot].initial(rows[:count], ids[:count])
            for block in cohort_order():
                self.guard.check()
                if block["phase"] == "held-out" and self.policy is None:
                    select_start, select_cpu = time.perf_counter_ns(), time.thread_time_ns()
                    self.policy = select_policies(self.results, self.root / "policy-freeze.json")
                    self.policy_pin = supervisor.pinned(self.root / "policy-freeze.json")
                    coordinator.write_once(
                        self.root / "policy-selection-cost.json",
                        {
                            "selection_wall_ns": time.perf_counter_ns() - select_start,
                            "selection_cpu_ns": time.thread_time_ns() - select_cpu,
                            "policy": self.policy_pin,
                            "held_out_inputs": 0,
                        },
                    )
                if self.policy is not None:
                    supervisor.check_pin(self.policy_pin)
                for label in block["trajectories"]:
                    result = self._trajectory(
                        block,
                        label,
                        tenants[block["key"]],
                        views[block["key"], block["count"]],
                        words,
                    )
                    self.results.append(result)
                    if result["status"] != "complete":
                        raise RuntimeError(
                            "Consumed trajectory failed; cohort stopped without replacement"
                        )
            if len(self.results) != 108:
                raise RuntimeError("Reserved 18 by six trajectory coverage incomplete")
            outcome["status"] = "complete"
        except BaseException as error:
            outcome["error_class"] = type(error).__name__
        finally:
            for operation in (
                lambda: self._stop(tuple(x for x in self.active if x != "telemetry")),
                lambda: self._stop(("telemetry",)),
                lambda: self.manager.close() if self.manager else None,
                lambda: self.provisioner.close() if self.provisioner else None,
                lambda: self.native_cache.close() if self.native_cache else None,
                lambda: self.ledger.close() if self.ledger else None,
            ):
                try:
                    operation()
                except BaseException as error:
                    outcome["cleanup_error_classes"].append(type(error).__name__)
                    outcome["status"] = "failed"
            os.sched_setaffinity(0, original_affinity)
            outcome.update(
                finished_ns=time.perf_counter_ns(),
                results=self.results,
                resource_inventory=None if self.ledger is None else self.ledger.inventory(),
                process_history=self.history,
                guard=self.guard.inventory(),
                policy=self.policy,
                keys_blocks_or_retries_not_replaced=True,
                scope=(
                    "Selected local CPU/shaped-loopback prototype; "
                    "no attestation/parameter assurance"
                ),
            )
            coordinator.write_once(self.root / "cohort-result.json", outcome)
        return outcome

    def _trajectory(self, block, label, tenant, view, words):
        """Independent actual worker preparation and owned owner/cache handles."""
        session = Session(self, block, label, tenant, view)
        policy = (
            "remote"
            if label in TRAJECTORIES[:3]
            else {"returning": "returning-cache", "fresh": "fresh-cache", "prefetch": "prefetch"}[
                label
            ]
        )
        runner = coordinator.TrajectoryRunner(
            None,
            policy=policy,
            label=session.label,
            words=words,
            rows=view.rows,
            ids=view.ids,
            output=session.result_path,
            guard=self.guard.check,
            operation_timeout_ns=self.freeze["guard"]["operation_timeout_ns"],
            setup=session.setup,
            update=lambda deadline: session.update(words, deadline),
            close_workers=session.close,
            cache_warmup=session.cache_warmup,
            stop_remote=session.stop_remote,
            remote_cpu=CPUS["owner"],
            background_cpu=CPUS["cache_background"],
            log=session.log,
            dimension=tenant.provisioner.geometry.dimension,
        )
        result = runner.run()
        result.update(
            key=block["key"],
            count=block["count"],
            block=block["block"],
            trajectory=label,
            trajectory_pin=supervisor.pinned(session.result_path),
        )
        if policy == "remote" and result["status"] == "complete":
            side = "protected" if session.mode == cert.MODES[1] else "producer"
            result["evaluator_projection_ns"] = _projection(
                json.loads(session.outputs[side].read_text())
            )
        if result["status"] == "complete":
            # Retire only after both the full independent oracle and cleanup
            # returned successfully. A trace alone cannot detect oracle faults.
            session.retire_success()
        coordinator.write_once(session.directory / "study-row.json", result)
        result["result_pin"] = supervisor.pinned(session.directory / "study-row.json")
        return result


class Session:
    """One independent preparation/race/update lifetime on shared client lanes."""

    def __init__(self, study, block, trajectory, tenant, view):
        self.study, self.block, self.trajectory, self.tenant, self.view = (
            study,
            block,
            trajectory,
            tenant,
            view,
        )
        self.label = f"k{block['key']}_n{block['count']}_b{block['block']}_{trajectory}"
        self.directory = study.root / self.label
        self.directory.mkdir()
        self.result_path = self.directory / "trajectory.json"
        self.log = trace.EventLog(self.label)
        self.live, self.outputs, self.configs, self.handles, self.retired = {}, {}, {}, [], []
        self.endpoint = self.path = self.assembler = None
        self.mode = cert.MODES[int(trajectory[1])] if trajectory.startswith("m") else None
        if trajectory == "prefetch":
            self.mode = (
                cert.MODES[1]
                if block["block"] == 0
                else study.policy["prefetch_held_out_mode"][str(block["count"])]
            )

    def _start(self, role, entry, cfg, cpu):
        ready, config, output = self.study._start(
            self.label + "_" + role, entry, cfg, cpu, self.directory
        )
        self.live[role], self.configs[role], self.outputs[role] = ready, config, output
        return ready

    def _rpc(self, role, verb, deadline):
        reply = roles.rpc(
            self.live[role]["port"],
            auth._pack([verb]),
            link=supervisor.UNSHAPED,
            cap=roles.native.PACKET_CAP,
            timeout_ns=min(
                self.study.freeze["guard"]["operation_timeout_ns"],
                deadline - time.perf_counter_ns(),
            ),
        )
        if auth._unpack(reply, limit=4096, array_cap=3)[0] != roles.OK_TAG:
            raise ValueError("Owned public control command did not complete")

    def _retain_upload_envelope(self, packet):
        fields = auth._unpack(packet, limit=roles.native.PACKET_CAP, array_cap=5)
        inner = auth._unpack(fields[1], limit=roles.native.PACKET_CAP, array_cap=5)
        payload = auth._unpack(inner[1], limit=roles.native.PACKET_CAP, array_cap=5)
        summary = auth._pack([inner[0], payload[:-1], inner[2]])
        self.study.provisioner.archive.put(summary, kind="record")

    def _upload(self, body, phase, deadline):
        with self.log.event(phase.decode() + "-signed-shared-upload"):
            packet = cohort_relay.sign_upload(
                self.tenant.namespace, phase, body, self.tenant.signing_owner()
            )
            self._retain_upload_envelope(packet)
            reply = self.endpoint.rpc(packet, deadline_ns=deadline)
            fields = auth._unpack(reply, limit=4096, array_cap=4)
            if fields != [roles.OK_TAG, phase, len(body), hashlib.sha256(body).digest()]:
                raise ValueError("Actual shared upload acknowledgement differs")
        return supervisor.pinned(self.directory / (phase.decode() + ".upload"))

    def _routing(self):
        return json.loads(self.routing.read_text())

    def _install_routing(self, name, value):
        cfg = self._routing()
        cfg[name] = value
        _atomic(self.routing, cfg)

    def _assembly_delivery(self, phase):
        return {
            "packet": supervisor.pinned(self.directory / (phase + ".cache")),
            "descriptor": supervisor.pinned(self.directory / (phase + ".cache-descriptor")),
        }

    def _retire(self, pin):
        supervisor.check_pin(pin)
        Path(pin["file"]).unlink()
        self.retired.append(pin)

    def setup(self, deadline):
        self.study.guard.check()
        self.routing = self.directory / "routing.json"
        coordinator.write_once(
            self.routing,
            {
                "role": "frontend",
                "service": "shared-client-relay",
                "search_port": None,
                "cap": roles.native.PACKET_CAP,
                "timeout_ns": self.study.freeze["guard"]["operation_timeout_ns"],
                "client_link": self.study.freeze["client_link"],
                "upload": None,
                "snapshot": None,
                "patch": None,
            },
        )
        relay_cfg = {
            "role": "frontend",
            "service": "owner-bound-cohort-relay",
            "routing_config": str(self.routing),
            "owner_anchor": self.tenant.anchor.hex(),
            "namespace": self.tenant.namespace.hex(),
            "uploads": [
                {
                    "phase": phase,
                    "file": str(self.directory / (phase + ".upload")),
                    "max_bytes": roles.native.PACKET_CAP - cohort_relay.OVERHEAD_RESERVE,
                }
                for phase in ("initial", "update")
            ],
        }
        relay_ready = self._start("relay", cohort_relay.__file__, relay_cfg, CPUS["relay"])
        self.endpoint = relay.OwnerEndpoint(
            relay_ready["port"],
            upload_budget=network.DirectionBudget(roles.CLIENT_LINK),
            cap=roles.native.PACKET_CAP,
            timeout_ns=self.study.freeze["guard"]["operation_timeout_ns"],
        )
        original_rpc = self.endpoint.rpc

        def retained_rpc(packet, *, deadline_ns=None):
            response = original_rpc(packet, deadline_ns=deadline_ns)
            fields = auth._unpack(packet, limit=roles.native.PACKET_CAP, array_cap=3)
            if fields[0] == b"search":
                self.study.provisioner.archive.put(response, kind="record")
            return response

        self.endpoint.rpc = retained_rpc
        if self.mode is None:
            body, service = (
                assembly.cache_body(self.view.cache_delivery),
                "public-cohort-cache-assembly",
            )
        else:
            record = self.view.record(self.mode)
            full = b"".join(
                chunk for _, chunk in record.packet_chunks(self.study.provisioner.archive)
            )
            body = (
                assembly.combined_body(
                    record, self.view.descriptor.packet, full, self.view.cache_delivery
                )
                if self.trajectory == "prefetch"
                else assembly.upload_body(record, self.view.descriptor.packet, full)
            )
            del full
            service = (
                "public-cohort-combined-assembly"
                if self.trajectory == "prefetch"
                else "public-cohort-enrollment-assembly"
            )
        upload = self._upload(body, b"initial", deadline)
        del body
        cfg = {
            "role": "frontend",
            "service": service,
            "owner_anchor": self.tenant.anchor.hex(),
            "root": str(self.directory),
            "initial": upload,
            "update": None,
        }
        if self.mode is None or self.trajectory == "prefetch":
            cfg.update(
                cache_initial_context=assembly.context_fields(self.view.cache_delivery.context),
                cache_update_context=None,
            )
        self._start("assembler", assembly.__file__, cfg, CPUS["assembler"])
        self._retire(upload)  # Exact public recovery inputs/signatures remain retained.
        if self.mode is None or self.trajectory == "prefetch":
            self._install_routing("snapshot", self._assembly_delivery("initial"))
            self.cache = self.tenant.cache_client(
                self.study.native_cache, self.view.cache_delivery.context
            )
            self.handles.append(self.cache)
        if self.mode is None:
            self.path = coordinator.CacheOwnerTrace(self.cache, self.endpoint, self.log)
            return self.path
        self.study.ledger.take("protected_signing_keys", 1, label=self.label + "-protected-signer")
        protected_cfg = self._role_config("protected", None, self.view, "initial")
        protected = self._start("protected", worker.__file__, protected_cfg, CPUS["protected"])
        frontend_cfg = self._role_config("frontend", protected["port"], self.view, "initial")
        frontend = self._start("producer", worker.__file__, frontend_cfg, CPUS["producer"])
        self._install_routing("search_port", frontend["port"])
        descriptor = context.DescriptorClient(self.tenant.anchor, self.view.descriptor.pin)
        self.handles.append(descriptor)
        with self.log.event("actual-owner-descriptor-acquisition"):
            descriptor.acquire(self.endpoint.rpc(auth._pack([b"descriptor"]), deadline_ns=deadline))
        keys = self.tenant.custody()
        self.handles.append(keys)
        # Only the selected worker has cloud-release authority. Other modes use
        # the honest owner's anchor; no cloud worker has those signing keys.
        anchors = tuple(
            (
                mode,
                bytes.fromhex(protected["local_verifier_public_key"])
                if mode == self.mode
                else self.tenant.anchor,
            )
            for mode in cert.MODES
        )
        client = owner.OwnerClient(descriptor, anchors, keys)
        self.handles.append(client)
        source = trace.OwnerQuerySource(
            keys,
            self.tenant.signing_owner(),
            domain=hashlib.sha256(self.label.encode()).digest(),
            encryption_limit=9 if self.trajectory == "prefetch" else 10,
            attempt_observer=lambda i: self.study.ledger.take(
                "query_encryptions", 1, label=f"{self.label}-q{i}"
            ),
            packet_observer=lambda packet, _i: self.study.provisioner.archive.put(
                packet, kind="query"
            ),
        )
        self.handles.append(source)
        self.path = trace.OwnerTrace(
            descriptor,
            self.endpoint,
            self.log,
            mode=self.mode,
            client=client,
            query_source=source,
            cache_client=self.cache if self.trajectory == "prefetch" else None,
        )
        return self.path

    def _role_config(self, role, protected_port, view, phase):
        return {
            "role": role,
            "mode": self.mode,
            "library": self.study.freeze["native_library"],
            "owner_anchor": self.tenant.anchor.hex(),
            "journal": str(self.directory / (role + ".journal")),
            "protected_port": protected_port,
            "current_pin": _pin_fields(view.descriptor.pin),
            "descriptor": supervisor.pinned(self.directory / (phase + ".descriptor")),
            "enrollment": supervisor.pinned(self.directory / (phase + ".enrollment")),
        }

    def cache_warmup(self, _deadline):
        self.study.guard.check()
        dimension = self.tenant.provisioner.geometry.dimension
        width = (dimension + 7) // 8
        self.study.native_cache.scan(bytes(3 * width), 3, dimension, bytes(width))

    def stop_remote(self, _deadline):
        self.study._stop(tuple(self.label + "_" + role for role in ("producer", "protected")))
        for role in ("producer", "protected"):
            self.live.pop(role, None)
        coordinator.write_once(
            self.directory / "settled-remote-inventory.json", self.path.inventory()
        )

    def update(self, words, deadline):
        encrypted = self.trajectory in TRAJECTORIES[:3]
        updated = self.tenant.update(
            self.view, words, label=self.label + "-update", encrypted=encrypted
        )
        delivery = updated.cache_delivery if encrypted else updated[0]
        if encrypted:
            record = updated.record(self.mode)
            body = assembly.upload_body(
                record,
                updated.descriptor.packet,
                self.study.provisioner.archive.read(record.groups[0]),
            )
        else:
            body = assembly.cache_body(delivery)
        pin = self._upload(body, b"update", deadline)
        cfg = json.loads(self.configs["assembler"].read_text())
        cfg["update"] = pin
        if not encrypted:
            cfg["cache_update_context"] = assembly.context_fields(delivery.context)
        _atomic(self.configs["assembler"], cfg)
        self._rpc("assembler", b"refresh", deadline)
        self._retire(pin)
        if encrypted:
            for role in ("protected", "producer"):
                cfg = json.loads(self.configs[role].read_text())
                cfg.update(
                    current_pin=_pin_fields(updated.descriptor.pin),
                    descriptor=supervisor.pinned(self.directory / "update.descriptor"),
                    enrollment=supervisor.pinned(self.directory / "update.enrollment"),
                )
                _atomic(self.configs[role], cfg)
                self._rpc(role, b"refresh", deadline)
            self.path.advance(
                updated.descriptor.pin, updated.descriptor.packet, deadline_ns=deadline
            )
            return self.path, updated.rows
        self._install_routing("patch", self._assembly_delivery("update"))
        if self.trajectory == "prefetch":
            self.path = coordinator.CacheOwnerTrace(self.cache, self.endpoint, self.log)
        self.path.advance(delivery.context, deadline_ns=deadline)
        self.path.patch(deadline_ns=deadline)
        return self.path, updated[1]

    def close(self):
        first_error = None
        operations = [
            lambda: self.study._stop(tuple(self.label + "_" + role for role in tuple(self.live))),
            lambda: (
                self.path.close()
                if self.path is not None
                else self.endpoint.close()
                if self.endpoint is not None
                else None
            ),
            *(handle.close for handle in reversed(self.handles)),
        ]
        for operation in operations:
            try:
                operation()
            except BaseException as error:
                if first_error is None:
                    first_error = error
        self.live.clear()
        if first_error is not None:
            raise first_error

    def retire_success(self):
        """Called only after the runner's complete oracle and cleanup succeed."""
        # Success scratch is reconstructible from archived groups/records and
        # descriptors. Failed partial files remain, and are counted by the guard.
        for name in (
            "initial.enrollment",
            "update.enrollment",
            "initial.cache",
            "update.cache",
        ):
            path = self.directory / name
            if path.exists():
                self._retire(supervisor.pinned(path))
        coordinator.write_once(self.directory / "retired-public-scratch.json", self.retired)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "run"))
    parser.add_argument("--addendum", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.action == "preflight":
        validate_execution(args.addendum)
        print(json.dumps({"status": "preflight-valid", "HE_keys_or_measurements": 0}))
    else:
        if args.output is None:
            parser.error("run requires a fresh --output directory")
        result = OwnerStudy(args.addendum, args.output).run()
        print(json.dumps({"status": result["status"], "results": len(result["results"])}))
        if result["status"] != "complete":
            raise SystemExit(1)


if __name__ == "__main__":
    main()
