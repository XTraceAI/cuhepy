#!/usr/bin/env python3
"""One frozen E122 public counterexample gate; resource time is not speed."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
import hashlib
from itertools import combinations
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

from experiments.bfv_search_lab import joint_root as lab  # noqa: E402

WORK = REPO.parent / "research-data/joint-root-20261003"
RAW = REPO / "benchmarks/results/publication-joint-root-20261003.json"
PREREG = "docs/research/joint-root-preregistration-20261003.md"
PREREG_SHA = "8119b49f7c7a3cd6ea48c2f7a13af063a97df7bb19fb43920c8e91d6326904dc"
OWNED = ("experiments/bfv_search_lab/joint_root.py",
         "experiments/bfv_search_lab/test_joint_root.py", "benchmarks/joint_root_lab.py")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encode(value):
    if is_dataclass(value):
        return encode(asdict(value))
    if type(value) is dict:
        return {str(key): encode(item) for key, item in value.items()}
    if type(value) in (tuple, list):
        return [encode(item) for item in value]
    return value


def write_json(path, value):
    path.write_text(json.dumps(encode(value), indent=2) + "\n")


def require(condition, name, evidence):
    if not condition:
        write_json(WORK / "main-failure.json", {"check": name, "evidence": evidence})
        raise AssertionError(name)


def independent_horner(witness, point, q):
    value = 0
    for coefficient in witness[::-1]:
        value = (value * point + coefficient) % q
    return value


def signed_action_audit(ctx):
    group, modulus = tuple(range(1, 2 * ctx.n, 2)), 2 * ctx.n
    require(all((g * h) % modulus in group for g in group for h in group),
            "group_closure", group)
    require(all(g * pow(g, -1, modulus) % modulus == 1 for g in group),
            "group_inverses", group)
    evaluation_checks = 0
    composition_checks = 0
    for g in group:
        for j in range(ctx.n):
            basis = tuple(int(i == j) for i in range(ctx.n))
            transformed = lab.signed_action(basis, g)
            expected = tuple(((-1) ** ((j * g) // ctx.n)) if i == (j * g) % ctx.n else 0
                             for i in range(ctx.n))
            require(transformed == expected, "signed_basis_action", (g, j))
            for e in group:
                point = pow(ctx.root, e, ctx.q)
                require(independent_horner(transformed, point, ctx.q)
                        == pow(ctx.root, g * e * j, ctx.q), "inverse_zero_set_direction", (g, e, j))
                evaluation_checks += 1
            for h in group:
                require(lab.signed_action(transformed, h)
                        == lab.signed_action(basis, g * h % modulus),
                        "signed_action_composition", (g, h, j))
                composition_checks += 1
    return {"group_size": len(group), "group_closure_pairs": len(group) ** 2,
            "group_inverse_checks": len(group), "basis_evaluation_checks": evaluation_checks,
            "basis_composition_checks": composition_checks,
            "witness_zero_set_transport": "sigma_g sends T to inverse(g)*T"}


def independent_orbit_audit(inventory):
    """Bitmask images independently check tuple-based canonical assignments."""
    ctx = inventory.context
    exponents = tuple(range(1, 2 * ctx.n, 2))
    universe = tuple(combinations(exponents, inventory.root_count))
    canonical = {}
    for roots in universe:
        transformed = []
        for g in exponents:
            mask = 0
            for e in roots:
                transformed_e = g * e % (2 * ctx.n)
                mask |= 1 << ((transformed_e - 1) // 2)
            transformed.append(tuple(e for i, e in enumerate(exponents) if mask & (1 << i)))
        canonical[roots] = min(transformed)
    require(tuple(item[0] for item in inventory.assignments) == universe,
            "complete_lexicographic_universe", {})
    require(all(canonical[roots] == representative
                and canonical[representative] == representative
                for roots, representative, _ in inventory.assignments),
            "independent_bitmask_canonicalization", {})
    require(len({canonical[roots] for roots in universe}) == len(inventory.orbits),
            "independent_orbit_class_count", {})
    return {"root_subsets": len(universe), "independent_group_actions": len(universe) * len(exponents),
            "orbit_count": len(inventory.orbits), "all_assigned_once": True,
            "all_canonicalizations_idempotent": True}


def main():
    start = monotonic()
    if not __debug__ or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE") != "0":
        raise ValueError("Frozen main requires PYTHONOPTIMIZE=0 and enabled assertions")
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))

    def timeout(_signum, _frame):
        raise TimeoutError("Registered 60-second wall ceiling")

    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(60)
    WORK.mkdir(parents=True, exist_ok=True)
    receipt = json.loads((WORK / "root-contract-freeze.json").read_text())
    require(sha(REPO / PREREG) == PREREG_SHA == receipt["contract_sha256"], "contract_pin", {})
    freeze = json.loads((WORK / "source-argv-freeze.json").read_text())
    require(freeze["argv"] == [sys.executable, *sys.argv]
            and freeze["environment"] == {"PYTHONOPTIMIZE": "0"}, "argv_environment_pin", {})
    for name, digest in freeze["source_sha256"].items():
        require(sha(Path(name)) == digest, "source_pin", name)
    output = WORK / "main"
    require(not output.exists() and not RAW.exists(), "one_fresh_main_only", {})
    output.mkdir()
    snapshot = output / "before-main-sources"
    snapshot.mkdir()
    for name in (*OWNED, PREREG):
        target = snapshot / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, target)
    phase = "root_selection"
    try:
        #The actual context/root/orbits are evaluated here, never on import.
        ctx = lab.least_root(16, 97)
        require(all(pow(z, 16, 97) != 96 for z in range(2, ctx.root)), "least_root_selector", {})
        write_json(output / "selected-public-root.json", {"context": ctx,
                                                          "selector_candidates": ctx.root - 1,
                                                          "powers": [pow(ctx.root, j, ctx.q) for j in range(32)]})
        phase = "complete_signed_orbit_inventory"
        action_audit = signed_action_audit(ctx)
        inventory = lab.orbit_inventory(ctx, 4)
        orbit_audit = independent_orbit_audit(inventory)
        require(orbit_audit["root_subsets"] == 1820, "all1820rootsets_before_mass", orbit_audit)
        inventory_path = output / "complete-orbit-inventory.json"
        write_json(inventory_path, inventory)
        inventory_digest = sha(inventory_path)
        representatives = tuple(orbit.representative for orbit in inventory.orbits)
        phase = "ascending_representative_mass_prefix"
        prefix_path = output / "mass-prefix.jsonl"

        def evaluate(roots):
            count = lab.count_roots(ctx, roots)
            require(count.total_count >= 1 and count.total_count & 1,
                    "zero_included_once_and_signed_pairs", count)
            if lab.is_quartic_packet(ctx, roots):
                require(count.total_count == 1, "known_structured_zero_only_control", count)
            if count.witness is not None:
                require(any(count.witness) and all(type(x) is int and x in (-1, 0, 1) for x in count.witness),
                        "strict_nonzero_witness", count)
                points = tuple(pow(ctx.root, e, ctx.q) for e in roots)
                require(all(independent_horner(count.witness, point, ctx.q) == 0 for point in points),
                        "independent_literal_Horner_witness", count)
            return count

        def completed(count, index):
            with prefix_path.open("a") as file:
                file.write(json.dumps(encode({"index": index, "count": count,
                                              "structured_quartic": lab.is_quartic_packet(ctx, count.roots)})) + "\n")

        status, counts = lab.scan_prefix(representatives, evaluate, limit=64, on_complete=completed)
        if status == "resource_bounded_inconclusive":
            write_json(output / "resource-stop.json", {"status": status, "phase": phase,
                                                       "completed_mass_records": len(counts),
                                                       "interrupted_mass_work_unknown": True,
                                                       "elapsed_wall_seconds": monotonic() - start,
                                                       "main_retry_permitted": False})
        if counts and counts[-1].witness is not None:
            final = counts[-1]
            require(not lab.is_quartic_packet(ctx, final.roots), "counterexample_nonpacket", final)
            transporter_checks = []
            for roots, representative, g in inventory.assignments:
                if representative == final.roots:
                    transformed = lab.signed_action(final.witness, pow(g, -1, 32))
                    require(all(independent_horner(transformed, pow(ctx.root, e, 97), 97) == 0
                                for e in roots), "counterexample_signed_orbit_transport", roots)
                    transporter_checks.append(roots)
            write_json(output / "counterexample.json", {"count": final,
                                                        "transported_rootsets": transporter_checks})
        for name, digest in freeze["source_sha256"].items():
            require(sha(Path(name)) == digest, "post_main_source_pin", name)
        result = {"packet": "Q48/E122", "created_utc": datetime.now(UTC).isoformat(),
                  "parent_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO,
                                                           text=True).strip(),
                  "status": status, "context": ctx, "root_selector": "least z in[2,96] withz^16=-1",
                  "action_audit": action_audit, "complete_orbit_audit": orbit_audit,
                  "complete_orbit_inventory_path": str(inventory_path),
                  "complete_orbit_inventory_sha256": inventory_digest,
                  "total_representatives": len(representatives), "mass_representatives_visited": len(counts),
                  "unvisited_representatives": len(representatives) - len(counts),
                  "mass_prefix_path": str(prefix_path),
                  "mass_prefix_sha256": sha(prefix_path) if prefix_path.exists() else None,
                  "counts": counts, "half_enumeration_visits": sum(count.half_visits for count in counts),
                  **lab.mass_counter_scope(status),
                  "extraction_visits": sum(count.extraction_visits for count in counts),
                  "vector_updates": sum(count.vector_updates for count in counts),
                  "extraction_vector_updates": sum(count.extraction_vector_updates for count in counts),
                  "structured_packet_exact_count": 1, "raw_law_denominator": 3 ** 16,
                  "zero_secret_included_per_count": 1, "zero_secret_added_again": False,
                  "source_argv_freeze_sha256": sha(WORK / "source-argv-freeze.json"),
                  "source_sha256": freeze["source_sha256"], "ordinary_control_ratio": 1,
                  "large_prime_or_HE_operations": 0, "timing_claims": False,
                  "scope": "fixed public tiny hypothesis discriminator; no original or security theorem"}
        write_json(RAW, result)
        write_json(output / "resource-diagnostic.json", {"elapsed_wall_seconds": monotonic() - start,
                                                         "scope": "resource guard only; not performance"})
        print(json.dumps({"packet": result["packet"], "status": status,
                          "raw_sha256": sha(RAW), "representatives_visited": len(counts),
                          "half_visits": result["half_enumeration_visits"]}))
    except (TimeoutError, MemoryError) as error:
        write_json(output / "resource-stop.json", {"status": "resource_bounded_inconclusive",
                                                   "phase": phase, "error_type": type(error).__name__,
                                                   "elapsed_wall_seconds": monotonic() - start,
                                                   "main_retry_permitted": False})
        raise


if __name__ == "__main__":
    main()
