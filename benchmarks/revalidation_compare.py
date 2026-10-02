#!/usr/bin/env python3
"""Compare immutable historical artifacts with serial revalidation receipts.

This is an offline analyzer. It never runs crypto, benchmarks, builds, telemetry
or tests. Timing observations do not identify contention as their cause. Exact
checks/count observations, source identity, resources and timings stay separate.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import random
import re
import statistics


@dataclass(frozen=True)
class Timing:
    path: str
    unit: str
    statistic: str
    scope: str
    value: float


def pointer(parts):
    """RFC6901 escaping keeps a variant called full/cpu one path component."""
    return "/" + "/".join(str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def leaves(value, parts=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from leaves(child, (*parts, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from leaves(child, (*parts, str(index)))
    else:
        yield parts, value


def metric_unit(parts):
    for part in reversed(parts):
        if re.search(r"(?:_ms|_milliseconds)(?:_|$)", part):
            return "ms"
        if re.search(r"(?:_ns|_nanoseconds)(?:_|$)", part):
            return "ns"
        if re.search(r"(?:_s|_seconds)(?:_|$)", part):
            return "s"
    return None


def timing_scope(parts):
    text = "/".join(parts).lower()
    if "controller" in text or "process_wall" in text:
        return "whole_process_or_controller"
    if "stage_sum" in text or "phase_sum" in text:
        return "stage_sum_model"
    if any(p == "setup" or p.startswith("setup_") for p in parts):
        return "setup_stage"
    if "diagnostic" in text or "outside_cost" in text or "excluded" in text:
        return "diagnostic_excluded_from_online_cost"
    return "runner_defined_timed_boundary"


def flatten_timings(raw):
    result = {}
    for parts, value in leaves(raw):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        unit = metric_unit(parts)
        if not unit or not math.isfinite(value):
            continue
        statistic = "observation"
        if any("interval" in p for p in parts):
            statistic = "reported_interval_bound"
        elif parts[-1] in {"mean", "median", "min", "minimum", "max", "maximum"}:
            statistic = parts[-1]
        elif parts[-1].startswith("p95"):
            statistic = "descriptive_p95"
        elif any("median" in p for p in parts):
            statistic = "median"
        elif any("mean" in p for p in parts):
            statistic = "mean"
        path = pointer(parts)
        result[path] = Timing(path, unit, statistic, timing_scope(parts), float(value))
    return result


def compare_timings(old, new):
    comparisons, incompatible = [], []
    for path in sorted(old.keys() & new.keys()):
        a, b = old[path], new[path]
        if (a.unit, a.statistic, a.scope) != (b.unit, b.statistic, b.scope):
            incompatible.append(path)
            continue
        comparisons.append({"metric_path": path, "unit": a.unit,
                            "statistic": a.statistic, "scope": a.scope,
                            "historical": a.value, "repeat": b.value,
                            "repeat_over_historical": b.value / a.value if a.value > 0 else None,
                            "absolute_change_in_same_unit": b.value - a.value})
    return {"matched": comparisons, "incompatible": incompatible,
            "missing_in_repeat": sorted(old.keys() - new.keys()),
            "new_only": sorted(new.keys() - old.keys())}


def sequence_alignment_issues(old, new, parts=()):
    """A JSON list index is not a trial identity after a workload changes."""
    issues = []
    if isinstance(old, dict) and isinstance(new, dict):
        for key in old.keys() & new.keys():
            issues.extend(sequence_alignment_issues(old[key], new[key], (*parts, key)))
    elif isinstance(old, list) and isinstance(new, list):
        if len(old) != len(new):
            return [{"path": pointer(parts), "reason": "sequence_length_changed",
                     "historical_length": len(old), "repeat_length": len(new)}]
        identity_keys = {"kind", "dataset", "mode", "mode_label", "method", "backend", "variant",
                         "rank", "n", "t", "q", "revision", "repetition", "ordinal", "process_repetition"}
        for index, (a, b) in enumerate(zip(old, new)):
            here = (*parts, str(index))
            changed = sorted(k for k in identity_keys if isinstance(a, dict) and isinstance(b, dict)
                             and k in a and k in b and a[k] != b[k])
            if changed:
                issues.append({"path": pointer(here), "reason": "record_identity_fields_changed",
                               "fields": changed})
            else:
                issues.extend(sequence_alignment_issues(a, b, here))
    return issues


def aligned_paths(values, issues):
    prefixes = [x["path"] for x in issues]
    return {path: value for path, value in values.items()
            if not any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)}


COUNT_KEYS = {"n", "t", "eta", "q_bits", "digit_bits", "dimension", "num_vectors",
              "count", "rank", "parts", "pool_size", "update_count", "terminal_bits",
              "exact_queries", "exact_mode_queries", "configuration_count", "searches"}
COUNT_SUFFIXES = ("_body_bytes_model", "_coefficient_bytes",
                  "_field_products", "_switches", "_ciphertexts")
PAYLOAD_KEYS = {"query_bytes", "response_bytes", "query_plus_response_bytes",
                "public_keys_bytes", "encrypted_index_bytes", "response_download_bytes",
                "query_upload_bytes", "ciphertext_bytes", "setup_keys_bytes"}


def semantic_observations(raw):
    checks, counts, payloads = {}, {}, {}
    for parts, value in leaves(raw):
        key = parts[-1]
        path = pointer(parts)
        if isinstance(value, bool) and (
            key.startswith("all_") and any(word in key for word in ("exact", "equal", "correct", "match", "roundtrip"))
            or key in {"complete_cpu_cuda_output_equal", "gate_pass_before_secret_decryption"}
        ):
            checks[path] = value
        # Restrict to labeled integral geometry/body/operation observations.
        # Random phases, ciphertexts, hashes and Python object/RSS bytes are not
        # deterministic count identities and are deliberately absent here.
        if type(value) is int and (key in COUNT_KEYS or key.endswith(COUNT_SUFFIXES)):
            counts[path] = value
        if ((key in PAYLOAD_KEYS or key.endswith("_body_bytes")) and type(value) in (int, float)
                and math.isfinite(value) and value >= 0):
            payloads[path] = value
    return {"reported_exact_checks": checks, "labeled_count_observations": counts,
            "serialized_payload_size_observations": payloads}


def compare_semantics(old, new):
    result = {}
    for section in old:
        a, b = old[section], new[section]
        common = a.keys() & b.keys()
        changed = [{"metric_path": p, "historical": a[p], "repeat": b[p]}
                   for p in sorted(common) if a[p] != b[p]]
        result[section] = {"matched_paths": len(common), "changed": changed,
                           "missing_in_repeat": sorted(a.keys() - b.keys()),
                           "new_only": sorted(b.keys() - a.keys())}
    result["scope"] = "Reported assertions and labeled observations only; schema/count changes need workload reconciliation. Serialized payload sizes may vary with encryption/key randomness and variable-length codecs; a size change alone is not a correctness failure. No equality of random ciphertexts, phases, keys or hashes is asserted."
    return result


def paired_ratio_report(blocks, *, draws=2000, seed=20261001):
    """Resample complete matched process blocks, never their query observations."""
    if not blocks or not 100 <= draws <= 10000:
        raise ValueError("Require nonempty blocks and 100..10000 bootstrap draws")
    signatures = {(b["unit"], b["statistic"], b["scope"]) for b in blocks}
    if len(signatures) != 1 or len({b["block_id"] for b in blocks}) != len(blocks):
        raise ValueError("Blocks must have compatible boundaries and unique process IDs")
    for b in blocks:
        if any(not math.isfinite(b[k]) or b[k] <= 0 for k in ("baseline", "candidate")):
            raise ValueError("Ratios require finite positive paired measurements")
    ratios = [b["candidate"] / b["baseline"] for b in blocks]
    geometric = math.exp(statistics.mean(math.log(r) for r in ratios))
    interval = None
    if len(blocks) >= 2:
        rng = random.Random(seed)
        estimates = sorted(math.exp(statistics.mean(math.log(ratios[rng.randrange(len(ratios))])
                                                       for _ in ratios)) for _ in range(draws))
        interval = [estimates[int(.025 * draws)], estimates[min(draws - 1, int(.975 * draws))]]
    margins = {}
    for margin in (0, .02, .05, .10):
        margins[str(margin)] = ("insufficient_independent_blocks" if interval is None else
                               "interval_supports_candidate_margin" if interval[1] < 1 - margin else
                               "interval_supports_candidate_slower" if interval[0] > 1 else
                               "unresolved_at_margin")
    unit, statistic, scope = next(iter(signatures))
    return {"independent_process_blocks": len(blocks), "unit": unit,
            "within_process_statistic": statistic, "scope": scope,
            "candidate_over_baseline_process_ratios": ratios,
            "geometric_mean_candidate_over_baseline": geometric,
            "block_bootstrap_95_interval": interval,
            "bootstrap_draws": draws if interval else 0,
            "small_sample_inference_provisional": len(blocks) < 20,
            "margin_sensitivity_not_universal_acceptance_thresholds": margins,
            "scope_note": "Matched process-block summaries; query/case repetitions inside a process are not independent host blocks. No stable tail or causal contention inference."}


def measured_contrasts(raw):
    """Explicit comparable costs for E26/E27/E43/E49/E77; no implicit unit joins."""
    result = []

    def add(name, baseline, candidate, unit, scope, *, geometry=None):
        if baseline > 0 and candidate > 0:
            result.append({"contrast": name, "baseline": float(baseline), "candidate": float(candidate),
                           "unit": unit, "statistic": "median", "scope": scope,
                           "geometry": geometry or {}})

    inner = raw.get("result", raw)
    if not isinstance(inner, dict):
        inner = raw
    summary = inner.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}  # E79 and other runners publish typed lists, not variant maps.
    for baseline, candidate in (("full", "crt_masks"), ("repair32", "allocated"), ("full", "allocated")):
        for device in ("cpu", "cuda"):
            a, b = summary.get(f"{baseline}/{device}"), summary.get(f"{candidate}/{device}")
            if a and b:
                for metric in ("evaluate_s", "local_total_s"):
                    if metric in a and metric in b:
                        add(f"{baseline}->{candidate}/{device}/{metric}", a[metric]["median"], b[metric]["median"],
                            "s", "server_API" if metric == "evaluate_s" else "runner_local_stage_sum")
    if raw.get("kind") == "public_seed_conditioned_affine_query_gate_known_control":
        for index, case in enumerate(raw["cases"]):
            rows = case["samples"]
            if rows:
                add(f"E77/geometry{index}/client_plus_trusted_factory", statistics.median(
                    s["baseline_client_stage_sum_ms"] for s in rows), statistics.median(
                    s["affine_client_plus_trusted_factory_stage_sum_ms"] for s in rows), "ms", "stage_sum_model",
                    geometry={k: case[k] for k in ("n", "q", "t", "eta", "paths", "counts")})
    if "sparse_delta" in summary and "full_reencrypt" in summary:
        for metric in ("total_update_stage_sum_s", "total_updates_stage_sum_s", "full_lifetime_stage_sum_s"):
            if metric in summary["sparse_delta"] and metric in summary["full_reencrypt"]:
                add(f"E43/full_reencrypt->sparse_delta/{metric}", summary["full_reencrypt"][metric]["median"],
                    summary["sparse_delta"][metric]["median"], "s", "stage_sum_model")
    if raw.get("kind") == "encrypted_index_trusted_factory":
        for baseline in ("plaintext", "numpy_plaintext"):
            if baseline in summary and "encrypted_index" in summary:
                for metric in ("offline_production_and_check_s", "complete_local_online_elapsed_s"):
                    add(f"E49/{baseline}->encrypted_index/{metric}", summary[baseline][metric]["median"],
                        summary["encrypted_index"][metric]["median"], "s",
                        "offline_stage_sum" if metric.startswith("offline") else "elapsed_online_request")
    return result


def source_hashes(raw):
    result = {}
    for field in ("source_sha256", "source_and_binary_sha256"):
        values = raw.get(field, {})
        if isinstance(values, dict):
            result.update({k: v for k, v in values.items() if isinstance(v, str)})
    return result


def source_identity(old, new, receipt, adaptations=None):
    a, b = source_hashes(old), source_hashes(new)
    common = a.keys() & b.keys()
    changed = sorted(p for p in common if a[p] != b[p])
    mode = receipt.get("execution_mode", "unspecified")
    identical = bool(a) and a == b
    declared = []
    if adaptations:
        root = Path(adaptations["source_copy"])
        for change in adaptations.get("changes", []):
            path = Path(change["path"])
            if path.is_relative_to(root):
                relative = str(path.relative_to(root))
                declared.append({"path": relative, "reason": change["reason"],
                                 "historical_matches_declared_before": a.get(relative) == change["before_sha256"],
                                 "repeat_matches_declared_after": b.get(relative) == change["after_sha256"]})
    explained = {c["path"] for c in declared if c["historical_matches_declared_before"] and c["repeat_matches_declared_after"]}
    return {"execution_label_from_receipt": mode, "historical_hashes_present": bool(a),
            "repeat_hashes_present": bool(b), "compared_hashes": len(common),
            "changed_paths": changed, "missing_repeat_paths": sorted(a.keys() - b.keys()),
            "declared_isolation_adaptations": declared,
            "changed_paths_without_exact_declared_before_after_match": sorted(set(changed) - explained),
            "new_hash_paths": sorted(b.keys() - a.keys()), "same_recorded_hash_map": identical,
            "historical_source_replication_certified": identical and mode == "historical_source_replication",
            "historical_head": old.get("git_head", old.get("environment", {}).get("revision")),
            "repeat_head": new.get("git_head", new.get("environment", {}).get("revision")),
            "scope": "Hash-map equality is content evidence only; current-source execution remains labeled current-source and may differ in runtime, keys and resources."}


def inventory_entries(paths):
    entries = {}
    for path in paths:
        data = json.loads(path.read_text())
        for entry in data.get("entries", data.get("artifacts", [])):
            entries[entry["original_raw"]] = entry
    return entries


def contrast_signature(raw, contrast):
    inner = raw.get("result", raw)
    fields = {k: inner.get(k, raw.get(k)) for k in (
        "kind", "dataset", "split_seed", "fixture_sha256", "count", "dimension", "n", "t", "q", "rank", "pool_size", "profile",
        "owner_arithmetic", "vectorized_plaintext_control", "update_count",
        "queries_per_nonfinal_update", "edited_rows_per_revision", "workload_digest_owner_local", "checker_rounds")}
    fields["contrast"] = contrast["contrast"]
    fields["geometry"] = contrast["geometry"]
    setup = inner.get("setup", {})
    fields["setup_geometry"] = {k: setup[k] for k in (
        "n", "t", "q", "q_bits", "eta", "digit_bits", "terminal_bits", "parts", "padded") if k in setup}
    return json.dumps(fields, sort_keys=True, separators=(",", ":"))


def analyze(repository, inventories, runs_dir, *, draws=2000, adaptations=None):
    entries = inventory_entries(inventories)
    comparisons, failed, groups = [], [], defaultdict(list)
    for receipt_path in sorted(runs_dir.rglob("receipt.json")):
        receipt = json.loads(receipt_path.read_text())
        if "job" not in receipt:
            continue
        job = receipt["job"]
        output = Path(job["new_raw"])
        if receipt.get("returncode") != 0 or not receipt.get("completed_successfully", True) or not output.is_file():
            failed.append({"job_id": job["id"], "receipt": str(receipt_path), "returncode": receipt.get("returncode"),
                           "fresh_output_present": output.is_file()})
            continue
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        if digest != receipt.get("new_raw_sha256"):
            raise ValueError("Fresh raw hash differs from execution receipt: " + str(output))
        new = json.loads(output.read_text())
        for original in job.get("original_raws", []):
            path = repository / original
            if not path.is_file():
                failed.append({"job_id": job["id"], "original_raw": original, "reason": "missing_original"})
                continue
            entry = entries.get(original, {})
            original_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            if entry.get("original_raw_sha256") and original_hash != entry["original_raw_sha256"]:
                raise ValueError("Immutable historical raw differs from inventory: " + original)
            old = json.loads(path.read_text())
            alignment_issues = sequence_alignment_issues(old, new)
            old_semantics, new_semantics = semantic_observations(old), semantic_observations(new)
            old_contrasts = {c["contrast"]: c for c in measured_contrasts(old)}
            new_contrasts = measured_contrasts(new)
            comparisons.append({"job_id": job["id"], "original_raw": original, "fresh_raw": str(output),
                                "original_sha256": original_hash, "fresh_sha256": digest,
                                "classification_from_inventory": entry.get("classification", "unlisted"),
                                "inventory_historical_source_drift": entry.get("current_source_drift", entry.get("changed_source_or_binary_paths", [])),
                                "source_identity": source_identity(old, new, receipt, adaptations),
                                "job_for_reproduction": job,
                                "resource_conditions": receipt.get("resource_conditions", {}),
                                "affinity": receipt.get("affinity"), "thread_environment": receipt.get("environment", {}),
                                "process_wall_s_recorded_separately": receipt.get("process_wall_s"),
                                "sequence_alignment_qualifications": alignment_issues,
                                "fresh_reported_check_totals": {
                                    "true": sum(new_semantics["reported_exact_checks"].values()),
                                    "false": sum(not v for v in new_semantics["reported_exact_checks"].values())},
                                "reported_semantics": compare_semantics(
                                    {k: aligned_paths(v, alignment_issues) for k, v in old_semantics.items()},
                                    {k: aligned_paths(v, alignment_issues) for k, v in new_semantics.items()}),
                                "timings": compare_timings(aligned_paths(flatten_timings(old), alignment_issues),
                                                           aligned_paths(flatten_timings(new), alignment_issues)),
                                "historical_within_process_contrasts": list(old_contrasts.values()),
                                "repeat_within_process_contrasts": new_contrasts})
            # Aliases of one output are not independent process replications.
            for c in new_contrasts:
                key = contrast_signature(new, c)
                if any(b["block_id"] == job["id"] for b in groups[key]):
                    continue
                groups[key].append({**c, "block_id": job["id"], "original_raw": original,
                                    "controller_sha256": receipt.get("driver_sha256", "unrecorded"),
                                    "historical_candidate_over_baseline": (old_contrasts[c["contrast"]]["candidate"] /
                                                                           old_contrasts[c["contrast"]]["baseline"])
                                    if c["contrast"] in old_contrasts else None,
                                    "resource_qualified": receipt.get("resource_conditions", {}).get("qualified_by_conditions", True)})
    contrasts = []
    for signature, blocks in sorted(groups.items()):
        clean = [b for b in blocks if not b["resource_qualified"]]
        controller_subsets = defaultdict(list)
        for block in blocks:
            controller_subsets[block["controller_sha256"]].append(block)
        contrasts.append({"signature": json.loads(signature), "blocks": blocks,
                          "all_recorded_blocks": paired_ratio_report(blocks, draws=draws),
                          "designated_low_load_blocks": paired_ratio_report(clean, draws=draws) if clean else None,
                          "controller_version_subsets": [{"controller_sha256": sha,
                              "block_ids": [b["block_id"] for b in subset],
                              "paired_ratio_report": paired_ratio_report(subset, draws=draws)}
                              for sha, subset in sorted(controller_subsets.items())],
                          "observed_point_direction_changes": [b["block_id"] for b in blocks
                              if b["historical_candidate_over_baseline"] is not None
                              and (b["candidate"] / b["baseline"] - 1) * (b["historical_candidate_over_baseline"] - 1) < 0],
                          "direction_change_scope": "Point-estimate screening flag, not a significant reversal, acceptance decision or causal attribution. Check interval, complete costs, resources and source/runtime drift."})
    return {"schema": 1, "kind": "offline_serial_revalidation_comparison", "comparisons": comparisons,
            "failed_or_missing_outputs": failed, "paired_contrasts": contrasts,
            "unmatched_inventory_artifacts": sorted(entries.keys() - {c["original_raw"] for c in comparisons}),
            "scope": "Current-source confirmations and historical observations remain distinct. Resource sampling qualifies observations but cannot prove exclusivity or causally attribute changes to contention. Exact checks and labeled counts are independent of timing analysis; dependent lifetime/network models require later regeneration. A passed subprocess is not universal correctness or security assurance."}


def markdown(report):
    lines = ["# Serial revalidation comparison", "", report["scope"], "",
             f"Compared {len(report['comparisons'])} historical/fresh artifact pairs. "
             f"Failed or missing outputs: {len(report['failed_or_missing_outputs'])}. "
             f"Inventory artifacts without a completed comparison: {len(report['unmatched_inventory_artifacts'])}.", "",
             "## Paired complete-cost and stage contrasts", "",
             "Ratios are candidate/baseline: below one favors the candidate. Intervals resample independent process blocks; small samples remain provisional. These contrasts do not supply deployment equivalence or a causal explanation.", "",
             "| Contrast / dataset | Process blocks | Historical ratios | Repeat ratio | Block interval | Low-load blocks |", "|---|---:|---|---:|---|---:|"]
    for row in report["paired_contrasts"]:
        s, r = row["signature"], row["all_recorded_blocks"]
        old = sorted({round(b["historical_candidate_over_baseline"], 6) for b in row["blocks"] if b["historical_candidate_over_baseline"] is not None})
        interval = r["block_bootstrap_95_interval"]
        label = s["contrast"].replace("|", "\\|") + " / " + str(s.get("dataset"))
        qualifiers = {k: s[k] for k in ("split_seed", "rank", "owner_arithmetic", "update_count",
                                      "vectorized_plaintext_control") if s.get(k) is not None}
        if qualifiers:
            label += " / " + json.dumps(qualifiers, sort_keys=True)
        lines.append(f"| {label} | {r['independent_process_blocks']} | {old} | {r['geometric_mean_candidate_over_baseline']:.4f} | {interval if interval else 'insufficient blocks'} | {row['designated_low_load_blocks']['independent_process_blocks'] if row['designated_low_load_blocks'] else 0} |")
    lines += ["", "## Identity and resource qualifications", ""]
    for row in report["comparisons"]:
        changed = row["source_identity"]["changed_paths"]
        checks = row["reported_semantics"]["reported_exact_checks"]
        counts = row["reported_semantics"]["labeled_count_observations"]
        lines.append(f"- `{row['job_id']}`: `{row['original_raw']}`; source-hash changes {len(changed)}, "
                     f"reported check changes {len(checks['changed'])}, labeled count changes {len(counts['changed'])}; "
                     f"resource qualified={row['resource_conditions'].get('qualified_by_conditions', 'unknown')}. "
                     "See JSON for missing paths, observations, source labels and exact metric boundaries.")
    lines += ["", "Timing changes alone do not establish that historical background work caused them. "
              "Changed workload/repetition counts and randomized fields require reconciliation before a correctness conclusion. "
              "Regenerate dependent cost models only after deciding which measurements are admissible.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--inventories", nargs="+", type=Path, required=True)
    parser.add_argument("--runs-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--markdown-out", type=Path, required=True)
    parser.add_argument("--bootstrap-samples", type=int, default=2000)
    parser.add_argument("--adaptations", type=Path, help="Recorded source-copy isolation adaptations; changes remain visible")
    args = parser.parse_args()
    if args.json_out.exists() or args.markdown_out.exists() or not 100 <= args.bootstrap_samples <= 10000:
        parser.error("Fresh report paths and 100..10000 bootstrap draws required")
    adaptations = json.loads(args.adaptations.read_text()) if args.adaptations else None
    report = analyze(args.repository, args.inventories, args.runs_dir, draws=args.bootstrap_samples, adaptations=adaptations)
    for path in (args.json_out, args.markdown_out):
        path.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    args.markdown_out.write_text(markdown(report))
    print(json.dumps({"artifact_pairs": len(report["comparisons"]), "contrast_groups": len(report["paired_contrasts"]),
                      "unmatched_artifacts": len(report["unmatched_inventory_artifacts"])}))


if __name__ == "__main__":
    main()
