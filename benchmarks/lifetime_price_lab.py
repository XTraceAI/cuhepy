#!/usr/bin/env python3
"""E57 calibrate only repetition0; expose prediction errors on repetition1.

Matched fixed geometry, count domains and controls. A price is a measurement
fit, not a latency bound or Gate C gain. Include all acquisition/fit cost for
an honest subsequent policy experiment; never hide its one-time calibration.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from statistics import mean
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import lifetime_prices as prices


def geometry(data):
    a, r = data["arguments"], data["resources_model"]
    return (a["count"], a["dimension"], a["rank"], a["n"], a["prime"], a["q_bits"], 21,
            r["columns"], r["replies"], a["edit_rows"])


def points(data, case):
    used, result = 0, []
    for epoch in case["epochs"]:
        if epoch["revision"]:
            report = epoch["report"]
            result.append((data["arguments"]["pool"] - used, epoch["complete_update_or_initial_prepare_s"],
                           len(report.get("public_reply_tiles_rebuilt", ())), report.get("retained_changed_rows", 0)))
        used += epoch["queries_completed"]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, nargs="+", required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    start = time.perf_counter()
    runs = [json.loads(p.read_text()) for p in args.inputs]
    profile = geometry(runs[0])
    if any(geometry(data) != profile for data in runs):
        parser.error("Calibration requires identical declared geometry")
    samples = {}
    acquisition = 0
    for data in runs:
        for case in data["cases"]:
            if case["repetition"] != 0:
                continue
            acquisition += case["complete_lifetime_s"]
            for pending, seconds, tiles, exceptions in points(data, case):
                key = (case["method"], tiles if case["method"] == "tile_reencrypt" else 0)
                feature = exceptions if case["method"] == "private_client_delta" else pending
                samples.setdefault(key, []).append((feature, seconds))
            if case["method"] == "private_client_delta":
                counts = {e["revision"]: e["report"].get("retained_changed_rows", 0) for e in case["epochs"]}
                samples.setdefault(("correction", 0), []).extend(
                    (counts[s["revision"]], s["private_delta_correction_s"]) for s in case["online"])
    fitted = {key: prices.fit(tuple(x for x, _ in values), tuple(y for _, y in values))
              for key, values in samples.items()}
    models = prices.Models(profile, fitted[("full_reencrypt", 0)],
                           tuple((tiles, price) for (method, tiles), price in fitted.items() if method == "tile_reencrypt"),
                           fitted[("private_client_delta", 0)], fitted[("correction", 0)])
    fit_s = time.perf_counter() - start
    heldout = []
    for run_id, data in enumerate(runs):
        for case in data["cases"]:
            if case["repetition"] != 1:
                continue
            for ordinal, (pending, seconds, tiles, exceptions) in enumerate(points(data, case)):
                key = (case["method"], tiles if case["method"] == "tile_reencrypt" else 0)
                feature = exceptions if case["method"] == "private_client_delta" else pending
                predicted = fitted[key].predict(feature)
                heldout.append({"input": run_id, "method": case["method"], "revision": ordinal + 1,
                                "feature": feature, "measured_s": seconds, "predicted_s": predicted,
                                "absolute_error_s": abs(predicted - seconds), "relative_error": abs(predicted - seconds) / seconds})
            if case["method"] == "private_client_delta":
                counts = {e["revision"]: e["report"].get("retained_changed_rows", 0) for e in case["epochs"]}
                for sample in case["online"]:
                    predicted = models.correction.predict(counts[sample["revision"]])
                    measured = sample["private_delta_correction_s"]
                    heldout.append({"input": run_id, "method": "correction", "revision": sample["revision"],
                                    "measured_s": measured, "predicted_s": predicted,
                                    "absolute_error_s": abs(predicted - measured), "relative_error": abs(predicted - measured) / measured})
    report = metadata([Path(__file__), ROOT / "experiments/bfv_search_lab/lifetime_prices.py"])
    report.update(kind="bounded_native_lifetime_price_calibration", models=models.json(), calibration_fit_s=fit_s,
                  training_acquisition_s=acquisition, training_repetition=0, heldout_repetition=1,
                  inputs=[{"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in args.inputs],
                  heldout=heldout, errors_by_method={method: {
                      "mean_absolute_error_s": mean(x["absolute_error_s"] for x in heldout if x["method"] == method),
                      "mean_relative_error": mean(x["relative_error"] for x in heldout if x["method"] == method),
                      "maximum_relative_error": max(x["relative_error"] for x in heldout if x["method"] == method)}
                      for method in {x["method"] for x in heldout}},
                  scope="Training and held-out repetitions of previously designed synthetic traces, not new unseen edit traces. "
                        "Counts/profile bounded; nonnegative affine fit, not a measured optimizer or proven cost bound. "
                        "Fresh prices exclude extra delta-snapshot migration work; actual policies must time it. "
                        "Entire training acquisition stage sums plus fit are retained for one-time/amortized reporting.")
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "training_acquisition_s": acquisition,
                      "errors_by_method": report["errors_by_method"]}))


if __name__ == "__main__":
    main()
