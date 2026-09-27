#!/usr/bin/env python3
"""Summarize single-threaded BGV NVTX ranges from an Nsight Systems SQLite export.

Diagnostic durations only. CPU CUDA API time can include waiting for kernels;
it is not device transfer time. Do not add overlapping CPU/GPU durations.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
from urllib.parse import quote


def summarize(path):
    result = {}
    with sqlite3.connect("file:" + quote(str(path.resolve())) + "?mode=ro", uri=True) as db:
        for name in ("transient", "persistent"):
            ranges = db.execute("SELECT start,end FROM NVTX_EVENTS WHERE text=? ORDER BY start", (name,)).fetchall()
            if not ranges:
                raise ValueError(f"No {name} NVTX ranges in this capture")
            rows = []
            for start, end in ranges:
                kernels = [{"name": text, "duration_ns": duration, "calls": count}
                           for text, duration, count in db.execute(
                               "SELECT s.value,SUM(k.end-k.start),COUNT(*) FROM CUPTI_ACTIVITY_KIND_KERNEL k "
                               "JOIN StringIds s ON k.demangledName=s.id WHERE k.start>=? AND k.end<=? GROUP BY s.value", (start, end))]
                api = [{"name": text, "duration_ns": duration, "calls": count}
                       for text, duration, count in db.execute(
                           "SELECT s.value,SUM(k.end-k.start),COUNT(*) FROM CUPTI_ACTIVITY_KIND_RUNTIME k "
                           "JOIN StringIds s ON k.nameId=s.id WHERE k.start>=? AND k.end<=? GROUP BY s.value", (start, end))]
                copy_ns, copy_bytes = db.execute(
                    "SELECT SUM(end-start),SUM(bytes) FROM CUPTI_ACTIVITY_KIND_MEMCPY WHERE start>=? AND end<=?", (start, end)).fetchone()
                rows.append({"range_ns": end - start, "kernels": kernels, "runtime_api": api,
                             "gpu_kernel_ns": sum(k["duration_ns"] for k in kernels),
                             "gpu_ntt_ns": sum(k["duration_ns"] for k in kernels if "ntt_fused" in k["name"]),
                             "gpu_copy_ns": copy_ns or 0, "gpu_copy_bytes": copy_bytes or 0})
            fields = ("range_ns", "gpu_kernel_ns", "gpu_ntt_ns", "gpu_copy_ns", "gpu_copy_bytes")
            result[name] = {"samples": rows, "means": {field: sum(row[field] for row in rows) / len(rows) for field in fields}}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlite", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    report = {"kind": "nsight_bgv_diagnostic", "scope": __doc__, "results": summarize(args.sqlite),
              "sqlite_sha256": hashlib.sha256(args.sqlite.read_bytes()).hexdigest(),
              "summarizer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
