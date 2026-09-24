"""Rank measured search variants under an explicit, analytical network model.

This selects among measured implementations for one recorded workload; it does
not select cryptographic parameters or predict larger indexes. Network estimates
assume sequential upload, compute, download and one RTT, without overlap, TLS,
congestion or attestation. This is a reporting tool, never a production router.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import math
from pathlib import Path
import statistics
from typing import Any


@dataclass(frozen=True)
class Estimate:
    variant: str
    local_ms: float
    modeled_network_ms: float
    estimated_ms: float
    query_bytes: int
    response_bytes: int


def rank(
    report: dict[str, Any],
    *,
    upload_mbps: float,
    download_mbps: float,
    rtt_ms: float = 0,
    allow_partial_scores: bool = False,
    allow_symmetric: bool = False,
    allow_precompute: bool = False,
    include_refill: bool = False,
) -> list[Estimate]:
    """Filter protocol/owner capabilities before minimizing estimated latency."""
    if (
        any(not math.isfinite(v) or v <= 0 for v in (upload_mbps, download_mbps))
        or not math.isfinite(rtt_ms)
        or rtt_ms < 0
    ):
        raise ValueError("Expected positive finite bandwidths and nonnegative RTT")
    if (
        report.get("kind") != "local_encrypted_benchmark_no_network_or_attestation"
        or report.get("all_distances_and_top3_correct") is not True
    ):
        raise ValueError("Expected a verified local search benchmark")
    field = "total_with_refill_s" if include_refill else "online_total_s"
    result = []
    for case in report["results"]:
        variant = case["variant"]
        if (
            (case["partials"] != 1 and not allow_partial_scores)
            or ("seeded" in variant and not allow_symmetric)
            or (variant.endswith("-pool") and not allow_precompute)
        ):
            continue
        samples = case["samples"]
        if not samples:
            raise ValueError("Missing measured samples")
        for sample in samples:
            if any(
                not isinstance(sample.get(key), (int, float))
                or not math.isfinite(sample[key])
                or sample[key] < 0
                for key in (field, "query_bytes", "response_bytes")
            ):
                raise ValueError("Invalid measured timings/payloads")
        local = [1000 * sample[field] for sample in samples]
        network = [
            rtt_ms
            + sample["query_bytes"] * 8 / (upload_mbps * 1000)
            + sample["response_bytes"] * 8 / (download_mbps * 1000)
            for sample in samples
        ]
        result.append(
            Estimate(
                variant,
                statistics.median(local),
                statistics.median(network),
                statistics.median(a + b for a, b in zip(local, network, strict=True)),
                int(statistics.median(sample["query_bytes"] for sample in samples)),
                int(statistics.median(sample["response_bytes"] for sample in samples)),
            )
        )
    return sorted(result, key=lambda item: (item.estimated_ms, item.variant))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--upload-mbps", type=float, default=100)
    parser.add_argument("--download-mbps", type=float, default=100)
    parser.add_argument("--rtt-ms", type=float, default=20)
    parser.add_argument("--allow-partial-scores", action="store_true")
    parser.add_argument("--allow-symmetric", action="store_true")
    parser.add_argument("--allow-precompute", action="store_true")
    parser.add_argument("--include-refill", action="store_true")
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    settings = vars(args).copy()
    del settings["report"]
    estimates = rank(report, **settings)
    print(
        json.dumps(
            {
                "kind": "analytical_network_projection_not_a_network_measurement",
                "num_vectors": report["num_vectors"],
                "config": report["config"],
                "settings": settings,
                "estimates": [asdict(item) for item in estimates],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
