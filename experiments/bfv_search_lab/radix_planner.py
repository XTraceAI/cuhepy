"""E16 reporting planner over measured layout AND precision choices.

Never selects security parameters or authorizes a response. Bandwidth/RTT are
an analytical serial-transfer model. Fresh setup charges measured preparation
and a coefficient-only registration transfer floor; framing, transport security
and attestation setup are unknown, not claimed free. An explicitly resident
layout has its keys/index and all measured terminal plans already prepared.
"""

from dataclasses import asdict, dataclass
import math
import statistics

from experiments.bfv_search_lab.radix_bgv import Layout

LAYOUTS = {"g1": (1, "distance"), "balanced2": (2, "balanced"),
           "distance2": (2, "distance"), "distance3": (3, "distance")}
SETUP_FIELDS = ("keygen_s", "evaluation_keys_s", "owner_prepare_s", "index_encode_s",
                "index_encrypt_s", "server_prepare_s", "index_prepare_s",
                "workspace_prepare_s", "planning_s", "terminal_prepare_s")


def _number(value, positive=False):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0 or (positive and value == 0):
        raise ValueError("Expected a finite nonnegative measured/model quantity")
    return value


@dataclass(frozen=True)
class Estimate:
    variant: str
    layout: str
    terminal_bits: int
    query_drop: int
    response_drop: int
    query_bytes: int
    response_bytes: int
    local_ms: float
    steady_ms: float
    setup_compute_ms: float
    setup_coefficient_bytes: int
    setup_ms_floor: float
    amortized_ms_floor: float


def rank(report, *, index_mode="owner", upload_mbps=None, download_mbps=None,
         rtt_ms=0, epoch_queries=1, resident_layouts=(), allow_radix=False):
    """Only measured Pareto plans; no timing interpolation between precisions."""
    if (report.get("kind") != "bgv_radix" or report.get("all_precision") is not True
        or report.get("packed_radix") is not True or report.get("vectorized_radix") is not True
        or index_mode not in ("owner", "public") or index_mode not in report.get("results", {})
        or type(epoch_queries) is not int or not 1 <= epoch_queries <= 10**12
        or type(allow_radix) is not bool or any(v not in LAYOUTS for v in resident_layouts)):
        raise ValueError("Expected an all-precision radix measurement and explicit settings")
    _number(rtt_ms)
    local = upload_mbps is None and download_mbps is None
    if local:
        if rtt_ms:
            raise ValueError("Local mode has no RTT")
    else:
        _number(upload_mbps, True)
        _number(download_mbps, True)
    measured = report["results"][index_mode]
    if measured.get("all_distances_and_stable_top3_correct") is not True:
        raise ValueError("Missing exact-result correctness checks")
    out = []
    for variant, name in measured["variants"].items():
        case = measured["cases"][name]
        label = case["layout_name"]
        if label not in LAYOUTS or measured["plaintext_decoders"][variant] != ("native" if label == "g1" else "numpy"):
            raise ValueError("Unexpected measured layout/client")
        layout = Layout(**case["layout"])
        if (layout.group, layout.mode) != LAYOUTS[label] or layout.dimension != report["dimension"]:
            raise ValueError("Inconsistent measured layout")
        layout.validate(case["n"], case["t"], report["num_vectors"])
        if label != "g1" and not allow_radix:
            continue
        plan = case["selected"]
        if plan not in case["pareto_frontier"]:
            raise ValueError("Selected precision was not in the measured public frontier")
        query, response = case["query_bytes"], case["response_bytes"]
        if (query != layout.packet_size(plan["query_bytes"], report["num_vectors"], "query")
            or response != layout.packet_size(plan["response_bytes"], report["num_vectors"], "response")):
            raise ValueError("Inconsistent framed payload bytes")
        rows = measured["samples"].get(variant+"/local", [])
        if not rows or len(rows) != report["repeats"]:
            raise ValueError("Missing measured local samples")
        for row in rows:
            _number(row["total_s"])
            if row["query_bytes"] != query or row["response_bytes"] != response:
                raise ValueError("Sample payload differs from the declared precision")
        local_ms = 1000*statistics.median(row["total_s"] for row in rows)
        network = 0 if local else rtt_ms+8*(query+4)/(upload_mbps*1000)+8*(response+4)/(download_mbps*1000)
        setup = case["setup"]
        compute = 1000*sum(_number(setup[k]) for k in SETUP_FIELDS)
        byte_fields = (setup["full_index_coefficient_bytes"], setup["full_key_coefficient_bytes"])
        if any(type(v) is not int or v <= 0 for v in byte_fields):
            raise ValueError("Missing coefficient registration-size floor")
        coefficients = sum(byte_fields)
        if label in resident_layouts:
            compute, coefficients = 0, 0
        setup_ms = compute+(0 if local else 8*coefficients/(upload_mbps*1000))
        steady = local_ms+network
        out.append(Estimate(variant, label, plan["terminal_bits"], plan["query_drop"], plan["response_drop"],
                            query, response, local_ms, steady, compute, coefficients, setup_ms,
                            steady+setup_ms/epoch_queries))
    return sorted(out, key=lambda e: (e.amortized_ms_floor, e.variant))


def break_even_queries(candidate, incumbent):
    """Epoch threshold after which candidate stays no slower; None if none."""
    delta = candidate.setup_ms_floor-incumbent.setup_ms_floor
    saving = incumbent.steady_ms-candidate.steady_ms
    if saving < 0:
        return None
    if saving == 0:
        return 1 if delta <= 0 else None
    return max(1, math.ceil(delta/saving))


def transport_validation(report, index_mode="owner"):
    """Predict from local samples, score against separate paced-link samples."""
    measured, out = report["results"][index_mode], {}
    for link, (up, down, rtt) in report["links_upload_mbps_download_mbps_rtt_ms"].items():
        predictions = rank(report, index_mode=index_mode, upload_mbps=up, download_mbps=down,
                           rtt_ms=rtt, resident_layouts=tuple(LAYOUTS), allow_radix=True)
        actual = {}
        for e in predictions:
            samples = measured["samples"].get(e.variant+"/"+link, [])
            if len(samples) != report["transport_repeats"] or not samples:
                raise ValueError("Missing separate paced-link measurements")
            actual[e.variant] = 1000*statistics.median(_number(r["total_s"]) for r in samples)
        best = min(actual, key=lambda k: (actual[k], k))
        picked = predictions[0]
        out[link] = dict(predicted=asdict(picked), measured_best=best,
                         measured_best_ms=actual[best], picked_measured_ms=actual[picked.variant],
                         measured_regret_ms=actual[picked.variant]-actual[best])
    return out
