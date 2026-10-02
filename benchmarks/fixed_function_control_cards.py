#!/usr/bin/env python3
"""Q0 paid geometry cards: counts and explicit unknowns, never HE timings."""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
import hashlib
import json
from math import ceil, log2
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata


def coded_access_card(rows, width, modulus, *, target_bits=128):
    """Rate-1/2 MDS control; code existence and real transport remain premises."""
    length = 2 * rows
    distance = rows + 1
    miss = 1 - distance / length
    samples = ceil(target_bits / -log2(miss))
    field_bytes = (modulus.bit_length() + 7) // 8
    return {
        "L": rows, "W": width, "field_modulus": str(modulus),
        "code_length": length, "minimum_distance": distance,
        "samples_for_fixed_error_128bit_target_not_system_assurance": samples,
        "field_bytes": field_bytes,
        "reply_body_bytes": rows * field_bytes,
        "coded_matrix_body_bytes": length * width * field_bytes,
        "authenticated_row_values_per_query_bytes": samples * width * field_bytes,
        "row_values_to_reply_ratio": samples * width / rows,
        "row_dot_products_per_query": samples * width,
        "code_exists_for_this_field_size": modulus >= length,
        "excluded_costs": ["paths/openings", "code evaluation", "query binding",
                           "fresh-query expansion", "setup verification", "extra RTT"],
        "scope": "Ordinary coded authenticated row access, not Maverick parameters or a protocol win.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new immutable result path")
    operator = ROOT / "benchmarks/results/publication-structured-operator-screen-20260930.json"
    global_control = ROOT / "benchmarks/results/publication-enrolled-global-service-control-20261001.json"
    sources = ROOT / "docs/research/publication-literature-sources.json"
    record = metadata([Path(__file__), operator, global_control, sources])
    geometry = []
    for p in json.loads(operator.read_text())["recorded_geometry_count_screens"]:
        card = coded_access_card(p["rows"], p["width"], p["inner_q"])
        card.update(dataset=p["dataset"], profile=p["profile"],
                    private_local_row_width=p["columns"],
                    private_query_coordinate_count=p["query_coordinate_count"],
                    generator_body_bytes=p["implicit_generator_entries"] * card["field_bytes"])
        geometry.append(card)
    private = []
    for c in json.loads(global_control.read_text())["cases"]:
        cost = c["homemade_he"]["cost_model"]
        m, h, t = c["count"], cost["query_coordinates"], cost["t"]
        bits = (t - 1).bit_length()
        private.append({
            "dataset": c["dataset"], "rows": m, "private_width": h, "field": t,
            "direct_dense_private_matvec_products": m * h,
            "bitline_projection_coordinates": 2 * bits,
            "bitline_minimal_support_keys_conjecture_to_test_in_E82": 2 ** bits + bits,
            "ordinary_line_keys": t,
            "Maverick_private_M": {
                "masked_matrix_entries": m * h,
                "P_entries": "m * N_x", "Q_entries": "N_y * h",
                "per_query_mask_correction_products": "m * t_x",
                "per_query_verification_row_products": "ell * t_y * h",
                "trapdoor_evaluation": "T_TDM(m,h); concrete recursive mode not implemented here",
                "preprocessing": "owner-paid masked matrix, P, Q and code generation",
                "parameter_status": "N_x,N_y,t_x,t_y,ell and concrete TDM uninstantiated; no timing/ranking",
            },
            "EMVP_compressed": {
                "encoded_width": "n >= h + k + ceil(lambda/log2(t)); security/code family may require padding",
                "encrypted_index_entries": "m * n", "upload_field_elements": "n",
                "uncompressed_reply_elements": "m * s; not the strongest wire control",
                "compressed_reply": "rate-1 AHE(m output values), paid encryption of p_prime and r_prime",
                "client_query_work": "secret code evaluation plus R*q_tilde trapdoor evaluation",
                "server_work": "m*n field products plus compressed AHE postprocessing",
                "integrity": "Figure 1/AHE postprocessing is not our full malicious-feedback integrity adapter",
                "parameter_status": "n,k,s,trapdoor,AHE conversion and integrity uninstantiated; no invented zero cost",
            },
        })
        geometry.append(dict(dataset=c["dataset"], profile="strong_global_E76", **coded_access_card(
            2 * cost["n"] * cost["replies"], h, int(c["homemade_he"]["q"]))))
    registry = json.loads(sources.read_text())
    archive = []
    for source in registry["sources"]:
        directory = ROOT / source.get("cache_directory", "../research-data/literature-20260930")
        pdf = directory / source["file"]
        assert hashlib.sha256(pdf.read_bytes()).hexdigest() == source["sha256"]
        archive.append({"id": source["id"], "pdf_sha256": source["sha256"],
                        "path": str(pdf.resolve())})
    record.update(kind="Q0_actual_geometry_and_paid_closest_control_cards",
                  public_operator_cards=geometry, private_matrix_cards=private,
                  archived_primary_pdfs_verified=archive,
                  scope="Exact counts/contract extraction only. No prior artifact, parameter assurance, performance comparison or new crypto protocol.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "operator_cards": len(geometry),
                      "private_cards": len(private), "verified_pdfs": len(archive)}))


if __name__ == "__main__":
    main()
