#!/usr/bin/env python3
"""E80 exact homemade module/LHE fixture and complete retained-profile counts.

No performance/security claim: even passing recovery does not approve LWE
parameters, sampling, adaptive feedback, remote enrollment or private timing.
"""

# ruff: noqa: E402 -- standalone research runner.

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import structured_module_oracle as module
from experiments.bfv_search_lab.test_structured_module_oracle import (
    encrypted_case, test_independent_integer_forward_adjoint_basis_H_Z_and_bounds,
)
from experiments.bfv_search_lab.test_supported_decoder import CASES


def recorded_profiles():
    paths, profiles = [], []
    for dataset in ("mushroom", "semeion"):
        path = ROOT / f"benchmarks/results/publication-anchor-{dataset}-20260930.json"
        paths.append(path)
        for profile in json.loads(path.read_text())["result"]["cases"]:
            c = profile["cost_model"]
            assert c["correction_coefficients"] == c["coordinate_columns"] * c["subring_degree"]
            profiles.append((dataset, profile["layout"], int(profile["q"]), c))
    path = ROOT / "benchmarks/results/publication-connect4-encrypted-controls-20260930.json"
    paths.append(path)
    for profile in json.loads(path.read_text())["cases"]:
        profiles.append(("connect4", profile["kind"], int(profile["q"]), profile["geometry"]))
    path = ROOT / "benchmarks/results/publication-enrolled-global-service-control-20261001.json"
    paths.append(path)
    for profile in json.loads(path.read_text())["cases"]:
        he = profile["homemade_he"]
        profiles.append((profile["dataset"], "E76_" + he["geometry_kind"], int(he["q"]), he["cost_model"]))
    screens = []
    for dataset, label, q, c in profiles:
        degrees = (c["subring_degree"],) * c["coordinate_columns"]
        assert sum(degrees) == c["correction_coefficients"]
        common = math.gcd(*degrees)
        variants = [module.count_screen(n=c["n"], replies=c["replies"], degrees=degrees, inner_q=q,
                                        query_bound=c["t"] // 2, m=m) for m in sorted({1, common})]
        scalar, best = variants[0], variants[-1]
        screens.append({"dataset": dataset, "profile": label, "t": c["t"], "common_degree": common,
                        "variants": variants, "H_coefficient_reduction": common,
                        "complete_registration_body_ratio_to_scalar_outer": best["client_registration_body_bytes"] / scalar["client_registration_body_bytes"],
                        "outer_reply_ratio_to_bitpacked_inner": best["outer_reply_body_bytes"] / best["recovered_inner_reply_body_bytes"],
                        "retained_existing_online_reply_serialized_bytes": c["online_response_body_bytes"],
                        "online_module_check_schoolbook_product_ratio_to_scalar_outer": common,
                        "unapproved_dimension_count_only_not_equal_security_comparison": True})
    return screens, paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a new immutable output path")
    algebra = []
    for n in (8, 16, 32):
        for degrees in ((2, 4, 8), (4, 8), (8, 8)):
            for replies in (1, 2):
                for m in (1, 2, 4, 8):
                    if any(d % m for d in degrees):
                        continue
                    test_independent_integer_forward_adjoint_basis_H_Z_and_bounds(n, degrees, replies, m)
                    algebra.append({"n": n, "degrees": degrees, "replies": replies, "m": m,
                                    "independent_signed_basis_forward_adjoint_H_Z_equal": True,
                                    "basis_columns_checked": sum(degrees)})
    screens, inputs = recorded_profiles()
    source_paths = [Path(__file__), ROOT / "docs/research/structured-module-preregistration-20261001.md",
                    ROOT / "benchmarks/dictionary_layout_lab.py", *inputs,
                    *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
                        "structured_module_oracle", "test_structured_module_oracle", "test_supported_decoder",
                        "structured_operator_oracle", "structured_registration_oracle", "reduction_oracles",
                        "crt_query_space", "crt_masked_bgv", "dyadic_crt", "score_layout", "shallow_bgv",
                        "owner_bgv", "seeded_bgv")), ROOT / "src/cuhepy/bfv/scheme.py"]
    result = metadata(source_paths)
    result.update(kind="E80_module_outer_LHE_fixture_and_full_object_count_screen",
                  algebra_cases=algebra, encrypted_search_cases=[encrypted_case(c) for c in CASES],
                  recorded_profiles=screens,
                  public_fixture_relation="y=D_m*(A_m*s+e+floor(q/Q)*x); pre-secret Z_m*u=C*y; recover exact D*x mod Q",
                  fixed_error_soundness_scope="Independent constant-binary rows give <=2^-kappa for a fixed nonzero ring error; no adaptive theorem.",
                  decision="Retain module closure/control. Literal retained-H route fails as universal paper winner: scalar best profiles get no gain and every outer reply grows. Investigate only a new complete release/registration step before acceleration.",
                  scope="Owner-local enrollment fixture, exact algebra and object/operation counts. Homemade arithmetic; no approved module-LWE/inner parameters, sampler, private timing, durable feedback policy, remote authenticated provisioning, cryptographic proof or timing benchmark. Counts expose unknown metadata and do not invent zero Hprime.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "algebra_cases": len(algebra),
                      "basis_columns_checked": sum(c["basis_columns_checked"] for c in algebra),
                      "exact_encrypted_queries": sum(c["exact_search_queries"] for c in result["encrypted_search_cases"]),
                      "recorded_profiles": len(screens),
                      "outer_reply_ratio_range": [min(c["outer_reply_ratio_to_bitpacked_inner"] for c in screens),
                                                   max(c["outer_reply_ratio_to_bitpacked_inner"] for c in screens)]}))


if __name__ == "__main__":
    main()
