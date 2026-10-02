"""E98 applicability guard for registered short-secret/large-error cost calls.

This is a research model audit, not validation of every estimator algorithm,
distribution, security level or protocol. It preserves inapplicable raw costs.
"""

from __future__ import annotations


def check(name, result, dimension, available):
    if (name not in ("usvp", "bdd", "dual", "dual_hybrid_default", "dual_hybrid_limited")
            or type(dimension) is not int or not 1 <= dimension <= 32768
            or type(available) is not int or not 1 <= available <= 1 << 32):
        raise ValueError("Outside the registered sample-budget audit")
    if result.get("status") != "finite_heuristic" or result.get("log2_rop") is None:
        return {"status": "no_finite_cost", "applicable_finite_cost": False}
    field = "d" if name in ("usvp", "bdd") else "m"
    value = result.get("cost", {}).get(field)
    try:
        count = int(value)
    except (TypeError, ValueError):
        return {"status": "missing_original_sample_or_dimension_evidence", "applicable_finite_cost": False}
    cap = dimension+available+1 if field == "d" else available
    applicable = 1 <= count <= cap
    return {"status": "sample_budget_pass_only" if applicable else "exceeds_original_sample_budget",
            "applicable_finite_cost": applicable, "checked_cost_field": field,
            "returned_value": count, "allowed_value": cap,
            "full_algorithm_distribution_security_approval": False}


def audit(profile):
    """Retain the original minimum; separately compute qualified partial minimum."""
    checks = {name: check("dual_hybrid_default" if name == "dual_hybrid" else name, result,
                          profile["target_prefix"], profile["available_independent_samples"])
              for name, result in profile["attacks"].items()}
    finite = [profile["attacks"][name]["log2_rop"] for name, c in checks.items() if c["applicable_finite_cost"]]
    return {"original_raw_minimum": profile["minimum_returned_log2_rop"], "original_call_checks": checks,
            "applicable_original_partial_minimum": min(finite) if finite else None,
            "qualified_original_partial_below128": bool(finite and min(finite) < 128),
            "parameter_approved": False}
