"""Regression: a finite cost cannot borrow nonexistent independent setup rows."""

import json
from pathlib import Path

import pytest

from experiments.bfv_search_lab import estimator_sample_budget as lab

ROOT = Path(__file__).resolve().parents[2]


def profiles():
    return json.loads((ROOT / "benchmarks/results/publication-switch-key-prefix-security-01-20261002.json").read_text())["profiles"]


def test_actual_finite_default_MATZOV_costs_overdraw_setup_samples():
    rows = profiles()
    checks = [lab.check("dual_hybrid_default", c["attacks"]["dual_hybrid"], c["target_prefix"],
                        c["available_independent_samples"]) for c in rows]
    finite = [c for c in checks if c["status"] != "no_finite_cost"]
    assert finite and all(c["status"] == "exceeds_original_sample_budget" for c in finite)
    assert all(c["returned_value"] > c["allowed_value"] for c in finite)


def test_actual_small_ring_raw_negative_is_not_an_applicable_cost():
    rows = [c for c in profiles() if c["source_N"] == 2048 and c["target_prefix"] == 512]
    assert len(rows) == 4
    for row in rows:
        got = lab.audit(row)
        assert got["original_raw_minimum"] < 128
        assert got["applicable_original_partial_minimum"] is None
        assert not got["qualified_original_partial_below128"] and not got["parameter_approved"]


def test_actual_large_ring_negative_survives_the_budget_check():
    rows = [c for c in profiles() if c["source_N"] == 16384 and c["target_prefix"] == 512]
    assert len(rows) == 8
    for row in rows:
        got = lab.audit(row)
        assert 0 < got["applicable_original_partial_minimum"] < 128
        assert got["qualified_original_partial_below128"] and not got["parameter_approved"]


def test_nonfinite_missing_or_unframed_calls_never_become_approval():
    assert lab.check("dual_hybrid_limited", {"status": "timeout_or_failed"}, 512, 20)["status"] == "no_finite_cost"
    assert not lab.check("dual_hybrid_limited", {"status": "finite_heuristic", "log2_rop": 1, "cost": {}}, 512, 20)["applicable_finite_cost"]
    for dimension, samples in ((True, 20), (512, True), (512, 0)):
        with pytest.raises(ValueError):
            lab.check("usvp", {}, dimension, samples)
