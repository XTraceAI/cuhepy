"""Planner tests isolate trust, disclosure, pool and accounting errors."""

from __future__ import annotations

from dataclasses import replace

import pytest

from experiments.bfv_search_lab import portfolio_costs as model


def candidate(**changes):
    return replace(model.Candidate("example", .05, 1000, 100000, 1000000, 1, 2, 900000, 9, 20000, 50000), **changes)


def test_pool_and_full_index_are_charged_even_with_unused_tokens():
    result = model.cost(candidate(), completed=1, upload_mbps=10, download_mbps=100, rtt_ms=40)
    assert result["online_serial_s_model"] == pytest.approx(.05 + .0008 + .008 + .04)
    assert result["offline_cost_per_completed_s_model"] == pytest.approx(3 + 1.52)
    assert result["body_bytes_per_completed_including_unused"] == 2001000
    assert result["unused_tokens"] == 8
    full = model.cost(candidate(), completed=9, upload_mbps=10, download_mbps=100, rtt_ms=40)
    assert full["offline_cost_per_completed_s_model"] == pytest.approx((3 + 1.52) / 9)
    with pytest.raises(ValueError, match="actually prepared pool"):
        model.cost(candidate(), completed=10, upload_mbps=10, download_mbps=100)


@pytest.mark.parametrize("contract,reason", [
    (model.Contract(disclosure="only_top_k", allow_unreviewed_research=True), "different output/disclosure"),
    (model.Contract(trusted_owner_preprocessing=False, allow_unreviewed_research=True), "trusted owner preprocessing unavailable"),
    (model.Contract(owner_coordinate_retention=False, allow_unreviewed_research=True), "plaintext coordinates forbidden"),
    (model.Contract(canonical_client_body_limit=19999, allow_unreviewed_research=True), "canonical private client body exceeds budget"),
    (model.Contract(owner_coordinate_body_limit=49999, allow_unreviewed_research=True), "owner coordinate body exceeds budget"),
    (model.Contract(), "research assurances incomplete"),
])
def test_faster_candidates_do_not_override_contracts(contract, reason):
    assert reason in model.rejection(candidate(local_s=0), contract)
    with pytest.raises(ValueError, match="satisfies"):
        model.choose((candidate(local_s=0),), contract, completed=9, upload_mbps=100, download_mbps=100)


def test_online_and_amortized_objectives_can_choose_different_candidates():
    a = candidate(name="faster online", local_s=.01, setup_s=100)
    b = candidate(name="cheaper setup", local_s=.05, setup_s=1)
    contract = model.Contract(allow_unreviewed_research=True)
    assert model.choose((a, b), contract, completed=9, upload_mbps=100, download_mbps=100,
                        objective="online_serial_s_model")[0] == a
    assert model.choose((a, b), contract, completed=9, upload_mbps=100, download_mbps=100)[0] == b
    assert set(model.pareto((a, b, candidate(name="dominated", local_s=1, setup_s=1000)))) == {a.name, b.name}


def test_incomplete_review_does_not_become_production_by_one_flag():
    for changes in ({"reviewed_protocol": True}, {"reviewed_parameters": True}, {"private_timing_assured": True}):
        assert model.rejection(candidate(**changes), model.Contract())
    reviewed = candidate(reviewed_protocol=True, reviewed_parameters=True, private_timing_assured=True)
    assert not model.rejection(reviewed, model.Contract())


def test_invalid_models_and_nonfinite_links_fail():
    for changes in ({"local_s": float("nan")}, {"prepared_tokens": 0}, {"response_bytes": -1}):
        with pytest.raises(ValueError):
            candidate(**changes).validate()
    for link in (0, -1, float("inf"), float("nan")):
        with pytest.raises(ValueError):
            model.cost(candidate(), completed=9, upload_mbps=link, download_mbps=100)
