"""Pricing must expose underidentification and never infer unseen geometry."""

import math

import pytest

from experiments.bfv_search_lab import lifetime_prices as prices


def test_positive_prices_identify_an_independent_synthetic_cost_law():
    features = (0, 1, 3, 5, 10)
    model = prices.fit(features, tuple(0.5 + 0.2 * x for x in features))
    assert math.isclose(model.predict(7), 1.9)
    # A decreasing sample does not give the optimizer a negative-work reward.
    declining = prices.fit(features, (1.0, 0.9, 0.8, 0.7, 0.5))
    assert declining.slope_s == 0 and declining.predict(10) >= declining.predict(0)


def test_prices_reject_unseen_counts_underidentification_and_nonfinite_data():
    for features, observations in (((4, 4, 4), (1, 2, 3)), ((0, 1), (1, 2)),
                                   ((0, 1, 2), (1, float("nan"), 3))):
        with pytest.raises(ValueError):
            prices.fit(features, observations)
    model = prices.fit((4, 8, 12), (0.2, 0.3, 0.4))
    for invalid in (3, 13, True):
        with pytest.raises(ValueError, match="domain"):
            model.predict(invalid)


def test_causal_rule_uses_current_costs_and_refuses_missing_geometry():
    geometry = (128, 32, 32, 4, 8)  # illustrative test geometry, not fitted timing.
    model = prices.Models(geometry, prices.Price(2, 0.1, 1, 8),
                          ((1, prices.Price(0.1, 0.01, 1, 8)),),
                          prices.Price(0.01, 0, 0, 128), prices.Price(0.01, 0.01, 0, 128))
    assert model.choose(geometry, pending=8, exceptions=1, dirty_tiles=1)[0] == "private_client_delta"
    assert model.choose(geometry, pending=8, exceptions=100, dirty_tiles=1)[0] == "tile_reencrypt"
    assert model.choose(geometry, pending=8, exceptions=100, dirty_tiles=2)[0] == "private_client_delta"
    with pytest.raises(ValueError, match="geometry"):
        model.choose((128, 32, 64, 4, 8), pending=8, exceptions=1, dirty_tiles=1)
    with pytest.raises(ValueError, match="horizon"):
        model.choose(geometry, pending=8, exceptions=1, dirty_tiles=1, horizon=9)
    assert prices.Models.load(model.json()) == model
