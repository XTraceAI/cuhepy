"""E57 bounded nonnegative measured prices for known lifecycle controls.

Fit only declared features of one fixed geometry on training repetitions.
Held-out measurements check prediction error; a fitted price is not a proven
latency bound. Domain checks prevent extrapolation to new keys/layouts/edit
sizes. Standard least squares, delta caching and a greedy rule are controls,
not a novelty or competitive-ratio claim. No future edits/queries are inputs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math

import numpy as np


@dataclass(frozen=True)
class Price:
    intercept_s: float
    slope_s: float
    minimum: int
    maximum: int

    def predict(self, feature):
        if (type(feature) is not int or not self.minimum <= feature <= self.maximum
                or not all(math.isfinite(x) and x >= 0 for x in (self.intercept_s, self.slope_s))):
            raise ValueError("Price outside measured feature domain")
        return self.intercept_s + self.slope_s * feature


def fit(features, seconds):
    """Exact active-set NNLS for only two features: intercept and count."""
    if (len(features) != len(seconds) or len(features) < 3
            or any(type(x) is not int or x < 0 for x in features)
            or any(not math.isfinite(y) or y < 0 for y in seconds)
            or len(set(features)) < 2):
        raise ValueError("Underidentified or invalid measured prices")
    scale = max(1, max(features))
    design = np.asarray([(1.0, x / scale) for x in features])
    target = np.asarray(seconds)
    candidates = [np.zeros(2)]
    for columns in ((0,), (1,), (0, 1)):
        estimate, *_ = np.linalg.lstsq(design[:, columns], target, rcond=None)
        if np.all(estimate >= 0):
            result = np.zeros(2)
            result[list(columns)] = estimate
            candidates.append(result)
    best = min(candidates, key=lambda x: float(np.sum((design @ x - target) ** 2)))
    return Price(float(best[0]), float(best[1] / scale), min(features), max(features))


@dataclass(frozen=True)
class Models:
    # Geometry includes data dimensions, field/key profile, reply/column
    # geometry and approved edit count. Exact equality is required at use.
    geometry: tuple[int, ...]
    full_refresh: Price
    tile_refresh: tuple[tuple[int, Price], ...]
    private_edit: Price
    correction: Price

    def choose(self, geometry, *, pending, exceptions, dirty_tiles, horizon=1):
        """Known greedy control: pay for the currently scheduled query batch.

        horizon is supplied by the trusted caller, not learned from future
        queries. Unknown tile counts have no fitted refresh price and are
        excluded. Migration overhead is not fitted by this first model;
        actual rebase/snapshot work must still be timed by the caller.
        """
        if (tuple(geometry) != self.geometry or type(pending) is not int or pending < 1
                or type(horizon) is not int or not 1 <= horizon <= pending
                or type(dirty_tiles) is not int or not 0 <= dirty_tiles <= self.geometry[-2]):
            raise ValueError("Unpriced lifecycle geometry or query horizon")
        # The owner edit is already approved/applied before this choice and is
        # common to both actions. Do not charge a sunk edit only to keeping.
        keep = horizon * self.correction.predict(exceptions)
        if not exceptions:
            return "private_client_delta", {"private_client_delta": keep}
        costs = {"private_client_delta": keep,
                 "full_reencrypt": self.full_refresh.predict(pending) + horizon * self.correction.predict(0)}
        for count, price in self.tile_refresh:
            if count == dirty_tiles:
                costs["tile_reencrypt"] = price.predict(pending) + horizon * self.correction.predict(0)
        return min(costs, key=costs.get), costs

    def json(self):
        return asdict(self)

    @classmethod
    def load(cls, data):
        return cls(tuple(data["geometry"]), Price(**data["full_refresh"]),
                   tuple((count, Price(**p)) for count, p in data["tile_refresh"]),
                   Price(**data["private_edit"]), Price(**data["correction"]))
