"""E22: data-dependent coordinate folding with exact per-record error budgets.

The owner groups equal, complementary, or nearby database columns. Expanding
a row's representative bits gives a template z. For EVERY query q,

    H(q,z) - H(x,z) <= H(q,x) <= H(q,z) + H(x,z).

The query folds its signed bits by group, so the lower bound costs one dot
product of length groups (+ one error feature when needed). Exact groups give
exact distances. This is a local research representation, not private routing,
an authenticated search service, or a new security parameter recommendation.
The map and column-error threshold depend on private index data: keep them on
the owner. Even the chosen layout size can reveal index structure.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.bfv_search_lab import linear_packing as packing


@dataclass(frozen=True)
class FoldPlan:
    dimension: int
    representatives: tuple[int, ...]
    # (group, complement): x[j] is approximated by x[representative] XOR complement.
    mapping: tuple[tuple[int, int], ...]
    max_error: int

    @property
    def features(self) -> int:
        return len(self.representatives) + bool(self.max_error)


def _words(query: int, rows: list[int], dimension: int) -> None:
    if (type(dimension) is not int or not 1 <= dimension <= 4096
            or type(query) is not int or not 0 <= query < 1 << dimension
            or any(type(x) is not int or not 0 <= x < 1 << dimension for x in rows)):
        raise ValueError("Invalid binary folding fixture")


def validate(plan: FoldPlan) -> None:
    _words(0, [], plan.dimension)
    groups = len(plan.representatives)
    if (not 1 <= groups <= plan.dimension or len(set(plan.representatives)) != groups
            or any(type(j) is not int or not 0 <= j < plan.dimension for j in plan.representatives)
            or len(plan.mapping) != plan.dimension or type(plan.max_error) is not int
            or not 0 <= plan.max_error <= plan.dimension
            or any(type(g) is not int or not 0 <= g < groups or type(c) is not int or c not in (0, 1)
                   for g, c in plan.mapping)
            or any(plan.mapping[j] != (g, 0) for g, j in enumerate(plan.representatives))):
        raise ValueError("Invalid folding map")


def _template(plan: FoldPlan, row: int) -> int:
    return sum((((row >> plan.representatives[g]) & 1) ^ c) << j
               for j, (g, c) in enumerate(plan.mapping))


def prepare(rows: list[int], dimension: int, max_column_errors: int = 0) -> FoldPlan:
    """Greedy owner preprocessing; every returned row budget is exact.

    Thresholding/greedy ordering affect compression, never the lower-bound
    guarantee. Exhaustive row residuals certify the final map. Recompute the
    budgets and epoch binding when the index changes; this is not an update API.
    """
    _words(0, rows, dimension)
    if (not rows or type(max_column_errors) is not int
            or not 0 <= max_column_errors <= len(rows) // 2):
        raise ValueError("Require a nonempty index and a valid column-error threshold")
    columns = [sum(((row >> j) & 1) << i for i, row in enumerate(rows)) for j in range(dimension)]
    representatives: list[int] = []
    mapping: list[tuple[int, int]] = []
    for j, column in enumerate(columns):
        best = (len(rows) + 1, 0, 0)
        for g, rep in enumerate(representatives):
            distance = (column ^ columns[rep]).bit_count()
            best = min(best, (min(distance, len(rows) - distance), g, int(distance > len(rows) // 2)))
        if best[0] <= max_column_errors:
            mapping.append((best[1], best[2]))
        else:
            mapping.append((len(representatives), 0))
            representatives.append(j)
    provisional = FoldPlan(dimension, tuple(representatives), tuple(mapping), dimension)
    maximum = max((row ^ _template(provisional, row)).bit_count() for row in rows)
    return FoldPlan(dimension, tuple(representatives), tuple(mapping), maximum)


def query_features(plan: FoldPlan, query: int) -> list[int]:
    validate(plan)
    _words(query, [], plan.dimension)
    weights = [0] * len(plan.representatives)
    for j, (g, complement) in enumerate(plan.mapping):
        weights[g] += (2 * ((query >> j) & 1) - 1) * (1 - 2 * complement)
    if plan.max_error:
        weights.append(1)
    return weights


def index_features(plan: FoldPlan, rows: list[int]) -> list[list[int]]:
    validate(plan)
    _words(0, rows, plan.dimension)
    result = []
    for row in rows:
        error = (row ^ _template(plan, row)).bit_count()
        if error > plan.max_error:
            raise ValueError("Row exceeds this index epoch's certified error range")
        features = [2 * ((row >> rep) & 1) - 1 for rep in plan.representatives]
        if plan.max_error:
            features.append(2 * error)
        result.append(features)
    return result


def lower_bounds(plan: FoldPlan, query: int, rows: list[int]) -> list[int]:
    """Plain integer oracle; negative template bounds can safely clamp to zero."""
    weights = query_features(plan, query)
    result = []
    for features in index_features(plan, rows):
        numerator = plan.dimension - sum(a * b for a, b in zip(weights, features, strict=True))
        assert numerator % 2 == 0
        result.append(max(0, numerator // 2))
    return result


def inputs(plan: FoldPlan, query: int, rows: list[int], n: int) -> tuple[list[int], list[list[int]], int]:
    return packing.pack(query_features(plan, query), index_features(plan, rows), n)


def decode(plan: FoldPlan, dots: list[int], prime: int) -> list[int]:
    """Decode the interval [-max_error, dimension], without a centered-dot guess.

    The dot can exceed t/2 although the distance interval fits. First divide
    (dimension-dot) by two IN THE FIELD, then unwrap that known interval.
    Range checks here are correctness checks on local test outputs, not a
    defense against chosen-ciphertext or selective-failure attacks.
    """
    validate(plan)
    if (type(prime) is not int or not prime % 2 or prime <= plan.dimension + plan.max_error
            or any(type(x) is not int or not 0 <= x < prime for x in dots)):
        raise ValueError("Plaintext modulus does not cover the certified distance interval")
    inverse = pow(2, -1, prime)
    result = []
    for dot in dots:
        distance = (plan.dimension - dot) * inverse % prime
        if distance > plan.dimension:
            distance -= prime
        if not -plan.max_error <= distance <= plan.dimension:
            raise ValueError("Local result lies outside the certified interval")
        result.append(max(0, distance))
    return result
