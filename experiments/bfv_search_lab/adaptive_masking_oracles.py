"""E34 exact ideal-mask transcripts, not a proof for encrypted preprocessing.

A query policy may even inspect the reused error vector and earlier toy
phases. It cannot inspect the CURRENT fresh pad before choosing the query.
Under that timing, delta=w-r is jointly independent of the reused errors.
Early linear disclosure, reuse and error-dependent token selection are failed
controls. No encryption/key/privacy/authentication API is introduced here.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from fractions import Fraction
import itertools

import gmpy2

from experiments.bfv_search_lab import crt_noise_budget as noise

Vector = tuple[int, ...]
Transcript = tuple[Vector, ...]


@dataclass(frozen=True)
class Distribution:
    field: int
    dimension: int
    requests: int
    mode: str
    counts: dict[tuple[Vector, Transcript], int]

    @property
    def mass(self) -> int:
        return sum(self.counts.values())

    def independence_distance(self) -> Fraction:
        """Exact TV distance of (errors,deltas) from its marginal product."""
        errors: Counter = Counter()
        deltas: Counter = Counter()
        for (e, ds), count in self.counts.items():
            errors[e] += count
            deltas[ds] += count
        total = self.mass
        difference = sum(abs(self.counts.get((e, ds), 0) * total - em * dm)
                         for e, em in errors.items() for ds, dm in deltas.items())
        return Fraction(difference, 2 * total * total)


def one_step(field: int, query: Vector) -> dict[Vector, int]:
    if (type(field) is not int or not 3 <= field <= 7 or not gmpy2.is_prime(field)
            or type(query) is not tuple or not 1 <= len(query) <= 2
            or any(type(x) is not int or not 0 <= x < field for x in query)):
        raise ValueError("Expected a tiny field query")
    return dict(Counter(tuple((w - r) % field for w, r in zip(query, pad, strict=True))
                        for pad in itertools.product(range(field), repeat=len(query))))


def joint(field: int = 5, dimension: int = 2, requests: int = 2, *, mode: str = "fresh") -> Distribution:
    """Exhaustive entropy accounting; every policy sees errors/history.

    Modes:
      fresh: query is fixed before the independent current mask is revealed;
      reuse: all requests use the first pad;
      early_linear: expose sum(current pad) before query commitment;
      select: reveal two candidate pads, select using the error vector.
    Toy histories include exact error-weighted phases, a deliberately stronger
    view than successful exact search provides. This does NOT model c0/c1 or
    the HE secret; replacing encrypted preprocessing needs its own argument.
    """
    if (type(field) is not int or not 3 <= field <= 7 or not gmpy2.is_prime(field)
            or type(dimension) is not int or not 1 <= dimension <= 2
            or type(requests) is not int or not 1 <= requests <= 3
            or mode not in ("fresh", "reuse", "early_linear", "select")):
        raise ValueError("Invalid tiny transcript")
    pad_count = 1 if mode == "reuse" else requests * (2 if mode == "select" else 1)
    if 3 ** dimension * field ** (dimension * pad_count) > 1 << 20:
        raise ValueError("Transcript enumeration exceeds the small-oracle budget")
    pads = tuple(itertools.product(range(field), repeat=dimension))
    errors = tuple(itertools.product(noise.cbd_counts(1), repeat=dimension))
    counts: Counter = Counter()
    for source in errors:
        e = tuple(value for value, _ in source)
        multiplicity = 1
        for _, mass in source:
            multiplicity *= mass
        for schedule in itertools.product(pads, repeat=pad_count):
            history: list[Vector] = []
            phase = 0
            for i in range(requests):
                # Arbitrarily error/history-dependent w, fixed before r in
                # the fresh model. The uniform-shift identity holds for any w.
                w = tuple((e[j] + phase + i * (j + 1) + sum(sum(ds) for ds in history)) % field
                          for j in range(dimension))
                pad = schedule[0] if mode == "reuse" else schedule[i]
                if mode == "early_linear":
                    # Only ONE linear form of the pad is disclosed. Force a
                    # matching form of delta to equal the error sign; full
                    # recovery of r is not necessary to violate independence.
                    w = ((sum(pad) + (1 if e[0] > 0 else -1 if e[0] < 0 else 0)) % field,
                         *((0,) * (dimension - 1)))
                elif mode == "select":
                    choices = schedule[2 * i:2 * i + 2]
                    def score(candidate: Vector, query: Vector = w, error: Vector = e) -> int:
                        ds = tuple((a - b) % field for a, b in zip(query, candidate, strict=True))
                        return sum(x * (v if v <= field // 2 else v - field) for x, v in zip(error, ds, strict=True))
                    pad = max(choices, key=score)
                delta = tuple((a - b) % field for a, b in zip(w, pad, strict=True))
                phase = sum(x * (v if v <= field // 2 else v - field) for x, v in zip(e, delta, strict=True))
                history.append(delta)
            counts[(e, tuple(history))] += multiplicity
    return Distribution(field, dimension, requests, mode, dict(counts))


def describe(distribution: Distribution) -> dict:
    distance = distribution.independence_distance()
    return {"field": distribution.field, "dimension": distribution.dimension,
            "requests": distribution.requests, "mode": distribution.mode,
            "exact_entropy_mass": distribution.mass, "support": len(distribution.counts),
            "error_delta_independence_tv": f"{distance.numerator}/{distance.denominator}",
            "exactly_independent_in_ideal_model": distance == 0,
            "scope": "Exact finite ideal-pad model only; no encrypted-preprocessing/PRG/HE proof."}
