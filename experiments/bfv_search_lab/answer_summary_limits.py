"""E39 exact counterexamples to distance-only moment/aggregate shortcuts.

Prouhet/Thue--Morse equal-power-sum partitions are classical. Their embedding
as valid binary Hamming instances is a control for this research portfolio,
not a novel impossibility theorem for HE, top-k, histograms or all summaries.
"""

from __future__ import annotations

from dataclasses import dataclass


def scores(values: tuple[int, ...], dimension: int) -> None:
    if (type(dimension) is not int or not 1 <= dimension <= 512 or not 1 <= len(values) <= 65536
            or any(type(x) is not int or not 0 <= x <= dimension for x in values)):
        raise ValueError("Expected bounded exact Hamming distances")


def moments(values: tuple[int, ...], degree: int) -> tuple[int, ...]:
    if (type(degree) is not int or not 0 <= degree <= 8 or not 1 <= len(values) <= 65536
            or any(type(x) is not int or not 0 <= x <= 512 for x in values)):
        raise ValueError("Expected a bounded moment oracle")
    return tuple(sum(x ** j for x in values) for j in range(degree + 1))


def rows(values: tuple[int, ...], dimension: int) -> tuple[int, ...]:
    """Query zero realizes every declared distance, including repeated rows."""
    scores(values, dimension)
    return tuple((1 << x) - 1 for x in values)


def thue_morse(degree: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    if type(degree) is not int or not 1 <= degree <= 8:
        raise ValueError("Expected a tiny equal-moment control degree")
    # prod_j(1-z^(2^j)) has a zero of order degree+1 at z=1.
    # Its signed exponents are the two popcount-parity classes.
    limit = 1 << (degree + 1)
    return tuple(i for i in range(limit) if i.bit_count() % 2 == 0), tuple(
        i for i in range(limit) if i.bit_count() % 2 == 1)


def top(values: tuple[int, ...], k: int = 3) -> tuple[tuple[int, int], ...]:
    scores(values, max(1, max(values)))
    if type(k) is not int or not 1 <= k <= len(values):
        raise ValueError("Invalid stable selection size")
    return tuple(sorted((x, i) for i, x in enumerate(values))[:k])


@dataclass(frozen=True)
class Collision:
    left: tuple[int, ...]
    right: tuple[int, ...]
    degree: int

    def describe(self) -> dict[str, object]:
        dimension = max(max(self.left), max(self.right), 1)
        a, b = moments(self.left, self.degree), moments(self.right, self.degree)
        assert a == b and top(self.left) != top(self.right)
        assert tuple(x.bit_count() for x in rows(self.left, dimension)) == self.left
        assert tuple(x.bit_count() for x in rows(self.right, dimension)) == self.right
        return {"degree": self.degree, "dimension": dimension, "left": self.left, "right": self.right,
                "equal_count_and_moments": a, "left_stable_top3": top(self.left), "right_stable_top3": top(self.right),
                "valid_query_zero_hamming_embedding": True}


def coverage(lower: tuple[int, ...], measured: dict[int, int], k: int = 3) -> bool:
    """Exact omitted-row test, including stable tie IDs; bounds must be trusted."""
    scores(lower, max(1, max(lower)))
    if (type(k) is not int or not 1 <= k <= len(lower) or len(measured) < k
            or any(type(i) is not int or not 0 <= i < len(lower) or type(d) is not int or not lower[i] <= d <= 512
                   for i, d in measured.items())):
        raise ValueError("Invalid measured rows or trusted lower bounds")
    threshold = sorted((d, i) for i, d in measured.items())[k - 1]
    return all((bound, i) > threshold for i, bound in enumerate(lower) if i not in measured)


def describe() -> dict[str, object]:
    controls = [Collision((0, 3, 3), (1, 1, 4), 2), Collision(*thue_morse(3), 3),
                Collision(*thue_morse(7), 7)]
    # A complete distance histogram still contains no mapping to source IDs.
    a, b = (0, 1, 2, 3), (3, 2, 1, 0)
    assert sorted(a) == sorted(b) and top(a) != top(b)
    return {"moment_collisions": [c.describe() for c in controls],
            "histogram_id_collision": {"left": a, "right": b, "left_top3": top(a), "right_top3": top(b)},
            "scope": "These specific distance-only summaries cannot determine exact stable top-k for all valid indices. "
                     "Not a lower bound against ID-aware summaries, comparisons, trusted selection, interactive protocols or FHE."}
