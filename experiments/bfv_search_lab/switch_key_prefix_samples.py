"""E98 exact public setup-row cancellation for diagnostic known-prefix keys."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from fractions import Fraction
from math import comb

from experiments.bfv_search_lab.batched_score_bridge import context
from experiments.bfv_search_lab.partial_packed_switch import Keys
from experiments.bfv_search_lab.target_prefix_samples import extract, positions


def row_pair(mask1, body1, mask2, body2, q, radix):
    """Public pair only: source cancels if its multipliers differ by radix."""
    if (type(q) is not int or not 3 <= q < 1 << 64 or q % 2 != 1
            or type(radix) is not int or not 3 <= radix <= 65535 or radix % 2 != 1
            or type(mask1) is not tuple):
        raise ValueError("Canonical bounded pair context required")
    n = len(mask1)
    positions(n, 1)
    if any(type(p) is not tuple or len(p) != n
           or any(type(x) is not int or not 0 <= x < q for x in p)
           for p in (mask1, body1, mask2, body2)):
        raise ValueError("Canonical public mask/body rows required")
    mask = tuple((b-radix*a) % q for a, b in zip(mask1, mask2, strict=True))
    body = tuple((b-radix*a) % q for a, b in zip(body1, body2, strict=True))
    return mask, body


def pairing_inventory(q, radix, skip):
    levels = context(q, radix)
    if type(skip) is not int or not 0 <= skip <= levels:
        raise ValueError("Invalid retained C2 levels")
    return tuple((family, j, j+1) for family, start in ((0, 0), (1, skip))
                 for j in range(start, levels-1, 2))


@dataclass(frozen=True)
class PublicPair:
    family: int
    levels: tuple[int, int]
    mask: tuple[int, ...]
    body: tuple[int, ...]
    samples: tuple[tuple[tuple[int, ...], int], ...]


def from_keys(keys):
    """Exact public transform, not proof of honest masks/errors/source multipliers."""
    if type(keys) is not Keys or type(keys.values) is not tuple or len(keys.values) != 2:
        raise ValueError("Both diagnostic source key families required")
    inventory = pairing_inventory(keys.q, keys.radix, keys.skipped_c2_levels)
    levels = context(keys.q, keys.radix)
    n = 0
    for rows, start in zip(keys.values, (0, keys.skipped_c2_levels), strict=True):
        if type(rows) is not tuple or len(rows) != levels-start:
            raise ValueError("Wrong retained level count")
        for pair in rows:
            if type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not tuple:
                raise ValueError("Canonical mask/body key row required")
            if not n:
                n = len(pair[0])
            if any(type(poly) is not tuple or len(poly) != n
                   or any(type(x) is not int or not 0 <= x < keys.q for x in poly) for poly in pair):
                raise ValueError("Incompatible or noncanonical key polynomials")
    positions(n, keys.target_prefix)
    result = []
    for family, first, second in inventory:
        start = keys.skipped_c2_levels if family else 0
        a, b = keys.values[family][first-start], keys.values[family][second-start]
        mask, body = row_pair(*a, *b, keys.q, keys.radix)
        result.append(PublicPair(family, (first, second), mask, body,
                                 extract(mask, body, keys.q, keys.target_prefix)))
    return tuple(result)


def sample_count(n, prefix, q, radix, skip):
    return len(positions(n, prefix))*len(pairing_inventory(q, radix, skip))


def error_distribution(eta, radix):
    """Exact integer mass of E2-radix*E1, each E an independent CBD_eta."""
    if (type(eta) is not int or not 1 <= eta <= 64
            or type(radix) is not int or not 3 <= radix <= 65535 or radix % 2 != 1):
        raise ValueError("Invalid paired CBD distribution")
    masses = {e: comb(2*eta, eta+e) for e in range(-eta, eta+1)}
    counts = Counter()
    for first, mass1 in masses.items():
        for second, mass2 in masses.items():
            counts[second-radix*first] += mass1*mass2
    denominator = 2**(4*eta)
    assert sum(counts.values()) == denominator and sum(e*c for e, c in counts.items()) == 0
    variance = Fraction(sum(e*e*c for e, c in counts.items()), denominator)
    assert variance == Fraction(eta*(radix*radix+1), 2)
    return counts, denominator
