"""E36 uniform centered-lift norm bounds for public CRT correction images.

Group proportional linear forms and maximize each group's norm over the
entire field. Summing those maxima is an upper bound even when the groups
are dependent. Exact tiny enumeration and constructive lower witnesses keep
the gap visible. No encryption gate is relaxed and no typical-mask estimate
is promoted to adaptive correctness. These are known finite-field identities.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import itertools
import random

import gmpy2
import numpy as np

from experiments.bfv_search_lab import crt_query_space as crt


@dataclass(frozen=True)
class Image:
    prime: int
    forms: tuple[tuple[int, ...], ...]

    @property
    def dimension(self) -> int:
        return len(self.forms[0])


def validate(image: Image) -> None:
    p = image.prime
    if (type(p) is not int or not 3 <= p <= 65537 or not gmpy2.is_prime(p)
            or type(image.forms) is not tuple or not 1 <= len(image.forms) <= 128
            or type(image.forms[0]) is not tuple or not 1 <= image.dimension <= 128
            or any(type(row) is not tuple or len(row) != image.dimension
                   or any(type(x) is not int or not 0 <= x < p for x in row) for row in image.forms)):
        raise ValueError("Expected a bounded prime-field linear image")


def norm(image: Image, value: tuple[int, ...]) -> int:
    validate(image)
    p = image.prime
    if (type(value) is not tuple or len(value) != image.dimension
            or any(type(x) is not int or not 0 <= x < p for x in value)):
        raise ValueError("Invalid correction-image coordinates")
    return sum(min(y, p - y) for row in image.forms
               if (y := sum(a * b for a, b in zip(row, value, strict=True)) % p))


def exact(image: Image, *, budget: int = 65536) -> tuple[int, tuple[int, ...]]:
    validate(image)
    if type(budget) is not int or not 1 <= budget <= 1 << 18 or image.prime ** image.dimension > budget:
        raise ValueError("Exact image enumeration exceeds its declared budget")
    best, witness = -1, (0,) * image.dimension
    for value in itertools.product(range(image.prime), repeat=image.dimension):
        score = norm(image, value)
        if score > best:
            best, witness = score, value
    return best, witness


def projective(image: Image) -> tuple[int, tuple[tuple[tuple[int, ...], tuple[int, ...], int], ...]]:
    """A disjoint cover of nonzero forms with exhaustive scalar maxima."""
    validate(image)
    p = image.prime
    groups: dict[tuple[int, ...], list[int]] = {}
    for row in image.forms:
        scale = next((x for x in row if x), 0)
        if not scale:
            continue
        inverse = pow(scale, -1, p)
        direction = tuple(x * inverse % p for x in row)
        groups.setdefault(direction, []).append(scale)
    rows = []
    for direction, scales in groups.items():
        bound = p // 2 if len(scales) == 1 else max(sum(min(y, p - y) for c in scales
                                                       if (y := c * a % p)) for a in range(p))
        rows.append((direction, tuple(scales), bound))
    return sum(row[2] for row in rows), tuple(rows)


def witness(image: Image, *, seed: int = 36, starts: int = 2) -> tuple[int, tuple[int, ...]]:
    """Deterministic research search; no claim that its maximizer is optimal."""
    validate(image)
    if type(starts) is not int or not 1 <= starts <= 4:
        raise ValueError("Bounded witness search expects one to four starts")
    p, d = image.prime, image.dimension
    matrix = np.asarray(image.forms, dtype=np.int64)
    rng = random.Random(seed)
    candidates = np.asarray([[rng.randrange(p) for _ in range(d)] for _ in range(32)], dtype=np.int64)
    values = candidates @ matrix.T % p
    scores = np.minimum(values, p - values).sum(axis=1)
    winner = int(scores.argmax())
    best, best_value = int(scores[winner]), tuple(map(int, candidates[winner]))
    for start in range(starts):
        current = np.asarray(best_value if start == 0 else (0,) * d, dtype=np.int64)
        phase = matrix @ current % p
        for _ in range(2):
            changed = False
            for j in range(d):
                possible = (phase[None, :] + (np.arange(p) - current[j])[:, None] * matrix[:, j][None, :]) % p
                scores = np.minimum(possible, p - possible).sum(axis=1)
                choice = int(scores.argmax())
                if int(scores[choice]) > int(np.minimum(phase, p - phase).sum()):
                    current[j], phase, changed = choice, possible[choice], True
            score = int(np.minimum(phase, p - phase).sum())
            if score > best:
                best, best_value = score, tuple(map(int, current))
            if not changed:
                break
    assert best == norm(image, best_value)
    return best, best_value


def describe(image: Image, *, seed: int = 36) -> dict:
    validate(image)
    p, b = image.prime, image.prime // 2
    z = sum(any(row) for row in image.forms)
    expectation = Fraction(z * b * (b + 1), p)
    expectation_ceiling = (expectation.numerator + expectation.denominator - 1) // expectation.denominator
    upper, groups = projective(image)
    method = "exhaustive scalar projective groups"
    if p ** image.dimension <= 65536:
        upper, value = exact(image)
        lower = upper
        method = "exhaustive entire image"
    else:
        lower, value = witness(image, seed=seed)
    witness_norm = norm(image, value)
    lower = max(lower, expectation_ceiling)
    assert lower <= upper <= z * b <= len(image.forms) * b
    return {"t": p, "dimension": image.dimension, "coefficients": len(image.forms), "nonzero_forms": z,
            "projective_groups": len(groups), "cube_bound": len(image.forms) * b, "nonzero_cube_bound": z * b,
            "uniform_expectation_lower_bound": str(expectation), "expectation_ceiling": expectation_ceiling,
            "proved_lower": lower, "proved_upper": upper, "witness_norm": witness_norm, "witness": value,
            "upper_method": method, "maximum_proved_exact": lower == upper,
            "scope": "Uniform image-norm analysis only; no encryption/profile or protocol gate changed."}


def generators(s: crt.Space) -> tuple[tuple[tuple[int, ...], Image], ...]:
    """Use only public geometry/scheduling; private affine maps are unnecessary.

    Interpolate one column at a time in the short ring. This constructs its
    exact generator, not sampled coefficients. Tiny tests independently compare
    every basis vector with the existing correction and full CRT encoders.
    """
    crt.validate(s)
    ctx, p = s.layout.context, s.layout.context.prime
    coordinate_maps = crt.split(s, tuple(range(s.dimension)))
    result = []
    for j, degree in enumerate(s.column_degrees):
        variables = tuple(sorted({row[j] for row in coordinate_maps if j < len(row)}))
        rows: list[list[int]] = [[] for _ in range(degree)]
        for variable in variables:
            if j < s.shared:
                rows[0].append(1)
                continue
            work = {leaf.path: [int(j < len(coordinate_maps[group]) and coordinate_maps[group][j] == variable)]
                    + [0] * (leaf.degree // s.stride - 1)
                    for leaf, group in zip(ctx.leaves, s.map_ids, strict=True)}
            for node in reversed(ctx.splits):
                left, right = work.pop(node.path + "0"), work.pop(node.path + "1")
                half, weighted = pow(2, -1, p), pow(2 * node.gamma, -1, p)
                work[node.path] = ([(a + b) * half % p for a, b in zip(left, right, strict=True)]
                                   + [(a - b) * weighted % p for a, b in zip(left, right, strict=True)])
            full = work[""]
            step = s.slots // degree
            assert not any(x for i, x in enumerate(full) if i % step)
            for row, coefficient in zip(rows, full[::step], strict=True):
                row.append(coefficient)
        image = Image(p, tuple(tuple(row) for row in rows))
        validate(image)
        result.append((variables, image))
    return tuple(result)


def space_bounds(s: crt.Space, *, seed: int = 36) -> dict:
    generated = generators(s)
    columns = [describe(image, seed=seed + j) for j, (_, image) in enumerate(generated)]
    # Summing column maxima is always an upper bound. A sum of constructive
    # lower bounds is valid only when the columns have disjoint inputs.
    schedules = [variables for variables, _ in generated]
    disjoint = len(set(i for row in schedules for i in row)) == sum(map(len, schedules))
    expectation = sum((Fraction(c["uniform_expectation_lower_bound"]) for c in columns), Fraction())
    expectation_ceiling = (expectation.numerator + expectation.denominator - 1) // expectation.denominator
    lower = sum(c["proved_lower"] for c in columns) if disjoint else max(
        expectation_ceiling, max(c["proved_lower"] for c in columns))
    return {"space_binding": s.binding.hex(), "columns": columns, "columns_have_disjoint_inputs": disjoint,
            "cube_norm_bound": sum(c["cube_bound"] for c in columns),
            "nonzero_forms": sum(c["nonzero_forms"] for c in columns),
            "uniform_norm_lower": lower, "uniform_norm_upper": sum(c["proved_upper"] for c in columns),
            "scope": "Bounds for the actual public linear image, not an independent-column assumption when sharing inputs."}
