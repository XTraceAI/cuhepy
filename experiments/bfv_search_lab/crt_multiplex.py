"""E26: polynomial CRT components sharing one ordinary full-ring BGV query.

For N=T*m and t admitting a primitive 2T-th root, X^N+1 factors into
X^m-zeta_l. Each factor holds an independent coefficient correlation circuit.
This is standard polynomial CRT packing, combined with local exact dictionaries;
it does NOT encrypt in a smaller security ring. All HE still uses degree N.

The existing butterfly can be reused when padded D divides m. Its generator
1+2N/D fixes the CRT idempotents, and trace/monomial operations act componentwise.
Rank/layout/map/epoch must be owner-pinned. No authentication or private timing
assurance is supplied; group sizes and selected common padding remain metadata.
"""

from __future__ import annotations

from dataclasses import dataclass

import gmpy2
import numpy as np

from experiments.bfv_search_lab import linear_packing as packing


@dataclass(frozen=True)
class Context:
    n: int
    parts: int
    prime: int
    roots: tuple[int, ...]

    @property
    def degree(self) -> int:
        return self.n // self.parts


def context(n: int, parts: int, prime: int) -> Context:
    if (type(n) is not int or not 8 <= n <= 32768 or n & (n - 1)
            or type(parts) is not int or not 1 <= parts <= min(64, n // 2) or parts & (parts - 1)
            or type(prime) is not int or not 3 <= prime <= 65537 or not gmpy2.is_prime(prime)
            or (prime - 1) % (2 * parts)):
        raise ValueError("Invalid full ring / polynomial CRT context")
    for a in range(2, prime):
        root = pow(a, (prime - 1) // (2 * parts), prime)
        if pow(root, parts, prime) == prime - 1:
            return Context(n, parts, prime, tuple(pow(root, 2 * i + 1, prime) for i in range(parts)))
    raise AssertionError("Prime field lacks expected CRT root")


def _validate(ctx: Context) -> None:
    expected = context(ctx.n, ctx.parts, ctx.prime)
    if ctx.roots != expected.roots:
        raise ValueError("Wrong canonical CRT roots")


def encode(ctx: Context, components: list[list[int]]) -> list[int]:
    _validate(ctx)
    if (len(components) != ctx.parts or any(len(row) != ctx.degree or any(type(x) is not int for x in row)
                                           for row in components)):
        raise ValueError("Invalid CRT component shape")
    p, inverse = ctx.prime, pow(ctx.parts, -1, ctx.prime)
    matrix = np.array([[inverse * pow(root, -k, p) % p for root in ctx.roots]
                       for k in range(ctx.parts)], dtype=np.int64)
    # Reduce with Python integers first: callers cannot overflow the int64 cast.
    rows = np.array([[x % p for x in row] for row in components], dtype=np.int64)
    values = (matrix @ rows % p).ravel()
    return [int(x if x <= p // 2 else x - p) for x in values]


def decode(ctx: Context, plaintext: list[int]) -> list[list[int]]:
    _validate(ctx)
    if len(plaintext) != ctx.n or any(type(x) is not int or not 0 <= x < ctx.prime for x in plaintext):
        raise ValueError("Invalid local CRT plaintext")
    matrix = np.array([[pow(root, k, ctx.prime) for k in range(ctx.parts)] for root in ctx.roots], dtype=np.int64)
    rows = np.array(plaintext, dtype=np.int64).reshape(ctx.parts, ctx.degree)
    return (matrix @ rows % ctx.prime).tolist()


@dataclass(frozen=True)
class Layout:
    context: Context
    padded: int
    features: tuple[int, ...]
    counts: tuple[int, ...]

    @property
    def virtual_count(self) -> int:
        return self.context.parts * max(self.counts, default=0)

    @property
    def cost(self) -> packing.PackingCost:
        return packing.packing_cost(self.padded, self.virtual_count, self.context.n)


def layout(ctx: Context, features: tuple[int, ...], counts: tuple[int, ...]) -> Layout:
    _validate(ctx)
    if (len(features) != ctx.parts or len(counts) != ctx.parts
            or any(type(x) is not int or x < 1 for x in features)
            or any(type(x) is not int or not 0 <= x <= 32768 for x in counts)):
        raise ValueError("Invalid component feature/count schedule")
    padded = 1 << (max(features) - 1).bit_length()
    if padded > min(ctx.degree, ctx.n // 2):
        raise ValueError("Component degree cannot hold common padded features")
    return Layout(ctx, padded, features, counts)


def validate_layout(plan: Layout) -> None:
    if layout(plan.context, plan.features, plan.counts) != plan:
        raise ValueError("Inconsistent component padding")


def query(plan: Layout, queries: list[list[int]]) -> list[int]:
    validate_layout(plan)
    if len(queries) != len(plan.features) or any(len(q) != f or any(type(x) is not int for x in q)
                                              for q, f in zip(queries, plan.features, strict=True)):
        raise ValueError("Invalid component queries")
    polys = [[0] * plan.context.degree for _ in queries]
    for poly, values in zip(polys, queries, strict=True):
        poly[plan.padded - len(values):plan.padded] = reversed(values)
    return encode(plan.context, polys)


def index(plan: Layout, groups: list[list[list[int]]]) -> list[list[int]]:
    validate_layout(plan)
    if (len(groups) != len(plan.counts) or any(len(rows) != count for rows, count in zip(groups, plan.counts, strict=True))
            or any(len(row) != f or any(type(x) is not int for x in row)
                   for rows, f in zip(groups, plan.features, strict=True) for row in rows)):
        raise ValueError("Invalid component index")
    capacity = plan.context.degree // plan.padded
    tiles = []
    for start in range(0, max(plan.counts), capacity):
        polys = [[0] * plan.context.degree for _ in groups]
        for poly, rows in zip(polys, groups, strict=True):
            for lane, values in enumerate(rows[start:start + capacity]):
                poly[lane * plan.padded:lane * plan.padded + len(values)] = values
        tiles.append(encode(plan.context, polys))
    assert len(tiles) == plan.cost.input_tiles
    return tiles


def unpack(plan: Layout, plaintexts: list[list[int]]) -> list[list[int]]:
    validate_layout(plan)
    if len(plaintexts) != plan.cost.response_ciphertexts:
        raise ValueError("Invalid component response count")
    decoded = [decode(plan.context, p) for p in plaintexts]
    degree = plan.context.degree
    capacity = degree // plan.padded
    inverse = pow(plan.padded, -1, plan.context.prime)
    result = []
    for component, count in enumerate(plan.counts):
        row = []
        for i in range(count):
            group, within = divmod(i, degree)
            tile, lane = divmod(within, capacity)
            row.append(decoded[group][component][lane * plan.padded + tile] * inverse % plan.context.prime)
        result.append(row)
    return result
