"""E27: unequal plaintext CRT components inside the same full encryption ring.

A complete binary prefix tree factors X^N+1 into X^m-zeta with different
power-of-two m. Splitting X^(2m)-gamma^2 uses X^m-gamma and X^m+gamma.
Recursive CRT is standard algebra, not a new cryptographic primitive. The
existing butterfly preserves all leaves when its common padded D divides each
m. Capacity imbalance, small leaves and every ciphertext are charged.

This is local owner preprocessing/decoding, not an authenticated wire parser.
Private maps, tree/layout and index epoch must be bound together by a reviewed
protocol. Full N is retained; parameter and private timing assurance are open.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

import gmpy2
import numpy as np

from experiments.bfv_search_lab import linear_packing as packing


@dataclass(frozen=True)
class Leaf:
    path: str
    degree: int
    root: int


@dataclass(frozen=True)
class Split:
    path: str
    degree: int
    gamma: int


@dataclass(frozen=True)
class Context:
    n: int
    prime: int
    leaves: tuple[Leaf, ...]
    splits: tuple[Split, ...]


@lru_cache(maxsize=256)
def _square_root(value: int, prime: int) -> int:
    # Small public fields only; deterministic roots and bounded enrollment work.
    for x in range(1, (prime + 1) // 2):
        if x * x % prime == value:
            return x
    raise ValueError("Plaintext field cannot split this CRT factor")


@lru_cache(maxsize=128)
def context(n: int, paths: tuple[str, ...], prime: int = 1153) -> Context:
    if (type(n) is not int or not 8 <= n <= 32768 or n & (n - 1)
            or type(prime) is not int or not 3 <= prime <= 65537 or not gmpy2.is_prime(prime)
            or type(paths) is not tuple or not 1 <= len(paths) <= 64
            or any(type(p) is not str or len(p) > min(6, n.bit_length() - 2) or set(p) - {"0", "1"} for p in paths)
            or tuple(sorted(set(paths))) != paths):
        raise ValueError("Invalid dyadic CRT context")
    leaves, splits = [], []
    prefixes = {p[:j] for p in paths for j in range(len(p) + 1)}

    def visit(path: str, degree: int, root: int) -> None:
        if path in paths:
            if any(p != path and p.startswith(path) for p in paths):
                raise ValueError("Overlapping CRT leaves")
            leaves.append(Leaf(path, degree, root))
            return
        if path not in prefixes or degree < 4:
            raise ValueError("Incomplete CRT leaf cover")
        gamma = _square_root(root, prime)
        splits.append(Split(path, degree, gamma))
        visit(path + "0", degree // 2, gamma)
        visit(path + "1", degree // 2, prime - gamma)

    visit("", n, prime - 1)
    return Context(n, prime, tuple(leaves), tuple(splits))


def validate(ctx: Context) -> None:
    if ctx != context(ctx.n, tuple(leaf.path for leaf in ctx.leaves), ctx.prime):
        raise ValueError("Inconsistent canonical dyadic context")


def encode(ctx: Context, components: list[list[int]]) -> list[int]:
    validate(ctx)
    if (len(components) != len(ctx.leaves)
            or any(len(row) != leaf.degree or any(type(x) is not int for x in row)
                   for row, leaf in zip(components, ctx.leaves, strict=True))):
        raise ValueError("Invalid dyadic component shape")
    p, inverse = ctx.prime, pow(2, -1, ctx.prime)
    work = {leaf.path: np.asarray([x % p for x in row], dtype=np.int64)
            for row, leaf in zip(components, ctx.leaves, strict=True)}
    for node in reversed(ctx.splits):
        left, right = work.pop(node.path + "0"), work.pop(node.path + "1")
        low = (left + right) * inverse % p
        high = (left - right) * pow(2 * node.gamma, -1, p) % p
        work[node.path] = np.concatenate((low, high))
    return [int(x if x <= p // 2 else x - p) for x in work[""]]


def decode(ctx: Context, plaintext: list[int]) -> list[list[int]]:
    validate(ctx)
    if len(plaintext) != ctx.n or any(type(x) is not int or not 0 <= x < ctx.prime for x in plaintext):
        raise ValueError("Invalid local dyadic plaintext")
    work = {"": np.asarray(plaintext, dtype=np.int64)}
    for node in ctx.splits:
        values = work.pop(node.path)
        half = node.degree // 2
        low, high = values[:half], values[half:] * node.gamma
        work[node.path + "0"] = (low + high) % ctx.prime
        work[node.path + "1"] = (low - high) % ctx.prime
    return [work[leaf.path].tolist() for leaf in ctx.leaves]


@dataclass(frozen=True)
class Layout:
    context: Context
    padded: int
    features: tuple[int, ...]
    counts: tuple[int, ...]

    @property
    def virtual_count(self) -> int:
        return max((count * (self.context.n // leaf.degree)
                    for count, leaf in zip(self.counts, self.context.leaves, strict=True)), default=0)

    @property
    def cost(self) -> packing.PackingCost:
        return packing.packing_cost(self.padded, self.virtual_count, self.context.n)


def layout(ctx: Context, features: tuple[int, ...], counts: tuple[int, ...]) -> Layout:
    validate(ctx)
    if (len(features) != len(ctx.leaves) or len(counts) != len(ctx.leaves)
            or any(type(f) is not int or f < 1 for f in features)
            or any(type(c) is not int or not 0 <= c <= 32768 for c in counts)):
        raise ValueError("Invalid dyadic feature/count schedule")
    padded = 1 << (max(features) - 1).bit_length()
    if padded > min(ctx.n // 2, *(leaf.degree for leaf in ctx.leaves)):
        raise ValueError("Smallest component cannot hold common padded features")
    return Layout(ctx, padded, features, counts)


def validate_layout(plan: Layout) -> None:
    if plan != layout(plan.context, plan.features, plan.counts):
        raise ValueError("Inconsistent dyadic padding")


def query(plan: Layout, weights: list[list[int]]) -> list[int]:
    validate_layout(plan)
    if (len(weights) != len(plan.features)
            or any(len(w) != f or any(type(x) is not int for x in w)
                   for w, f in zip(weights, plan.features, strict=True))):
        raise ValueError("Invalid dyadic query features")
    polys = [[0] * leaf.degree for leaf in plan.context.leaves]
    for poly, values in zip(polys, weights, strict=True):
        poly[plan.padded - len(values):plan.padded] = reversed(values)
    return encode(plan.context, polys)


def index(plan: Layout, groups: list[list[list[int]]]) -> list[list[int]]:
    validate_layout(plan)
    if (len(groups) != len(plan.counts)
            or any(len(g) != c for g, c in zip(groups, plan.counts, strict=True))
            or any(len(row) != f or any(type(x) is not int for x in row)
                   for g, f in zip(groups, plan.features, strict=True) for row in g)):
        raise ValueError("Invalid dyadic index features")
    tiles = []
    for tile in range(plan.cost.input_tiles):
        polys = [[0] * leaf.degree for leaf in plan.context.leaves]
        for poly, rows in zip(polys, groups, strict=True):
            capacity = len(poly) // plan.padded
            for lane, values in enumerate(rows[tile * capacity:(tile + 1) * capacity]):
                poly[lane * plan.padded:lane * plan.padded + len(values)] = values
        tiles.append(encode(plan.context, polys))
    return tiles


def unpack(plan: Layout, plaintexts: list[list[int]]) -> list[list[int]]:
    validate_layout(plan)
    if len(plaintexts) != plan.cost.response_ciphertexts:
        raise ValueError("Invalid dyadic response count")
    decoded = [decode(plan.context, p) for p in plaintexts]
    inverse = pow(plan.padded, -1, plan.context.prime)
    result = []
    for component, (leaf, count) in enumerate(zip(plan.context.leaves, plan.counts, strict=True)):
        capacity = leaf.degree // plan.padded
        row = []
        for i in range(count):
            group, within = divmod(i, leaf.degree)
            tile, lane = divmod(within, capacity)
            row.append(decoded[group][component][lane * plan.padded + tile] * inverse % plan.context.prime)
        result.append(row)
    return result
