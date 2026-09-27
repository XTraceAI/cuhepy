"""E19: low-rank proposals with exhaustive integer lower-bound certificates.

SVD is only an offline proposal heuristic on a PUBLIC, tiny lookup table.
For integer factors U,V and scale S we choose column offsets b and row offsets
a so U[q] dot V[bucket] + a[q] + b[bucket] <= S * L[q,bucket]
for every possible query and reachable bucket. Correctness never relies on a
floating-point approximation or a sample of rows. Negative bounds are allowed;
clamping happens only after summing/decoding, not inside an uncharged circuit.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from experiments.bfv_search_lab import linear_packing as packing
from experiments.bfv_search_lab import syndrome_oracle as syndrome


@dataclass(frozen=True)
class CertifiedLookup:
    code: syndrome.BlockCode
    scale: int
    buckets: tuple[int, ...]
    query: tuple[tuple[int, ...], ...]
    index: tuple[tuple[int, ...], ...]
    row_offsets: tuple[int, ...]
    column_offsets: tuple[int, ...]
    # Bounds only the encrypted part; owner adds its known row offset later.
    numerator_bound: int

    @property
    def rank(self) -> int:
        return len(self.query[0])


def _matrix(code: syndrome.BlockCode) -> tuple[tuple[int, ...], list[list[int]]]:
    if code.width > 8:
        raise ValueError("Certificate enumeration is limited to eight-bit blocks")
    buckets = syndrome._buckets(code)
    tables = [syndrome.conditioned_table(code, q) for q in range(1 << code.width)]
    return buckets, [[table[b] for b in buckets] for table in tables]


def certify(
    code: syndrome.BlockCode, query: tuple[tuple[int, ...], ...],
    index: tuple[tuple[int, ...], ...], scale: int, row_offsets: tuple[int, ...],
) -> CertifiedLookup:
    """Turn ANY finite integer factor proposal into a safe one-sided lookup.

    First take each column's minimum exact residual. Then raise each row by
    its remaining minimum slack. These operations need no numerical solver.
    Safety is independent of proposal quality; selectivity is not.
    """
    buckets, table = _matrix(code)
    rank = len(query[0]) if query else 0
    if (type(scale) is not int or scale < 1 or rank < 1
            or len(query) != len(table) or len(index) != len(buckets)
            or len(row_offsets) != len(table) or any(type(a) is not int for a in row_offsets)
            or any(len(row) != rank or any(type(a) is not int for a in row) for row in (*query, *index))):
        raise ValueError("Invalid integer factor proposal")
    products = [[sum(a * b for a, b in zip(q, x, strict=True)) for x in index] for q in query]
    column = tuple(min(scale * table[q][b] - products[q][b] - row_offsets[q] for q in range(len(table)))
                   for b in range(len(buckets)))
    offsets = tuple(row_offsets[q] + min(scale * value - products[q][b] - row_offsets[q] - column[b]
                                        for b, value in enumerate(row))
                    for q, row in enumerate(table))
    bound = max(abs(value + column[b]) for row in products for b, value in enumerate(row))
    return CertifiedLookup(code, scale, buckets, query, index, offsets, column, bound)


def svd_proposal(code: syndrome.BlockCode, rank: int, quantization: int = 32) -> CertifiedLookup:
    """Double-centered SVD proposal; exact integer certification follows it."""
    buckets, table = _matrix(code)
    if (type(rank) is not int or not 1 <= rank <= min(len(table), len(buckets))
            or type(quantization) is not int or not 1 <= quantization <= 1024):
        raise ValueError("Invalid toy SVD settings")
    array = np.asarray(table, dtype=np.float64)
    row_mean, col_mean = array.mean(axis=1), array.mean(axis=0)
    centered = array - row_mean[:, None] - col_mean[None, :] + array.mean()
    left, values, right = np.linalg.svd(centered, full_matrices=False)
    root = np.sqrt(values[:rank])
    query = tuple(tuple(int(round(float(x))) for x in row)
                  for row in left[:, :rank] * root * quantization)
    index = tuple(tuple(int(round(float(x))) for x in row)
                  for row in (root[:, None] * right[:rank, :]).T * quantization)
    scale = quantization**2
    offsets = tuple(int(round(float(x) * scale)) for x in row_mean)
    return certify(code, query, index, scale, offsets)


def verify(model: CertifiedLookup) -> bool:
    """Independent exhaustive check of an in-memory certificate (not a proof API)."""
    buckets, table = _matrix(model.code)
    if (type(model.scale) is not int or model.scale < 1 or buckets != model.buckets
            or len(model.query) != len(table) or len(model.index) != len(buckets)
            or len(model.row_offsets) != len(table) or len(model.column_offsets) != len(buckets)
            or not model.query or not model.query[0] or type(model.numerator_bound) is not int
            or model.numerator_bound < 0
            or any(type(x) is not int for x in (*model.row_offsets, *model.column_offsets))
            or any(len(row) != model.rank or any(type(x) is not int for x in row)
                   for row in (*model.query, *model.index))):
        return False
    for q, row in enumerate(table):
        for b, value in enumerate(row):
            raw = sum(x * y for x, y in zip(model.query[q], model.index[b], strict=True)) + model.column_offsets[b]
            if abs(raw) > model.numerator_bound or raw + model.row_offsets[q] > model.scale * value:
                return False
    return True


def _context(models: list[CertifiedLookup], query: int, rows: list[int]) -> int:
    dimension = sum(model.code.width for model in models)
    if (not models or len({model.scale for model in models}) != 1
            or type(query) is not int or not 0 <= query < 1 << dimension
            or any(type(row) is not int or not 0 <= row < 1 << dimension for row in rows)):
        raise ValueError("Invalid disjoint certified-lookup fixture")
    return dimension


def feature_vectors(
    models: list[CertifiedLookup], query: int, rows: list[int],
) -> tuple[list[int], list[list[int]], int]:
    """One extra encrypted feature holds the sum of all column corrections."""
    _context(models, query, rows)
    weights: list[int] = []
    features: list[list[int]] = [[] for _ in rows]
    bias = [0] * len(rows)
    offset = owner_offset = 0
    for model in models:
        mask = (1 << model.code.width) - 1
        q = (query >> offset) & mask
        weights.extend(model.query[q])
        owner_offset += model.row_offsets[q]
        positions = {b: i for i, b in enumerate(model.buckets)}
        for i, row in enumerate(rows):
            word = (row >> offset) & mask
            bucket = model.code.syndromes[word] * (model.code.width + 1) + word.bit_count()
            b = positions[bucket]
            features[i].extend(model.index[b])
            bias[i] += model.column_offsets[b]
        offset += model.code.width
    weights.append(1)
    for values, b in zip(features, bias, strict=True):
        values.append(b)
    return weights, features, owner_offset


def lower_bounds(models: list[CertifiedLookup], query: int, rows: list[int]) -> list[int]:
    weights, features, offset = feature_vectors(models, query, rows)
    return [max(0, (sum(a * b for a, b in zip(weights, row, strict=True)) + offset) // models[0].scale)
            for row in features]


def inputs(
    models: list[CertifiedLookup], query: int, rows: list[int], n: int,
) -> tuple[list[int], list[list[int]], int, int]:
    weights, features, offset = feature_vectors(models, query, rows)
    qp, tiles, padded = packing.pack(weights, features, n)
    return qp, tiles, padded, offset


def decode(models: list[CertifiedLookup], dots: list[int], owner_offset: int, prime: int) -> list[int]:
    _context(models, 0, [])
    bound = sum(model.numerator_bound for model in models)
    if (type(prime) is not int or not prime % 2 or prime <= 2 * bound
            or type(owner_offset) is not int
            or any(type(x) is not int or not 0 <= x < prime for x in dots)):
        raise ValueError("Plaintext modulus does not cover the corrected integer dot product")
    centered = [x if x <= prime // 2 else x - prime for x in dots]
    if any(abs(x) > bound for x in centered):
        raise ValueError("Local result outside the public numerator bound")
    return [max(0, (x + owner_offset) // models[0].scale) for x in centered]
