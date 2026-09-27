"""E26: exact affine column relations over a small plaintext prime field.

Rows x are represented as a + u*B, with a fixed binary anchor a and u equal
to differences at pivot coordinates. B is the row-reduced basis of x-a.
The owner retains B, not per-row exceptions. Its transformed private query
gives H(q,x) = H(q,a) + u*(B*(1-2q)) modulo t, unwrapped in [0,d].

These are ordinary affine algebra identities, not a novel primitive. Maps are
private index-derived state, must be pinned to the index epoch, and may be as
informative/large as the original data for small blocks. All preprocessing and
query arithmetic is variable-time. Correctness checks are not authentication.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct

import gmpy2
import numpy as np

from experiments.bfv_search_lab import folded_filter as folded


@dataclass(frozen=True)
class Plan:
    dimension: int
    prime: int
    anchor: int
    pivots: tuple[int, ...]
    basis: tuple[tuple[int, ...], ...]

    @property
    def rank(self) -> int:
        return len(self.pivots)

    @property
    def features(self) -> int:
        return max(1, self.rank)  # A dummy zero feature supports constant blocks.


def _field(dimension: int, prime: int) -> None:
    if (type(prime) is not int or not dimension < prime <= 65537
            or not prime % 2 or not gmpy2.is_prime(prime)):
        raise ValueError("Require an odd small prime covering exact distances")


def validate(plan: Plan) -> None:
    folded._words(plan.anchor, [], plan.dimension)
    _field(plan.dimension, plan.prime)
    if (len(plan.basis) != plan.rank or tuple(sorted(set(plan.pivots))) != plan.pivots
            or any(type(j) is not int or not 0 <= j < plan.dimension for j in plan.pivots)
            or any(len(row) != plan.dimension or any(type(x) is not int or not 0 <= x < plan.prime for x in row)
                   for row in plan.basis)
            or any(row[p] != int(i == j) for i, row in enumerate(plan.basis) for j, p in enumerate(plan.pivots))):
        raise ValueError("Invalid affine basis or pivot identity")


def prepare(rows: list[int], dimension: int, prime: int = 1153) -> Plan:
    """Exact modular elimination, followed by certification of EVERY input row."""
    folded._words(0, rows, dimension)
    _field(dimension, prime)
    if not 1 <= len(rows) <= 32768 or len(rows) * dimension > 8 << 20:
        raise ValueError("Affine enrollment exceeds bounded research workload")
    width = (dimension + 7) // 8
    raw = b"".join(x.to_bytes(width, "little") for x in rows)
    bits = np.unpackbits(np.frombuffer(raw, dtype=np.uint8).reshape(len(rows), width),
                         axis=1, bitorder="little")[:, :dimension].astype(np.int64)
    differences = bits - bits[0]
    work = differences % prime
    pivots: list[int] = []
    for j in range(dimension):
        rank = len(pivots)
        choices = np.flatnonzero(work[rank:, j])
        if not len(choices):
            continue
        winner = rank + int(choices[0])
        work[[rank, winner]] = work[[winner, rank]]
        work[rank] = work[rank] * pow(int(work[rank, j]), -1, prime) % prime
        # All products fit int64 under the explicit d/prime bounds.
        work[rank + 1:, j:] = (work[rank + 1:, j:] - work[rank + 1:, j, None] * work[rank, j:]) % prime
        pivots.append(j)
    basis = work[:len(pivots)].copy()
    for i in reversed(range(len(pivots))):
        basis[:i] = (basis[:i] - basis[:i, pivots[i], None] * basis[i]) % prime
    if not np.array_equal(differences[:, pivots] @ basis % prime, differences % prime):
        raise AssertionError("Affine relation fails exact whole-index certification")
    plan = Plan(dimension, prime, rows[0], tuple(pivots), tuple(tuple(map(int, r)) for r in basis))
    validate(plan)
    return plan


def index_features(plan: Plan, rows: list[int]) -> list[list[int]]:
    """Owner enrollment also rejects rows that do not belong to the pinned affine space."""
    validate(plan)
    folded._words(0, rows, plan.dimension)
    result = [[((row >> j) & 1) - ((plan.anchor >> j) & 1) for j in plan.pivots] for row in rows]
    basis = np.asarray(plan.basis, dtype=np.int64).reshape(plan.rank, plan.dimension)
    coordinates = np.asarray(result, dtype=np.int64).reshape(len(rows), plan.rank)
    reconstructed = coordinates @ basis % plan.prime
    for row, decoded in zip(rows, reconstructed, strict=True):
        if any(int(value) != (((row >> j) & 1) - ((plan.anchor >> j) & 1)) % plan.prime
               for j, value in enumerate(decoded)):
            raise ValueError("Row outside pinned affine index epoch")
    return result if plan.rank else [[0] for _ in rows]


def query_features(plan: Plan, query: int) -> tuple[list[int], int]:
    validate(plan)
    folded._words(query, [], plan.dimension)
    signs = [1 - 2 * ((query >> j) & 1) for j in range(plan.dimension)]
    values = [sum(a * b for a, b in zip(row, signs, strict=True)) % plan.prime for row in plan.basis]
    weights = [x if x <= plan.prime // 2 else x - plan.prime for x in values]
    return weights if weights else [0], (query ^ plan.anchor).bit_count()


def decode(plan: Plan, dots: list[int], offset: int) -> list[int]:
    validate(plan)
    if (type(offset) is not int or not 0 <= offset <= plan.dimension
            or any(type(x) is not int or not 0 <= x < plan.prime for x in dots)):
        raise ValueError("Invalid local affine result")
    result = [(x + offset) % plan.prime for x in dots]
    if any(x > plan.dimension for x in result):
        raise ValueError("Affine score outside exact distance range")
    return result


def canonical_map(plan: Plan) -> bytes:
    """Size-audit encoding: implicit pivot identity, sparse nonpivot relations.

    No transport parser or authentication claim. This private map contains the
    anchor and all affine relations, but no per-row coordinates or residuals.
    """
    validate(plan)
    coordinate_bytes = max(1, ((plan.dimension - 1).bit_length() + 7) // 8)
    group_bytes = max(1, ((max(1, plan.rank) - 1).bit_length() + 7) // 8)
    coefficient_bytes = (plan.prime.bit_length() + 7) // 8
    body = bytearray(struct.pack("<HIH", plan.dimension, plan.prime, plan.rank))
    body.extend(plan.anchor.to_bytes((plan.dimension + 7) // 8, "little"))
    for pivot in plan.pivots:
        body.extend(pivot.to_bytes(coordinate_bytes, "little"))
    for j in sorted(set(range(plan.dimension)) - set(plan.pivots)):
        entries = [(g, row[j]) for g, row in enumerate(plan.basis) if row[j]]
        body.extend(len(entries).to_bytes(2, "little"))
        for g, value in entries:
            body.extend(g.to_bytes(group_bytes, "little"))
            body.extend(value.to_bytes(coefficient_bytes, "little"))
    return bytes(body)
