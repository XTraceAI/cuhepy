"""E50: strong owner-local controls for exact affine search.

An affine pivot coordinate is x_j - a_j. For binary rows, retaining x_j
costs ONE bit, not two ternary bits. Constant blocks retain no coordinates.
These caches deliberately retain private row information and require no HE,
correlations or remote verifier. They expose when outsourcing is unnecessary.

Inputs are trusted, already certified owner maps/coordinates, as in encrypted
enrollment. This module checks shape/coverage, but is not a remote parser or
an independent certificate of membership in the owner's affine space.
Byte counts are canonical bodies/models, not Python resident-memory claims.
"""

from __future__ import annotations

from dataclasses import dataclass
import heapq
import zlib

import numpy as np

from experiments.bfv_search_lab import affine_dictionary as affine


@dataclass(frozen=True)
class Result:
    scores: tuple[int, ...]
    top3: tuple[tuple[int, int], ...]


def _ids(ids):
    if (type(ids) is not tuple or not 1 <= len(ids) <= 32768
            or any(type(i) is not int or not 0 <= i < 1 << 64 for i in ids)
            or len(set(ids)) != len(ids)):
        raise ValueError("Require unique uint64 stable IDs")


def _result(scores, ids):
    scores = tuple(map(int, scores))
    return Result(scores, tuple(heapq.nsmallest(3, zip(scores, ids, strict=True))))


class Coordinates:
    def __init__(self, candidate, groups, ids, *, mode="packed"):
        _ids(ids)
        if mode not in ("packed", "expanded") or len(groups) != len(candidate.blocks):
            raise ValueError("Invalid coordinate cache mode/block schedule")
        if sorted(i for b in candidate.blocks for i in b.positions) != list(range(len(ids))):
            raise ValueError("Incomplete or duplicate coordinate-cache row coverage")
        self.ids, self.dimension, self.mode = ids, candidate.dimension, mode
        self._blocks = []
        unique_maps = tuple(dict.fromkeys(b.mapping for b in candidate.blocks))
        for block, group in zip(candidate.blocks, groups, strict=True):
            plan = block.mapping
            affine.validate(plan)
            if (plan.dimension != self.dimension or len(group) != len(block.positions)
                    or any(len(row) != plan.features or any(type(x) is not int for x in row)
                           for row in group)):
                raise ValueError("Incorrect certified coordinate shape")
            anchor = np.asarray([(plan.anchor >> p) & 1 for p in plan.pivots], dtype=np.int8)
            if plan.rank:
                # Validate before an int8 conversion that might wrap malformed data.
                if any(x + int(a) not in (0, 1) for row in group
                       for x, a in zip(row, anchor, strict=True)):
                    raise ValueError("Pivot differences do not encode binary coordinates")
                values = np.asarray(group, dtype=np.int8)
            else:
                if any(row != [0] and row != (0,) for row in group):
                    raise ValueError("Constant-block dummy coordinates must be zero")
                values = np.empty((len(group), 0), dtype=np.int8)
            if mode == "packed":
                bits = np.asarray(values + anchor, dtype=np.uint8)
                body = np.packbits(bits.reshape(-1), bitorder="little").tobytes()
            else:
                values.setflags(write=False)
                body = values
            self._blocks.append((block.positions, affine.compile_bits(plan), anchor, body))
        self._blocks = tuple(self._blocks)
        self.coordinate_body_bytes = sum(len(body) if isinstance(body, bytes) else body.nbytes
                                         for _, _, _, body in self._blocks)
        self.private_map_body_bytes = sum(len(affine.canonical_map(p)) for p in unique_maps)
        self.stable_ids_and_permutation_bytes_model = 12 * len(ids)

    def query(self, word):
        scores = [None] * len(self.ids)
        for positions, mapping, anchor, body in self._blocks:
            weights, offset = affine.bit_query_features(mapping, word)
            rank = len(anchor)
            if rank:
                if self.mode == "packed":
                    values = np.unpackbits(np.frombuffer(body, dtype=np.uint8), bitorder="little",
                                           count=len(positions) * rank).reshape(len(positions), rank)
                    values = values.astype(np.int8) - anchor
                else:
                    values = body
                # rank<=512 and t<=65537: the complete sum fits signed int64.
                dots = values @ np.asarray(weights, dtype=np.int64)
                decoded = (dots + offset) % mapping.prime
                if np.any(decoded > self.dimension):
                    raise ValueError("Cached affine score outside exact distance range")
            else:
                decoded = [offset] * len(positions)
            for position, score in zip(positions, decoded, strict=True):
                scores[position] = int(score)
        return _result(scores, self.ids)


class CompressedRows:
    """Strong raw-data control: charge decompression and decoding every query."""
    def __init__(self, rows, ids, dimension):
        _ids(ids)
        if (type(dimension) is not int or not 1 <= dimension <= 512 or len(rows) != len(ids)
                or any(type(x) is not int or not 0 <= x < 1 << dimension for x in rows)):
            raise ValueError("Invalid bounded binary plaintext cache")
        self.ids, self.dimension = ids, dimension
        width = (dimension + 7) // 8
        self.body = zlib.compress(b"".join(x.to_bytes(width, "little") for x in rows), level=9)
        self.raw_scratch_body_bytes_model = width * len(ids)

    def query(self, word):
        if type(word) is not int or not 0 <= word < 1 << self.dimension:
            raise ValueError("Invalid binary query")
        raw = zlib.decompress(self.body)
        width = (self.dimension + 7) // 8
        scores = ((word ^ int.from_bytes(raw[i:i + width], "little")).bit_count()
                  for i in range(0, len(raw), width))
        return _result(scores, self.ids)


class RawRows:
    def __init__(self, rows, ids, dimension):
        _ids(ids)
        if (type(dimension) is not int or not 1 <= dimension <= 512 or len(rows) != len(ids)
                or any(type(x) is not int or not 0 <= x < 1 << dimension for x in rows)):
            raise ValueError("Invalid raw plaintext cache")
        self.rows, self.ids, self.dimension = tuple(rows), ids, dimension

    def query(self, word):
        if type(word) is not int or not 0 <= word < 1 << self.dimension:
            raise ValueError("Invalid binary query")
        return _result(((word ^ row).bit_count() for row in self.rows), self.ids)
