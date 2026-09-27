"""Local plaintext result experiments; no authentication or decryption permission.

Keep the original trace decoder and full stable sort as the oracle. A public
lookup table maps the D-scaled correlation residues directly to Hamming scores.
Heap selection costs O(count log k) and preserves ties by original vector index.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import heapq
import struct

from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


@dataclass(frozen=True)
class SearchResult:
    top: tuple[tuple[int, int], ...]  # (original index, Hamming distance)
    distances: tuple[int, ...] | None


def from_native(data: tuple[bytes, bytes], count: int, k: int, all_distances: bool) -> SearchResult:
    distances, top = data
    if len(distances) != (count * 4 if all_distances else 0) or len(top) != min(count, k) * 8:
        raise ValueError("Incorrect native result byte count")
    return SearchResult(tuple((i, d) for i, d in struct.iter_unpack("<II", top)),
                        tuple(struct.unpack(f"<{count}I", distances)) if all_distances else None)


def validate_layout(n: int, t: int, count: int, dimension: int, k: int, all_distances: bool) -> None:
    if (type(n) is not int or not 8 <= n <= 32768 or n & (n - 1)
        or type(t) is not int or not 3 <= t < (1 << 30) or t % 2 != 1
        or type(count) is not int or not 0 <= count <= 64 * n
        or type(dimension) is not int or not 1 <= dimension <= n // 2 or t <= 2 * dimension
        or type(k) is not int or not 0 <= k <= 64 or type(all_distances) is not bool):
        raise ValueError("Invalid local BGV result layout")


@lru_cache(maxsize=32)
def _table(t: int, dimension: int) -> tuple[int, ...]:
    if t > 65536:
        raise ValueError("The result lookup experiment caps its public table at 65536 entries")
    padded = 1 << (dimension - 1).bit_length()
    table = [-1] * t
    for distance in range(dimension + 1):
        table[padded * (dimension - 2 * distance) % t] = distance
    return tuple(table)


def decode_lookup(plaintexts: list[list[int]], count: int, dimension: int,
                  pk: bgv.PublicKey) -> list[int]:
    validate_layout(pk.n, pk.t, count, dimension, 0, True)
    if (len(plaintexts) != (count + pk.n - 1) // pk.n
        or any(len(p) != pk.n or any(type(x) is not int or not 0 <= x < pk.t for x in p)
               for p in plaintexts)):
        raise ValueError("Invalid lookup response shape")
    table = _table(pk.t, dimension)
    padded = 1 << (dimension - 1).bit_length()
    capacity, result = pk.n // padded, []
    for group, poly in enumerate(plaintexts):
        for position in range(min(pk.n, count - group * pk.n)):
            tile, lane = divmod(position, capacity)
            distance = table[poly[lane * padded + tile]]
            if distance < 0:
                raise ValueError("Invalid trace correlation")
            result.append(distance)
    return result


def finish(plaintexts: list[list[int]], count: int, dimension: int, pk: bgv.PublicKey,
           *, k: int = 3, all_distances: bool = True, method: str = "lookup") -> SearchResult:
    validate_layout(pk.n, pk.t, count, dimension, k, all_distances)
    if method not in ("sort", "heap", "lookup"):
        raise ValueError("Unknown local result method")
    distances = (decode_lookup(plaintexts, count, dimension, pk) if method == "lookup"
                 else trace.decode(plaintexts, count, dimension, pk))
    def key(i: int) -> tuple[int, int]:
        return distances[i], i
    selected = (sorted(range(count), key=key)[:k] if method == "sort"
                else heapq.nsmallest(k, range(count), key=key))
    return SearchResult(tuple((i, distances[i]) for i in selected),
                        tuple(distances) if all_distances else None)
