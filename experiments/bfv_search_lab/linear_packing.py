"""Owner-side generic dot-product layouts for local homemade BGV experiments.

These helpers do not authenticate remote replies. Non-binary features require
the ordinary conservative BGV bounds, not the binary support-bound shortcut.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PackingCost:
    features: int
    padded: int
    count: int
    input_tiles: int
    switches: int
    response_ciphertexts: int


def packing_cost(features: int, count: int, n: int = 16384) -> PackingCost:
    """Count the existing butterfly circuit, including partially filled tiles."""
    if (type(features) is not int or features < 1 or type(count) is not int or count < 0
            or type(n) is not int or n < 2 or n & (n - 1)):
        raise ValueError("Invalid dot-product dimensions")
    padded = 1 << (features - 1).bit_length()
    if padded > n // 2:
        raise ValueError("Features exceed trace capacity")
    capacity = n // padded
    tiles = (count + capacity - 1) // capacity
    switches = tiles  # One relinearization per product.
    for start in range(0, tiles, padded):
        live, shift = min(padded, tiles - start), padded // 2
        while shift:
            live = min(live, shift)
            switches += live
            shift //= 2
    return PackingCost(features, padded, count, tiles, switches, (count + n - 1) // n)


def pack(
    query: list[int], rows: list[list[int]], n: int,
) -> tuple[list[int], list[list[int]], int]:
    """Reverse the query and concatenate index rows; encrypt before server use."""
    if (any(type(x) is not int for x in query)
            or any(len(row) != len(query) or any(type(x) is not int for x in row) for row in rows)):
        raise ValueError("Expected equally sized integer feature vectors")
    model = packing_cost(len(query), len(rows), n)
    padded, capacity = model.padded, n // model.padded
    qp = [0] * n
    qp[padded - len(query):padded] = reversed(query)
    tiles = [[0] * n for _ in range(model.input_tiles)]
    for i, row in enumerate(rows):
        tile, lane = divmod(i, capacity)
        tiles[tile][lane * padded:lane * padded + len(row)] = row
    return qp, tiles, padded


def unpack(
    plaintexts: list[list[int]], count: int, padded: int, n: int, prime: int,
) -> list[int]:
    """Undo the butterfly trace scale; leave dot products as field residues."""
    model = packing_cost(padded, count, n)
    if (model.padded != padded or type(prime) is not int or prime < 3 or not prime % 2
            or len(plaintexts) != model.response_ciphertexts
            or any(len(p) != n or any(type(x) is not int or not 0 <= x < prime for x in p)
                   for p in plaintexts)):
        raise ValueError("Invalid local dot-product response")
    inverse, capacity = pow(padded, -1, prime), n // padded
    result = []
    for i in range(count):
        group, within = divmod(i, n)
        tile, lane = divmod(within, capacity)
        result.append(plaintexts[group][lane * padded + tile] * inverse % prime)
    return result
