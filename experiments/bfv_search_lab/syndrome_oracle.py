"""E19: exact block filters, including a query-conditioned coset/weight bound.

Plaintext selectivity models and owner-side layout for a tiny encrypted test.
Exposing syndromes, block weights, survivor IDs or thresholds changes privacy.
No omission certificate, private routing or remote decryption protocol is
implemented here.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import random

from experiments.bfv_search_lab.answer_oracles import validate_field


@dataclass(frozen=True)
class BlockCode:
    width: int
    rank: int
    columns: tuple[int, ...]
    syndromes: tuple[int, ...]
    leaders: tuple[int, ...]


def make_code(width: int, rank: int, seed: int = 0) -> BlockCode:
    """Small public full-rank binary map with a deterministic random extension."""
    if (type(width) is not int or not 1 <= width <= 10
            or type(rank) is not int or not 1 <= rank <= width):
        raise ValueError("Toy code requires 1 <= rank <= width <= 10")
    rng = random.Random(seed)
    columns = [1 << j for j in range(rank)]
    unused = [x for x in range(1, 1 << rank) if x not in columns]
    rng.shuffle(unused)
    for _ in range(rank, width):
        columns.append(unused.pop() if unused else rng.randrange(1, 1 << rank))
    syndromes = [0] * (1 << width)
    leaders = [width + 1] * (1 << rank)
    for value in range(1 << width):
        if value:
            lowest = value & -value
            syndromes[value] = syndromes[value ^ lowest] ^ columns[lowest.bit_length() - 1]
        syndrome = syndromes[value]
        leaders[syndrome] = min(leaders[syndrome], value.bit_count())
    assert all(value <= width for value in leaders)  # Identity columns ensure full rank.
    return BlockCode(width, rank, tuple(columns), tuple(syndromes), tuple(leaders))


def conditioned_table(code: BlockCode, query: int) -> tuple[int, ...]:
    """min distance(q,y) over y with a specified (H*y, weight(y)).

    y=x is feasible, hence this is a lower bound for any index block x. Empty
    buckets use the sentinel width+1 and must never stand in for a real block.
    Table construction enumerates all 2**width words and depends on the query.
    """
    if type(query) is not int or not 0 <= query < 1 << code.width:
        raise ValueError("Invalid query block")
    result = [code.width + 1] * ((1 << code.rank) * (code.width + 1))
    for value, syndrome in enumerate(code.syndromes):
        at = syndrome * (code.width + 1) + value.bit_count()
        result[at] = min(result[at], (query ^ value).bit_count())
    return tuple(result)


def block_bounds(
    code: BlockCode, query: int, value: int, table: tuple[int, ...] | None = None,
) -> tuple[int, int, int, int]:
    """Return weight, syndrome, parity-corrected max and conditioned lower bounds."""
    if (type(query) is not int or type(value) is not int
            or not 0 <= query < 1 << code.width or not 0 <= value < 1 << code.width):
        raise ValueError("Invalid binary block")
    if table is None:
        table = conditioned_table(code, query)
    if len(table) != (1 << code.rank) * (code.width + 1):
        raise ValueError("Wrong conditioned table size")
    delta_weight = abs(value.bit_count() - query.bit_count())
    delta_syndrome = code.leaders[code.syndromes[value] ^ code.syndromes[query]]
    combined = max(delta_weight, delta_syndrome)
    combined += (delta_weight - combined) % 2  # Hamming parity is determined by weights.
    conditioned = table[code.syndromes[value] * (code.width + 1) + value.bit_count()]
    return delta_weight, delta_syndrome, combined, conditioned


def vector_bounds(query: int, rows: list[int], codes: list[BlockCode]) -> dict[str, list[int]]:
    dimension = sum(code.width for code in codes)
    if (not codes or type(query) is not int or not 0 <= query < 1 << dimension
            or any(type(row) is not int or not 0 <= row < 1 << dimension for row in rows)):
        raise ValueError("Rows/query must match the disjoint block dimensions")
    names = ("weight", "syndrome", "parity_max", "conditioned")
    results = {name: [0] * len(rows) for name in names}
    offset = 0
    for code in codes:
        mask = (1 << code.width) - 1
        q = (query >> offset) & mask
        table = conditioned_table(code, q)
        for i, row in enumerate(rows):
            bounds = block_bounds(code, q, (row >> offset) & mask, table)
            for name, bound in zip(names, bounds, strict=True):
                results[name][i] += bound
        offset += code.width
    return results


def _buckets(code: BlockCode) -> tuple[int, ...]:
    return tuple(sorted({s * (code.width + 1) + x.bit_count()
                         for x, s in enumerate(code.syndromes)}))


@dataclass(frozen=True)
class LookupBasis:
    prime: int
    buckets: tuple[int, ...]
    query_features: tuple[tuple[int, ...], ...]
    index_features: tuple[tuple[int, ...], ...]

    @property
    def rank(self) -> int:
        return len(self.query_features[0])


@lru_cache(maxsize=64)
def factor_table(code: BlockCode, prime: int) -> LookupBasis:
    """Exact public rank factorization A=C*R mod p, using original columns C.

    A[q,b] is the conditioned distance to bucket b. All possible query blocks
    are enumerated, so this preprocessing reveals no actual query or index.
    The index features can be full-field values: do not reuse binary/sparse
    noise bounds. Rank is a bilinear-feature count, not a universal cost bound.
    """
    validate_field(prime, code.width, 0)
    if code.width > 8:
        raise ValueError("Public factorization reference limited to eight-bit blocks")
    buckets = _buckets(code)
    original = []
    for query in range(1 << code.width):
        table = conditioned_table(code, query)
        original.append([table[bucket] for bucket in buckets])
    work = [row.copy() for row in original]
    pivots: list[int] = []
    for column in range(len(buckets)):
        rank = len(pivots)
        pivot = next((i for i in range(rank, len(work)) if work[i][column]), None)
        if pivot is None:
            continue
        work[rank], work[pivot] = work[pivot], work[rank]
        inverse = pow(work[rank][column], -1, prime)
        row = [x * inverse % prime for x in work[rank]]
        work[rank] = row
        # Reduced row echelon form makes each pivot column a unit vector.
        for i in range(len(work)):
            if i != rank and work[i][column]:
                scale = work[i][column]
                work[i] = [(a - scale * b) % prime for a, b in zip(work[i], row, strict=True)]
        pivots.append(column)
    query_features = tuple(tuple(row[j] for j in pivots) for row in original)
    index_features = tuple(tuple(work[i][j] for i in range(len(pivots))) for j in range(len(buckets)))
    return LookupBasis(prime, buckets, query_features, index_features)


def lookup_expansion(
    codes: list[BlockCode], count: int, n: int = 16384, *, factorized_prime: int | None = None,
) -> dict[str, int]:
    """Cost gate for an exact depth-one encrypted one-hot lookup construction.

    Encrypt one-hot index features and a query-dependent table, then take their
    dot product using the existing coefficient-packing circuit. This is a cost
    model, not a fast private routing or authentication implementation.
    """
    dimension = sum(c.width for c in codes)
    if factorized_prime is not None:
        validate_field(factorized_prime, dimension, 0)
    prefix = "onehot" if factorized_prime is None else "factorized"
    features = sum(len(_buckets(c)) if factorized_prime is None else factor_table(c, factorized_prime).rank
                   for c in codes)
    if (not codes or type(count) is not int or count < 1 or type(n) is not int
            or n < 2 or n & (n - 1)):
        raise ValueError("Expected codes, positive count and power-of-two ring")

    def cost(length: int) -> tuple[int, int, int]:
        padded = 1 << (length - 1).bit_length()
        if padded > n // 2:
            raise ValueError("One-hot or original layout exceeds this ring's trace capacity")
        tiles = (count + n // padded - 1) // (n // padded)
        switches = tiles
        for start in range(0, tiles, padded):
            live, shift = min(padded, tiles - start), padded // 2
            while shift:
                live = min(live, shift)
                switches += live
                shift //= 2
        return padded, tiles, switches

    base_padded, base_tiles, base_switches = cost(dimension)
    padded, tiles, switches = cost(features)
    return {f"{prefix}_features": features, f"{prefix}_padded": padded, f"{prefix}_input_tiles": tiles,
            f"{prefix}_switches": switches, "original_features": dimension,
            "original_padded": base_padded, "original_input_tiles": base_tiles,
            "original_switches": base_switches, "query_plaintext_entries": features}


def lookup_inputs(
    query: int, rows: list[int], codes: list[BlockCode], n: int, *, factorized_prime: int | None = None,
) -> tuple[list[int], list[list[int]], int]:
    """Owner-side exact one-hot/table layout for the homemade encrypted pilot.

    These plaintext arrays must be encrypted before server use. The map itself
    is public and data independent. Filter scores alone do not provide the
    private selection, omitted-result proof or authenticated response protocol.
    """
    dimension = sum(c.width for c in codes)
    if (type(query) is not int or not 0 <= query < 1 << dimension
            or any(type(x) is not int or not 0 <= x < 1 << dimension for x in rows)):
        raise ValueError("Invalid binary lookup fixture")
    if factorized_prime is not None:
        validate_field(factorized_prime, dimension, 0)
    model = lookup_expansion(codes, max(1, len(rows)), n, factorized_prime=factorized_prime)
    prefix = "onehot" if factorized_prime is None else "factorized"
    padded = model[f"{prefix}_padded"]
    capacity = n // padded
    query_poly = [0] * n
    tiles = [[0] * n for _ in range((len(rows) + capacity - 1) // capacity)]
    bit_offset = feature_offset = 0
    for code in codes:
        bucket_ids = _buckets(code)
        positions = {bucket: i for i, bucket in enumerate(bucket_ids)}
        mask = (1 << code.width) - 1
        q = (query >> bit_offset) & mask
        basis = None if factorized_prime is None else factor_table(code, factorized_prime)
        table = conditioned_table(code, q)
        weights = tuple(table[bucket] for bucket in bucket_ids) if basis is None else basis.query_features[q]
        for j, weight in enumerate(weights):
            query_poly[padded - 1 - feature_offset - j] = weight
        for i, row in enumerate(rows):
            block = (row >> bit_offset) & mask
            bucket = code.syndromes[block] * (code.width + 1) + block.bit_count()
            tile, lane = divmod(i, capacity)
            if basis is None:
                tiles[tile][lane * padded + feature_offset + positions[bucket]] = 1
            else:
                features = basis.index_features[positions[bucket]]
                for j, value in enumerate(features):
                    tiles[tile][lane * padded + feature_offset + j] = value
        bit_offset += code.width
        feature_offset += len(weights)
    return query_poly, tiles, padded


def selectivity(query: int, rows: list[int], codes: list[BlockCode], k: int = 3) -> dict:
    """Use the *oracle* kth radius to isolate selectivity; its discovery is not free.

    Also record fixed radii and whether they already cover k results. Equal-bound
    candidates are retained. A successful filter still scans all derived
    features; survivor reduction is not a measured encrypted speedup.
    """
    if type(k) is not int or not 1 <= k <= len(rows):
        raise ValueError("Require 1 <= k <= row count")
    bounds = vector_bounds(query, rows, codes)
    distances = [(query ^ row).bit_count() for row in rows]
    expected = sorted(range(len(rows)), key=lambda i: (distances[i], i))[:k]
    radius = distances[expected[-1]]
    results = {}
    for name, values in bounds.items():
        assert all(bound <= distance for bound, distance in zip(values, distances, strict=True))
        candidates = [i for i, value in enumerate(values) if value <= radius]
        recovered = sorted(candidates, key=lambda i: (distances[i], i))[:k]
        assert recovered == expected
        results[name] = {"survivors": len(candidates), "mean_bound": sum(values) / len(values),
                         "exact_topk_preserved": True}
    fixed = []
    for threshold in sorted({0, 4, 16, 64, 96, 128, 192, radius}):
        fixed.append({"radius": threshold, "within_radius": sum(x <= threshold for x in distances),
                      "covers_k": sum(x <= threshold for x in distances) >= k,
                      "survivors": {name: sum(x <= threshold for x in values)
                                    for name, values in bounds.items()}})
    return {
        "count": len(rows), "dimension": sum(code.width for code in codes), "k": k,
        "oracle_kth_radius": radius, "filters": results, "fixed_radii": fixed,
        "feature_block_visits": len(rows) * len(codes),
        "public_conditioned_table_entries_per_query": sum((1 << c.rank) * (c.width + 1) for c in codes),
        "conditioned_table_word_evaluations_per_query": sum(1 << c.width for c in codes),
        "conceptual_feature_bits_per_vector": sum(c.rank + c.width.bit_length() for c in codes),
        "privacy_or_authentication_implemented": False,
    }
