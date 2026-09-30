"""E35 private rank discovery separated from public plaintext CRT geometry.

Discovery cuts are grouping decisions, not polynomial factors. They need not
have roots in the eventual plaintext field. Only the FINAL allocated cover
must split X^N+1. Maps are independently fitted/certified over each candidate
field; no map reduction from a different field is used as an enrollment proof.

Correctness/cost selection only: full encryption N is unchanged, and none of
these candidates supplies RLWE, private-timing or protocol certification.
Existing deterministic key gates/evaluators remain authoritative at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

import gmpy2

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import crt_noise_budget as noise
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import rank_partition as partition


@dataclass(frozen=True)
class Groups:
    blocks: tuple[partition.Block, ...]
    cuts: tuple[partition.Cut, ...]
    source_digest: str
    dimension: int
    n: int
    prime: int
    target: int


def max_slots(prime: int) -> int:
    if type(prime) is not int or not 3 <= prime <= 65537 or not gmpy2.is_prime(prime):
        raise ValueError("Expected a bounded odd plaintext prime")
    # A depth-d dyadic split requires an element of order 2**(d+1).
    return min(64, ((prime - 1) & -(prime - 1)) // 2)


def fit(rows: list[int], dimension: int, order: tuple[int, ...], *, prime: int, n: int = 16384,
        target: int = 32, initial_parts: int = 8, max_depth: int = 10, policy: str = "hybrid") -> Groups:
    """Bounded greedy private cuts; their depth is independent of CRT roots.

    Retain E27's proposal ordering when its temporary capacities are nonzero,
    so a same-field control can reproduce old grouping. Those capacities only
    rank proposals here. Final allocation certifies actual capacity separately.
    """
    affine._field(dimension, prime)
    partition.epoch_digest(rows, dimension)
    if (not 1 <= len(rows) <= 32768 or len(rows) * dimension > 8 << 20
            or type(n) is not int or not 8 <= n <= 32768 or n & (n - 1)
            or type(target) is not int or not 1 <= target <= n // 2 or target & (target - 1)
            or type(initial_parts) is not int or not 1 <= initial_parts <= min(64, len(rows))
            or initial_parts & (initial_parts - 1) or tuple(sorted(order)) != tuple(range(len(rows)))
            or type(max_depth) is not int or not 0 <= max_depth <= 10
            or initial_parts.bit_length() - 1 > max_depth or policy not in ("hybrid", "median")):
        raise ValueError("Invalid geometry-independent rank workload")
    depth = initial_parts.bit_length() - 1
    paths = tuple(format(i, f"0{depth}b") for i in range(initial_parts)) if depth else ("",)
    blocks = []
    for i, path in enumerate(paths):
        initial_positions = order[len(rows) * i // initial_parts:len(rows) * (i + 1) // initial_parts]
        mapping = affine.prepare([rows[j] for j in initial_positions], dimension, prime)
        blocks.append(partition.Block(path, initial_positions, mapping))
    cuts = []
    while True:
        bad = next((i for i, block in enumerate(blocks) if block.mapping.features > target), None)
        if bad is None:
            break
        block = blocks[bad]
        if len(block.path) >= max_depth or len(blocks) >= 64:
            raise ValueError("Rank discovery exceeds its private leaf/depth budget")
        degree = max(1, n >> (len(block.path) + 1))
        proposals = []
        for coordinate, positions in partition._options(rows, block.positions, dimension, policy):
            if not all(positions):
                continue
            maps = tuple(affine.prepare([rows[j] for j in group], dimension, prime) for group in positions)
            ranks = tuple(p.rank for p in maps)
            if coordinate is not None and any(r >= block.mapping.rank for r in ranks):
                raise AssertionError("A varying binary-coordinate cut must reduce affine rank")
            sizes = tuple(map(len, positions))
            score = (max(0, max(ranks) - target), max((size * target + degree - 1) // degree for size in sizes),
                     sum(len(affine.canonical_map(p)) for p in maps), -1 if coordinate is None else coordinate)
            proposals.append((score, coordinate, positions, maps))
        if not proposals:
            raise ValueError("No nonempty exact private rank split")
        _, coordinate, positions, maps = min(proposals, key=lambda p: p[0])
        cuts.append(partition.Cut(block.path, coordinate, block.mapping.rank,
                                  (maps[0].rank, maps[1].rank), (len(positions[0]), len(positions[1]))))
        blocks[bad:bad + 1] = [partition.Block(block.path + str(i), group, mapping)
                               for i, (group, mapping) in enumerate(zip(positions, maps, strict=True))]
    result = Groups(tuple(blocks), tuple(cuts), partition.epoch_digest(rows, dimension), dimension, n, prime, target)
    validate(result, rows)
    return result


def validate(groups: Groups, rows: list[int]) -> None:
    affine._field(groups.dimension, groups.prime)
    if (groups.source_digest != partition.epoch_digest(rows, groups.dimension)
            or type(groups.n) is not int or not 8 <= groups.n <= 32768 or groups.n & (groups.n - 1)
            or type(groups.target) is not int or not 1 <= groups.target <= groups.n // 2 or groups.target & (groups.target - 1)
            or sorted(i for b in groups.blocks for i in b.positions) != list(range(len(rows)))
            or not 1 <= len(groups.blocks) <= 64
            or any(not b.positions or b.mapping.dimension != groups.dimension or b.mapping.prime != groups.prime
                   or b.mapping.features > groups.target for b in groups.blocks)):
        raise ValueError("Stale, incomplete or infeasible private rank groups")
    paths = tuple(b.path for b in groups.blocks)
    if (tuple(sorted(set(paths))) != paths or any(len(p) > 10 or set(p) - {"0", "1"} for p in paths)
            or any(a != b and b.startswith(a) for a in paths for b in paths)):
        raise ValueError("Invalid private discovery tree")
    depth = max(map(len, paths))
    if sum(1 << (depth - len(p)) for p in paths) != 1 << depth:
        raise ValueError("Incomplete private discovery cover")
    for block in groups.blocks:
        affine.index_features(block.mapping, [rows[i] for i in block.positions])


def refit(groups: Groups, rows: list[int], prime: int) -> Groups:
    """Fixed-membership control: fit afresh, not reuse modularly reduced maps."""
    validate(groups, rows)
    blocks = tuple(partition.Block(b.path, b.positions,
                                    affine.prepare([rows[i] for i in b.positions], groups.dimension, prime))
                   for b in groups.blocks)
    # Cut ranks belonged to the old field; they are not carried into this
    # control as if they certified the newly fitted groups.
    result = Groups(blocks, (), groups.source_digest, groups.dimension, groups.n, prime, groups.target)
    validate(result, rows)
    return result


def allocate(groups: Groups, rows: list[int], slots: int) -> partition.Candidate:
    """Exact fixed-map occupancy, then a valid coalesced FINAL CRT cover."""
    validate(groups, rows)
    if type(slots) is not int or not 1 <= slots <= max_slots(groups.prime) or slots & (slots - 1):
        raise ValueError("Final CRT slots need roots in the chosen field")
    # Validate actual roots too; divisibility is not a substitute for the
    # existing independent factor/CRT oracle.
    depth = slots.bit_length() - 1
    paths = tuple(format(i, f"0{depth}b") for i in range(slots)) if depth else ("",)
    tree.context(groups.n, paths, groups.prime)
    grouped: dict[affine.Plan, list[int]] = {}
    for block in groups.blocks:
        grouped.setdefault(block.mapping, []).extend(block.positions)
    maps = tuple(grouped)
    positions = tuple(tuple(grouped[p]) for p in maps)
    padded = 1 << (max(p.features for p in maps) - 1).bit_length()
    capacity = groups.n // slots // padded
    if capacity < 1:
        raise ValueError("Final slot cannot hold the padded rank")
    tiles, allocation = partition.allocate_slots(tuple(map(len, positions)), slots, capacity)
    labels = [i for i, count in enumerate(allocation) for _ in range(count)]
    leaves: list[tuple[str, int]] = []

    def cover(path: str, start: int, stop: int) -> None:
        if stop - start == 1 or all(label == labels[start] for label in labels[start:stop]):
            leaves.append((path, labels[start]))
        else:
            middle = (start + stop) // 2
            cover(path + "0", start, middle)
            cover(path + "1", middle, stop)

    cover("", 0, slots)
    offsets, blocks = [0] * len(maps), []
    for path, group in leaves:
        count = min(len(positions[group]) - offsets[group], tiles * (groups.n >> len(path)) // padded)
        piece = positions[group][offsets[group]:offsets[group] + count]
        offsets[group] += count
        blocks.append(partition.Block(path, piece, maps[group]))
    assert offsets == list(map(len, positions))
    ctx = tree.context(groups.n, tuple(b.path for b in blocks), groups.prime)
    layout = tree.layout(ctx, tuple(b.mapping.features for b in blocks), tuple(len(b.positions) for b in blocks))
    result = partition.Candidate(layout, tuple(blocks), groups.cuts, groups.source_digest, groups.dimension,
                                 partition.map_body_bytes(tuple(blocks)), groups.target)
    partition.validate_epoch(result, rows)
    assert layout.cost.input_tiles == tiles
    return result


@lru_cache(maxsize=512)
def modulus(n: int, bits: int) -> int:
    if (type(n) is not int or not 8 <= n <= 32768 or n & (n - 1)
            or type(bits) is not int or not n.bit_length() + 1 <= bits <= 56):
        raise ValueError("Invalid bounded NTT modulus search")
    q = ((1 << bits) - 2) // (2 * n) * (2 * n) + 1
    while q > 2 * n and not gmpy2.is_prime(q):
        q -= 2 * n
    if q <= 2 * n:
        raise ValueError("No prime in the bounded word-modulus interval")
    return q


def rounds(q: int, *, budget: int = 1024, integrity_bits: int = 128) -> int:
    if (type(q) is not int or q < 3 or not gmpy2.is_prime(q) or type(budget) is not int or not 1 <= budget <= 65536
            or type(integrity_bits) is not int or not 32 <= integrity_bits <= 256):
        raise ValueError("Invalid conditional fingerprint target")
    for count in range(1, 9):
        if q ** count >= budget * (1 << integrity_bits):
            return count
    raise ValueError("Fingerprint target exceeds the existing round budget")


def describe(candidate: partition.Candidate) -> dict:
    maps = tuple(dict.fromkeys(b.mapping for b in candidate.blocks))
    s = crt.space(candidate.layout, tuple(maps.index(b.mapping) for b in candidate.blocks))
    n, t = s.layout.context.n, s.layout.context.prime
    deterministic = crt.cost(s)["worst_case_phase_bound"]
    statistical = noise.certificate(noise.Profile(s)).total
    profiles = {}
    for name, bound in (("deterministic", deterministic), ("fixed_cbd", statistical)):
        analytic = None
        for trial in range(max(16, n.bit_length() + 1), 57):
            try:
                q_trial = modulus(n, trial)
            except ValueError:
                continue
            if 2 * bound < q_trial:
                analytic = trial
                break
        if analytic is None:
            raise ValueError("Phase bound exceeds the modeled word-modulus range")
        bits = max(32, analytic)  # Existing owner/key APIs require >=32 bits.
        q = modulus(n, bits)
        count = rounds(q)
        profiles[name] = {"bound": bound, "minimum_analytic_q_bits_model": analytic,
                          "implemented_api_minimum_q_bits": bits, "q": q, "rounds": count,
                          "cost": crt.cost(s, q_bits=bits, rounds=count)}
    return {"t": t, "n": n, "target": candidate.target, "F": s.columns, "h": s.dimension,
            "W": sum(s.column_degrees), "slots": s.slots, "replies": s.layout.cost.response_ciphertexts,
            "private_map_body_bytes": candidate.map_bytes, "profiles": profiles,
            "scope": "Correctness/cost frontier, not security estimates. Below-32-bit Q is modeled only."}
