"""Public correctness-bound/byte planner for independent query and c0-response rounding.

Enumerates ring-preserving representations, never observed private noise. The
Pareto frontier describes byte counts only. Link ranking ignores codec compute
and is an experiment selector, not a production parameter or latency oracle.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

import msgpack

from experiments.bfv_search_lab import shallow_bgv as bgv, compact_bgv as compact
from experiments.bfv_search_lab import compressed_query_bgv as query, seeded_bgv as seeded
from experiments.bfv_search_lab import compressed_response_bgv as response
from experiments.bfv_search_lab.native_bgv import NativeServer, PreparedIndex


@dataclass(frozen=True)
class Plan:
    query_drop: int | None
    terminal_bits: int
    response_drop: int | None
    query_bytes: int
    response_bytes: int
    query_bound: int
    terminal_bounds: tuple[int, ...]
    final_bounds: tuple[int, ...]

    @property
    def total_bytes(self) -> int:
        return self.query_bytes + self.response_bytes


def query_size(pk: bgv.PublicKey, drop: int | None) -> int:
    envelope: list[bytes | int]
    if drop is None:
        width = pk.n * pk.q.bit_length() // 8
        envelope = [seeded._TAG, bytes.fromhex(pk.key_id), bytes(32), b""]
    else:
        width = query.parameters(pk, drop).body_bytes
        envelope = [query._TAG, bytes.fromhex(pk.key_id), bytes(32), drop, b""]
    return len(msgpack.packb(envelope, use_bin_type=True)) - 2 + response._binary_cost(width)


def enumerate_plans(
    server: NativeServer,
    index: PreparedIndex,
    dimension: int,
    *,
    terminal_bits: tuple[int, ...] = (25, 26, 28, 32),
) -> list[Plan]:
    pk = server.pk
    if index.count < 1 or not terminal_bits or len(set(terminal_bits)) != len(terminal_bits):
        raise ValueError("Expected a nonempty index and distinct response precisions")
    # A dummy polynomial is only a vehicle for the existing public bound
    # schedule. No encryption/decryption or private noise inspection occurs.
    zeros = tuple([0] * pk.n)
    base_query_bytes = query_size(pk, None)
    plans = []
    for drop in (None, *range(1, pk.q.bit_length())):
        try:
            query_bound = (
                pk.t // 2 + pk.t * pk.eta
                if drop is None
                else query.parameters(pk, drop).query_bound
            )
            q_bytes = query_size(pk, drop)
            if drop is not None and q_bytes >= base_query_bytes:
                continue  # More bytes and no smaller bound than the seeded representation.
            full_bounds = server._bounds(
                bgv.Ciphertext((zeros, zeros), pk.key_id, query_bound), index, True
            )
        except ValueError:
            continue
        for bits in terminal_bits:
            p = compact.terminal_modulus(pk.q, pk.t, bits)
            try:
                reduced = tuple(compact.reduced_bound(b, pk, p) for b in full_bounds)
            except ValueError:
                continue
            base_response = response.packet_size(pk, index.count, dimension, bits, None)
            for response_drop in (None, *range(1, bits)):
                extra = (
                    0
                    if response_drop is None
                    else query.coefficient_encoding(p, pk.t, response_drop).added_bound
                )
                final = tuple(b + extra for b in reduced)
                if any(2 * b >= p for b in final):
                    continue
                r_bytes = response.packet_size(pk, index.count, dimension, bits, response_drop)
                if response_drop is not None and r_bytes >= base_response:
                    continue
                plans.append(
                    Plan(drop, bits, response_drop, q_bytes, r_bytes, query_bound, reduced, final)
                )
    return plans


def pareto(plans: list[Plan]) -> list[Plan]:
    """Keep representations for which neither direction can shrink without growing the other."""
    best_response = math.inf
    result = []
    for plan in sorted(plans, key=lambda p: (p.query_bytes, p.response_bytes, p.terminal_bits)):
        if plan.response_bytes < best_response:
            result.append(plan)
            best_response = plan.response_bytes
    return result


def select(plans: list[Plan], upload_mbps: float, download_mbps: float) -> Plan:
    if not plans or any(not math.isfinite(v) or v <= 0 for v in (upload_mbps, download_mbps)):
        raise ValueError("Expected plans and positive finite link rates")
    return min(
        plans,
        key=lambda p: (
            p.query_bytes / upload_mbps + p.response_bytes / download_mbps,
            p.total_bytes,
            p.terminal_bits,
        ),
    )
