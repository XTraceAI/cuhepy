"""E24: share one ciphertext between template scores and fixed exact witnesses.

Two existing butterfly evaluations under the SAME key can have disjoint useful
coefficient positions. Shift the witness output into a certified gap, then add
the ciphertexts. Each region keeps its own trace scale. This saves no query or
evaluation work: the owner prepares a second query and extra witness index.

The support certificate describes the HONEST circuit's plaintext zero pattern.
It is not a check on an untrusted ciphertext. Bind both evaluated inputs, layouts
and complete response in a future authenticated protocol before private use.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.bfv_search_lab import linear_packing as packing
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


@dataclass(frozen=True)
class Placement:
    n: int
    primary_padded: int
    primary_count: int
    witness_padded: int
    witness_count: int
    shift: int


def positions(n: int, padded: int, count: int) -> tuple[int, ...]:
    cost = packing.packing_cost(padded, count, n)
    if cost.padded != padded or count > n:
        raise ValueError("One-response support model requires a power-of-two layout and count <= N")
    capacity = n // padded
    return tuple((i % capacity) * padded + i // capacity for i in range(count))


def place(n: int, primary_padded: int, primary_count: int, witness_padded: int, witness_count: int) -> Placement:
    """Find a non-wrapping monomial shift with disjoint honest output support.

    This searches only a single shift, not arbitrary free coefficient scatter.
    Failure means this construction cannot share a response for those layouts.
    """
    left = positions(n, primary_padded, primary_count)
    right = positions(n, witness_padded, witness_count)
    if not left or not right:
        raise ValueError("Require nonempty primary and witness outputs")
    occupied = sum(1 << x for x in left)
    witness = sum(1 << x for x in right)
    for shift in range(n - max(right)):
        if not occupied & (witness << shift):
            return Placement(n, primary_padded, primary_count, witness_padded, witness_count, shift)
    raise ValueError("No disjoint non-wrapping monomial placement")


def validate(plan: Placement) -> None:
    left = positions(plan.n, plan.primary_padded, plan.primary_count)
    right = positions(plan.n, plan.witness_padded, plan.witness_count)
    if (not left or not right or type(plan.shift) is not int or plan.shift < 0
            or max(right) + plan.shift >= plan.n
            or set(left) & {x + plan.shift for x in right}):
        raise ValueError("Overlapping or out-of-range witness support")


def combine(
    primary: bgv.Ciphertext, witness: bgv.Ciphertext, plan: Placement, pk: bgv.PublicKey,
) -> bgv.Ciphertext:
    validate(plan)
    bgv._validate(primary, pk)
    bgv._validate(witness, pk)
    if pk.n != plan.n or len(primary.components) != 2 or len(witness.components) != 2:
        raise ValueError("Wrong two-component witness context")
    return trace._add(primary, trace._monomial(witness, plan.shift, pk), pk)


def decode(plain: list[int], plan: Placement, prime: int) -> tuple[list[int], list[int]]:
    """Return both sets of field dot products; interpretation belongs to owner."""
    validate(plan)
    if (type(prime) is not int or prime < 3 or not prime % 2 or len(plain) != plan.n
            or any(type(x) is not int or not 0 <= x < prime for x in plain)):
        raise ValueError("Invalid local multiplexed plaintext")
    left = [plain[i] * pow(plan.primary_padded, -1, prime) % prime
            for i in positions(plan.n, plan.primary_padded, plan.primary_count)]
    right = [plain[i + plan.shift] * pow(plan.witness_padded, -1, prime) % prime
             for i in positions(plan.n, plan.witness_padded, plan.witness_count)]
    return left, right
