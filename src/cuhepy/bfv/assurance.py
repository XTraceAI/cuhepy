"""Reviewable public parameter policy and conservative Hamming noise bounds.

These are engineering evidence, not independent security certification. Bounds
assume honestly generated ternary secrets/ephemerals, bounded CBD errors, and
the exact existing square-difference, rotation, mask and merge circuit. They
do not validate an attacker-created ciphertext or replace the receipt gate.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from fractions import Fraction

from cuhepy.bfv.security import BFVExecutionPolicy
from cuhepy.bfv.scheme import _coefficient_modulus, _parameter_modulus
from cuhepy.types import BFVParameters


def bfv_review_policy() -> BFVExecutionPolicy:
    """Larger ring for parameter review, preserving Q, t and the existing circuit.

    The raw BFV and earlier session defaults remain unchanged. This profile
    needs fresh keys/index and a larger public-key import allowance. Its name
    deliberately does not assert a production or cryptographic security level.
    """
    return BFVExecutionPolicy(
        params=BFVParameters(poly_modulus_degree=16384, rns_modulus=True),
        max_public_key_bytes=256 * 1024 * 1024,
    )


def _ceil(value: Fraction) -> int:
    return -(-value.numerator // value.denominator)


@dataclass(frozen=True)
class BFVHammingNoiseBound:
    """Bounds for v in phase(c) = floor(Q/t)*m + v (mod Q), coefficientwise."""

    encrypted: int
    difference: int
    squared: int
    key_switch: int
    tile: int
    merged: int
    compacted: int
    original_rounding_error_numerator: int
    terminal_rounding_error_numerator: int
    original_modulus: int
    terminal_modulus: int

    @property
    def sufficient(self) -> bool:
        # Strict inequalities cover both rounding boundaries. The numerator
        # already includes plaintext representative error from Q mod t.
        return (
            2 * self.original_rounding_error_numerator < self.original_modulus
            and 2 * self.terminal_rounding_error_numerator < self.terminal_modulus
        )

    def as_dict(self) -> dict[str, int | bool]:
        return {**asdict(self), "sufficient": self.sufficient}


def hamming_noise_bound(policy: BFVExecutionPolicy, vector_count: int) -> BFVHammingNoiseBound:
    """Bound every coefficient for the full supported binary Hamming workload.

    Uses ||a*b||_infinity <= N ||a||_infinity ||b||_infinity in Z[X]/(X^N+1).
    All arithmetic is exact integer/rational arithmetic, with outward rounding.
    See docs/research/native-bfv-predecryption.md for the multiplication lift
    terms and the limits of this source-level derivation.
    """
    if type(vector_count) is not int or not 1 <= vector_count <= policy.max_vectors:
        raise ValueError("Vector count exceeds the local policy")
    p = policy.params
    n, t, eta = p.poly_modulus_degree, p.plain_modulus, p.error_eta
    q = int(_parameter_modulus(p))
    target = min(int(_coefficient_modulus(policy.response_modulus_bits)), q)
    delta, remainder = divmod(q, t)
    width = 1 << (policy.embed_len - 1).bit_length()
    capacity = n // width
    tiles = min(width, (vector_count + capacity - 1) // capacity)
    digits = (p.coeff_modulus_bits + p.decomposition_bits - 1) // p.decomposition_bits
    switch = n * digits * ((1 << p.decomposition_bits) - 1) * eta

    # e_pk*u + e0 + e1*s, followed by the canonical plaintext subtraction.
    encrypted = (2 * n + 1) * eta
    difference = 2 * encrypted + remainder
    # Canonical components bound the INTEGER phase lift k in
    # phase = delta*m + v + Q*k, even when squaring the same ciphertext.
    lift = _ceil(Fraction((n + 1) * (q - 1) + delta * (t - 1) + difference, q))
    message_product = n * (t - 1) ** 2
    message_carry = (message_product + t - 1 + t - 1) // t
    tensor_rounding = Fraction(1 + n + n * n, 2)
    squared = (
        _ceil(
            remainder * message_carry
            + Fraction(delta * remainder * message_product, q)
            + 2 * n * (t - 1) * difference
            + Fraction(t * n * difference**2, q)
            + 2 * t * n * difference * lift
            + 2 * remainder * n * (t - 1) * lift
            + tensor_rounding
        )
        + switch
    )

    # Each automorphism changes coefficient signs and performs one key switch;
    # the following add introduces at most one further plaintext carry.
    tile = squared
    for _ in range(width.bit_length() - 1):
        tile = 2 * tile + switch + 2 * remainder
    tile = n * (t - 1) * tile + remainder * message_carry
    # A merge of K tiles has K-1 rotate/add nodes, regardless of partial-tree shape.
    merged = tiles * tile + (tiles - 1) * (switch + 2 * remainder)
    compacted = _ceil(Fraction(target * merged, q) + (t - 1) + Fraction(n + 1, 2))
    return BFVHammingNoiseBound(
        encrypted,
        difference,
        squared,
        switch,
        tile,
        merged,
        compacted,
        t * merged + remainder * (t - 1),
        t * compacted + (target % t) * (t - 1),
        q,
        target,
    )
