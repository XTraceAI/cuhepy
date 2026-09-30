"""E32: integer-rounded CBD tail budget for a fixed symmetric linear circuit.

Fresh symmetric phase is m+t*e, e~CBD(eta) independently in every coefficient.
For corrections fixed before enrollment, each output error has variance proxy
t^2*eta/2*(1+sum ||alpha_j||_2^2). Message/carry coefficients are bounded
separately by floor(t/2)*(1+sum ||alpha_j||_1).

The finite-epoch union bound is a correctness hypothesis, NOT lattice security
bits, a deterministic phase bound, or an adaptive-query protocol guarantee.
It does not apply to public-key encryption, ciphertext products, rounded
responses, correlated errors, or corrections chosen using encryption errors.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from math import comb, isqrt

from experiments.bfv_search_lab import crt_query_space as crt


def ceil_root_ratio(numerator: int, denominator: int) -> int:
    if type(numerator) is not int or numerator < 0 or type(denominator) is not int or denominator < 1:
        raise ValueError("Expected a nonnegative exact ratio")
    root = isqrt(numerator // denominator)
    return root + int(root * root * denominator < numerator)


@dataclass(frozen=True)
class Profile:
    space: crt.Space
    eta: int = 21
    correctness_bits: int = 128
    query_budget: int = 1024
    assumption: str = "corrections-fixed-before-enrollment-v1"

    @property
    def binding(self) -> bytes:
        body = {"space": self.space.binding.hex(), "eta": self.eta,
                "correctness_bits": self.correctness_bits, "query_budget": self.query_budget,
                "assumption": self.assumption}
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).digest()


def validate(profile: Profile) -> None:
    crt.validate(profile.space)
    if (type(profile.eta) is not int or not 1 <= profile.eta <= 64
            or type(profile.correctness_bits) is not int or not 32 <= profile.correctness_bits <= 256
            or type(profile.query_budget) is not int or not 1 <= profile.query_budget <= 65536
            or profile.assumption != "corrections-fixed-before-enrollment-v1"):
        raise ValueError("Invalid bounded fixed-correction noise profile")


@dataclass(frozen=True)
class Certificate:
    profile_binding: bytes
    message_bound: int
    squared_weight_norm: int
    tail_bound: int

    @property
    def total(self) -> int:
        return self.message_bound + self.tail_bound


def certificate(profile: Profile, short: tuple[tuple[int, ...], ...] | None = None) -> Certificate:
    """Upward-rounded union bound; short=None certifies every bounded correction.

    ln(2*N*R*B/epsilon) < 0.7*(bit_length(2*N*R*B)+correctness_bits).
    The integer square-root inequality avoids floating-point underestimation.
    Cross-query/coefficient independence is NOT needed by a union bound; each
    individual correction must be independent of the reused enrollment errors.
    """
    validate(profile)
    s = profile.space
    b = s.layout.context.prime // 2
    if short is None:
        norm = b * sum(s.column_degrees)
        squared = b * b * sum(s.column_degrees)
    else:
        if (type(short) is not tuple or len(short) != s.columns
                or any(type(row) is not tuple or len(row) != degree
                       or any(type(x) is not int or not -b <= x <= b for x in row)
                       for row, degree in zip(short, s.column_degrees, strict=True))):
            raise ValueError("Invalid centered correction coefficients")
        norm = sum(abs(x) for row in short for x in row)
        squared = sum(x * x for row in short for x in row)
    n, t = s.layout.context.n, s.layout.context.prime
    replies = max(1, s.layout.cost.response_ciphertexts)
    exponent = (2 * n * replies * profile.query_budget).bit_length() + profile.correctness_bits
    tail = ceil_root_ratio(t * t * profile.eta * (1 + squared) * 7 * exponent, 10)
    return Certificate(profile.binding, b * (1 + norm), squared, tail)


def cbd_counts(eta: int) -> tuple[tuple[int, int], ...]:
    """Exact finite CBD distribution; denominator is 2**(2*eta)."""
    if type(eta) is not int or not 1 <= eta <= 64:
        raise ValueError("Invalid CBD width")
    return tuple((e, comb(2 * eta, eta + e)) for e in range(-eta, eta + 1))


def weighted_counts(weights: tuple[int, ...], eta: int) -> dict[int, int]:
    """Tiny exact integer-distribution oracle, never used by encryption."""
    errors = cbd_counts(eta)
    if (type(weights) is not tuple or not 1 <= len(weights) <= 16
            or any(type(x) is not int for x in weights) or sum(map(abs, weights)) * eta > 4096):
        raise ValueError("Exact distribution exceeds the small-oracle bound")
    result = {0: 1}
    for weight in weights:
        updated: dict[int, int] = {}
        for value, count in result.items():
            for error, mass in errors:
                target = value + weight * error
                updated[target] = updated.get(target, 0) + count * mass
        result = updated
    return result


def describe(profile: Profile) -> dict:
    result = asdict(certificate(profile))
    result.update(total=certificate(profile).total, assumption=profile.assumption,
                  correctness_bits=profile.correctness_bits, query_budget=profile.query_budget,
                  profile_binding=profile.binding.hex())
    return result
