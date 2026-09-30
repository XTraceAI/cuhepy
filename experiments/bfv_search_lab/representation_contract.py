"""E41: bounded immutable inputs and count models for exact representations.

This is an owner-side research compiler contract, not a network protocol or
parameter allowlist. Profiles remain research-only; correctness and a formal
fingerprint target do not certify HE privacy or private timing. Body models
exclude object/RSS overhead, framing, HE keys and service scheduling.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

import gmpy2

from experiments.bfv_search_lab import field_frontier as fields


@dataclass(frozen=True)
class Workload:
    rows: tuple[int, ...]
    ids: tuple[int, ...]
    dimension: int

    def validate(self) -> None:
        if (type(self.dimension) is not int or not 1 <= self.dimension <= 512
                or type(self.rows) is not tuple or not 1 <= len(self.rows) <= 32768
                or type(self.ids) is not tuple or len(self.ids) != len(self.rows)
                or any(type(x) is not int or not 0 <= x < 1 << self.dimension for x in self.rows)
                or any(type(i) is not int or not 0 <= i < 1 << 64 for i in self.ids)
                or len(set(self.ids)) != len(self.ids)):
            raise ValueError("Invalid binary workload or unique stable identifiers")

    @property
    def digest(self) -> str:
        self.validate()
        h = hashlib.sha256(b"cuhepy/research/exact-representation/input/v1\0")
        h.update(self.dimension.to_bytes(2, "little"))
        h.update(len(self.rows).to_bytes(4, "little"))
        width = (self.dimension + 7) // 8
        for row, identifier in zip(self.rows, self.ids, strict=True):
            h.update(row.to_bytes(width, "little"))
            h.update(identifier.to_bytes(8, "little"))
        return h.hexdigest()

    def expected(self, query: int) -> tuple[int, ...]:
        self.validate()
        if type(query) is not int or not 0 <= query < 1 << self.dimension:
            raise ValueError("Query outside the binary dimension")
        return tuple((row ^ query).bit_count() for row in self.rows)

    def top_k(self, scores: tuple[int, ...], k: int = 3) -> tuple[tuple[int, int], ...]:
        self.validate()
        if (type(scores) is not tuple or len(scores) != len(self.rows)
                or any(type(x) is not int or not 0 <= x <= self.dimension for x in scores)
                or type(k) is not int or not 1 <= k <= len(self.rows) + 3):
            raise ValueError("Invalid exact score array or selection count")
        return tuple(sorted(zip(scores, self.ids, strict=True))[:k])


@dataclass(frozen=True)
class Profile:
    n: int
    prime: int
    q_bits: int = 32
    eta: int = 21
    check_bits: int = 128
    attempt_budget: int = 1024

    def validate(self, dimension: int) -> None:
        if (type(self.n) is not int or not 8 <= self.n <= 32768 or self.n & (self.n - 1)
                or type(self.prime) is not int or not dimension < self.prime <= 65537
                or not self.prime % 2 or not gmpy2.is_prime(self.prime)
                or type(self.q_bits) is not int or not 32 <= self.q_bits <= 56
                or type(self.eta) is not int or not 1 <= self.eta <= 64
                or type(self.check_bits) is not int or not 32 <= self.check_bits <= 256
                or type(self.attempt_budget) is not int or not 1 <= self.attempt_budget <= 65536):
            raise ValueError("Invalid research-only representation profile")

    @property
    def q(self) -> int:
        return fields.modulus(self.n, self.q_bits)

    @property
    def assurance(self) -> str:
        return "research_only"

    def require_production(self) -> None:
        raise ValueError("Representation profile has no production assurance")


@dataclass(frozen=True)
class Resources:
    query_coordinates: int
    columns: int
    correction_coefficients: int
    replies: int
    query_body_bytes: int
    response_body_bytes: int
    expanded_index_body_bytes: int
    native_index_word_bytes: int
    private_map_body_bytes: int
    id_permutation_body_bytes: int
    checker_body_bytes_model: int
    client_audit_body_bytes_model: int
    offline_answer_body_bytes_per_token_model: int
    owner_coordinate_body_bytes_model: int
    phase_bound: int
    checker_rounds: int
    verifier_products_model: int
    server_pointwise_products_model: int

    @property
    def online_body_bytes(self) -> int:
        return self.query_body_bytes + self.response_body_bytes

    @property
    def static_vector(self) -> tuple[int, ...]:
        """Complete-plan static dominance axes, excluding future update costs."""
        return (self.online_body_bytes, self.expanded_index_body_bytes,
                self.client_audit_body_bytes_model, self.native_index_word_bytes,
                self.verifier_products_model, self.server_pointwise_products_model,
                self.offline_answer_body_bytes_per_token_model,
                self.owner_coordinate_body_bytes_model)


@dataclass(frozen=True)
class Budget:
    client_audit_body_bytes: int | None = None
    expanded_index_body_bytes: int | None = None
    max_replies: int | None = None

    def rejection(self, resources: Resources) -> tuple[str, ...]:
        limits = (self.client_audit_body_bytes, self.expanded_index_body_bytes, self.max_replies)
        if any(x is not None and (type(x) is not int or x < 0) for x in limits):
            raise ValueError("Invalid explicitly supplied count-model budget")
        reasons = []
        for label, value, limit in zip(
            ("client audit body", "expanded index body", "replies"),
            (resources.client_audit_body_bytes_model, resources.expanded_index_body_bytes, resources.replies),
            limits, strict=True,
        ):
            if limit is not None and value > limit:
                reasons.append(f"{label} exceeds budget")
        return tuple(reasons)
