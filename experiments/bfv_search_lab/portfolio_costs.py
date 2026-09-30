"""E39 contract-filtered, serial recorded-stage/body planning models.

This planner consumes measured candidates; it does not certify parameters,
privacy, private timing, a deployed wire protocol, RAM usage or network latency.
Pool setup/unused tokens are charged in full. Extrapolation past the measured
pool is refused. A candidate cannot silently change the client's disclosure,
preprocessing trust or plaintext-retention contract just because it is faster.
"""

from __future__ import annotations

from dataclasses import dataclass
import math


@dataclass(frozen=True)
class Candidate:
    name: str
    local_s: float
    query_bytes: int
    response_bytes: int
    index_bytes: int
    setup_s: float
    pool_s: float
    pool_bytes: int
    prepared_tokens: int
    canonical_client_body_bytes: int
    owner_coordinate_body_bytes: int
    output: str = "all_distances"
    trusted_owner_preprocessing: bool = True
    requires_plaintext_coordinates: bool = True
    reviewed_protocol: bool = False
    reviewed_parameters: bool = False
    private_timing_assured: bool = False

    def validate(self) -> None:
        if (not self.name or self.output not in ("all_distances", "only_top_k")
                or any(not math.isfinite(x) or x < 0 for x in (self.local_s, self.setup_s, self.pool_s))
                or any(type(x) is not int or x < 0 for x in (
                    self.query_bytes, self.response_bytes, self.index_bytes, self.pool_bytes,
                    self.canonical_client_body_bytes, self.owner_coordinate_body_bytes))
                or type(self.prepared_tokens) is not int or not 1 <= self.prepared_tokens <= 65536):
            raise ValueError("Invalid bounded measured candidate")


@dataclass(frozen=True)
class Contract:
    disclosure: str = "all_distances"
    trusted_owner_preprocessing: bool = True
    owner_coordinate_retention: bool = True
    canonical_client_body_limit: int = 1 << 30
    owner_coordinate_body_limit: int = 1 << 30
    allow_unreviewed_research: bool = False

    def validate(self) -> None:
        if (self.disclosure not in ("all_distances", "only_top_k")
                or any(type(x) is not int or x < 0 for x in (
                    self.canonical_client_body_limit, self.owner_coordinate_body_limit))):
            raise ValueError("Invalid planning contract")


def rejection(candidate: Candidate, contract: Contract) -> tuple[str, ...]:
    candidate.validate()
    contract.validate()
    reasons = []
    if candidate.output != contract.disclosure:
        reasons.append("different output/disclosure")
    if candidate.trusted_owner_preprocessing and not contract.trusted_owner_preprocessing:
        reasons.append("trusted owner preprocessing unavailable")
    if candidate.requires_plaintext_coordinates and not contract.owner_coordinate_retention:
        reasons.append("plaintext coordinates forbidden")
    if candidate.canonical_client_body_bytes > contract.canonical_client_body_limit:
        reasons.append("canonical private client body exceeds budget")
    if candidate.owner_coordinate_body_bytes > contract.owner_coordinate_body_limit:
        reasons.append("owner coordinate body exceeds budget")
    if not contract.allow_unreviewed_research and not (
            candidate.reviewed_protocol and candidate.reviewed_parameters and candidate.private_timing_assured):
        reasons.append("research assurances incomplete")
    return tuple(reasons)


def cost(candidate: Candidate, *, completed: int, upload_mbps: float, download_mbps: float,
         rtt_ms: float = 40) -> dict[str, float | int]:
    candidate.validate()
    if (type(completed) is not int or not 1 <= completed <= candidate.prepared_tokens
            or any(not math.isfinite(x) or x <= 0 for x in (upload_mbps, download_mbps))
            or not math.isfinite(rtt_ms) or rtt_ms < 0):
        raise ValueError("Expected a finite link model within the actually prepared pool")
    network_s = 8 * candidate.query_bytes / (upload_mbps * 1e6) + 8 * candidate.response_bytes / (download_mbps * 1e6)
    offline_upload_bytes = candidate.index_bytes + candidate.pool_bytes
    preparation_s = (candidate.setup_s + candidate.pool_s + 8 * offline_upload_bytes / (upload_mbps * 1e6)) / completed
    return {"online_serial_s_model": candidate.local_s + network_s + rtt_ms / 1000,
            "amortized_serial_s_model": candidate.local_s + network_s + rtt_ms / 1000 + preparation_s,
            "offline_cost_per_completed_s_model": preparation_s,
            "body_bytes_per_completed_including_unused": offline_upload_bytes / completed + candidate.query_bytes + candidate.response_bytes,
            "prepared_tokens": candidate.prepared_tokens, "completed": completed,
            "unused_tokens": candidate.prepared_tokens - completed}


def choose(candidates: tuple[Candidate, ...], contract: Contract, *, objective: str = "amortized_serial_s_model",
           completed: int, upload_mbps: float, download_mbps: float, rtt_ms: float = 40) -> tuple[Candidate, dict[str, float | int]]:
    if objective not in ("amortized_serial_s_model", "online_serial_s_model"):
        raise ValueError("Unknown recorded-stage objective")
    eligible = tuple(c for c in candidates if not rejection(c, contract))
    if not eligible:
        raise ValueError("No measured candidate satisfies the stated contract")
    ranked = [(c, cost(c, completed=completed, upload_mbps=upload_mbps, download_mbps=download_mbps, rtt_ms=rtt_ms))
              for c in eligible]
    return min(ranked, key=lambda pair: (pair[1][objective], pair[0].name))


def pareto(candidates: tuple[Candidate, ...]) -> tuple[str, ...]:
    """Recorded median time/body frontier, not statistical dominance confidence."""
    def vector(c: Candidate) -> tuple[float, int, int, int, float, int]:
        c.validate()
        return (c.local_s, c.response_bytes + c.query_bytes, c.index_bytes,
                c.canonical_client_body_bytes, c.setup_s + c.pool_s, c.pool_bytes)
    coordinates = tuple(map(vector, candidates))
    return tuple(c.name for i, c in enumerate(candidates) if not any(
        all(a <= b for a, b in zip(other, coordinates[i], strict=True))
        and any(a < b for a, b in zip(other, coordinates[i], strict=True))
        for j, other in enumerate(coordinates) if i != j))
