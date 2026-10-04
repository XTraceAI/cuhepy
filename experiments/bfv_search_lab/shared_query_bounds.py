"""Q74 exact public envelopes for shared-query feature-major BGV.

Expansion, lazy relinearization and bounded gadget preimages are known controls.
This module screens their complete composed graph. No secret, sampled noise,
large key generation, timing estimate or cryptographic parameter approval occurs.
The one changed policy derives only the final expansion level from the preceding
canonical anchor; both its signed branches and all radix cross terms are paid.
"""

from __future__ import annotations

from dataclasses import dataclass

POLICIES = ("canonical30", "derived_last30")
INDEX_MODES = ("owner", "public_key")


@dataclass(frozen=True)
class Profile:
    n: int
    dimension: int
    q: int
    p: int
    t: int
    eta: int
    index_mode: str
    policy: str

    def __post_init__(self):
        if (
            any(
                type(x) is not int
                for x in (self.n, self.dimension, self.q, self.p, self.t, self.eta)
            )
            or not 8 <= self.n <= 32768
            or self.n & (self.n - 1)
            or not 3 <= self.dimension <= min(self.n // 2, 512)
            or not 32 <= self.q.bit_length() <= 240
            or not 2 * self.padded < self.t < self.p < self.q
            or self.t % 2 != 1
            or self.p % 2 != 1
            or (self.p - self.q) % self.t
            or not 1 <= self.eta <= 64
            or self.index_mode not in INDEX_MODES
            or self.policy not in POLICIES
        ):
            raise ValueError("Invalid enrolled shared-query profile")

    @property
    def padded(self):
        return 1 << (self.dimension - 1).bit_length()

    @property
    def levels(self):
        return self.padded.bit_length() - 1

    @property
    def ell(self):
        return (self.q.bit_length() + 29) // 30

    @property
    def digit_bound(self):
        return (1 << 30) - 1

    @property
    def query_bound(self):
        return self.t // 2 + self.t * self.eta

    @property
    def index_bound(self):
        return self.t // 2 + self.t * self.eta * (
            1 if self.index_mode == "owner" else 2 * self.n + 1
        )

    @property
    def scale(self):
        return self.t * self.eta * self.n * self.ell

    @property
    def canonical_error(self):
        return self.scale * self.digit_bound

    @property
    def retained_state_bound(self):
        # E^+_j = sigma^-1(d_j) + sum_a d_a * digit_j(K_A[a]);
        # E^- has the same norm, with a minus and a signed monomial shift.
        b = self.digit_bound
        return b + self.n * self.ell * b * b

    def level_rows(self):
        phase, rows = self.query_bound, []
        for level in range(self.levels):
            derived = self.policy == "derived_last30" and level == self.levels - 1
            source = self.retained_state_bound if derived else self.digit_bound
            error = self.scale * source
            phase = 2 * phase + error
            rows.append(
                {
                    "level": level,
                    "nodes": 1 << level,
                    "mode": "derived" if derived else "canonical",
                    "source_digit_absolute_bound": source,
                    "switch_error_bound": error,
                    "output_phase_bound": phase,
                    "retain_child_state": self.policy == "derived_last30"
                    and level == self.levels - 2,
                }
            )
        return tuple(rows)

    def envelope(self):
        rows = self.level_rows()
        expanded = rows[-1]["output_phase_bound"]
        before_relin = self.n * self.dimension * self.index_bound * expanded
        output = before_relin + self.canonical_error
        terminal = (self.p * output + self.q - 1) // self.q + ((self.n + 1) * self.t + 1) // 2
        all_stages_q = all(2 * r["output_phase_bound"] < self.q for r in rows)
        q_safe = all_stages_q and 2 * output < self.q
        p_safe = 2 * terminal < self.p
        return {
            "query_phase_bound": self.query_bound,
            "index_phase_bound": self.index_bound,
            "level_rows": rows,
            "expanded_phase_bound": expanded,
            "pre_relinearization_phase_bound": before_relin,
            "output_phase_bound": output,
            "output_phase_bound_bits": output.bit_length(),
            "terminal_phase_bound": terminal,
            "all_expansion_stages_Q_safe": all_stages_q,
            "complete_Q_guard": q_safe,
            "complete_P_guard": p_safe,
            "admitted": q_safe and p_safe,
            "noise_is_public_deterministic_box_not_private_diagnostic": True,
        }

    def require_safe(self):
        if not self.envelope()["admitted"]:
            raise ValueError("Unsafe full original-query/contraction/terminal envelope")

    def inventory(self, count, primes):
        if (
            type(count) is not int
            or not 1 <= count <= 64 * self.n
            or type(primes) is not int
            or not 1 <= primes <= 4
        ):
            raise ValueError("Invalid source inventory")
        groups = (count + self.n - 1) // self.n
        switches = self.padded - 1
        derived = self.padded // 2 if self.policy == "derived_last30" else 0
        cuts = switches - derived
        qpoly = (self.n * self.q.bit_length() + 7) // 8
        old_tiles = old_rotations = 0
        for start in range(0, count, self.n):
            occupied = min(self.n, count - start)
            m = (occupied + self.n // self.padded - 1) // (self.n // self.padded)
            old_tiles += m
            old_rotations += sum(min(1 << k, m) for k in range(self.levels))
        state_anchors = self.padded // 4 if derived else 0
        return {
            "records": count,
            "groups": groups,
            "index_ciphertexts": self.dimension * groups,
            "query_ciphertexts": 1,
            "query_expansion_switches": switches,
            "canonical_expansion_source_polynomials": cuts,
            "derived_expansion_nodes": derived,
            "retained_integer_state_anchor_nodes": state_anchors,
            "ciphertext_products": self.dimension * groups,
            "delayed_relinearizations": groups,
            "source_polynomials": cuts + groups,
            "terminal_Q_polynomials": 2 * groups,
            "source_and_terminal_Q_body_bytes": (cuts + 3 * groups) * qpoly,
            "seeded_query_coefficient_and_seed_body_bytes": qpoly + 32,
            "index_coefficient_and_seed_body_bytes": self.dimension
            * groups
            * (qpoly + 32 if self.index_mode == "owner" else 2 * qpoly),
            "evaluation_key_Q_coefficient_body_bytes": (self.levels + 1) * 2 * self.ell * qpoly,
            "additional_shared_key_A_canonical_digit_body_bytes": self.ell**2 * self.n * 30 // 8
            if derived
            else 0,
            "all_expanded_query_RNS_component_body_bytes": 2 * self.padded * self.n * primes * 8,
            "complete_compact_coefficient_body_bytes": 2
            * groups
            * ((self.n * self.p.bit_length() + 7) // 8),
            "old_coefficient_input_ciphertexts": old_tiles,
            "old_coefficient_input_rotations": old_rotations,
            "old_canonical_source_and_terminal_Q_body_bytes": (
                old_tiles + old_rotations + 2 * groups
            )
            * qpoly,
            "scope": "Exact graph/packed-body inventory, including partial geometry. No headers, native liveness, latency, full preparation/update, attestation or parameter approval. Integer-state arithmetic remains additional.",
        }
