"""E40 fixed-map ring/capacity body models, not new encryption profiles.

Reuse a certified private grouping but allocate final CRT occupancy afresh for
each N. More/smaller replies can cancel a smaller ring. No security estimate,
key generation, ciphertext decryption or runtime parameter gate is changed.
"""

from __future__ import annotations

from dataclasses import replace

from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import field_frontier as fields
from experiments.bfv_search_lab import rank_partition as partition


def public(candidate: partition.Candidate) -> space.Space:
    maps = tuple(dict.fromkeys(block.mapping for block in candidate.blocks))
    return space.space(candidate.layout, tuple(maps.index(block.mapping) for block in candidate.blocks))


def describe(groups: fields.Groups, rows: list[int], *, n: int, slots: int, q_bits: int = 32) -> dict:
    fields.validate(groups, rows)
    if type(q_bits) is not int or not 32 <= q_bits <= 56:
        raise ValueError("Expected a bounded word-modulus body model")
    candidate = fields.allocate(replace(groups, n=n), rows, slots)
    s = public(candidate)
    q = fields.modulus(n, q_bits)
    rounds = fields.rounds(q)
    model = space.cost(s, q_bits=q_bits, rounds=rounds)
    if 2 * model["worst_case_phase_bound"] >= q:
        raise ValueError("Modeled honest-circuit phase does not fit Q")
    capacity = n * model["replies"]
    assert capacity >= len(rows)
    return {"n": n, "t": groups.prime, "q": str(q), "q_bits": q_bits, "slots": slots,
            "F": s.columns, "h": s.dimension, "W": sum(s.column_degrees), "replies": model["replies"],
            "allocated_reply_coefficients": capacity, "occupied_score_count": len(rows),
            "reply_capacity_slack_fraction": 1 - len(rows) / capacity,
            "query_body_bytes_model": model["online_query_body_bytes"],
            "response_body_bytes_model": model["online_response_body_bytes"],
            "encrypted_index_body_bytes_model": model["expanded_index_body_bytes"],
            "offline_seeded_answer_body_bytes_model": model["offline_seeded_answer_body_bytes_per_token"],
            "native_ntt_index_word_bytes_model": model["native_ntt_index_word_bytes"],
            "checker_full_response_coefficients_model": 2 * capacity,
            "honest_phase_bound_model": model["worst_case_phase_bound"],
            "requires_new_parameter_assurance": n != groups.n,
            "scope": "Certified plaintext layout/body/phase MODEL. Fixed private maps; no HE timing, new key profile or security claim."}
