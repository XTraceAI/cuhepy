"""E63 exact support certificates for coefficient deletion before score decode.

Cipher decryption is componentwise C0 + C1*S before centered-Q reduction.
Keep ALL C1 and each C0 coordinate whose field phase contributes to any
returned score. Dropping other C0 coordinates preserves a public linear
decoder; aggregating/reducing C0 in F_t does not commute with centered-Q
decryption. This is an owner-local algebra/cost oracle, not an authenticated
split-CRT projection implementation or a general compression lower bound.
Sample extraction, decoder support and linear fingerprints are prior ideas.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import score_layout


@dataclass(frozen=True)
class Certificate:
    n: int
    kept_c0: tuple[tuple[int, ...], ...]

    @property
    def full_coefficient_count(self):
        return 2 * self.n * len(self.kept_c0)

    @property
    def projected_coefficient_count(self):
        return self.n * len(self.kept_c0) + sum(map(len, self.kept_c0))

    def body_bytes_model(self, q_bits):
        if type(q_bits) is not int or not 32 <= q_bits <= 56:
            raise ValueError("Bounded full-Q coefficient width required")
        return (q_bits * self.projected_coefficient_count + 7) // 8


def certify(layout):
    tree.validate_layout(layout)
    n, replies = layout.context.n, layout.cost.response_ciphertexts
    if n * replies > 1 << 20:
        raise ValueError("Decoder support exceeds bounded coefficient oracle")
    kept = [set() for _ in range(replies)]
    for leaf, count in zip(layout.context.leaves, layout.counts, strict=True):
        capacity = leaf.degree // layout.padded
        for row in range(count):
            reply, within = divmod(row, leaf.degree)
            tile, lane = divmod(within, capacity)
            local = lane * layout.padded + tile
            # Repeated public CRT reductions P(low)+gamma*P(high) have
            # nonzero factors at every ancestor; inverse padding is nonzero.
            kept[reply].update(range(local, n, leaf.degree))
    return Certificate(n, tuple(tuple(sorted(indices)) for indices in kept))


def matrix_oracle(layout):
    """Independent basis-column oracle; linearity makes this complete for layout."""
    tree.validate_layout(layout)
    n, replies = layout.context.n, layout.cost.response_ciphertexts
    if n > 64 or n * replies > 1024 or sum(layout.counts) > 128:
        raise ValueError("Exhaustive decoder matrix oracle is tiny only")
    supports = []
    for reply in range(replies):
        kept = []
        for coordinate in range(n):
            phase = [[0] * n for _ in range(replies)]
            phase[reply][coordinate] = 1
            decoded = tree.unpack(layout, phase)
            if any(value for row in decoded for value in row):
                kept.append(coordinate)
        supports.append(tuple(kept))
    return Certificate(n, tuple(supports))


def equal_old_cost_counterexample():
    ctx = tree.context(32, ("0", "1"), 17)
    balanced = space.space(score_layout.layout(ctx, (4, 4), (8, 8)), (0, 1))
    skewed = space.space(score_layout.layout(ctx, (4, 4), (12, 4)), (0, 1))
    old_a, old_b = space.cost(balanced, q_bits=32), space.cost(skewed, q_bits=32)
    assert old_a == old_b  # Same h/F/W/R/full bodies/bounds/check counts.
    a, b = certify(balanced.layout), certify(skewed.layout)
    assert a == matrix_oracle(balanced.layout) and b == matrix_oracle(skewed.layout)
    assert a.projected_coefficient_count == 48 and b.projected_coefficient_count == 56
    return {"old_resource_vector": old_a, "balanced_counts": (8, 8), "skewed_counts": (12, 4),
            "balanced_kept_c0": a.kept_c0, "skewed_kept_c0": b.kept_c0,
            "balanced_projected_body_bytes_model": a.body_bytes_model(32),
            "skewed_projected_body_bytes_model": b.body_bytes_model(32),
            "full_body_bytes_model": 256}
