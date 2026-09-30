"""E62 restricted coefficient omission, with a dedicated verification/decoder.

For ONE full-ring, score-only CRT leaf, row scores use C0[0:active] while every
C1 coefficient can affect them through the full ternary secret. Drop only
unused C0 entries; verify all supplied C0 and ALL C1 before SK use. Never pass
the zero-padded internal check object to ordinary BGV decryption: its omitted
phases have no full-ciphertext bound. Multi-leaf/plaintext-field projections
are rejected. This changes the checked relation in a separate research-only
profile; it does not weaken any existing client/gate or provide new HE.
Known coefficient selection/fingerprints are not a novelty claim. Private
timing, authenticated setup, seeded privacy and parameter review remain open.
"""

from __future__ import annotations

from dataclasses import dataclass

import gmpy2
from gmpy2 import mpz

from cuhepy.bfv.scheme import _ring_product
from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import crt_linear_check as checks
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import score_layout
from experiments.bfv_search_lab import shallow_bgv as bgv


def active_counts(space):
    crt.validate(space)
    layout, n = space.layout, space.layout.context.n
    if (not isinstance(layout, score_layout.Layout) or len(layout.context.leaves) != 1
            or layout.context.leaves[0].path != "" or layout.context.leaves[0].degree != n
            or layout.padded != 1 or any(degree != 1 for degree in space.column_degrees)
            or not layout.counts[0]):
        raise ValueError("Projection requires one complete full-ring score-only leaf")
    return tuple(min(n, layout.counts[0] - j * n) for j in range(layout.cost.response_ciphertexts))


@dataclass(frozen=True)
class Reply:
    c0_active: tuple[tuple[mpz, ...], ...]
    c1: tuple[tuple[mpz, ...], ...]
    key_id: str
    phase_bounds: tuple[int, ...]

    def validate(self, space, pk):
        counts = active_counts(space)
        if (type(self.c0_active) is not tuple or type(self.c1) is not tuple or type(self.phase_bounds) is not tuple
                or self.key_id != pk.key_id or len(self.c0_active) != len(counts) or len(self.c1) != len(counts)
                or len(self.phase_bounds) != len(counts) or (pk.n, pk.t) != (space.layout.context.n, space.layout.context.prime)
                or any(type(p) is not tuple or len(p) != count for p, count in zip(self.c0_active, counts, strict=True))
                or any(type(p) is not tuple or len(p) != pk.n for p in self.c1)
                or any(type(b) is not int or not 0 <= b < pk.q // 2 for b in self.phase_bounds)
                or any(not isinstance(x, (int, mpz)) or isinstance(x, bool) or not 0 <= x < pk.q
                       for p in (*self.c0_active, *self.c1) for x in p)):
            raise ValueError("Invalid pinned projected response")

    def _check_ciphertexts(self, space, pk):
        """Internal fingerprint carrier ONLY; not an ordinary decryptable cipher."""
        self.validate(space, pk)
        return tuple(bgv.Ciphertext((c0 + (mpz(0),) * (pk.n - len(c0)), c1), self.key_id, bound)
                     for c0, c1, bound in zip(self.c0_active, self.c1, self.phase_bounds, strict=True))

    @property
    def coefficients(self):
        return tuple(x for c0, c1 in zip(self.c0_active, self.c1, strict=True) for p in (c0, c1) for x in p)


def project(output, space, pk):
    counts = active_counts(space)
    masked.validate_ciphertexts(output, len(counts), pk)
    reply = Reply(tuple(c.components[0][:count] for c, count in zip(output, counts, strict=True)),
                  tuple(c.components[1] for c in output), pk.key_id, tuple(c.phase_bound for c in output))
    reply.validate(space, pk)
    return reply


def parse(body, space, pk, phase_bounds):
    """Count/order/field pinned by owner; bounds are checked against the relation."""
    counts = active_counts(space)
    values = codec.unpack(body, sum(counts) + len(counts) * pk.n, int(pk.q))
    c0, c1, cursor = [], [], 0
    for count in counts:
        c0.append(values[cursor:cursor + count])
        cursor += count
        c1.append(values[cursor:cursor + pk.n])
        cursor += pk.n
    reply = Reply(tuple(c0), tuple(c1), pk.key_id, phase_bounds)
    reply.validate(space, pk)
    return reply


class ProjectedCheck(checks.EpochCheck):
    """Known ideal-vector family over exactly active C0 plus full C1 coordinates.

    This Python/GMP oracle is deliberately separate from NativeVectorCheck's
    fixed full-vector hash. The inherited adjoint preparation uses these same
    weights. We make no native speed claim; unused C0 weights are exactly zero.
    """

    def __init__(self, index, pk, *, rounds=4, budget=1024):
        active_counts(index.space)
        super().__init__(index, pk, rounds=rounds, budget=budget)

    def _challenges(self):
        counts = active_counts(self.space)
        for challenge in super()._challenges():
            yield tuple((c0[:count] + (mpz(0),) * (self.pk.n - count), c1)
                        for (c0, c1), count in zip(challenge, counts, strict=True))


def _selected_phase(reply, pk, sk):
    """Only verified supplied coordinates have an honest phase/range bound."""
    if sk.key_id != pk.key_id or len(sk.s) != pk.n:
        raise ValueError("Wrong HE secret for projected response")
    result = []
    for c0, c1, bound in zip(reply.c0_active, reply.c1, reply.phase_bounds, strict=True):
        product = _ring_product(c1, sk.s, pk.q)
        coefficients = []
        for value, offset in zip(c0, product, strict=False):
            reduced = (value + offset) % pk.q
            phase = reduced if reduced <= pk.q // 2 else reduced - pk.q
            if abs(phase) > bound:
                raise AssertionError("Approved projected coordinate exceeded its honest phase bound")
            coefficients.append(int(phase % pk.t))
        result.append(tuple(coefficients))
    return tuple(result)


def open_once(checker, request, reply, pk, sk):
    """Pinned trusted checker/request; false or malformed candidates use no SK.

    Bounds/epoch/context/token gates and global accounting belong to the
    supplied checker. Return only active field products after exact relation
    acceptance. Caller adds its approved private map/anchor score offsets.
    """
    try:
        if not isinstance(reply, Reply):
            raise ValueError("Projected reply object required")
        internal = reply._check_ciphertexts(request.space, pk)
    except (ValueError, TypeError):
        # Still burn the token/attempt using a canonical-gate failure. A global
        # AttemptBudget wrapper, when supplied, burns before this checker call.
        checker.verify_once(request, ())
        return None
    if not checker.verify_once(request, internal):
        return None
    return _selected_phase(reply, pk, sk)


def open_body_once(checker, request, body, pk, sk, phase_bounds):
    try:
        reply = parse(body, request.space, pk, phase_bounds)
    except (ValueError, TypeError):
        checker.verify_once(request, ())
        return None
    return open_once(checker, request, reply, pk, sk)


def plaintext_field_projection_counterexample():
    """Even C0%t at EVERY coordinate does not preserve centered-Q decryption."""
    q, t, c0, product = 257, 17, 15, 5
    altered = c0 + 7 * t
    def decode(value):
        phase = (value + product) % q
        centered = phase if phase <= q // 2 else phase - q
        return centered % t
    assert c0 % t == altered % t and decode(c0) != decode(altered)
    return {"q": q, "t": t, "original_c0": c0, "altered_c0": altered,
            "fixed_c1_secret_product": product, "identical_c0_mod_t": c0 % t,
            "original_decoded": decode(c0), "altered_decoded": decode(altered)}


def c1_dependency_witness(n, omitted, target):
    """Every C1 coordinate can affect ANY kept coefficient for a legal ternary s.

    Structural coefficient-deletion counterexample, not a claim against
    public trusted C1 reconstruction (E48) or a key-distribution proof.
    """
    if (type(n) is not int or not 8 <= n <= 32 or n & (n - 1)
            or type(omitted) is not int or type(target) is not int or not 0 <= omitted < n or not 0 <= target < n):
        raise ValueError("Bounded coefficient-dependency witness required")
    q, secret_at = mpz(65537), (target - omitted) % n
    changed = tuple(mpz(int(i == omitted)) for i in range(n))
    secret = tuple(mpz(int(i == secret_at)) for i in range(n))
    value = _ring_product(changed, secret, q)[target]
    assert value in (1, q - 1) and gmpy2.is_prime(q)
    return int(value)
