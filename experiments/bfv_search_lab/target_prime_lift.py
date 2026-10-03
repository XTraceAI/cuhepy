"""E107 bounded exact scalar terminal relations and matched known controls.

These integer predicates do not implement a commitment, range proof, remote
verification protocol or authenticated release. They use no native HE helper.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from math import gcd

import gmpy2

TINY_CONTEXTS = ((3, 7, 11, 5), (5, 7, 11, 3), (5, 7, 17, 3), (5, 11, 7, 3))
NATIVE_SCALAR_PROFILE = (1152921504606846577, 1152921504606846097, 4294966477, 17)
RICH_GATES = frozenset(("source_range", "output_range", "remainder_range", "wrap_range",
                        "limb0", "limb1", "target", "modt"))
REDUCED_GATES = RICH_GATES - {"wrap_range", "modt"}


@lru_cache(maxsize=128)
def _prime64(n):
    """Repository-style probable-prime gate; field claims assume primality.

    No primality certificate, HE parameter or OS-entropy assurance is supplied.
    The exact scalar equalities themselves use only coprimality and oddness.
    """
    return (type(n) is int and 3 <= n < 1 << 64 and n % 2 == 1
            and bool(gmpy2.is_prime(n, 32)))


@dataclass(frozen=True)
class Context:
    p0: int
    p1: int
    p: int
    t: int

    @property
    def q(self):
        return self.p0*self.p1

    def validate(self):
        if (any(type(x) is not int for x in (self.p0, self.p1, self.p, self.t))
                or not _prime64(self.p0) or not _prime64(self.p1) or self.p0 == self.p1
                or not 3 <= self.t < 1 << 32 or self.t % 2 != 1
                or not self.t < self.p < 1 << 64 or not _prime64(self.p)
                or gcd(self.q, self.p) != 1 or gcd(self.t, self.q*self.p) != 1
                or (self.p-self.q) % self.t):
            raise ValueError("Wrong bounded scalar context")
        return self

    def digest(self):
        self.validate()
        value = json.dumps((self.p0, self.p1, self.p, self.t), separators=(",", ":"))
        return hashlib.sha256(value.encode()).hexdigest()

    def admit_native_scalar(self):
        """Pin the earlier immutable diagnostic profile, not general native use."""
        self.validate()
        if (self.p0, self.p1, self.p, self.t) != NATIVE_SCALAR_PROFILE:
            raise ValueError("Not the frozen native scalar diagnostic profile")
        return self


@dataclass(frozen=True)
class Witness:
    c: int
    y: int
    k: int
    r: int

    def lift(self, ctx):
        return self.y+ctx.p*self.k


def _grammar(ctx, entries, omit, gates):
    if type(ctx) is not Context:
        raise ValueError("Expected a pinned scalar context")
    ctx.validate()
    if any(type(x) is not int or x.bit_length() > 256 for x in entries):
        raise ValueError("Expected bounded integer witness grammar")
    if (type(omit) not in (tuple, set, frozenset) or any(type(x) is not str for x in omit)
            or not set(omit) <= gates):
        raise ValueError("Unknown diagnostic omitted condition")
    return frozenset(omit)


def rich_predicate(ctx, c, y, k, r, *, omit=()):
    """Exact three-field/trit statement; omissions are diagnostic only.

    The canonical ranges and l modt force any CRT wrap of D to be zero.
    A missing lift/wrap condition can corrupt a committed lift while retaining
    an honest y; it is not an attack on the reduced statement below.
    """
    omitted = _grammar(ctx, (c, y, k, r), omit, RICH_GATES)
    lift = y+ctx.p*k
    difference = ctx.q*lift-ctx.p*c-ctx.t*r
    checks = {"source_range": 0 <= c < ctx.q, "output_range": 0 <= y < ctx.p,
              "remainder_range": 2*abs(r) < ctx.q, "wrap_range": k in (-1, 0, 1),
              "limb0": difference % ctx.p0 == 0, "limb1": difference % ctx.p1 == 0,
              "target": difference % ctx.p == 0, "modt": (lift-c) % ctx.t == 0}
    return all(value for name, value in checks.items() if name not in omitted)


def reduced_predicate(ctx, c, y, r, *, omit=()):
    """Strong shared control: a centered remainder eliminates lift and trit.

    Both Q limbs pin r uniquely. The existing target modulus then pins y.
    Integer l=(P*c+t*r)/Q is derived; no supplied-lift gate is necessary.
    Global source/parameter binding remains external to this scalar relation.
    """
    omitted = _grammar(ctx, (c, y, r), omit, REDUCED_GATES)
    remainder_equation = ctx.t*r+ctx.p*c
    checks = {"source_range": 0 <= c < ctx.q, "output_range": 0 <= y < ctx.p,
              "remainder_range": 2*abs(r) < ctx.q,
              "limb0": remainder_equation % ctx.p0 == 0,
              "limb1": remainder_equation % ctx.p1 == 0,
              "target": (ctx.q*y-ctx.t*r) % ctx.p == 0}
    return all(value for name, value in checks.items() if name not in omitted)


def integer_predicate(ctx, c, y, k, r):
    """Independent exact-integer comparator for the rich finite tuple domain."""
    _grammar(ctx, (c, y, k, r), (), RICH_GATES)
    lift = y+ctx.p*k
    return (0 <= c < ctx.q and 0 <= y < ctx.p and k in (-1, 0, 1)
            and 2*abs(r) < ctx.q and (lift-c) % ctx.t == 0
            and ctx.q*lift-ctx.p*c == ctx.t*r)


def nearest_lift(ctx, c):
    """Independent exact minimization over adjacent c-modt integer lifts."""
    _grammar(ctx, (c,), (), RICH_GATES)
    if not 0 <= c < ctx.q:
        raise ValueError("Noncanonical pinned source")
    residue = c % ctx.t
    quotient = (ctx.p*c-ctx.q*residue)//(ctx.q*ctx.t)
    candidates = (residue+ctx.t*quotient, residue+ctx.t*(quotient+1))
    distances = tuple(abs(ctx.q*x-ctx.p*c) for x in candidates)
    assert distances[0] != distances[1]  # Q and t are odd, so no half-integer tie.
    return candidates[distances[1] < distances[0]]


def derive(ctx, c):
    """Unique centered modular remainder, exact integer lift, canonical output."""
    _grammar(ctx, (c,), (), RICH_GATES)
    if not 0 <= c < ctx.q:
        raise ValueError("Noncanonical pinned source")
    canonical = (-ctx.p*c*pow(ctx.t, -1, ctx.q)) % ctx.q
    r = canonical if 2*canonical < ctx.q else canonical-ctx.q
    numerator = ctx.p*c+ctx.t*r
    assert numerator % ctx.q == 0
    lift = numerator//ctx.q
    k, y = divmod(lift, ctx.p)
    witness = Witness(c, y, k, r)
    assert integer_predicate(ctx, c, y, k, r)
    return witness


def cost_card(ctx):
    """Scalar representation widths/counts only; no proof bytes or cycle cost."""
    ctx.validate()
    return {"q_bits": ctx.q.bit_length(), "q_limb_bits": (ctx.p0.bit_length(), ctx.p1.bit_length()),
            "target_bits": ctx.p.bit_length(), "source_unsigned_bits": (ctx.q-1).bit_length(),
            "centered_remainder_twos_complement_bits": ctx.q.bit_length(),
            "output_unsigned_bits": (ctx.p-1).bit_length(), "rich_wrap_trit_distinct_values": 3,
            "rich_wrap_trit_fixed_width_bits": 2, "reduced_wrap_trit_bits": 0,
            "rich_modular_equations": 3, "rich_modt_equations": 1, "reduced_modular_equations": 3,
            "three_field_description_conditional_on_registered_moduli_primality": True,
            "fresh_auxiliary_modulus_strict_lower_bound_twice": 4*ctx.p+ctx.t,
            "fresh_auxiliary_modulus_is_optional_known_control": True,
            "candidate_and_generic_receive_identical_remainder_elimination_and_existing_target": True,
            "source_binding_canonical_switch_and_authenticated_release_additional": True,
            "range_commitment_challenges_openings_provisioning_and_lifecycle_cost_unknown": True,
            "counts_are_not_proof_bytes_elapsed_time_parameter_or_security_assurance": True}
