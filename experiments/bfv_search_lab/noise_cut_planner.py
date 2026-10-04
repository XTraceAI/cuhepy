"""Q70 finite noise-aware verification-cut grammar, an exact known-method DP.

All noise is a public worst-case box bound. The residue classes of the packing
suffix are nested, so a subtree's scalar peak is compositional via max, rather
than summing unrelated level maxima. Common digit availability/bounds, work and
shared digit-key levels are separate state. This models one charged direct
implementation, not the fastest generic fusion or a deployed verifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import math

from experiments.bfv_search_lab import tensor_gadget_seed as seed


@dataclass(frozen=True)
class Profile:
    n: int
    d: int
    q: int
    p: int
    t: int
    eta: int
    bits: int
    product_bound: int  # Includes the unchanged canonical30 relinearization.

    def __post_init__(self):
        values = (
            self.n,
            self.d,
            self.q,
            self.p,
            self.t,
            self.eta,
            self.bits,
            self.product_bound,
        )
        if (
            any(type(x) is not int for x in values)
            or self.n < 8
            or self.n & (self.n - 1)
            or not 2 <= self.d <= self.n // 2
            or self.d & (self.d - 1)
            or not 1 <= self.bits <= 30
            or self.eta < 0
            or self.product_bound < 0
            or not 2 * self.d < self.t < self.p < self.q
            or (self.p - self.q) % self.t
            or self.p % 2 != 1
        ):
            raise ValueError("Invalid public planner profile")

    @property
    def ell(self):
        return (self.q.bit_length() + self.bits - 1) // self.bits

    @property
    def digit_bound(self):
        return (1 << self.bits) - 1

    @property
    def state_increment(self):
        return self.n * self.ell * self.digit_bound**2

    @property
    def scale(self):
        return self.t * self.eta * self.n * self.ell

    @property
    def factor(self):
        return 1 + self.n * self.ell * self.digit_bound

    @property
    def canonical_error(self):
        return self.scale * self.digit_bound

    @property
    def seed_bound(self):
        return seed.seed_bound(self.n, self.q, self.bits)

    def terminal_bound(self, peak):
        return (self.p * peak + self.q - 1) // self.q + ((self.n + 1) * self.t + 1) // 2

    def safe(self, peak):
        return 2 * peak < self.q and 2 * self.terminal_bound(peak) < self.p

    @property
    def maximum_peak(self):
        rounding = ((self.n + 1) * self.t + 1) // 2
        allowance = (self.p - 1) // 2 - rounding
        return min((self.q - 1) // 2, self.q * allowance // self.p)

    def live_state(self, state, peak):
        # Binary maintenance cannot reduce the common norm or current envelope.
        # The cheapest possible future derived switch has suffix weight1.
        # Unary canonical reset needs no old state and remains possible opaque.
        return state is not None and peak + self.scale * state <= self.maximum_peak


@dataclass(frozen=True)
class Plan:
    # level=-1 denotes a leaf; inactive leaves/subtrees use mode="zero".
    level: int
    count: int
    mode: str
    retain: bool
    left: Plan | None = None
    right: Plan | None = None


@dataclass(frozen=True)
class Label:
    state: int | None
    peak: int
    removed: int
    seeds: int
    work: int  # Charged direct ring-product equivalents, not timing/NTT count.
    digit_key_levels: int
    plan: Plan


class PlannerLimit(RuntimeError):
    pass


def node(profile, level, count, left, right, mode, retain):
    """One legal transition; source/plus availability is never inferred from noise."""
    if mode not in ("canonical", "derived") or type(retain) is not bool or count < 1:
        raise ValueError("Illegal node action")
    both = left.state is not None and right.state is not None
    unary = right.plan.count == 0
    common = left.state + right.state if both else None
    if mode == "derived" and not both:
        raise ValueError("Derived source requires both common states")
    if retain and mode == "canonical" and not unary and not both:
        raise ValueError("Binary canonical minus source cannot supply its plus state")
    source = common if mode == "derived" else profile.digit_bound
    if not retain:
        state = None
    elif mode == "derived":
        state = common * profile.factor
    elif unary:
        state = profile.digit_bound * profile.factor
    else:
        state = common + profile.state_increment
    weight = profile.d >> (level + 1)
    return Label(
        state,
        max(left.peak, right.peak) + weight * profile.scale * source,
        left.removed + right.removed + (mode == "derived"),
        left.seeds + right.seeds,
        left.work + right.work + 2 * profile.ell + (profile.ell**2 if retain else 0),
        left.digit_key_levels
        | right.digit_key_levels
        | ((1 << level) if retain else 0),
        Plan(level, count, mode, retain, left.plan, right.plan),
    )


def leaf(profile, present, seeded):
    if not present:
        return Label(0, 0, 0, 0, 0, 0, Plan(-1, 0, "zero", False))
    return Label(
        profile.seed_bound if seeded else None,
        profile.d * profile.product_bound,
        0,
        int(seeded),
        2 * profile.ell**2 + 4 * profile.ell if seeded else 0,
        0,
        Plan(-1, 1, "seed" if seeded else "plain", bool(seeded)),
    )


def dominates(a, b):
    # Known-state availability is monotone: it enables every transition that
    # unknown state permits and possibly more. Smaller common norms stay safe.
    sa, sb = (
        math.inf if a.state is None else a.state,
        math.inf if b.state is None else b.state,
    )
    return (
        sa <= sb
        and a.peak <= b.peak
        and a.removed >= b.removed
        and a.seeds <= b.seeds
        and a.work <= b.work
        and a.digit_key_levels & b.digit_key_levels == a.digit_key_levels
    )


def pareto(labels, cap, compare=None):
    kept = []
    for value in sorted(
        labels,
        key=lambda x: (
            -x.removed,
            x.work,
            x.seeds,
            x.peak,
            x.digit_key_levels,
            math.inf if x.state is None else x.state,
        ),
    ):
        relation = dominates if compare is None else compare
        if any(relation(old, value) for old in kept):
            continue
        kept = [old for old in kept if not relation(value, old)]
        kept.append(value)
        if len(kept) > cap:
            raise PlannerLimit("Pareto label cap exceeded; no exact optimum reported")
    return tuple(kept)


def frontier(
    profile,
    count,
    allow_seed,
    *,
    label_cap=2000,
    merge_cap=3000000,
    transition_cap=50000,
    comparison_cap=5000000,
):
    if (
        type(count) is not int
        or not 1 <= count <= profile.d
        or type(allow_seed) is not bool
    ):
        raise ValueError("Invalid finite planner request")
    merged, comparisons, dead_states = 0, 0, 0

    def compare(a, b):
        nonlocal comparisons
        comparisons += 1
        if comparisons > comparison_cap:
            raise PlannerLimit(
                "Dominance comparison cap exceeded; no exact optimum reported"
            )
        return dominates(a, b)

    @lru_cache(None)
    def visit(level, present):
        nonlocal merged, dead_states
        if present == 0:
            return (Label(0, 0, 0, 0, 0, 0, Plan(level, 0, "zero", False)),)
        if level == -1:
            values = tuple(
                leaf(profile, True, seeded)
                for seeded in (False, True)
                if allow_seed or not seeded
            )
            return tuple(
                v
                for v in values
                if v.state is None or profile.live_state(v.state, v.peak)
            )
        left = visit(level - 1, (present + 1) // 2)
        right = visit(level - 1, present // 2)
        out = {}
        for a in left:
            for b in right:
                merged += 1
                if merged > merge_cap:
                    raise PlannerLimit(
                        "Candidate merge cap exceeded; no exact optimum reported"
                    )
                for mode in ("canonical", "derived"):
                    for retain in (False, True):
                        try:
                            result = node(profile, level, present, a, b, mode, retain)
                        except ValueError:
                            continue
                        # Ancestor contributions are nonnegative; prune unsafe
                        # partial peaks using the very same final Q/P guards.
                        if profile.safe(result.peak):
                            if retain and not profile.live_state(
                                result.state, result.peak
                            ):
                                dead_states += 1
                                continue
                            key = (
                                result.state,
                                result.peak,
                                result.removed,
                                result.seeds,
                                result.work,
                                result.digit_key_levels,
                            )
                            out.setdefault(key, result)
                            if len(out) > transition_cap:
                                raise PlannerLimit(
                                    "Distinct transition cap exceeded; no exact optimum reported"
                                )
        return pareto(out.values(), label_cap, compare)

    values = visit(profile.d.bit_length() - 2, count)
    # Root state is unused, so compare root labels after discarding it. This
    # does not remove any charged work already performed by a retained plan.
    roots = [
        Label(None, v.peak, v.removed, v.seeds, v.work, v.digit_key_levels, v.plan)
        for v in values
    ]
    result = pareto(roots, label_cap, compare)
    stats = {
        "candidate_merges": merged,
        "memo_subproblems": visit.cache_info().currsize,
        "root_labels": len(result),
        "exact_within_declared_grammar": True,
        "dominance_comparisons": comparisons,
        "dead_retention_branches_removed": dead_states,
    }
    return result, stats


def select(values):
    """Minimum source cuts; ties price direct work, seeds and public digit state."""
    if not values:
        raise ValueError("No safe schedule")
    return min(
        values,
        key=lambda v: (
            -v.removed,
            v.work,
            v.seeds,
            v.digit_key_levels.bit_count(),
            v.peak,
        ),
    )


def replay(profile, plan):
    if (
        type(plan) is not Plan
        or plan.level != profile.d.bit_length() - 2
        or type(plan.count) is not int
        or not 1 <= plan.count <= profile.d
    ):
        raise ValueError("Wrong complete root coverage")
    return _replay(profile, plan)


def _replay(profile, plan):
    """Strict full plan replay, independent of the DP's memoization/pruning."""
    if (
        type(plan) is not Plan
        or type(plan.count) is not int
        or type(plan.retain) is not bool
        or type(plan.level) is not int
    ):
        raise ValueError("Immutable exact plan grammar required")
    if plan.mode == "zero":
        if (
            plan.count != 0
            or plan.retain
            or plan.left is not None
            or plan.right is not None
        ):
            raise ValueError("Invalid inactive subtree")
        return Label(0, 0, 0, 0, 0, 0, plan)
    if plan.level == -1:
        if (
            plan.count != 1
            or plan.left is not None
            or plan.right is not None
            or plan.mode not in ("plain", "seed")
            or plan.retain != (plan.mode == "seed")
        ):
            raise ValueError("Invalid leaf")
        return leaf(profile, True, plan.mode == "seed")
    if (
        type(plan.left) is not Plan
        or type(plan.right) is not Plan
        or plan.left.level != plan.level - 1
        or plan.right.level != plan.level - 1
        or plan.left.count != (plan.count + 1) // 2
        or plan.right.count != plan.count // 2
    ):
        raise ValueError("Wrong subtree coverage")
    return node(
        profile,
        plan.level,
        plan.count,
        _replay(profile, plan.left),
        _replay(profile, plan.right),
        plan.mode,
        plan.retain,
    )


def ledger(profile, value):
    qpoly = (profile.n * profile.q.bit_length() + 7) // 8
    nodes = sum(
        min(profile.d >> (j + 1), value.plan.count)
        for j in range(profile.d.bit_length() - 1)
    )
    relin_ell = (profile.q.bit_length() + 29) // 30
    products = (4 + 2 * relin_ell) * value.plan.count
    key_polys = 2 * profile.ell * (profile.d.bit_length() - 1)
    return {
        "tiles": value.plan.count,
        "digit_bits": profile.bits,
        "rotation_columns": profile.ell,
        "removed_source_cuts": value.removed,
        "source_and_terminal_Q_body_bytes": (
            value.plan.count + nodes - value.removed + 2
        )
        * qpoly,
        "canonical30_source_and_terminal_Q_body_bytes": (value.plan.count + nodes + 2)
        * qpoly,
        "rotation_key_Q_body_bytes": key_polys * qpoly,
        "additional_rotation_key_Q_body_bytes_vs30": (
            key_polys - 2 * relin_ell * (profile.d.bit_length() - 1)
        )
        * qpoly,
        "public_A_digit_levels": value.digit_key_levels.bit_count(),
        "public_A_digits_packed_body_bytes": value.digit_key_levels.bit_count()
        * profile.ell**2
        * ((profile.n * profile.bits + 7) // 8),
        "seeded_leaves": value.seeds,
        "direct_modeled_rotation_seed_state_ring_product_equivalents": value.work,
        "unchanged_tensor_relin_ring_product_equivalents": products,
        "direct_modeled_total_ring_product_equivalents": products + value.work,
        "full_phase_box_bound": value.peak,
        "phase_box_bound_bits": value.peak.bit_length(),
        "terminal_box_bound": profile.terminal_bound(value.peak),
        "Q_P_guard": profile.safe(value.peak),
        "complete_admission_or_latency_implemented": False,
        "scope": "Exact logical counts for a priced direct implementation and safe common-lift box envelope. Generic controls receive identical grammar; fusion may lower actual work. Input/query/index/functional-key alternatives, decoder, transform counts, dynamic memory/scratch, verifier/proof/attestation/network/lifetime/update costs remain separate. No optimal full-service or performance claim.",
    }
