"""E65 static support-aware grammar, with exhaustive row-allocation controls.

Keep the existing exact private-map boundary states and full profile/costs.
For each complete plan, enumerate every capacity-valid distribution of each
map's ordered rows over its contiguous CRT leaves. No cost-only partial prune
is used. New wire counts price C0 decoder support plus ALL C1; full index,
answers, verification work and state remain conservatively charged unchanged.
This is a bounded static oracle/planner supplement, not a new lifecycle DP,
native speed gain, general layout optimum or originality claim. Future base,
noise, mask exposure/seed and global-allowance state is NOT optimized here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from fractions import Fraction
import itertools
import math

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import decryption_support as support
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import rank_partition as partition
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import representation_planner as planner


@dataclass(frozen=True)
class Plan:
    compiled: oracle.Compiled
    certificate: support.Certificate

    @property
    def response_body_bytes_model(self):
        return self.certificate.body_bytes_model(self.compiled.profile.q.bit_length())

    @property
    def static_vector(self):
        original = self.compiled.resources
        return (original.query_body_bytes + self.response_body_bytes_model, *original.static_vector[1:])


@dataclass(frozen=True)
class Search:
    plans: tuple[Plan, ...]
    frontier: tuple[Plan, ...]
    original_controls: tuple[Plan, ...]
    balanced_controls: tuple[Plan, ...]
    original_compile_attempts: int
    row_allocation_attempts: int
    exact: bool


def view(plan):
    return Plan(plan, support.certify(plan.query_space.layout))


def redistribute(plan, counts):
    """Fixed maps/CRT cover, every original ID, canonical within-map row order."""
    original = plan.query_space
    if (type(counts) is not tuple or len(counts) != len(original.map_ids)
            or any(type(c) is not int or c < 0 or c > plan.resources.replies * leaf.degree
                   for c, leaf in zip(counts, original.layout.context.leaves, strict=True))):
        raise ValueError("Invalid bounded row allocation")
    maps, positions = oracle.grouped(plan.choice, plan.workload, plan.profile.prime)
    if maps != plan.maps or any(sum(c for c, i in zip(counts, original.map_ids, strict=True) if i == group) != len(row)
                               for group, row in enumerate(positions)):
        raise ValueError("Row allocation changes map membership or coverage")
    offsets, blocks = [0] * len(maps), []
    for leaf, count, group in zip(original.layout.context.leaves, counts, original.map_ids, strict=True):
        start = offsets[group]
        blocks.append(partition.Block(leaf.path, positions[group][start:start + count], maps[group]))
        offsets[group] += count
    constructor = type(original.layout)
    if constructor is not tree.Layout:
        raise ValueError("Static support grammar requires a legacy reply layout")
    layout = constructor(original.layout.context, original.layout.padded, original.layout.features, counts)
    # The E41 grammar uses legacy Layout. Reject new constructors rather than
    # guessing dataclass signatures or weakening the declared static grammar.
    if layout.cost.response_ciphertexts != plan.resources.replies:
        raise ValueError("Static support grammar requires the unchanged complete legacy reply geometry")
    candidate = replace(plan.candidate, layout=layout, blocks=tuple(blocks))
    partition.validate_epoch(candidate, list(plan.workload.rows))
    s = replace(original, layout=layout)
    space.validate(s)
    groups = tuple(tuple(tuple(row) for row in affine.index_features(b.mapping, [plan.workload.rows[i] for i in b.positions]))
                   for b in blocks)
    # All old complete resource counts depend on maps/coverage/N/R/widths,
    # which were pinned above. Only projected response support is a new axis.
    return replace(plan, candidate=candidate, query_space=s, groups=groups)


def _compositions(total, capacities):
    """Canonical exact bounded compositions, allowing unused replica leaves."""
    def visit(index, remaining, prefix):
        if index == len(capacities):
            if not remaining:
                yield prefix
            return
        lower = max(0, remaining - sum(capacities[index + 1:]))
        for count in range(lower, min(remaining, capacities[index]) + 1):
            yield from visit(index + 1, remaining - count, prefix + (count,))
    yield from visit(0, total, ())


def allocations(plan):
    """Bounded tiny catalog; caller counts/limits every complete distribution."""
    s, r = plan.query_space, plan.resources.replies
    if len(plan.workload.rows) > 128 or len(s.map_ids) > 8:
        raise ValueError("Support-allocation grammar is a tiny static experiment")
    indices = tuple(tuple(j for j, group in enumerate(s.map_ids) if group == i) for i in range(len(plan.maps)))
    # Stream complete combinations under the caller's whole-plan work budget.
    def combine(group, counts):
        if group == len(indices):
            yield tuple(counts)
            return
        for values in _compositions(sum(s.layout.counts[j] for j in indices[group]),
                                    tuple(r * s.layout.context.leaves[j].degree for j in indices[group])):
            candidate = list(counts)
            for j, count in zip(indices[group], values, strict=True):
                candidate[j] = count
            yield from combine(group + 1, candidate)
    yield from combine(0, [0] * len(s.map_ids))


def balanced_counts(plan):
    """Known greedy proportional-occupancy control, with exact fraction ties."""
    s, counts = plan.query_space, [0] * len(plan.query_space.map_ids)
    for group in range(len(plan.maps)):
        members = tuple(j for j, i in enumerate(s.map_ids) if i == group)
        total = sum(s.layout.counts[j] for j in members)
        for _ in range(total):
            choices = tuple(j for j in members if counts[j] < plan.resources.replies * s.layout.context.leaves[j].degree)
            best = min(choices, key=lambda j: (Fraction(counts[j], s.layout.context.leaves[j].degree), j))
            counts[best] += 1
    return tuple(counts)


def dominates(left, right):
    if left.compiled.profile != right.compiled.profile:
        return False
    a, b = left.static_vector, right.static_vector
    return a != b and all(x <= y for x, y in zip(a, b, strict=True))


def pareto(plans):
    # This is a final STATIC frontier only. Keep all plans separately so no
    # lifecycle successor is silently discarded on projected cost alone.
    front = []
    for plan in plans:
        if any(dominates(other, plan) for other in front):
            continue
        front = [other for other in front if not dominates(plan, other)]
        front.append(plan)
    return tuple(front)


def search(workload, root, profile, *, slots=(1, 2, 4), equal_forms=True, limit=10000):
    if type(limit) is not int or not 1 <= limit <= 100000:
        raise ValueError("Invalid static support-search work budget")
    original = planner.search(workload, root, profile, slots=slots, equal_forms=equal_forms, limit=limit)
    result, attempts = [], 0
    for plan in original.plans:
        for counts in allocations(plan):
            if attempts == limit:
                raise ValueError("Static support row-allocation search exceeds work budget")
            attempts += 1
            result.append(view(redistribute(plan, counts)))
    complete = tuple(result)
    return Search(complete, pareto(complete), tuple(view(p) for p in original.plans),
                  tuple(view(redistribute(p, balanced_counts(p))) for p in original.plans),
                  original.attempted, attempts, original.exact)


def cartesian_oracle_counts(plan):
    """Independent tiny Cartesian traversal, not the composition generator."""
    s = plan.query_space
    if len(s.map_ids) > 4 or len(plan.workload.rows) > 12:
        raise ValueError("Independent Cartesian row oracle is tiny only")
    widths = tuple(min(len(plan.workload.rows), plan.resources.replies * leaf.degree) + 1
                   for leaf in s.layout.context.leaves)
    if math.prod(widths) > 100000:
        raise ValueError("Cartesian row-allocation oracle exceeds work budget")
    totals = tuple(sum(c for c, i in zip(s.layout.counts, s.map_ids, strict=True) if i == group)
                   for group in range(len(plan.maps)))
    return tuple(counts for counts in itertools.product(*(range(w) for w in widths))
                 if all(sum(c for c, i in zip(counts, s.map_ids, strict=True) if i == group) == total
                        for group, total in enumerate(totals)))
