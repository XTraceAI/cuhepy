"""E41 exact boundary-state DP and complete-plan Pareto selection.

The DP merges only choices assigning the SAME exact private map to the SAME
positions, in the same first-occurrence group order. It does not discard a
partial state on rank, local cost, or equal query values. Final geometry and
all resource axes are evaluated afterwards. Optimality is restricted to the
oracle's fixed tree, raw/affine node choices and contiguous slot grammar.

This optimizer is for owner-side, bounded research workloads. A beam cap is
an explicitly uncertified heuristic, with missed frontiers measured against
the exhaustive reference; it carries no approximation or security guarantee.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab.representation_contract import Budget, Profile, Workload


@dataclass(frozen=True)
class Search:
    plans: tuple[oracle.Compiled, ...]
    frontier: tuple[oracle.Compiled, ...]
    rejected: tuple[tuple[str, str], ...]
    node_state_counts: tuple[tuple[str, int, int], ...]
    attempted: int
    exact: bool


def signature(choice: oracle.Choice):
    groups: dict[affine.Plan, list[int]] = {}
    for piece in choice.pieces:
        groups.setdefault(piece.mapping, []).extend(piece.positions)
    return tuple((mapping, tuple(positions)) for mapping, positions in groups.items())


def boundary_choices(workload: Workload, root: oracle.Node, prime: int, *, limit: int = 4096,
                     beam: int | None = None) -> tuple[tuple[oracle.Choice, ...], tuple[tuple[str, int, int], ...]]:
    oracle.validate_tree(workload, root)
    affine._field(workload.dimension, prime)
    if (type(limit) is not int or not 1 <= limit <= 100000
            or beam is not None and (type(beam) is not int or not 1 <= beam <= limit)):
        raise ValueError("Invalid boundary-state or heuristic budget")
    raw, counts = oracle.raw_map(workload.dimension, prime), []

    def visit(node):
        fitted = affine.prepare([workload.rows[i] for i in node.positions], workload.dimension, prime)
        candidates = [oracle.Choice((oracle.Piece(node.path, node.positions, raw, "raw"),)),
                      oracle.Choice((oracle.Piece(node.path, node.positions, fitted, "affine"),))]
        if node.children:
            left, right = map(visit, node.children)
            if len(left) * len(right) + 2 > limit:
                raise ValueError("Boundary-state cross product exceeds work limit")
            candidates.extend(oracle.Choice(a.pieces + b.pieces) for a in left for b in right)
        retained = {}
        for choice in candidates:
            retained.setdefault(signature(choice), choice)
        before = len(retained)
        result = tuple(retained.values())
        if beam is not None and len(result) > beam:
            # Deliberately simple rank-first control. This ignores response
            # capacity, shared forms, checking and future update dependencies.
            result = tuple(sorted(result, key=lambda c: (max(p.mapping.features for p in c.pieces),
                                                        sum(m.features for m, _ in signature(c)), c.name))[:beam])
        counts.append((node.path, before, len(result)))
        return result

    result = visit(root)
    return result, tuple(counts)


def dominates(left: oracle.Compiled, right: oracle.Compiled) -> bool:
    # Do not silently trade parameters or nominal security for speed/state.
    if left.profile != right.profile:
        return False
    a, b = left.resources.static_vector, right.resources.static_vector
    return all(x <= y for x, y in zip(a, b, strict=True)) and a != b


def pareto(plans: tuple[oracle.Compiled, ...]) -> tuple[oracle.Compiled, ...]:
    """Keep cost ties; equal static cost does not mean equal update behavior."""
    front = []
    for plan in plans:
        if any(dominates(other, plan) for other in front):
            continue
        front = [other for other in front if not dominates(plan, other)]
        front.append(plan)
    return tuple(front)


def search(workload: Workload, root: oracle.Node, profile: Profile, *, slots=(1, 2, 4, 8),
           budget: Budget = Budget(), limit: int = 100000, beam: int | None = None,
           equal_forms: bool = True) -> Search:
    profile.validate(workload.dimension)
    if type(limit) is not int or not 1 <= limit <= 1000000:
        raise ValueError("Invalid complete planner work limit")
    choices, counts = boundary_choices(workload, root, profile.prime, beam=beam)
    plans, rejected, attempted = [], [], 0
    for choice in choices:
        maps, _ = oracle.grouped(choice, workload, profile.prime)
        for count in slots:
            if type(count) is not int or not 1 <= count <= 64 or count & (count - 1):
                raise ValueError("Invalid final slot catalog")
            if count < len(maps):
                continue
            if attempted == limit:
                raise ValueError("Complete planner exceeds work limit")
            for allocation in oracle.allocations(count, len(maps), limit=limit - attempted):
                attempted += 1
                name = f"{choice.name}:{allocation}"
                try:
                    plan = oracle.compile_choice(workload, choice, profile, allocation, equal_forms=equal_forms)
                    reasons = budget.rejection(plan.resources)
                    if reasons:
                        rejected.append((name, "; ".join(reasons)))
                    else:
                        plans.append(plan)
                except ValueError as error:
                    rejected.append((name, str(error)))
    complete = tuple(plans)
    return Search(complete, pareto(complete), tuple(rejected), counts, attempted, beam is None)
