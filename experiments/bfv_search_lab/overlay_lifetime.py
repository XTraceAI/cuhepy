"""E55 exact checkpoint/exception frontier over the E52 finite map catalog.

E54 makes an important strong control explicit: current rows need not be in
the encrypted BASE map's span when private client deltas correct its scores.
Choose between keeping that base and replacing it with a fresh feasible plan.
The boundary must retain the exact encrypted-base revision, not just current
rank, exception count or phase age. All unused replacement tokens are charged.

This is a finite hindsight count oracle. Ordinary checkpointing/delta caching
and Pareto DP are known ingredients; no runtime/online/novelty/security claim
follows. No exposed pad is reused. Fresh replacement keeps the full HE profile;
key setup/discovery are common external costs. E43 repair remains a separate
control after its vectorized measured regression, rather than a forced action.
"""

from __future__ import annotations

from dataclasses import astuple, dataclass

from experiments.bfv_search_lab import lifetime_planner as lifetime


@dataclass(frozen=True)
class Cost:
    encrypted: lifetime.Cost = lifetime.Cost()
    private_owner_update_body_bytes_model: int = 0
    client_delta_popcounts: int = 0
    client_delta_range_scan_entries: int = 0
    owner_delta_word_operations_model: int = 0
    peak_private_delta_body_bytes_model: int = 0
    peak_owner_base_and_current_row_body_bytes_model: int = 0

    @property
    def vector(self):
        return astuple(self.encrypted) + astuple(self)[1:]

    def plus(self, other):
        a, b = astuple(self)[1:], astuple(other)[1:]
        return Cost(self.encrypted.plus(other.encrypted),
                    *(x + y if i < 4 else max(x, y) for i, (x, y) in enumerate(zip(a, b, strict=True))))

    def dominates(self, other):
        return self != other and all(a <= b for a, b in zip(self.vector, other.vector, strict=True))


@dataclass(frozen=True)
class Path:
    entry: int
    base_revision: int
    cost: Cost
    actions: tuple[tuple[str, str, int], ...]


class Problem:
    def __init__(self, trace, entries, profile):
        self.base = lifetime.Problem(trace, entries, profile)
        self.trace, self.entries, self.profile = trace, entries, profile
        self.plans = self.base.plans

    def _owner_rows(self):
        w = self.trace.revisions[0]
        # Charge base/current owner binary row bodies as well as the existing
        # int8-coordinate model. Object copies/scratch/RSS remain additional.
        return 2 * len(w.rows) * ((w.dimension + 7) // 8)

    def fresh_cost(self, revision, entry, *, method):
        work = self.base._cost(revision, entry, method)
        return Cost(work, peak_owner_base_and_current_row_body_bytes_model=self._owner_rows())

    def delta_cost(self, revision, entry, base_revision):
        plan = self.plans[base_revision][entry]
        current, base = self.trace.revisions[revision], self.trace.revisions[base_revision]
        previous = self.trace.revisions[revision - 1]
        changed_now = sum(a != b for a, b in zip(current.rows, previous.rows, strict=True))
        exceptions = sum(a != b for a, b in zip(current.rows, base.rows, strict=True))
        width = (current.dimension + 7) // 8
        r, q = plan.resources, self.trace.queries[revision]
        # No new ciphertext/checker/native preprocessing occurs. The frozen
        # base and its unused pool remain intact; only their online use is paid.
        work = lifetime.Cost(public_evaluate_products=r.server_pointwise_products_model * q,
                             full_check_products=r.verifier_products_model * q,
                             response_body_bytes=r.response_body_bytes * q)
        return Cost(work, 64 + changed_now * (8 + 2 * width), 4 * exceptions * q,
                    2 * len(current.rows) * q, 3 * changed_now,
                    64 + exceptions * (8 + 2 * width), self._owner_rows())

    def starts(self):
        return tuple(Path(i, 0, self.fresh_cost(0, i, method="enroll"), ((e.name, "enroll", 0),))
                     for i, e in enumerate(self.entries) if self.plans[0][i] is not None)

    def successors(self, revision, path):
        # Deltas require no certification of current rows against the base's
        # affine map. This is the key semantic difference from frozen repairs.
        results = [Path(path.entry, path.base_revision,
                        path.cost.plus(self.delta_cost(revision, path.entry, path.base_revision)),
                        path.actions + ((self.entries[path.entry].name, "client_delta", path.base_revision),))]
        for i, entry in enumerate(self.entries):
            if self.plans[revision][i] is not None:
                method = "refresh" if i == path.entry else "migrate"
                results.append(Path(i, revision, path.cost.plus(self.fresh_cost(revision, i, method=method)),
                                    path.actions + ((entry.name, method, revision),)))
        return tuple(results)


def pareto(paths):
    unique = {}
    for path in paths:
        unique.setdefault(path.cost, path)
    return tuple(sorted((p for p in unique.values() if not any(q.cost.dominates(p.cost) for q in unique.values())),
                        key=lambda p: p.cost.vector))


def _expand(problem, revision, active, limit):
    if type(limit) is not int or not 1 <= limit <= 1000000:
        raise ValueError("Invalid exact overlay work limit")
    result = []
    for path in active:
        for successor in problem.successors(revision, path):
            if len(result) >= limit:
                raise ValueError("Exact overlay schedules exceed research work limit")
            result.append(successor)
    return tuple(result)


def dynamic_program(problem, *, work_limit=100000):
    active, counts = problem.starts(), []
    counts.append(len(active))
    for revision in range(1, len(problem.trace.revisions)):
        states = {}
        for path in _expand(problem, revision, active, work_limit):
            states.setdefault((path.entry, path.base_revision), []).append(path)
        active = tuple(p for paths in states.values() for p in pareto(paths))
        counts.append(len(active))
    return pareto(active), tuple(counts)


def exhaustive(problem, *, work_limit=100000):
    active, counts = problem.starts(), []
    counts.append(len(active))
    for revision in range(1, len(problem.trace.revisions)):
        active = _expand(problem, revision, active, work_limit)
        counts.append(len(active))
    return pareto(active), tuple(counts)
