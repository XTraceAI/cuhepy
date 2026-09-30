"""E52 finite-trace oracle for reserve, pending-pad repair and phase rebasing.

This is a HINDSIGHT modeled oracle, not an online predictor or deployed update
protocol. It combines exact certified maps with conservative accumulated phase
bounds. All prepared/remaining tokens and state are charged. Private catalog
semantics and noise age are retained in the DP boundary: equal rank is unsafe.

The model reports arithmetic/byte vectors, not seconds. Catalog fitting and
oracle execution time must be recorded separately; no Gate C or novelty claim
follows. Known affine reservation, incremental HE and dynamic programming are
ingredients. Insert/delete, durable authentication and learned policies remain
outside this fixed-ID model.
"""

from __future__ import annotations

from dataclasses import astuple, dataclass

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab.representation_contract import Profile, Workload


@dataclass(frozen=True)
class Entry:
    name: str
    choice: oracle.Choice
    allocation: tuple[int, ...]
    equal_forms: bool = True


def reserve(workload, directions, prime, *, name):
    """Whole-block affine map with explicitly owner-supplied mutable bits.

    Initial rows plus anchor XOR each allowed bit generate the span. Reserved
    coordinates may be zero initially but still cost encrypted columns/pads.
    Certification never assumes that an arbitrary future edit stays in it.
    """
    workload.validate()
    if (type(directions) is not tuple or tuple(sorted(set(directions))) != directions
            or any(type(j) is not int or not 0 <= j < workload.dimension for j in directions)):
        raise ValueError("Invalid finite owner reserve directions")
    rows = list(workload.rows) + [workload.rows[0] ^ (1 << j) for j in directions]
    mapping = affine.prepare(rows, workload.dimension, prime)
    choice = oracle.Choice((oracle.Piece("", tuple(range(len(workload.rows))), mapping, "affine"),))
    return Entry(name, choice, (1,))


@dataclass(frozen=True)
class Trace:
    revisions: tuple[Workload, ...]
    queries: tuple[int, ...]
    prepared_tokens: int

    def validate(self, profile):
        if (not self.revisions or len(self.queries) != len(self.revisions)
                or len(self.revisions) > 16 or type(self.prepared_tokens) is not int
                or not 1 <= self.prepared_tokens <= profile.attempt_budget
                or any(type(q) is not int or q < 0 for q in self.queries)
                or sum(self.queries) > self.prepared_tokens):
            raise ValueError("Invalid bounded fixed-ID token trace")
        first = self.revisions[0]
        for w in self.revisions:
            w.validate()
            profile.validate(w.dimension)
            if (w.ids, w.dimension) != (first.ids, first.dimension):
                raise ValueError("Lifetime trace changes stable IDs or dimension")


@dataclass(frozen=True)
class Cost:
    fresh_ciphertext_coefficients: int = 0
    added_ciphertext_coefficients: int = 0
    private_dot_terms: int = 0
    private_certification_terms_model: int = 0
    public_evaluate_products: int = 0
    full_check_products: int = 0
    response_body_bytes: int = 0
    peak_client_body_bytes_model: int = 0
    peak_owner_int8_coordinates_bytes: int = 0
    peak_pending_body_bytes_model: int = 0
    peak_server_native_word_bytes_model: int = 0

    def plus(self, other):
        a, b = astuple(self), astuple(other)
        return Cost(*(x + y if i < 7 else max(x, y) for i, (x, y) in enumerate(zip(a, b, strict=True))))

    def dominates(self, other):
        a, b = astuple(self), astuple(other)
        return all(x <= y for x, y in zip(a, b, strict=True)) and a != b


@dataclass(frozen=True)
class Path:
    entry: int
    age: int
    cost: Cost
    actions: tuple[tuple[str, str, int], ...]


class Problem:
    def __init__(self, trace: Trace, entries: tuple[Entry, ...], profile: Profile):
        trace.validate(profile)
        if (not 1 <= len(entries) <= 16 or len(set(e.name for e in entries)) != len(entries)):
            raise ValueError("Require a bounded uniquely named exact map catalog")
        self.trace, self.entries, self.profile = trace, entries, profile
        plans = []
        for workload in trace.revisions:
            row = []
            for entry in entries:
                try:
                    row.append(oracle.compile_choice(workload, entry.choice, profile, entry.allocation,
                                                     equal_forms=entry.equal_forms))
                except ValueError:
                    row.append(None)  # Includes span, capacity and fresh-noise rejection.
            plans.append(tuple(row))
        self.plans = tuple(plans)

    def _cost(self, revision, entry, method):
        p = self.plans[revision][entry]
        remaining = self.trace.prepared_tokens - sum(self.trace.queries[:revision])
        cells = sum(len(g) * f for g, f in zip(p.groups, p.query_space.layout.features, strict=True))
        changed_cells = changed_certificate = 0
        if revision:
            previous = self.trace.revisions[revision - 1]
            for b in p.candidate.blocks:
                changed = sum(p.workload.rows[i] != previous.rows[i] for i in b.positions)
                changed_cells += changed * b.mapping.features
                changed_certificate += changed * b.mapping.rank * p.dimension
        certificate = (sum(len(b.positions) * b.mapping.rank * p.dimension for b in p.candidate.blocks)
                       if method in ("enroll", "migrate") else changed_certificate)
        r, profile = p.resources, self.profile
        words = 2 * profile.n * r.replies
        ciphertext_words = words * (r.columns + remaining)
        query_count = self.trace.queries[revision]
        width = (profile.q.bit_length() + 7) // 8
        # This charges the actual client's retained public/secret key body too;
        # a hypothetical context-only client is not substituted for today's ABI.
        key_body = 2 * profile.n * width + (2 * profile.n + 7) // 8
        pad_body = r.query_coordinates * ((profile.prime.bit_length() + 7) // 8)
        return Cost(ciphertext_words, ciphertext_words if method == "repair" else 0,
                    (changed_cells if method == "repair" else cells) * remaining,
                    certificate, r.server_pointwise_products_model * query_count,
                    r.verifier_products_model * query_count + r.checker_rounds * (ciphertext_words + r.correction_coefficients),
                    r.response_body_bytes * query_count, r.client_audit_body_bytes_model + key_body,
                    cells, remaining * (r.response_body_bytes + pad_body + r.checker_rounds * width),
                    r.native_index_word_bytes)

    def starts(self):
        return tuple(Path(i, 1, self._cost(0, i, "enroll"), ((entry.name, "enroll", 1),))
                     for i, entry in enumerate(self.entries) if self.plans[0][i] is not None)

    def successors(self, revision, path):
        results = []
        for i, entry in enumerate(self.entries):
            p = self.plans[revision][i]
            if p is None:
                continue
            methods = [("refresh" if i == path.entry else "migrate", 1)]
            age = path.age + 1
            if i == path.entry and 2 * p.resources.phase_bound * age < self.profile.q:
                methods.append(("repair", age))
            for method, age in methods:
                cost = path.cost.plus(self._cost(revision, i, method))
                results.append(Path(i, age, cost, path.actions + ((entry.name, method, age),)))
        return tuple(results)


def pareto(paths):
    # Equal cost vectors need only one witness at the FINAL boundary.
    unique = {}
    for p in paths:
        unique.setdefault(p.cost, p)
    return tuple(sorted((p for p in unique.values() if not any(
        q.cost.dominates(p.cost) for q in unique.values())), key=lambda p: astuple(p.cost)))


def dynamic_program(problem: Problem, *, work_limit=100000):
    """Exact Pareto DP within this catalog/trace/model; no beam or rank merge."""
    active = problem.starts()
    counts = [len(active)]
    for revision in range(1, len(problem.trace.revisions)):
        generated = _expand(problem, revision, active, work_limit)
        states = {}
        for p in generated:
            # Catalog entry includes exact maps, positions, alignment and field.
            # Noise age and implicit consumed-prefix count fix every future
            # transition/cost. Rank or F alone cannot replace this state.
            states.setdefault((p.entry, p.age), []).append(p)
        active = tuple(q for paths in states.values() for q in pareto(paths))
        counts.append(len(active))
    return pareto(active), tuple(counts)


def exhaustive(problem: Problem, *, work_limit=100000):
    """Independent schedule enumeration: NEVER prunes an intermediate prefix."""
    active = problem.starts()
    counts = [len(active)]
    for revision in range(1, len(problem.trace.revisions)):
        active = _expand(problem, revision, active, work_limit)
        counts.append(len(active))
    return pareto(active), tuple(counts)


def _expand(problem, revision, paths, work_limit):
    if type(work_limit) is not int or not 1 <= work_limit <= 1000000:
        raise ValueError("Invalid exact lifetime research work limit")
    generated = []
    for path in paths:
        for successor in problem.successors(revision, path):
            if len(generated) >= work_limit:
                raise ValueError("Exact lifetime schedules exceed research work limit")
            generated.append(successor)
    return tuple(generated)
