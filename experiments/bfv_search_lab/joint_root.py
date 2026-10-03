"""E122 bounded public raw-ternary joint-root oracle; not HE or a theorem.

Signed Galois orbits preserve the law, not independence of root events.
MITM counts retain all four-vector collisions and the zero secret once.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from itertools import combinations
from math import isqrt


def _integers(*values):
    if any(type(value) is not int for value in values):
        raise ValueError("Expected exact integers")


def _ring(n, q):
    _integers(n, q)
    if (n not in (2, 4, 16) or not 3 <= q <= 257 or q % (2 * n) != 1
            or any(q % divisor == 0 for divisor in range(2, isqrt(q) + 1))):
        raise ValueError("Expected a bounded fully split prime ring")


@dataclass(frozen=True)
class Context:
    n: int
    q: int
    root: int

    def validate(self):
        _ring(self.n, self.q)
        _integers(self.root)
        if (not 1 < self.root < self.q or pow(self.root, self.n, self.q) != self.q - 1
                or pow(self.root, 2 * self.n, self.q) != 1
                or len({pow(self.root, j, self.q) for j in range(2 * self.n)}) != 2 * self.n):
            raise ValueError("Expected an exact primitive2N root")
        return self

    @property
    def group(self):
        self.validate()
        return tuple(range(1, 2 * self.n, 2))


def least_root(n, q):
    """Fixed public selector; the N16/q97 call belongs only to the one main."""
    _ring(n, q)
    for root in range(2, q):
        if pow(root, n, q) == q - 1:
            return Context(n, q, root).validate()
    raise ValueError("No primitive root under the frozen selector")


def _rootset(ctx, roots):
    if type(ctx) is not Context:
        raise ValueError("Expected a public context")
    ctx.validate()
    if (type(roots) is not tuple or not 1 <= len(roots) <= min(ctx.n, 4)
            or any(type(e) is not int or not 1 <= e < 2 * ctx.n or not e & 1 for e in roots)
            or roots != tuple(sorted(set(roots)))):
        raise ValueError("Expected sorted distinct odd root exponents")


def _action(roots, g, modulus):
    return tuple(sorted(g * e % modulus for e in roots))


def action(ctx, roots, g):
    _rootset(ctx, roots)
    _integers(g)
    if not 1 <= g < 2 * ctx.n or not g & 1:
        raise ValueError("Expected an odd Galois unit")
    return _action(roots, g, 2 * ctx.n)


def signed_action(coefficients, g):
    if (type(coefficients) is not tuple or len(coefficients) not in (2, 4, 16)
            or any(type(x) is not int or x not in (-1, 0, 1) for x in coefficients)):
        raise ValueError("Expected a strict raw ternary polynomial")
    n = len(coefficients)
    _integers(g)
    if not 1 <= g < 2 * n or not g & 1:
        raise ValueError("Expected an odd signed automorphism")
    result = [0] * n
    for j, value in enumerate(coefficients):
        position = j * g % (2 * n)
        result[position % n] = value * (-1 if position >= n else 1)
    return tuple(result)


def horner(coefficients, point, q):
    _integers(point, q)
    if (type(coefficients) is not tuple or not coefficients
            or any(type(x) is not int for x in coefficients) or not 0 <= point < q or q < 2):
        raise ValueError("Malformed public Horner input")
    value = 0
    for coefficient in reversed(coefficients):
        value = (point * value + coefficient) % q
    return value


def verify_witness(ctx, roots, witness):
    _rootset(ctx, roots)
    if (type(witness) is not tuple or len(witness) != ctx.n or not any(witness)
            or any(type(x) is not int or x not in (-1, 0, 1) for x in witness)):
        raise ValueError("Expected a nonzero strict ternary witness")
    if any(horner(witness, pow(ctx.root, e, ctx.q), ctx.q) for e in roots):
        raise ValueError("Witness does not annihilate all stated roots")
    return witness


@dataclass(frozen=True)
class Orbit:
    representative: tuple[int, ...]
    members: tuple[tuple[int, ...], ...]
    stabilizer: tuple[int, ...]


@dataclass(frozen=True)
class Inventory:
    context: Context
    root_count: int
    orbits: tuple[Orbit, ...]
    #Each item: root tuple, representative, g taking representative to tuple.
    assignments: tuple[tuple[tuple[int, ...], tuple[int, ...], int], ...]

    def validate(self):
        if type(self.context) is not Context:
            raise ValueError("Expected an exact public context")
        ctx = self.context.validate()
        _integers(self.root_count)
        if not 1 <= self.root_count <= min(ctx.n, 4):
            raise ValueError("Invalid bounded root-set size")
        universe = tuple(combinations(ctx.group, self.root_count))
        if type(self.orbits) is not tuple or type(self.assignments) is not tuple:
            raise ValueError("Expected exact orbit inventory tuples")
        for item in self.assignments:
            if type(item) is not tuple or len(item) != 3:
                raise ValueError("Malformed root-set assignment record")
            _rootset(ctx, item[0])
            _rootset(ctx, item[1])
            _integers(item[2])
        if tuple(item[0] for item in self.assignments) != universe:
            raise ValueError("Incomplete or reordered root-set assignment")
        coverage = set()
        representatives = []
        by_rep = {}
        for orbit in self.orbits:
            if type(orbit) is not Orbit:
                raise ValueError("Expected an exact orbit record")
            _rootset(ctx, orbit.representative)
            if type(orbit.members) is not tuple or type(orbit.stabilizer) is not tuple:
                raise ValueError("Malformed orbit member/stabilizer grammar")
            for member in orbit.members:
                _rootset(ctx, member)
            _integers(*orbit.stabilizer)
            expected = tuple(sorted({_action(orbit.representative, g, 2 * ctx.n) for g in ctx.group}))
            stabilizer = tuple(g for g in ctx.group
                               if _action(orbit.representative, g, 2 * ctx.n) == orbit.representative)
            if (type(orbit.members) is not tuple or type(orbit.stabilizer) is not tuple
                    or orbit.members != expected or orbit.stabilizer != stabilizer
                    or orbit.representative != min(expected)
                    or len(expected) * len(stabilizer) != len(ctx.group)
                    or coverage.intersection(expected)):
                raise ValueError("False or overlapping signed Galois orbit")
            coverage.update(expected)
            representatives.append(orbit.representative)
            by_rep[orbit.representative] = set(expected)
        if coverage != set(universe) or representatives != sorted(set(representatives)):
            raise ValueError("Orbit inventory does not partition the entire universe")
        for roots, representative, g in self.assignments:
            _integers(g)
            if (representative not in by_rep or roots not in by_rep[representative]
                    or g not in ctx.group or _action(representative, g, 2 * ctx.n) != roots):
                raise ValueError("Invalid orbit transporter")
        return self


def orbit_inventory(ctx, root_count):
    if type(ctx) is not Context:
        raise ValueError("Expected a public context")
    ctx.validate()
    _integers(root_count)
    if not 1 <= root_count <= min(ctx.n, 4):
        raise ValueError("Invalid bounded root-set size")
    group = ctx.group
    assigned, orbits = {}, []
    for roots in combinations(group, root_count):
        if roots in assigned:
            continue
        images = tuple((_action(roots, g, 2 * ctx.n), g) for g in group)
        members = tuple(sorted({image for image, _ in images}))
        if roots != min(members):
            raise AssertionError("Ascending partition lost its canonical representative")
        orbits.append(Orbit(roots, members, tuple(g for image, g in images if image == roots)))
        for member in members:
            assigned[member] = (roots, min(g for image, g in images if image == member))
    records = tuple((roots, *assigned[roots]) for roots in sorted(assigned))
    return Inventory(ctx, root_count, tuple(orbits), records).validate()


def is_quartic_packet(ctx, roots):
    _rootset(ctx, roots)
    if ctx.n != 16 or len(roots) != 4:
        return False
    return roots == tuple(sorted((roots[0] + 8 * j) % 32 for j in range(4)))


def root_columns(ctx, roots):
    _rootset(ctx, roots)
    points = tuple(pow(ctx.root, e, ctx.q) for e in roots)
    return tuple(tuple(pow(point, j, ctx.q) for point in points) for j in range(ctx.n))


def _columns(columns, q):
    _integers(q)
    if (not 3 <= q <= 257 or type(columns) is not tuple or len(columns) not in (1, 2, 8)
            or type(columns[0]) is not tuple or not 1 <= len(columns[0]) <= 4
            or any(type(column) is not tuple or len(column) != len(columns[0])
                   or any(type(x) is not int or not 0 <= x < q for x in column)
                   for column in columns)):
        raise ValueError("Malformed bounded projected half columns")


def half_vectors(columns, q, counters=None):
    """Lexicographic ternary leaves; update vectors without per-leaf powers."""
    _columns(columns, q)
    values = []

    def walk(j, vector):
        if j == len(columns):
            if counters is not None:
                counters["leaves"] += 1
            yield tuple(values), vector
            return
        for coefficient in (-1, 0, 1):
            if coefficient:
                updated = tuple((a + coefficient * b) % q
                                for a, b in zip(vector, columns[j], strict=True))
                if counters is not None:
                    counters["vector_updates"] += 1
            else:
                updated = vector
            values.append(coefficient)
            yield from walk(j + 1, updated)
            values.pop()

    yield from walk(0, (0,) * len(columns[0]))


@dataclass(frozen=True)
class HalfTable:
    width: int
    q: int
    arity: int
    counts: dict[tuple[int, ...], int]
    #Only the right table retains its TWO lexicographically first assignments.
    samples: dict[tuple[int, ...], tuple[tuple[int, ...], ...]] | None
    leaves: int
    vector_updates: int

    def validate(self):
        _integers(self.width, self.q, self.arity, self.leaves, self.vector_updates)
        if (self.width not in (1, 2, 8) or not 3 <= self.q <= 257 or not 1 <= self.arity <= 4
                or self.leaves != 3 ** self.width or not 0 <= self.vector_updates <= 2 * self.leaves
                or type(self.counts) is not dict or not 1 <= len(self.counts) <= self.leaves
                or any(type(key) is not tuple or len(key) != self.arity
                       or any(type(x) is not int or not 0 <= x < self.q for x in key)
                       or type(count) is not int or count < 1 for key, count in self.counts.items())
                or sum(self.counts.values()) != self.leaves):
            raise ValueError("Malformed half multiplicity histogram")
        if self.samples is not None:
            if type(self.samples) is not dict or set(self.samples) != set(self.counts):
                raise ValueError("Missing right witness buckets")
            for key, samples in self.samples.items():
                if (type(samples) is not tuple or len(samples) != min(2, self.counts[key])
                        or any(type(sample) is not tuple or len(sample) != self.width
                               or any(type(x) is not int or x not in (-1, 0, 1) for x in sample)
                               for sample in samples)
                        or samples != tuple(sorted(set(samples)))):
                    raise ValueError("Malformed two-smallest right witness cache")
        return self


def half_table(columns, q, *, keep_samples):
    _columns(columns, q)
    if type(keep_samples) is not bool:
        raise ValueError("Expected an exact diagnostic Boolean")
    counts, samples = Counter(), {} if keep_samples else None
    counters = {"leaves": 0, "vector_updates": 0}
    for assignment, vector in half_vectors(columns, q, counters):
        counts[vector] += 1
        if samples is not None:
            bucket = samples.get(vector, ())
            if len(bucket) < 2:
                samples[vector] = bucket + (assignment,)
    return HalfTable(len(columns), q, len(columns[0]), dict(counts), samples,
                     counters["leaves"], counters["vector_updates"]).validate()


def recover_nonzero(left_columns, right):
    """Rescan L in lex order; two R samples suffice to exclude only zero."""
    if type(right) is not HalfTable:
        raise ValueError("Expected a strict right half histogram")
    _columns(left_columns, right.q)
    right.validate()
    if (right.samples is None or len(left_columns) != right.width
            or len(left_columns[0]) != right.arity):
        raise ValueError("Recovery requires a matching right witness cache")
    counters = {"leaves": 0, "vector_updates": 0}
    for left, vector in half_vectors(left_columns, right.q, counters):
        opposite = tuple(-x % right.q for x in vector)
        for sample in right.samples.get(opposite, ()):
            witness = left + sample
            if any(witness):
                return witness, counters["leaves"], counters["vector_updates"]
    raise ValueError("Claimed nonzero collision has no recoverable witness")


@dataclass(frozen=True)
class Count:
    roots: tuple[int, ...]
    total_count: int
    denominator: int
    n: int
    half_visits: int
    left_keys: int
    right_keys: int
    vector_updates: int
    extraction_visits: int
    extraction_vector_updates: int
    witness: tuple[int, ...] | None

    def validate(self):
        _integers(self.total_count, self.denominator, self.n, self.half_visits,
                  self.left_keys, self.right_keys, self.vector_updates,
                  self.extraction_visits, self.extraction_vector_updates)
        if (self.n not in (2, 4, 16) or self.denominator != 3 ** self.n
                or not 1 <= self.total_count <= self.denominator or not self.total_count & 1
                or self.half_visits != 2 * 3 ** (self.n // 2)
                or min(self.left_keys, self.right_keys) < 1
                or max(self.left_keys, self.right_keys) > 3 ** (self.n // 2)
                or not 0 <= self.vector_updates <= 2 * self.half_visits
                or not 0 <= self.extraction_visits <= 3 ** (self.n // 2)
                or not 0 <= self.extraction_vector_updates <= 2 * 3 ** (self.n // 2)):
            raise ValueError("Malformed exact root-count ledger")
        if (type(self.roots) is not tuple or not 1 <= len(self.roots) <= min(4, self.n)
                or any(type(e) is not int or not 1 <= e < 2 * self.n or not e & 1 for e in self.roots)
                or self.roots != tuple(sorted(set(self.roots)))):
            raise ValueError("Malformed count root tuple")
        if self.total_count == 1:
            if self.witness is not None or self.extraction_visits or self.extraction_vector_updates:
                raise ValueError("Zero-only count cannot include a nonzero extraction")
        elif (type(self.witness) is not tuple or len(self.witness) != self.n
              or any(type(x) is not int or x not in (-1, 0, 1) for x in self.witness)
              or not any(self.witness) or not self.extraction_visits):
            raise ValueError("Nonzero count needs a nonzero strict ternary witness")
        return self


def count_roots(ctx, roots):
    columns = root_columns(ctx, roots)
    width = ctx.n // 2
    left = half_table(columns[:width], ctx.q, keep_samples=False)
    right = half_table(columns[width:], ctx.q, keep_samples=True)
    count = sum(mass * right.counts.get(tuple(-x % ctx.q for x in vector), 0)
                for vector, mass in left.counts.items())
    witness, visits, updates = None, 0, 0
    if count > 1:
        witness, visits, updates = recover_nonzero(columns[:width], right)
        verify_witness(ctx, roots, witness)  #Independent of projected-column evaluation.
    return Count(roots, count, 3 ** ctx.n, ctx.n, left.leaves + right.leaves,
                 len(left.counts), len(right.counts), left.vector_updates + right.vector_updates,
                 visits, updates, witness).validate()


def scan_prefix(representatives, evaluate, *, limit, on_complete=None):
    """Trusted evaluator/controller seam; synthetic status tests are not laws."""
    _integers(limit)
    if (not 1 <= limit <= 64 or type(representatives) is not tuple or not representatives
            or len(representatives) > 1820 or any(type(rep) is not tuple for rep in representatives)
            or any(not 1 <= len(rep) <= 4
                   or any(type(e) is not int or not 1 <= e < 32 or not e & 1 for e in rep)
                   or rep != tuple(sorted(set(rep))) for rep in representatives)
            or representatives != tuple(sorted(set(representatives)))):
        raise ValueError("Invalid frozen representative prefix")
    records = []
    try:
        for representative in representatives[:limit]:
            result = evaluate(representative)
            if type(result) is not Count or result.validate().roots != representative:
                raise ValueError("Evaluator returned a mismatched count")
            records.append(result)
            if on_complete is not None:
                on_complete(result, len(records))
            if result.witness is not None:
                return "counterexample_found", tuple(records)
    except (TimeoutError, MemoryError):
        return "resource_bounded_inconclusive", tuple(records)
    status = ("full_fixed_inventory_no_counterexample" if len(records) == len(representatives)
              else "bounded_prefix_inconclusive")
    return status, tuple(records)


def mass_counter_scope(status):
    """Interrupted partial records are not counters for all executed work."""
    if type(status) is not str or status not in (
            "counterexample_found", "full_fixed_inventory_no_counterexample",
            "bounded_prefix_inconclusive", "resource_bounded_inconclusive"):
        raise ValueError("Unknown bounded-gate status")
    interrupted = status == "resource_bounded_inconclusive"
    return {"counter_scope": "completed_mass_records_only",
            "interrupted_mass_work_unknown": interrupted,
            "total_work_counter_complete": not interrupted,
            "counter_completeness_scope": "mass half leaves/vector updates; other preparation/verification excluded"}
