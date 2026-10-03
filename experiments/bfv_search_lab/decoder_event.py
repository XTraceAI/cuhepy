"""E111 exact conditional CBD cells and an independently checked event cover.

The only native screen is the disclosed E105 diagnostic with admitted terminal
precision. Its decoder event is already empty under the ordinary uniform cap.
Canonical-residue interval arithmetic is supplied equally to the generic tree;
this module supplies neither a cryptographic proof nor a new noise theorem.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from fractions import Fraction
import hashlib
from itertools import product
import json
from math import prod

from experiments.bfv_search_lab import carry_trace_noise as carry
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import finite_lifetime_noise as noise


def _int(value):
    if type(value) is not int:
        raise ValueError("Exact integer required")
    return value


def _poly(value, n=8):
    if type(value) is not tuple or len(value) != n:
        raise ValueError("Whole bounded polynomial required")
    return tuple(_int(x) for x in value)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class Interval:
    lower: int
    upper: int

    def __post_init__(self):
        if _int(self.lower) > _int(self.upper):
            raise ValueError("Ordered integer interval required")

    def add(self, other):
        return Interval(self.lower+other.lower, self.upper+other.upper)

    def scale(self, value):
        _int(value)
        return Interval(min(value*self.lower, value*self.upper), max(value*self.lower, value*self.upper))


@dataclass(frozen=True)
class Cell:
    """A rectangle of the original CBD atoms, with exact literal-coin mass."""

    atoms: tuple[tuple[int, ...], ...]

    def __post_init__(self):
        if (type(self.atoms) is not tuple or not 1 <= len(self.atoms) <= 8
                or any(type(a) is not tuple or not a or tuple(sorted(set(a))) != a
                       or any(type(x) is not int or x not in (-1, 0, 1) for x in a) for a in self.atoms)):
            raise ValueError("Nonempty bounded CBD atom sets required")

    @classmethod
    def root(cls, n):
        if type(n) is not int or not 1 <= n <= 8:
            raise ValueError("Bounded CBD dimension required")
        return cls(((-1, 0, 1),)*n)

    @property
    def mass(self):
        return prod(sum(2 if x == 0 else 1 for x in a) for a in self.atoms)

    @property
    def support(self):
        return prod(map(len, self.atoms))

    @property
    def singleton(self):
        return all(len(a) == 1 for a in self.atoms)

    def split(self):
        i = next((i for i, a in enumerate(self.atoms) if len(a) != 1), None)
        if i is None:
            return ()
        return tuple(Cell(self.atoms[:i]+((x,),)+self.atoms[i+1:]) for x in self.atoms[i])


def affine_interval(constant, weights, cell):
    if type(weights) is not tuple or len(weights) != len(cell.atoms):
        raise ValueError("One coefficient per original CBD atom required")
    result = Interval(_int(constant), constant)
    for weight, atoms in zip(weights, cell.atoms, strict=True):
        result = result.add(Interval(atoms[0], atoms[-1]).scale(weight))
    return result


def canonical_arcs(interval, modulus):
    """Exact continuous-interval image modulo m, at most two sorted arcs.

    This encloses an affine CBD cell; it does not assert that its every integer
    or every pair of digit values occurs with independent probability.
    """
    if _int(modulus) < 2:
        raise ValueError("Positive residue modulus required")
    if interval.upper-interval.lower >= modulus-1:
        return (Interval(0, modulus-1),)
    lo, hi = interval.lower % modulus, interval.upper % modulus
    if interval.lower//modulus == interval.upper//modulus:
        return (Interval(lo, hi),)
    return (Interval(0, hi), Interval(lo, modulus-1))


def digit_interval(arcs, level, bits=4):
    if type(level) is not int or not 0 <= level <= 60 or type(bits) is not int or not 1 <= bits <= 60:
        raise ValueError("Bounded radix position required")
    values = tuple(image for arc in arcs for image in canonical_arcs(
        Interval(arc.lower >> (bits*level), arc.upper >> (bits*level)), 1 << bits))
    if not values:
        raise ValueError("Nonempty canonical arcs required")
    return Interval(min(x.lower for x in values), max(x.upper for x in values))


@dataclass(frozen=True)
class AffineEvent:
    """Abstract boundary-test event; not an alternative native parameter set."""

    constants: tuple[int, ...]
    matrix: tuple[tuple[int, ...], ...]
    radius: int

    def __post_init__(self):
        if (type(self.constants) is not tuple or not 1 <= len(self.constants) <= 8
                or type(self.matrix) is not tuple or len(self.matrix) != len(self.constants)
                or type(self.matrix[0]) is not tuple or not 1 <= len(self.matrix[0]) <= 8
                or any(type(row) is not tuple or len(row) != len(self.matrix[0]) for row in self.matrix)
                or _int(self.radius) < 0):
            raise ValueError("Bounded abstract affine event required")
        for row in self.matrix:
            for value in row:
                _int(value)
        for value in self.constants:
            _int(value)

    @property
    def n(self):
        return len(self.matrix[0])

    @property
    def event_digest(self):
        return digest({"abstract_affine_boundary_diagnostic": asdict(self)})

    def bound(self, cell):
        if len(cell.atoms) != self.n:
            raise ValueError("Wrong event cell dimension")
        return tuple(affine_interval(c, row, cell) for c, row in zip(self.constants, self.matrix, strict=True))

    def classify(self, cell):
        bounds = self.bound(cell)
        if all(-self.radius <= x.lower <= x.upper <= self.radius for x in bounds):
            return "safe"
        if any(x.lower > self.radius or x.upper < -self.radius for x in bounds):
            return "unsafe"
        return "unresolved"


@dataclass(frozen=True)
class NativeBound:
    original: tuple[Interval, ...]
    source_arcs: tuple[tuple[Interval, ...], ...]
    digit_ranges: tuple[tuple[Interval, ...], ...]
    maintenance: tuple[Interval, ...]
    phase: tuple[Interval, ...]
    phase_cap: int
    terminal_cap: int


@dataclass(frozen=True)
class Evaluation:
    original: tuple[int, ...]
    maintenance: tuple[int, ...]
    final_phase: tuple[int, ...]
    canonical: tuple[int, ...]
    digits: tuple[tuple[int, ...], ...]
    components: tuple[tuple[int, ...], tuple[int, ...]]
    terminal: tuple[tuple[int, ...], tuple[int, ...]]
    terminal_phase: tuple[int, ...]
    plaintext: tuple[int, ...]
    distances: tuple[int, ...] | None
    ranked_ids: tuple[int, ...] | None
    failed: bool


def _switch(source, key, q):
    digits = carry.digit_columns(source)
    products = tuple(tuple(noise.multiply(d, row[k]) for d, row in zip(digits, key, strict=True)) for k in range(2))
    return tuple(tuple(sum(p[i] for p in family) % q for i in range(8)) for family in products)


def round_coefficient(c, q, p, t):
    """Exact nearest t-congruent lift; output is reduced only by the caller."""
    if any(type(x) is not int for x in (c, q, p, t)) or not 0 <= c < q or not 3 <= t < p < q:
        raise ValueError("Canonical bounded terminal coefficient required")
    residue = c % t
    return ((2*(p*c-q*residue)+q*t)//(2*q*t))*t+residue


class NativeEvent:
    """Trusted local compiler of the ONE disclosed E105 graph and event.

    Its registered key phases are checked; independent API extraction checks
    are paid by the runner. A digest does not authenticate a server's compiler.
    """

    n, q, t, bits, levels, ids = 8, (1 << 61)-1, 5, 4, 16, (20, 40, 10)

    def __init__(self, graph, query_bits):
        if (graph.n != self.n or graph.q != self.q or graph.t != self.t
                or graph.keys.padded != 2 or graph.keys.digit_bits != self.bits
                or len(graph.keys.rotations) != 1 or graph.keys.rotations[0][0] != 9
                or graph.pk.eta != 1 or type(query_bits) is not tuple or len(query_bits) != 2
                or any(type(x) is not int or x not in (0, 1) for x in query_bits)):
            raise ValueError("Registered E105 N8/D2/t5/Q61/CBD1 context required")
        self.query_bits = query_bits
        self.secret = _poly(graph.secret)
        self.index_message, self.index_error = _poly(graph.index_message), _poly(graph.index_error)
        self.index_mask, self.query_mask = _poly(graph.index_mask), _poly(graph.query_mask)
        if (any(x not in (-1, 0, 1) for x in self.secret+self.index_error)
                or any(not -2 <= x <= 2 for x in self.index_message)
                or any(not 0 <= x < self.q for x in self.index_mask+self.query_mask)):
            raise ValueError("Supported secret/error/message/canonical masks required")
        self.keys = tuple(tuple(tuple(_poly(tuple(map(int, p))) for p in row) for row in family)
                          for family in (graph.keys.relin, graph.keys.rotations[0][1]))
        self.errors = tuple(tuple(_poly(tuple(row)) for row in family) for family in graph.errors)
        targets = noise.multiply(self.secret, self.secret), carry.automorphism(self.secret, 9)
        for key, errors, target in zip(self.keys, self.errors, targets, strict=True):
            if len(key) != 16 or len(errors) != 16 or any(len(row) != 2 for row in key):
                raise ValueError("Exactly sixteen two-component gadget rows required")
            for j, (row, error) in enumerate(zip(key, errors, strict=True)):
                if any(e not in (-1, 0, 1) for e in error) or any(not 0 <= x < self.q for p in row for x in p):
                    raise ValueError("Supported fixed gadget errors and canonical key required")
                phase = noise.add(row[0], noise.multiply(row[1], self.secret))
                if tuple(x % self.q for x in phase) != tuple(((1 << (4*j))*v+5*e) % self.q
                                                             for v, e in zip(target, error, strict=True)):
                    raise ValueError("Wrong registered full-Q key phase")
        self.p = int(compact.terminal_modulus(graph.pk.q, 5, 16))
        self.message = (1-2*query_bits[1], 1-2*query_bits[0])+(0,)*6
        self.index_phase = tuple(m+5*e for m, e in zip(self.index_message, self.index_error, strict=True))
        self.index_body = tuple((v-z) % self.q for v, z in zip(self.index_phase,
                                                               noise.multiply(self.index_mask, self.secret), strict=True))
        self.query_body = tuple((m-z) % self.q for m, z in zip(self.message,
                                                             noise.multiply(self.query_mask, self.secret), strict=True))
        c2 = tuple(x % self.q for x in noise.multiply(self.index_mask, self.query_mask))
        self.relin = _switch(c2, self.keys[0], self.q)
        residual = noise.switch_residual(c2, self.errors[0], self.q, 16, 5)
        self.fixed_maintenance = carry.projection(residual)
        self.original_mean = carry.projection(noise.multiply(self.index_phase, self.message))
        units = tuple(tuple(int(i == j) for i in range(8)) for j in range(8))
        self.source_columns = tuple(carry.projection(tuple(5*x for x in noise.multiply(self.index_phase, u))) for u in units)
        self.mask_columns = tuple(carry.automorphism(carry.monomial(tuple(5*x for x in noise.multiply(self.index_mask, u)), -1), 9)
                                  for u in units)
        mask0 = noise.add(noise.add(noise.multiply(self.query_body, self.index_mask),
                                   noise.multiply(self.query_mask, self.index_body)), self.relin[1])
        self.beta = tuple(x % self.q for x in carry.automorphism(carry.monomial(mask0, -1), 9))
        self.expected_plaintext = tuple(x % 5 for x in carry.projection(noise.multiply(self.index_message, self.message)))
        self.expected_distances = tuple(sum(a != b for a, b in zip(query_bits, row, strict=True))
                                        for row in ((0, 0), (0, 1), (1, 0)))
        self.expected_rank = tuple(i for _, i in sorted(zip(self.expected_distances, self.ids, strict=True)))
        # This premise holds for every joint E, not separately sampled terms.
        if (any(x % 5 for col in self.source_columns for x in col)
                or any(x % 5 for x in self.fixed_maintenance)
                or tuple(x % 5 for x in self.original_mean) != self.expected_plaintext):
            raise ValueError("Missing complete same-E plaintext congruence")
        self.event_digest = digest({"registered_conditional_native_event": {
            "q": self.q, "t": self.t, "p": self.p, "bits": query_bits, "ids": self.ids,
            "secret": self.secret, "index_message": self.index_message, "index_error": self.index_error,
            "index_mask": self.index_mask, "query_mask": self.query_mask, "keys": self.keys, "errors": self.errors}})

    def bound(self, cell):
        if len(cell.atoms) != 8:
            raise ValueError("Whole N8 same-error cell required")
        original = tuple(affine_interval(self.original_mean[k], tuple(c[k] for c in self.source_columns), cell) for k in range(8))
        arcs = tuple(canonical_arcs(affine_interval(self.beta[k], tuple(c[k] for c in self.mask_columns), cell), self.q) for k in range(8))
        digits = tuple(tuple(digit_interval(a, j) for a in arcs) for j in range(16))
        maintenance = []
        for k in range(8):
            value = Interval(self.fixed_maintenance[k], self.fixed_maintenance[k])
            for digit, error in zip(digits, self.errors[1], strict=True):
                for coefficient, weight in zip(digit, noise.coefficient_weights(error, k, 5), strict=True):
                    value = value.add(coefficient.scale(weight))
            maintenance.append(value)
        phase = tuple(a.add(b) for a, b in zip(original, maintenance, strict=True))
        cap = max(max(abs(x.lower), abs(x.upper)) for x in phase)
        terminal_cap = (self.p*cap+self.q-1)//self.q+((self.n+1)*self.t+1)//2
        return NativeBound(original, arcs, digits, tuple(maintenance), phase, cap, terminal_cap)

    def classify(self, cell):
        bound = self.bound(cell)
        if 2*bound.phase_cap < self.q and 2*bound.terminal_cap < self.p:
            return "safe"
        if cell.singleton:
            return "unsafe" if self.evaluate(tuple(a[0] for a in cell.atoms)).failed else "safe"
        return "unresolved"

    def evaluate(self, errors):
        errors = _poly(errors)
        if any(e not in (-1, 0, 1) for e in errors):
            raise ValueError("Only the registered fresh CBD1 support required")
        query_body = tuple((v+5*e) % self.q for v, e in zip(self.query_body, errors, strict=True))
        c0 = noise.add(noise.multiply(query_body, self.index_body), self.relin[0])
        c1 = noise.add(noise.add(noise.multiply(query_body, self.index_mask),
                               noise.multiply(self.query_mask, self.index_body)), self.relin[1])
        shifted = tuple(tuple(x % self.q for x in carry.monomial(p, -1)) for p in (c0, c1))
        transformed = tuple(tuple(x % self.q for x in carry.automorphism(p, 9)) for p in shifted)
        switched = _switch(transformed[1], self.keys[1], self.q)
        components = tuple(tuple(x % self.q for x in noise.add(a, b)) for a, b in
                           ((shifted[0], noise.add(transformed[0], switched[0])), (shifted[1], switched[1])))
        digits = carry.digit_columns(transformed[1])
        original = tuple(self.original_mean[k]+sum(e*c[k] for e, c in zip(errors, self.source_columns, strict=True)) for k in range(8))
        residual = noise.switch_residual(transformed[1], self.errors[1], self.q, 16, 5)
        maintenance = noise.add(self.fixed_maintenance, residual)
        final = noise.add(original, maintenance)
        actual = noise.add(components[0], noise.multiply(components[1], self.secret))
        if tuple(x % self.q for x in actual) != tuple(x % self.q for x in final):
            raise AssertionError("Same-E symbolic/full-cipher phase disagreement")
        terminal = tuple(tuple(round_coefficient(c, self.q, self.p, 5) % self.p for c in poly) for poly in components)
        terminal_phase = tuple(((x+self.p//2) % self.p)-self.p//2
                               for x in noise.add(terminal[0], noise.multiply(terminal[1], self.secret)))
        plaintext = tuple(x % 5 for x in terminal_phase)
        dots = tuple(((plaintext[k]*pow(2, -1, 5)+2) % 5)-2 for k in (0, 2, 4))
        distances = None if any((2-x) % 2 for x in dots) else tuple((2-x)//2 for x in dots)
        ranked = None if distances is None else tuple(i for _, i in sorted(zip(distances, self.ids, strict=True)))
        failed = plaintext != self.expected_plaintext or distances != self.expected_distances or ranked != self.expected_rank
        return Evaluation(original, maintenance, final, transformed[1], digits, components, terminal,
                          terminal_phase, plaintext, distances, ranked, failed)

    def uniform_control(self):
        product_cap, switch_cap = 8*7**2, 5*8*15*16
        phase_cap = 2*(product_cap+switch_cap)+switch_cap
        terminal_cap = (self.p*phase_cap+self.q-1)//self.q+23
        assert phase_cap == 29584 and terminal_cap == 24 and 2*terminal_cap < self.p
        return {"product_cap": product_cap, "switch_cap": switch_cap, "whole_trace_cap": phase_cap,
                "terminal_cap": terminal_cap, "failure_interval": ["0", "0"],
                "canonical_digit_independence_not_assumed": True}


@dataclass(frozen=True)
class Node:
    cell: Cell
    status: str
    children: tuple[Node, ...] = ()


@dataclass(frozen=True)
class Certificate:
    event_digest: str
    rule: str
    root: Node


def certify(event, *, rule="generic", max_depth=8):
    if rule not in ("generic", "candidate-residue") or type(max_depth) is not int or not 0 <= max_depth <= event.n:
        raise ValueError("Registered rule and bounded tree depth required")

    def visit(cell, depth):
        status = event.classify(cell)
        if status != "unresolved" or depth == max_depth:
            return Node(cell, status)
        children = cell.split()
        return Node(cell, "branch", tuple(visit(child, depth+1) for child in children))

    # Exact residue images are ordinary interval arithmetic. The equally
    # optimized generic control gets precisely the candidate rule and cache.
    return Certificate(event.event_digest, rule, visit(Cell.root(event.n), 0))


def check_certificate(event, certificate):
    """Recompute cell bounds/masses and exact cover; no native graph replay.

    Singleton native unsafe claims require the declared literal decoder; safe
    non-singleton native leaves use the rounding-margin theorem only.
    """
    if (type(certificate) is not Certificate or certificate.event_digest != event.event_digest
            or certificate.rule not in ("generic", "candidate-residue")
            or type(certificate.root) is not Node or certificate.root.cell != Cell.root(event.n)):
        raise ValueError("Wrong pinned event certificate")
    counts = {"nodes": 0, "branch_nodes": 0, "safe_leaves": 0, "unsafe_leaves": 0,
              "unresolved_leaves": 0, "safe_mass": 0, "unsafe_mass": 0,
              "unresolved_mass": 0, "covered_distinct_states": 0}

    def visit(node):
        if type(node) is not Node or type(node.cell) is not Cell or type(node.children) is not tuple:
            raise ValueError("Strict cell certificate grammar required")
        counts["nodes"] += 1
        if node.status == "branch":
            if (not node.children or any(type(child) is not Node for child in node.children)
                    or tuple(child.cell for child in node.children) != node.cell.split()):
                raise ValueError("Branch must partition the original atom cell exactly")
            counts["branch_nodes"] += 1
            for child in node.children:
                visit(child)
            return
        if node.children or node.status not in ("safe", "unsafe", "unresolved"):
            raise ValueError("Wrong leaf grammar")
        if node.status != "unresolved" and event.classify(node.cell) != node.status:
            raise ValueError("Unsound leaf event claim")
        counts[node.status+"_leaves"] += 1
        counts[node.status+"_mass"] += node.cell.mass
        counts["covered_distinct_states"] += node.cell.support

    visit(certificate.root)
    denominator = 4**event.n
    if sum(counts[k+"_mass"] for k in ("safe", "unsafe", "unresolved")) != denominator:
        raise ValueError("Missing exact CBD mass")
    counts.update({"denominator": denominator, "failure_lower": str(Fraction(counts["unsafe_mass"], denominator)),
                   "failure_upper": str(Fraction(counts["unsafe_mass"]+counts["unresolved_mass"], denominator)),
                   "safe_lower": str(Fraction(counts["safe_mass"], denominator)),
                   "abstract_diagnostic": type(event) is AffineEvent})
    return counts


def certificate_bytes(certificate):
    """Declared JSON cell cover, not cryptographic proof/opening bytes."""
    return json.dumps(asdict(certificate), sort_keys=True, separators=(",", ":")).encode()


def weighted_states(n):
    Cell.root(n)
    for errors in product((-1, 0, 1), repeat=n):
        yield errors, 1 << errors.count(0)
