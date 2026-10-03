"""Q57 exact symbolic census of the existing native BGV butterfly.

This is a public algebra/count oracle, not a verifier, TEE, benchmark, or a
novel compiler. Canonical digit sources are opaque typed inputs: a linear map
is never moved through full-Q decomposition or terminal rounding. The generic
control is explicitly granted the same exact normalization and shared basis.

Operators normalize to sums of X**h sigma_b(k) sigma_a(x), with at most one
fixed key/index polynomial k per term. Separate dictionary atoms are sufficient
adjoint materializations, not an optimum or a lower bound on protected memory.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
import hashlib
import json
from typing import Iterable, Mapping


@dataclass(frozen=True, order=True)
class Atom:
    """X**shift sigma_symbol(symbol) sigma_argument(input)."""

    shift: int = 0
    argument: int = 1
    symbol: str = ""
    symbol_auto: int = 1


@dataclass(frozen=True)
class Operator:
    n: int
    terms: tuple[tuple[Atom, int], ...]

    @classmethod
    def make(cls, n: int, terms: Iterable[tuple[Atom, int]]) -> Operator:
        if type(n) is not int or n < 2 or n & (n-1):
            raise ValueError("Power-of-two polynomial dimension required")
        accumulated = Counter()
        for atom, weight in terms:
            if type(atom) is not Atom or type(weight) is not int:
                raise TypeError("Exact typed atoms and integer weights required")
            if atom.argument % 2 != 1 or atom.symbol_auto % 2 != 1:
                raise ValueError("Automorphism exponents must be odd")
            shift = atom.shift % (2*n)
            canonical = Atom(shift % n, atom.argument % (2*n), atom.symbol,
                             atom.symbol_auto % (2*n) if atom.symbol else 1)
            accumulated[canonical] += weight * (-1 if shift >= n else 1)
        return cls(n, tuple(sorted((a, w) for a, w in accumulated.items() if w)))

    @classmethod
    def identity(cls, n: int) -> Operator:
        return cls.make(n, ((Atom(), 1),))

    @classmethod
    def monomial(cls, n: int, shift: int) -> Operator:
        return cls.make(n, ((Atom(shift), 1),))

    @classmethod
    def automorphism(cls, n: int, exponent: int) -> Operator:
        return cls.make(n, ((Atom(argument=exponent), 1),))

    @classmethod
    def convolution(cls, n: int, symbol: str) -> Operator:
        if not symbol:
            raise ValueError("A fixed polynomial identity is required")
        return cls.make(n, ((Atom(symbol=symbol), 1),))

    def scale(self, coefficient: int) -> Operator:
        return self.make(self.n, ((a, coefficient*w) for a, w in self.terms))

    def __add__(self, other: Operator) -> Operator:
        self._compatible(other)
        return self.make(self.n, self.terms + other.terms)

    def _compatible(self, other: Operator) -> None:
        if type(other) is not Operator or other.n != self.n:
            raise ValueError("Operators belong to different polynomial rings")

    def compose(self, inner: Operator) -> Operator:
        """Compose exactly; reject a two-fixed-polynomial term in this family.

        Such a term can be represented by a more general algebra, but is not
        required by the frozen native graph between canonical cuts. Rejecting
        it ensures the claimed degree-one dependency invariant is executable.
        """
        self._compatible(inner)
        terms = []
        for outer, a in self.terms:
            for inside, b in inner.terms:
                if outer.symbol and inside.symbol:
                    raise ValueError("Two fixed-polynomial factors exceed this typed family")
                symbol = outer.symbol or inside.symbol
                turned = (outer.symbol_auto if outer.symbol else
                          outer.argument*inside.symbol_auto)
                terms.append((Atom(outer.shift+outer.argument*inside.shift,
                                   outer.argument*inside.argument, symbol, turned), a*b))
        return self.make(self.n, terms)

    def evaluate(self, value: tuple[int, ...], fixed: Mapping[str, tuple[int, ...]],
                 q: int) -> tuple[int, ...]:
        """Independent slow coefficient arithmetic for small exact tests."""
        if type(q) is not int or q < 3 or len(value) != self.n:
            raise ValueError("Wrong public arithmetic shape")
        result = [0]*self.n
        for atom, weight in self.terms:
            vector = automorphism(value, atom.argument, q)
            if atom.symbol:
                vector = multiply(automorphism(fixed[atom.symbol], atom.symbol_auto, q),
                                  vector, q)
            vector = monomial(vector, atom.shift, q)
            result = [(a+weight*b) % q for a, b in zip(result, vector, strict=True)]
        return tuple(result)


def monomial(value: tuple[int, ...], shift: int, q: int) -> tuple[int, ...]:
    result, n = [0]*len(value), len(value)
    for i, x in enumerate(value):
        position = (i+shift) % (2*n)
        result[position % n] = (x if position < n else -x) % q
    return tuple(result)


def automorphism(value: tuple[int, ...], exponent: int, q: int) -> tuple[int, ...]:
    n = len(value)
    if exponent % 2 != 1:
        raise ValueError("Not a negacyclic automorphism")
    result = [0]*n
    for i, x in enumerate(value):
        position = i*exponent % (2*n)
        result[position % n] = (x if position < n else -x) % q
    return tuple(result)


def multiply(left: tuple[int, ...], right: tuple[int, ...], q: int) -> tuple[int, ...]:
    if len(left) != len(right):
        raise ValueError("Polynomial lengths differ")
    n, result = len(left), [0]*len(left)
    for i, x in enumerate(left):
        for j, y in enumerate(right):
            position = i+j
            result[position % n] += x*y*(-1 if position >= n else 1)
    return tuple(x % q for x in result)


@dataclass(frozen=True)
class Node:
    name: str
    inputs: tuple[tuple[str, Operator], ...]
    canonical: bool = False
    terminal: bool = False
    semantic_tiles: frozenset[int] = frozenset()


@dataclass(frozen=True)
class Graph:
    n: int
    padded: int
    tiles: int
    digits: int
    nodes: tuple[Node, ...]
    finals: tuple[str, str]
    digit_sources: tuple[str, ...]
    rotations: int

    @property
    def mandatory(self) -> frozenset[str]:
        return frozenset(node.name for node in self.nodes if node.canonical or node.terminal)

    @property
    def optional(self) -> frozenset[str]:
        return frozenset(node.name for node in self.nodes if not node.canonical and not node.terminal)


def butterfly_graph(n: int, padded: int, tiles: int, digits: int = 4) -> Graph:
    """One actual native group, including the one-tile partial-group schedule."""
    if (type(n) is not int or n < 2 or n & (n-1) or type(padded) is not int
            or padded < 1 or padded & (padded-1) or padded > n//2
            or type(tiles) is not int or not 1 <= tiles <= padded
            or type(digits) is not int or not 1 <= digits <= 16):
        raise ValueError("Invalid butterfly geometry")
    one = Operator.identity(n)
    nodes, digit_sources, work = [], [], []
    initial = Operator.monomial(n, 1-padded)
    for i in range(tiles):
        a0, a1 = (Operator.convolution(n, f"index:{i}:{k}") for k in range(2))
        dependencies = frozenset((i,))
        tensor = tuple(f"tensor:{i}:{k}" for k in range(3))
        nodes.extend((Node(tensor[0], (("query:0", a0),), semantic_tiles=dependencies),
                      Node(tensor[1], (("query:0", a1), ("query:1", a0)),
                           semantic_tiles=dependencies),
                      Node(tensor[2], (("query:1", a1),), canonical=True,
                           semantic_tiles=dependencies)))
        inputs = [[], []]
        inputs[0].append((tensor[0], initial))
        inputs[1].append((tensor[1], initial))
        for digit in range(digits):
            source = f"digit:{tensor[2]}:{digit}"
            digit_sources.append(source)
            for k in range(2):
                op = initial.compose(Operator.convolution(n, f"relin:{digit}:{k}"))
                inputs[k].append((source, op))
        pair = tuple(f"product:{i}:{k}" for k in range(2))
        nodes.extend(Node(pair[k], tuple(inputs[k]), semantic_tiles=dependencies) for k in range(2))
        work.append((pair, dependencies))
    shift, exponent, stage, rotations = padded//2, 1+2*n//padded, 0, 0
    while shift:
        merged = []
        auto, right_shift = (Operator.automorphism(n, exponent),
                             Operator.monomial(n, shift))
        for position in range(min(shift, len(work))):
            left, dependencies = work[position]
            right = work[position+shift] if position+shift < len(work) else None
            if right:
                dependencies = dependencies | right[1]
            cut = f"rotation:{stage}:{position}:source"
            cut_inputs = [(left[1], auto)]
            if right:
                cut_inputs.append((right[0][1], auto.compose(right_shift).scale(-1)))
            nodes.append(Node(cut, tuple(cut_inputs), canonical=True,
                              semantic_tiles=dependencies))
            pair = tuple(f"rotation:{stage}:{position}:out{k}" for k in range(2))
            inputs = [[(left[0], one+auto)], [(left[1], one)]]
            if right:
                inputs[0].append((right[0][0], right_shift+auto.compose(right_shift).scale(-1)))
                inputs[1].append((right[0][1], right_shift))
            for digit in range(digits):
                source = f"digit:{cut}:{digit}"
                digit_sources.append(source)
                for k in range(2):
                    inputs[k].append((source, Operator.convolution(n, f"switch:{stage}:{digit}:{k}")))
            nodes.extend(Node(pair[k], tuple(inputs[k]), semantic_tiles=dependencies) for k in range(2))
            merged.append((pair, dependencies))
            rotations += 1
        work, shift, exponent, stage = merged, shift//2, exponent*exponent % (2*n), stage+1
    finals = work[0][0]
    # Terminal full-Q polynomials remain part of the relation; the trusted
    # checker subsequently rounds ALL coordinates and frames the final packet.
    nodes = [Node(node.name, node.inputs, node.canonical, node.name in finals,
                  node.semantic_tiles) for node in nodes]
    return Graph(n, padded, tiles, digits, tuple(nodes), finals, tuple(digit_sources), rotations)


def cuts_for(graph: Graph, policy: str) -> frozenset[str]:
    if policy == "every-local":
        return frozenset(node.name for node in graph.nodes)
    if policy == "product-cut":
        return graph.mandatory | frozenset(node.name for node in graph.nodes
                                          if node.name.startswith("product:"))
    if policy == "maximal-affine":
        return graph.mandatory
    raise ValueError("Unknown explicitly bounded cut policy")


def _cut_validation(graph: Graph, cuts: frozenset[str]) -> None:
    names = frozenset(node.name for node in graph.nodes)
    if type(cuts) is not frozenset or not graph.mandatory <= cuts or not cuts <= names:
        raise ValueError("All canonical/terminal sources and only actual nodes must be retained")


def compile_equations(graph: Graph, cuts: frozenset[str]) -> dict[str, dict[str, Operator]]:
    """Independent generic sparse affine elimination, tiny-geometry oracle.

    Each residual has target coefficient +I and input coefficients -L. These
    exact expressions are intentionally also the strongest generic control.
    """
    _cut_validation(graph, cuts)
    one = Operator.identity(graph.n)
    values, residuals = {}, {}
    for node in graph.nodes:
        expression = {}
        for parent, op in node.inputs:
            source = values.get(parent, {parent: one})
            for variable, coefficient in source.items():
                term = op.compose(coefficient)
                expression[variable] = expression.get(variable, Operator.make(graph.n, ())) + term
        expression = {k: v for k, v in expression.items() if v.terms}
        if node.name in cuts:
            residuals[node.name] = {node.name: one, **{k: v.scale(-1) for k, v in expression.items()}}
            values[node.name] = {node.name: one}
        else:
            values[node.name] = expression
    return residuals


def _reachable_outputs(graph: Graph, source: str, cuts: frozenset[str], *,
                       initial: Iterable[tuple[str, Operator]] = ()) -> dict[str, Operator]:
    """Matrix-free one-source propagation; no dense N-by-N materialization."""
    consumers = defaultdict(list)
    positions = {node.name: i for i, node in enumerate(graph.nodes)}
    for node in graph.nodes:
        for parent, op in node.inputs:
            consumers[parent].append((node.name, op))
    pending = {name: op for name, op in initial}
    if not pending:
        for name, op in consumers[source]:
            pending[name] = pending.get(name, Operator.make(graph.n, ())) + op
    results = {}
    # A tiny heap would also work; a set of reached nodes and the fixed order
    # avoids visiting the unrelated branches for every individual source.
    ready = set(pending)
    while ready:
        name = min(ready, key=positions.__getitem__)
        ready.remove(name)
        expression = pending.pop(name)
        if not expression.terms:
            continue
        if name in cuts:
            results[name] = expression
            continue
        for child, op in consumers[name]:
            combined = op.compose(expression)
            pending[child] = pending.get(child, Operator.make(graph.n, ())) + combined
            ready.add(child)
    return results


def _digest_atoms(atoms: Iterable[Atom]) -> str:
    body = [[a.shift, a.argument, a.symbol, a.symbol_auto] for a in sorted(atoms)]
    return hashlib.sha256(json.dumps(body, separators=(",", ":")).encode()).hexdigest()


def census(graph: Graph, cuts: frozenset[str]) -> dict:
    """Exact atomic basis dictionary, compressed only across independent tiles.

    Index atoms are unique to their tile even if ciphertext bytes happen to
    match. Key atoms share the enrolled key identity across all consumers.
    Bilinear row weights and adjoint linear combinations remain real work.
    """
    _cut_validation(graph, cuts)
    fixed, index_counts, index_hashes = set((Atom(),)), [], []
    coefficient_terms, source_equation_pairs = len(cuts), len(cuts)
    # Query contributions are split by independent fixed tile polynomial.
    # They are counted as a basis, not independent query adjoints: the final
    # strongest generic control can SUM their contributions into two h_query.
    for tile in range(graph.tiles):
        tile_atoms = set()
        contributions = ((f"tensor:{tile}:0", 0), (f"tensor:{tile}:1", 0),
                         (f"tensor:{tile}:1", 1), (f"tensor:{tile}:2", 1))
        for name, component in contributions:
            op = Operator.convolution(graph.n, f"index:{tile}:{component}")
            outputs = _reachable_outputs(graph, "", cuts, initial=((name, op),))
            source_equation_pairs += len(outputs)
            coefficient_terms += sum(len(x.terms) for x in outputs.values())
            tile_atoms.update(atom for x in outputs.values() for atom, _ in x.terms)
        index_counts.append(len(tile_atoms))
        # Canonicalize the *tile identity only* in this compressed record.
        index_hashes.append(_digest_atoms(Atom(a.shift, a.argument,
                                             a.symbol.replace(f"index:{tile}:", "index:local:"),
                                             a.symbol_auto) for a in tile_atoms))
    inputs = list(graph.digit_sources) + [node.name for node in graph.nodes
                                          if node.name in cuts and not node.canonical]
    for source in inputs:
        outputs = _reachable_outputs(graph, source, cuts)
        source_equation_pairs += len(outputs)
        coefficient_terms += sum(len(x.terms) for x in outputs.values())
        fixed.update(atom for x in outputs.values() for atom, _ in x.terms)
    fixed = frozenset(fixed)
    if any(atom.symbol.startswith("index:") for atom in fixed):
        raise AssertionError("An index map leaked into fixed key state")
    return {"cuts": len(cuts), "canonical_digit_sources": graph.tiles+graph.rotations,
            "canonical_digit_variables": len(graph.digit_sources), "rotations": graph.rotations,
            "terminal_polynomials": 2, "optional_cuts": len(cuts-graph.mandatory),
            "index_atomic_operators": sum(index_counts),
            "fixed_atomic_operators": len(fixed),
            "all_atomic_operators": sum(index_counts)+len(fixed),
            "index_atoms_per_tile": index_counts, "index_dictionary_hashes_per_tile": index_hashes,
            "fixed_dictionary_sha256": _digest_atoms(fixed),
            "fixed_dictionary": [[a.shift, a.argument, a.symbol, a.symbol_auto] for a in sorted(fixed)],
            "coefficient_atom_occurrences": coefficient_terms,
            "source_equation_pairs_before_query_bundling": source_equation_pairs,
            "update_invalidation": {"one_tile_index_basis_atoms": index_counts[0],
                                    "all_query_adjoint_vectors_per_prime_round": 2,
                                    "key_basis_atoms": 0,
                                    "source_values": "all descendant canonical values may change; not stored adjoint invalidations"},
            "generic_control": "same exact symbolic elimination, basis, bilinear weights and adjoint combinations"}


def body_ledger(graph: Graph, cuts: frozenset[str], *, q_bits: int = 120,
                terminal_bits: int = 25, primes: int = 2, rounds: int = 3) -> dict:
    """Serialization/state MODELS; no ABI, measured allocation or timing."""
    _cut_validation(graph, cuts)
    source_width = (q_bits+7)//8
    digit_sources = graph.tiles+graph.rotations
    variables = 2+len(cuts)+digit_sources*graph.digits
    return {"full_Q_canonical_body_bytes_model": len(cuts)*graph.n*source_width,
            "witness_digit_values_derived_not_transmitted": digit_sources*graph.digits*graph.n,
            "terminal_full_Q_body_bytes_included": 2*graph.n*source_width,
            "compact_final_body_bytes_separate_model": (2*graph.n*terminal_bits+7)//8,
            "one_row_residual_matrix_shape_per_prime": [len(cuts), graph.n],
            "full_materialized_adjoints_bytes_upper_model": variables*graph.n*primes*rounds*8,
            "bilinear_entropy_field_elements_fresh_model": primes*rounds*(len(cuts)+graph.n),
            "terminal_coordinates_trusted_rounding": 2*graph.n,
            "framing_context_hash_receipt_transport_entropy_sampling_not_counted": True,
            "static_models_not_timings_or_minimum_state": True}


def evaluate_trace(graph: Graph, query: tuple[tuple[int, ...], tuple[int, ...]],
                   fixed: Mapping[str, tuple[int, ...]], q: int, digit_bits: int) -> dict[str, tuple[int, ...]]:
    """Public schoolbook execution of the typed graph for small exact oracles."""
    if q.bit_length() > digit_bits*graph.digits:
        raise ValueError("Digit count cannot represent full Q")
    values = {f"query:{k}": tuple(x % q for x in query[k]) for k in range(2)}
    mask = (1 << digit_bits)-1
    for node in graph.nodes:
        result = [0]*graph.n
        for parent, op in node.inputs:
            term = op.evaluate(values[parent], fixed, q)
            result = [(a+b) % q for a, b in zip(result, term, strict=True)]
        values[node.name] = tuple(result)
        if node.canonical:
            for digit in range(graph.digits):
                values[f"digit:{node.name}:{digit}"] = tuple((x >> (digit_bits*digit)) & mask for x in result)
    return values


def evaluate_residuals(graph: Graph, equations: dict[str, dict[str, Operator]],
                       values: Mapping[str, tuple[int, ...]], fixed: Mapping[str, tuple[int, ...]],
                       q: int) -> dict[str, tuple[int, ...]]:
    residuals = {}
    for name, expression in equations.items():
        result = [0]*graph.n
        for source, op in expression.items():
            vector = op.evaluate(values[source], fixed, q)
            result = [(a+b) % q for a, b in zip(result, vector, strict=True)]
        residuals[name] = tuple(result)
    return residuals


def independent_butterfly(graph: Graph, query, fixed, q: int, digit_bits: int):
    """Literal independent coefficient schedule, without symbolic operators."""
    def add(a, b, sign=1):
        return tuple((x+sign*y) % q for x, y in zip(a, b, strict=True))

    def switch(poly, prefix):
        result = [(0,)*graph.n, (0,)*graph.n]
        for j in range(graph.digits):
            digits = tuple((x >> (digit_bits*j)) & ((1 << digit_bits)-1) for x in poly)
            for k in range(2):
                result[k] = add(result[k], multiply(digits, fixed[f"{prefix}:{j}:{k}"], q))
        return tuple(result)

    work = []
    for i in range(graph.tiles):
        a0, a1 = fixed[f"index:{i}:0"], fixed[f"index:{i}:1"]
        tensor = (multiply(query[0], a0, q),
                  add(multiply(query[0], a1, q), multiply(query[1], a0, q)),
                  multiply(query[1], a1, q))
        correction = switch(tensor[2], "relin")
        work.append(tuple(monomial(add(tensor[k], correction[k]), 1-graph.padded, q)
                          for k in range(2)))
    shift, exponent, stage = graph.padded//2, 1+2*graph.n//graph.padded, 0
    while shift:
        merged = []
        for i in range(min(shift, len(work))):
            plus = minus = work[i]
            if i+shift < len(work):
                right = tuple(monomial(p, shift, q) for p in work[i+shift])
                plus = tuple(add(a, b) for a, b in zip(work[i], right, strict=True))
                minus = tuple(add(a, b, -1) for a, b in zip(work[i], right, strict=True))
            turned = tuple(automorphism(p, exponent, q) for p in minus)
            correction = switch(turned[1], f"switch:{stage}")
            merged.append((add(plus[0], add(turned[0], correction[0])),
                           add(plus[1], correction[1])))
        work, shift, exponent, stage = merged, shift//2, exponent*exponent % (2*graph.n), stage+1
    return work[0]
