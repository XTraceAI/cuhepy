"""Q71 bounded generic public-coefficient fusion of complete linear relations.

The normal form is sum K(X)*sigma_e(x). Public products, distributivity and
automorphism composition are known controls. A fixed cap inserts a materialized
boundary; this greedy adapter makes no optimality claim. Every original residual
survives. Exact toy evaluation is public only, with no release or entropy API.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
import hashlib
import json

from experiments.bfv_search_lab import noise_cut_relation as relation


@dataclass(frozen=True, order=True)
class Public:
    name: tuple


@dataclass(frozen=True, order=True)
class Monomial:
    shift: int
    factors: tuple[tuple[Public, int], ...]


# Public coefficient = sum weight * X**shift * product sigma_e(public).
Coefficient = tuple[tuple[Monomial, int], ...]
ONE = ((Monomial(0, ()), 1),)


@dataclass(frozen=True)
class Graph:
    n: int
    q: int
    nodes: tuple[relation.Node, ...]
    residuals: tuple[int, ...]
    anchors: tuple[int, ...] = ()
    pairs: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class Limits:
    terms: int = 32
    monomials: int = 256
    degree: int = 3
    nodes: int = 400_000
    recipes: int = 1_000_000

    def __post_init__(self):
        if any(type(x) is not int or x < 1 for x in self.__dict__.values()):
            raise ValueError("Positive immutable compiler caps required")


class LimitReached(RuntimeError):
    """No truncated output or optimum is returned on a resource limit."""


@dataclass(frozen=True)
class Fused:
    graph: Graph
    boundaries: tuple[tuple[int, str], ...]
    limits: Limits


class Builder:
    """Shared generic DAG builder; value types may be public recipes."""

    def __init__(self, n, q):
        self.n, self.q, self.nodes, self.cache = n, q, [], {}
        self.zero = self.intern(relation.Node("zero", ()))

    def intern(self, node):
        if node not in self.cache:
            self.cache[node] = len(self.nodes)
            self.nodes.append(node)
        return self.cache[node]

    def input(self, name):
        return self.intern(relation.Node("input", (), name))

    def add(self, a, b):
        if a == self.zero:
            return b
        if b == self.zero:
            return a
        return self.intern(relation.Node("add", tuple(sorted((a, b)))))

    def sub(self, a, b):
        if a == b:
            return self.zero
        if b == self.zero:
            return a
        return self.intern(relation.Node("sub", (a, b)))

    def scale(self, a, scalar):
        scalar %= self.q
        if a == self.zero or not scalar:
            return self.zero
        if scalar == 1:
            return a
        return self.intern(relation.Node("scale", (a,), scalar))

    def multiply(self, a, public):
        if a == self.zero:
            return a
        return self.intern(relation.Node("multiply", (a,), public))

    def permute(self, a, exponent=1, shift=0):
        exponent, shift = exponent % (2 * self.n), shift % (2 * self.n)
        if exponent % 2 != 1:
            raise ValueError("Odd automorphism required")
        if a == self.zero or (exponent, shift) == (1, 0):
            return a
        return self.intern(relation.Node("permute", (a,), (exponent, shift)))

    def sum(self, terms):
        out = self.zero
        for value in terms:
            out = self.add(out, value)
        return out


def from_relation(value):
    """Preserve exact public constants; hash identity permits equal sharing."""
    if type(value) is not relation.Relation:
        raise TypeError("Trusted complete relation required")
    constants, nodes = {}, []
    for node in value.nodes:
        if node.kind == "multiply":
            raw = json.dumps(node.value, separators=(",", ":")).encode()
            name = Public(("constant", hashlib.sha256(raw).hexdigest()))
            constants[name] = node.value
            node = relation.Node(node.kind, node.args, name)
        nodes.append(node)
    return Graph(value.n, value.q, tuple(nodes), value.residuals), constants


def coefficient(n, q, terms):
    values = Counter()
    for monomial, weight in terms:
        shift = monomial.shift % (2 * n)
        factors = tuple(sorted((p, e % (2 * n)) for p, e in monomial.factors))
        if any(type(p) is not Public or e % 2 != 1 for p, e in factors):
            raise ValueError("Enrolled public factors and odd automorphisms required")
        values[Monomial(shift % n, factors)] += weight * (-1 if shift >= n else 1)
    return tuple(sorted((m, w % q) for m, w in values.items() if w % q))


def _merge(n, q, a, b, sign=1):
    return coefficient(n, q, (*a, *((m, sign * w) for m, w in b)))


def _turn(n, q, value, exponent, shift):
    return coefficient(
        n,
        q,
        (
            (
                Monomial(
                    exponent * m.shift + shift,
                    tuple((p, exponent * e) for p, e in m.factors),
                ),
                w,
            )
            for m, w in value
        ),
    )


def _public_multiply(n, q, value, public):
    return coefficient(
        n,
        q,
        ((Monomial(m.shift, (*m.factors, (public, 1))), w) for m, w in value),
    )


def _validate(graph):
    if (
        type(graph) is not Graph
        or type(graph.n) is not int
        or graph.n < 2
        or graph.n & (graph.n - 1)
        or type(graph.q) is not int
        or graph.q < 3
        or type(graph.nodes) is not tuple
        or type(graph.residuals) is not tuple
        or not graph.residuals
    ):
        raise ValueError("Frozen trusted polynomial DAG required")
    arity = {
        "zero": 0,
        "input": 0,
        "add": 2,
        "sub": 2,
        "scale": 1,
        "multiply": 1,
        "permute": 1,
    }
    for i, node in enumerate(graph.nodes):
        if (
            type(node) is not relation.Node
            or node.kind not in arity
            or type(node.args) is not tuple
            or len(node.args) != arity[node.kind]
            or any(type(a) is not int or not 0 <= a < i for a in node.args)
        ):
            raise ValueError("Unknown operation or invalid acyclic operand")
        if node.kind == "multiply" and type(node.value) is not Public:
            raise ValueError("Explicit immutable public polynomial identity required")
        if node.kind == "permute" and (
            type(node.value) is not tuple
            or len(node.value) != 2
            or any(type(x) is not int for x in node.value)
            or node.value[0] % 2 != 1
        ):
            raise ValueError("Wrong signed permutation")
        if node.kind == "scale" and type(node.value) is not int:
            raise ValueError("Integer scalar required")
    if any(
        type(i) is not int or not 0 <= i < len(graph.nodes) for i in graph.residuals
    ):
        raise ValueError("Complete residual roots required")
    if type(graph.anchors) is not tuple or any(
        type(i) is not int or not 0 <= i < len(graph.nodes) for i in graph.anchors
    ):
        raise ValueError("Wrong enrolled shared boundaries")
    if type(graph.pairs) is not tuple or any(
        type(pair) is not tuple
        or len(pair) != 2
        or any(type(i) is not int or not 0 <= i < len(graph.nodes) for i in pair)
        for pair in graph.pairs
    ):
        raise ValueError("Wrong enrolled paired kernel boundaries")
    if len({i for pair in graph.pairs for i in pair}) != 2 * len(graph.pairs) or any(
        i not in graph.anchors for pair in graph.pairs for i in pair
    ):
        raise ValueError("Paired kernels require unique enrolled boundaries")
    # Pairing is a schedule contract, not permission to hide dependency cycles
    # inside a kernel. The contracted kernel graph must stay acyclic.
    if graph.pairs:
        groups = {i: min(pair) for pair in graph.pairs for i in pair}
        labels = {groups.get(i, i) for i in range(len(graph.nodes))}
        edges = {i: set() for i in labels}
        indegrees = dict.fromkeys(labels, 0)
        for i, node in enumerate(graph.nodes):
            target = groups.get(i, i)
            for a in node.args:
                origin = groups.get(a, a)
                if origin != target and target not in edges[origin]:
                    edges[origin].add(target)
                    indegrees[target] += 1
        ready = deque(i for i, count in indegrees.items() if not count)
        visited = 0
        while ready:
            visited += 1
            for child in edges[ready.popleft()]:
                indegrees[child] -= 1
                if not indegrees[child]:
                    ready.append(child)
        if visited != len(labels):
            raise ValueError("Paired kernel contraction must be acyclic")


def fuse(graph, limits=Limits()):
    """Known bounded distributive normalization, identical for every scheme."""
    _validate(graph)
    if type(limits) is not Limits:
        raise ValueError("Frozen public limits required")
    if len(graph.nodes) > limits.nodes:
        raise LimitReached("original DAG node cap")
    n, q, forms, boundaries, volume = graph.n, graph.q, [], {}, 0
    for i, node in enumerate(graph.nodes):
        if node.kind == "zero":
            form = {}
        elif node.kind == "input":
            form = {(i, 1): ONE}
            boundaries[i] = "input"
        elif node.kind in ("add", "sub"):
            form = dict(forms[node.args[0]])
            sign = 1 if node.kind == "add" else -1
            for term, c in forms[node.args[1]].items():
                value = _merge(n, q, form.get(term, ()), c, sign)
                if value:
                    form[term] = value
                else:
                    form.pop(term, None)
        elif node.kind == "scale":
            form = {
                term: coefficient(n, q, ((m, w * node.value) for m, w in c))
                for term, c in forms[node.args[0]].items()
            }
            form = {term: c for term, c in form.items() if c}
        elif node.kind == "multiply":
            form = {
                term: _public_multiply(n, q, c, node.value)
                for term, c in forms[node.args[0]].items()
            }
        else:
            e, h = node.value
            form = {
                (basis, e * a % (2 * n)): _turn(n, q, c, e, h)
                for (basis, a), c in forms[node.args[0]].items()
            }
        reason = "enrolled_shared_boundary" if i in graph.anchors else None
        if len(form) > limits.terms:
            reason = "variable_automorphism_terms"
        elif sum(map(len, form.values())) > limits.monomials:
            reason = "public_monomials"
        elif any(len(m.factors) > limits.degree for c in form.values() for m, _w in c):
            reason = "public_degree"
        if reason:
            boundaries[i] = reason
            form = {(i, 1): ONE}
        volume += sum(map(len, form.values()))
        if volume > limits.recipes:
            raise LimitReached("accumulated coefficient monomial cap")
        forms.append(form)

    output, made, expressions = Builder(n, q), {}, {}
    paired = {i: pair for pair in graph.pairs for i in pair}
    scheduled_pairs = set()

    def materialize(i):
        if i in made:
            return made[i]
        if i in paired and paired[i] not in scheduled_pairs:
            pair = paired[i]
            scheduled_pairs.add(pair)
            for member in pair:
                materialize(member)
            return made[i]
        node = graph.nodes[i]
        if node.kind == "input":
            value = output.input(node.value)
        else:
            args = tuple(emit(forms[a]) for a in node.args)
            if node.kind == "multiply":
                c = ((Monomial(0, ((node.value, 1),)), 1),)
                value = output.multiply(args[0], c)
            elif node.kind == "permute":
                value = output.permute(args[0], *node.value)
            elif node.kind == "scale":
                value = output.scale(args[0], node.value)
            elif node.kind == "zero":
                value = output.zero
            else:
                value = getattr(output, node.kind)(*args)
        made[i] = value
        return value

    def emit(form):
        frozen = tuple(sorted(form.items()))
        if frozen in expressions:
            return expressions[frozen]
        terms = []
        for (basis, exponent), c in frozen:
            value = materialize(basis)
            if len(c) == 1 and not c[0][0].factors:
                m, w = c[0]
                value = output.scale(output.permute(value, exponent, m.shift), w)
            else:
                value = output.multiply(output.permute(value, exponent), c)
            terms.append(value)
        value = output.sum(terms)
        expressions[frozen] = value
        return value

    roots = tuple(emit(forms[i]) for i in graph.residuals)
    return Fused(
        Graph(n, q, tuple(output.nodes), roots),
        tuple(sorted(boundaries.items())),
        limits,
    )


def ring_product(a, b, q):
    """Exact coefficient arithmetic for the public tiny oracle only."""
    if len(a) != len(b):
        raise ValueError("Different polynomial dimensions")
    n, out = len(a), [0] * len(a)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[(i + j) % n] += x * y * (-1 if i + j >= n else 1)
    return tuple(x % q for x in out)


def turn(poly, exponent, shift, q):
    n, out = len(poly), [0] * len(poly)
    for i, x in enumerate(poly):
        at = (i * exponent + shift) % (2 * n)
        out[at % n] = x * (-1 if at >= n else 1) % q
    return tuple(out)


def coefficients(graph, constants):
    """Prepare and share exact final public composite polynomials."""
    n, q = graph.n, graph.q
    cache, atoms = {}, {}
    for node in graph.nodes:
        if node.kind != "multiply" or node.value in cache:
            continue
        out = [0] * n
        for m, w in node.value:
            value = (1, *((0,) * (n - 1)))
            for p, e in m.factors:
                if (p, e) not in atoms:
                    raw = constants[p]
                    if type(raw) is not tuple or len(raw) != n:
                        raise ValueError("Wrong enrolled public polynomial")
                    atoms[p, e] = turn(raw, e, 0, q)
                value = ring_product(value, atoms[p, e], q)
            value = turn(value, 1, m.shift, q)
            out = [(a + w * b) % q for a, b in zip(out, value, strict=True)]
        cache[node.value] = tuple(out)
    return cache


def evaluate(graph, bindings, multipliers):
    """Complete coefficient-vector residuals, no scalar ring evaluation."""
    n, q, values = graph.n, graph.q, []
    for node in graph.nodes:
        if node.kind == "zero":
            value = (0,) * n
        elif node.kind == "input":
            value = bindings[node.value]
            if type(value) is not tuple or len(value) != n:
                raise ValueError("Wrong immutable bound input")
        elif node.kind in ("add", "sub"):
            a, b = (values[j] for j in node.args)
            sign = 1 if node.kind == "add" else -1
            value = tuple((x + sign * y) % q for x, y in zip(a, b, strict=True))
        elif node.kind == "scale":
            value = tuple(x * node.value % q for x in values[node.args[0]])
        elif node.kind == "permute":
            value = turn(values[node.args[0]], *node.value, q)
        elif node.kind == "multiply":
            value = ring_product(values[node.args[0]], multipliers[node.value], q)
        else:
            raise ValueError("Unknown operation")
        values.append(value)
    return tuple(values[i] for i in graph.residuals)


def bindings(compiled, sources, outputs):
    """Validate the entire common-Q grammar before any arithmetic or coins."""
    if (
        type(compiled) is not relation.Relation
        or type(sources) is not tuple
        or len(sources) != len(compiled.source_layout)
    ):
        raise ValueError("Wrong complete immutable source coverage")
    out = dict(compiled.trusted_inputs)
    for slot, (source, (g, level, node, bits)) in enumerate(
        zip(sources, compiled.source_layout, strict=True)
    ):
        if (
            type(source) is not relation.Source
            or any(
                type(x) is not int for x in (source.group, source.level, source.node)
            )
            or (source.group, source.level, source.node) != (g, level, node)
        ):
            raise ValueError("Wrong source identity or order")
        poly = relation.polynomial(source.polynomial, compiled)
        for j in range((compiled.q.bit_length() + bits - 1) // bits):
            out["source-digit", slot, j] = tuple(
                (x >> (j * bits)) & ((1 << bits) - 1) for x in poly
            )
    if type(outputs) is not tuple or len(outputs) != compiled.groups:
        raise ValueError("Wrong complete output coverage")
    for g, pair in enumerate(outputs):
        if type(pair) is not tuple or len(pair) != 2:
            raise ValueError("Two complete immutable outputs required")
        for c, row in enumerate(pair):
            out["output", g, c] = relation.polynomial(row, compiled)
    return out


def prune(graph):
    """Exact reachable subgraph; complete residual order is preserved."""
    active, todo = set(), list(graph.residuals)
    while todo:
        i = todo.pop()
        if i not in active:
            active.add(i)
            todo.extend(graph.nodes[i].args)
    positions, nodes = {}, []
    for i in sorted(active):
        positions[i] = len(nodes)
        node = graph.nodes[i]
        nodes.append(
            relation.Node(node.kind, tuple(positions[a] for a in node.args), node.value)
        )
    return Graph(
        graph.n,
        graph.q,
        tuple(nodes),
        tuple(positions[i] for i in graph.residuals),
        tuple(positions[i] for i in graph.anchors if i in active),
        tuple(
            tuple(positions[i] for i in pair)
            for pair in graph.pairs
            if all(i in active for i in pair)
        ),
    )


def live_arrays(graph, retained=()):
    """Sufficient fixed creation-order, out-of-place polynomial schedule."""
    uses = Counter(a for node in graph.nodes for a in node.args)
    uses.update(graph.residuals)
    uses.update(retained)
    roots = Counter(graph.residuals)
    live, peak = set(), 0
    for i, node in enumerate(graph.nodes):
        live.add(i)
        peak = max(peak, len(live))
        for a in node.args:
            uses[a] -= 1
            if not uses[a]:
                live.discard(a)
        uses[i] -= roots[i]
        if not uses[i]:
            live.discard(i)
    return peak


def public_recipes(graph):
    """Shared public preparation DAG, also valid pointwise in the NTT domain."""
    build = Builder(graph.n, graph.q)
    finals, dependencies = {}, {}

    def atom(p, e):
        return build.permute(build.input(p.name), e)

    for node in graph.nodes:
        if node.kind != "multiply" or node.value in finals:
            continue
        terms, deps = [], set()
        for m, w in node.value:
            factors = [atom(p, e) for p, e in m.factors]
            deps.update(p for p, _e in m.factors)
            if not factors:
                value = build.input(("unit-polynomial",))
            else:
                value = factors[0]
                for factor in factors[1:]:
                    value = build.intern(
                        relation.Node("public-product", tuple(sorted((value, factor))))
                    )
            terms.append(build.scale(build.permute(value, shift=m.shift), w))
        root = build.sum(terms)
        finals[node.value] = root
        dependencies[node.value] = frozenset(deps)
    recipes = Graph(graph.n, graph.q, tuple(build.nodes), tuple(finals.values()))
    return recipes, finals, dependencies


def _counts(graph):
    kinds = Counter(node.kind for node in graph.nodes)
    shifts = sum(node.kind == "permute" and node.value[1] != 0 for node in graph.nodes)
    autos = sum(node.kind == "permute" and node.value[0] != 1 for node in graph.nodes)
    return {
        "operations": dict(kinds),
        "polynomial_word_product_passes": kinds["multiply"]
        + kinds["public-product"]
        + kinds["scale"]
        + shifts,
        "polynomial_add_sub_passes": kinds["add"] + kinds["sub"],
        "polynomial_automorphism_permutation_passes": autos,
        "signed_monomial_NTT_word_product_passes": shifts,
    }


def resource_ledger(graph, rounds=3, primes=2):
    """Sufficient complete forward checker/preparation counts, never timings."""
    graph = prune(graph)
    raw_recipes, finals, deps = public_recipes(graph)
    recipes = prune(raw_recipes) if raw_recipes.residuals else raw_recipes
    # A public product has two dynamic DAG arguments during preparation.
    online, setup = _counts(graph), _counts(recipes)
    word_polynomial_bytes = graph.n * primes * 8
    online.update(
        nodes=len(graph.nodes),
        complete_residual_polynomials=len(graph.residuals),
        distinct_bound_input_polynomials=sum(n.kind == "input" for n in graph.nodes),
        input_forward_prime_NTTs=sum(n.kind == "input" for n in graph.nodes) * primes,
        final_batched_inverse_prime_NTTs=rounds * primes,
        fresh_row_field_elements=rounds * primes * len(graph.residuals),
        fresh_complete_residual_accumulation_word_MACs=rounds
        * primes
        * graph.n
        * len(graph.residuals),
        DAG_word_product_count=online["polynomial_word_product_passes"]
        * graph.n
        * primes,
        scheduled_out_of_place_live_dynamic_polynomial_arrays=live_arrays(graph),
        live_dynamic_RNS_word_bytes=live_arrays(graph) * word_polynomial_bytes,
        fresh_accumulator_RNS_word_bytes=rounds * word_polynomial_bytes,
    )
    recipe_inputs = {n.value for n in recipes.nodes if n.kind == "input"}
    setup.update(
        unique_public_composite_polynomials=len(finals),
        cached_public_multiplier_RNS_word_bytes=len(finals) * word_polynomial_bytes,
        distinct_public_atomic_polynomials=len(recipe_inputs),
        public_atomic_forward_prime_NTTs=len(recipe_inputs) * primes,
        setup_word_products=setup["polynomial_word_product_passes"] * graph.n * primes,
        setup_word_add_sub=setup["polynomial_add_sub_passes"] * graph.n * primes,
        scheduled_public_setup_live_RNS_word_bytes=live_arrays(
            recipes, recipes.residuals
        )
        * word_polynomial_bytes,
        raw_public_base_and_key_digit_storage_is_separate=True,
    )
    # Sufficient low-state alternative: recompute each coefficient recipe at
    # every dynamic use, with sharing inside that one recipe only.
    uses = Counter(n.value for n in graph.nodes if n.kind == "multiply")
    streaming = Counter()
    stream_peak = 0
    for c, root in finals.items():
        piece = prune(Graph(raw_recipes.n, raw_recipes.q, raw_recipes.nodes, (root,)))
        counts = _counts(piece)
        stream_peak = max(stream_peak, live_arrays(piece))
        streaming["per_query_public_atomic_forward_prime_NTTs"] += (
            uses[c] * sum(n.kind == "input" for n in piece.nodes) * primes
        )
        streaming["per_query_public_setup_word_products"] += (
            uses[c] * counts["polynomial_word_product_passes"] * graph.n * primes
        )
        streaming["per_query_public_setup_word_add_sub"] += (
            uses[c] * counts["polynomial_add_sub_passes"] * graph.n * primes
        )
        streaming["per_query_public_permutation_passes"] += (
            uses[c] * counts["polynomial_automorphism_permutation_passes"]
        )
    streaming["sufficient_public_recipe_peak_RNS_word_bytes"] = (
        stream_peak * word_polynomial_bytes
    )
    updates = []
    tile_ids = sorted(
        {
            p.name[1]
            for ps in deps.values()
            for p in ps
            if p.name[0] in ("index", "index-digit", "index-sum")
        }
    )
    for tile in tile_ids:
        affected = [
            c
            for c, ps in deps.items()
            if any(
                p.name[0] in ("index", "index-digit", "index-sum") and p.name[1] == tile
                for p in ps
            )
        ]
        updates.append(
            {
                "tile": tile,
                "invalidated_final_public_polynomials": len(affected),
                "invalidated_final_RNS_word_bytes": len(affected)
                * word_polynomial_bytes,
            }
        )
    return {
        "online": online,
        "cached_preparation": setup,
        "on_demand_public_preparation_per_query": dict(streaming),
        "fixed_position_index_update": updates,
        "scope": "Exact counts for this sufficient bounded generic DAG and public recipes; two-prime uint64 NTT representation model. No optimum, measured peak memory, latency, protected execution or native admission. Packed enrollment/index and immutable tape, common-Q digit extraction, NTT scratch/root tables, allocation, serialization/transport, terminal rounding and update authentication are additional. Whole-polynomial fresh batching is counted but not authorized by this diagnostic API.",
    }
