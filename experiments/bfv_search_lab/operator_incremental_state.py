"""Q59 fixed-coins PUBLIC algebra diagnostic for native BGV verification state.

No HE key, enclave, receipt, GPU update, admission, or reusable secret coins are
implemented. Exact adjoints and delta updates are known controls. The caller
must not interpret state equality as approval to reuse coins across epochs.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Mapping

from experiments.bfv_search_lab import operator_state_discriminator as state


def adjoint(op: state.Operator, vector: tuple[int, ...], fixed: Mapping[str, tuple[int, ...]],
            prime: int) -> tuple[int, ...]:
    """Exact transpose from signed permutations and negacyclic convolution.

    M_k^T is convolution by k(X^-1); sigma_a^T=sigma_(a^-1).
    This known matrix-free identity is checked against a dense basis oracle.
    """
    if len(vector) != op.n:
        raise ValueError("Wrong adjoint polynomial dimension")
    result = [0]*op.n
    for atom, weight in op.terms:
        term = state.monomial(vector, -atom.shift, prime)
        if atom.symbol:
            poly = state.automorphism(fixed[atom.symbol], atom.symbol_auto, prime)
            turned = (poly[0], *(-x % prime for x in reversed(poly[1:])))
            term = state.multiply(turned, term, prime)
        term = state.automorphism(term, pow(atom.argument, -1, 2*op.n), prime)
        result = [(a+weight*b) % prime for a, b in zip(result, term, strict=True)]
    return tuple(result)


def dense_adjoint_control(op, vector, fixed, prime):
    columns = []
    for i in range(op.n):
        basis = tuple(int(j == i) for j in range(op.n))
        image = op.evaluate(basis, fixed, prime)
        columns.append(sum(a*b for a, b in zip(vector, image, strict=True)) % prime)
    return tuple(columns)


def index_only(op: state.Operator) -> state.Operator:
    return state.Operator.make(op.n, ((a, w) for a, w in op.terms
                                     if a.symbol.startswith("index:")))


def index_dependency_invariant(equations) -> str:
    """Reject index dependence outside original-query maps; hash fixed maps."""
    fixed_equations = {}
    for name, expression in equations.items():
        fixed_equations[name] = {}
        for source, op in expression.items():
            if not source.startswith("query:"):
                if index_only(op).terms:
                    raise ValueError("Index-dependent non-query coefficient map")
                fixed_equations[name][source] = [[a.shift, a.argument, a.symbol,
                                                 a.symbol_auto, weight] for a, weight in op.terms]
    return hashlib.sha256(json.dumps(fixed_equations, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class DiagnosticCoins:
    """Explicitly public diagnostic values, not protected protocol randomness."""
    prime: int
    row_weights: tuple[tuple[str, int], ...]
    coefficient_weights: tuple[int, ...]


def query_adjoints(equations, fixed, coins: DiagnosticCoins, *, delta=False,
                   dense_control=False):
    if type(coins) is not DiagnosticCoins or type(delta) is not bool:
        raise TypeError("Exact public diagnostic coin record required")
    n = len(coins.coefficient_weights)
    row = dict(coins.row_weights)
    if len(row) != len(coins.row_weights) or set(row) != set(equations):
        raise ValueError("Exactly one weight for every complete residual required")
    if any(type(x) is not int or not 0 <= x < coins.prime
           for x in (*row.values(), *coins.coefficient_weights)):
        raise ValueError("Noncanonical diagnostic field element")
    index_dependency_invariant(equations)
    result = [[0]*n for _ in range(2)]
    implementation = dense_adjoint_control if dense_control else adjoint
    for name, expression in equations.items():
        for k in range(2):
            op = expression.get(f"query:{k}")
            if op is None:
                continue
            if delta:
                op = index_only(op)
            vector = implementation(op, coins.coefficient_weights, fixed, coins.prime)
            result[k] = [(a+row[name]*b) % coins.prime
                         for a, b in zip(result[k], vector, strict=True)]
    return tuple(tuple(r) for r in result)


def index_delta(before, after):
    if set(before) != set(after):
        raise ValueError("An index update cannot change graph/key polynomial identities")
    delta, changed = {}, []
    for name in before:
        if len(before[name]) != len(after[name]):
            raise ValueError("Index update polynomial lengths differ")
        if not name.startswith("index:") and before[name] != after[name]:
            raise ValueError("Index-only update changed a fixed switching key")
        delta[name] = tuple(b-a for a, b in zip(before[name], after[name], strict=True))
        if before[name] != after[name]:
            changed.append(name)
    return delta, tuple(sorted(changed))


def apply_delta(before, increment, prime):
    return tuple(tuple((a+b) % prime for a, b in zip(x, y, strict=True))
                 for x, y in zip(before, increment, strict=True))


def semantic_invalidation(graph: state.Graph, changed_tiles: frozenset[int]):
    if (type(changed_tiles) is not frozenset or any(type(i) is not int
            or not 0 <= i < graph.tiles for i in changed_tiles)):
        raise ValueError("Incorrect tile update support")
    return {"canonical_source_values": sum(node.canonical and bool(node.semantic_tiles & changed_tiles)
                                           for node in graph.nodes),
            "all_affine_node_values": sum(bool(node.semantic_tiles & changed_tiles) for node in graph.nodes),
            "terminal_polynomials": sum(node.terminal and bool(node.semantic_tiles & changed_tiles)
                                        for node in graph.nodes),
            "nonquery_checking_coefficient_maps": 0,
            "query_adjoint_vectors_per_prime_round": 2 if changed_tiles else 0,
            "value_dependencies_are_not_checking_map_dependencies": True}


def edit_scripts(vectors: int, capacity: int):
    if vectors < 32*capacity or vectors % capacity:
        raise ValueError("The fixed edit panel needs at least32 full tiles")
    tiles = vectors//capacity
    return {"one-row": (17,), "one-tile": tuple(range(capacity)),
            "dispersed32-rows": tuple(capacity*(i*tiles//32) for i in range(32)),
            "whole-snapshot": tuple(range(vectors))}
