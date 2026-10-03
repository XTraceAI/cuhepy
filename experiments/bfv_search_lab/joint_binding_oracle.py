"""E101 generic affine elimination with explicit global canonical BGV cuts.

Homemade bounded algebra oracle, not an efficient receiver/proof/HE scheme.
Packed expansion with three output components and no-rotation relinearization
are DIFFERENT graphs. No BFV scaling, terminal conversion or private key here.
Canonical constraints precede ideal field residuals; field equations alone
admit false internal traces even when the final ciphertext is honest.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import hashlib
from itertools import product
from math import gcd

from gmpy2 import is_prime


def convolution(a, b, q):
    """Independent literal signed integer convolution, reduced afterwards."""
    if len(a) != len(b):
        raise ValueError("Unequal polynomial lengths")
    n, result = len(a), [0] * len(a)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            result[(i + j) % n] += x * y * (-1 if i + j >= n else 1)
    return tuple(x % q for x in result)


def _add(a, b, q, scale=1):
    result = dict(a)
    for at, value in b.items():
        result[at] = (result.get(at, 0) + scale * value) % q
        if not result[at]:
            del result[at]
    return result


def _poly_add(a, b, q, scale=1):
    return tuple(_add(x, y, q, scale) for x, y in zip(a, b, strict=True))


def _permute(poly, q, *, exponent=1, shift=0):
    n, result = len(poly), [{} for _ in poly]
    for i, row in enumerate(poly):
        position = i * exponent + shift
        result[position % n] = _add(result[position % n], row, q,
                                    -1 if (position // n) % 2 else 1)
    return tuple(result)


def _constant_product(poly, constant, q):
    n, result = len(poly), [{} for _ in poly]
    for i, row in enumerate(poly):
        for j, value in enumerate(constant):
            result[(i + j) % n] = _add(result[(i + j) % n], row, q,
                                       -value if i + j >= n else value)
    return tuple(result)


def _evaluate(row, features, q):
    return sum(value * features[at] for at, value in row.items()) % q


def digits(poly, q, bits):
    ell = (q.bit_length() + bits - 1) // bits
    return tuple(tuple((value >> (j * bits)) & ((1 << bits) - 1)
                       for value in poly) for j in range(ell))


@dataclass(frozen=True)
class Cut:
    name: str
    source: tuple[dict[int, int], ...]
    feature_ids: tuple[tuple[int, ...], ...]


@dataclass(frozen=True)
class Graph:
    n: int
    q: int
    digit_bits: int
    cuts: tuple[Cut, ...]
    output_rows: tuple[dict[int, int], ...]
    output_shape: tuple[tuple[int, ...], ...]
    feature_count: int
    digest: bytes
    kind: str


@dataclass(frozen=True)
class Certificate:
    statement: bytes
    cut_digits: tuple[tuple[tuple[int, ...], ...], ...]
    output: tuple[tuple[tuple[int, ...], ...], ...]


def compile_graph(*, n, q, digit_bits, index, rotations=(), relin_key=None, kept_c0=None):
    """Generic substitution, with no graph-specific adjoint optimization.

    Index grammar is [column][reply][component][coefficient]. Rotations are
    [(odd exponent, [digit][component][coefficient])]. Only the no-expansion
    path may relinearize here, avoiding a silent change to E73's wire relation.
    Small bounds prevent accidentally using a dense toy compiler on real N.
    """
    if (type(n) is not int or n not in (2, 4, 8, 16, 32) or type(q) is not int or not 3 <= q < 1 << 128
            or type(digit_bits) is not int or not 1 <= digit_bits <= 8
            or type(index) is not tuple or not 1 <= len(index) <= 4
            or type(index[0]) is not tuple or not 1 <= len(index[0]) <= 4
            or type(rotations) is not tuple or len(rotations) > 2):
        raise ValueError("Expected bounded graph geometry")
    replies, ell = len(index[0]), (q.bit_length() + digit_bits - 1) // digit_bits

    def pair(value):
        return (type(value) is tuple and len(value) == 2
                and all(type(p) is tuple and len(p) == n
                        and all(type(x) is int and 0 <= x < q for x in p) for p in value))

    if any(type(column) is not tuple or len(column) != replies or not all(map(pair, column)) for column in index):
        raise ValueError("Noncanonical pinned index")
    if any(type(item) is not tuple or len(item) != 2 for item in rotations):
        raise ValueError("Incorrect rotation entry grammar")
    for exponent, key in rotations:
        if (type(exponent) is not int or exponent % 2 == 0 or type(key) is not tuple
                or len(key) != ell or not all(map(pair, key))):
            raise ValueError("Incorrect signed rotation/key grammar")
    if ((1 << len(rotations)) < len(index) or (1 << len(rotations)) > n
            or (relin_key is not None and (rotations or len(index) != 1
                or type(relin_key) is not tuple or len(relin_key) != ell or not all(map(pair, relin_key))))):
        raise ValueError("Separate packed expansion and no-rotation relin graphs")
    kept = tuple(tuple(range(n)) for _ in range(replies)) if kept_c0 is None else kept_c0
    if (type(kept) is not tuple or len(kept) != replies
            or any(type(row) is not tuple or tuple(sorted(set(row))) != row
                   or any(type(i) is not int or not 0 <= i < n for i in row) for row in kept)):
        raise ValueError("Owner-pinned C0 support required")
    cursor, cuts = 2 * n, []

    def cut(source, name):
        nonlocal cursor
        ids = tuple(tuple(range(cursor + j * n, cursor + (j + 1) * n)) for j in range(ell))
        cursor += ell * n
        cuts.append(Cut(name, source, ids))
        return tuple(tuple({at: 1} for at in row) for row in ids)

    def switched(split, key):
        parts = []
        for k in range(2):
            result = tuple({} for _ in range(n))
            for digit, item in zip(split, key, strict=True):
                result = _poly_add(result, _constant_product(digit, item[k], q), q)
            parts.append(result)
        return tuple(parts)

    original = tuple(tuple({k * n + i: 1} for i in range(n)) for k in range(2))
    work = (original,)
    for level, (exponent, key) in enumerate(rotations):
        even, odd = [], []
        for branch, value in enumerate(work):
            rot = tuple(_permute(p, q, exponent=exponent) for p in value)
            split = cut(rot[1], f"expansion:{level}:{branch}")
            k0, k1 = switched(split, key)
            rotated = (_poly_add(rot[0], k0, q), k1)
            even.append(tuple(_poly_add(a, b, q) for a, b in zip(value, rotated, strict=True)))
            odd.append(tuple(_permute(_poly_add(a, b, q, -1), q, shift=-(1 << level))
                             for a, b in zip(value, rotated, strict=True)))
        work = tuple(even + odd)
    output = []
    for reply in range(replies):
        parts = [tuple({} for _ in range(n)) for _ in range(3)]
        for column, query in zip(index, work[:len(index)], strict=True):
            a0, a1 = column[reply]
            terms = ((_constant_product(query[0], a0, q),),
                     (_constant_product(query[1], a0, q), _constant_product(query[0], a1, q)),
                     (_constant_product(query[1], a1, q),))
            for k, items in enumerate(terms):
                for term in items:
                    parts[k] = _poly_add(parts[k], term, q)
        if relin_key is not None:
            split = cut(parts[2], f"relin:{reply}")
            k0, k1 = switched(split, relin_key)
            parts = [_poly_add(parts[0], k0, q), _poly_add(parts[1], k1, q)]
        output.append((tuple(parts[0][i] for i in kept[reply]), *parts[1:]))
    rows = tuple(row for item in output for poly in item for row in poly)
    shape = tuple(tuple(map(len, item)) for item in output)
    digest = hashlib.sha256(repr((n, q, digit_bits, index, rotations, relin_key, kept)).encode()).digest()
    return Graph(n, q, digit_bits, tuple(cuts), rows, shape, cursor, digest,
                 "native_no_rotation_relin_algebra" if relin_key is not None else "packed_query_unswitched")


def statement(graph, query, parent):
    if (type(query) is not tuple or len(query) != 2
            or any(type(p) is not tuple or len(p) != graph.n
                   or any(type(x) is not int or not 0 <= x < graph.q for x in p) for p in query)
            or type(parent) is not bytes or len(parent) != 32):
        raise ValueError("Canonical original input and pinned parent digest required")
    return hashlib.sha256(b"E101-toy-statement\0" + graph.digest + parent + repr(query).encode()).digest()


def honest_certificate(graph, query, parent):
    pinned = statement(graph, query, parent)
    features = [x for p in query for x in p] + [0] * (graph.feature_count - 2 * graph.n)
    witnesses = []
    for cut in graph.cuts:
        source = tuple(_evaluate(row, features, graph.q) for row in cut.source)
        split = digits(source, graph.q, graph.digit_bits)
        witnesses.append(split)
        for ids, values in zip(cut.feature_ids, split, strict=True):
            for at, value in zip(ids, values, strict=True):
                features[at] = value
    flat = iter(_evaluate(row, features, graph.q) for row in graph.output_rows)
    output = tuple(tuple(tuple(next(flat) for _ in range(length)) for length in shape)
                   for shape in graph.output_shape)
    return Certificate(pinned, tuple(witnesses), output)


def features_of(graph, query, parent, certificate, *, canonical=True):
    """Structural parsing + public integer checks, without secret arithmetic."""
    if (type(certificate) is not Certificate or type(certificate.statement) is not bytes
            or len(certificate.statement) != 32 or certificate.statement != statement(graph, query, parent)
            or type(certificate.cut_digits) is not tuple or len(certificate.cut_digits) != len(graph.cuts)
            or type(certificate.output) is not tuple or len(certificate.output) != len(graph.output_shape)):
        raise ValueError("Wrong statement/trace grammar")
    B, result = 1 << graph.digit_bits, [x for p in query for x in p]
    for cut, split in zip(graph.cuts, certificate.cut_digits, strict=True):
        if (type(split) is not tuple or len(split) != len(cut.feature_ids)
                or any(type(row) is not tuple or len(row) != graph.n
                       or any(type(x) is not int or not 0 <= x < (B if canonical else graph.q)
                              for x in row) for row in split)):
            raise ValueError("Noncanonical shared integer digits")
        if canonical and any(sum(split[j][i] * B**j for j in range(len(split))) >= graph.q
                             for i in range(graph.n)):
            raise ValueError("Global representative exceeds Q")
        result.extend(x for row in split for x in row)
    for item, shape in zip(certificate.output, graph.output_shape, strict=True):
        if (type(item) is not tuple or len(item) != len(shape)
                or any(type(poly) is not tuple or len(poly) != size
                       or any(type(x) is not int or not 0 <= x < graph.q for x in poly)
                       for poly, size in zip(item, shape, strict=True))):
            raise ValueError("Wrong canonical output/support body")
    return tuple(result)


def constraint_rows(graph):
    """All cut recomposition rows, then projected final-output rows."""
    B, rows = 1 << graph.digit_bits, []
    for cut in graph.cuts:
        for i, source in enumerate(cut.source):
            digit = {cut.feature_ids[j][i]: pow(B, j, graph.q) for j in range(len(cut.feature_ids))}
            rows.append(_add(digit, source, graph.q, -1))
    return tuple(rows) + graph.output_rows


def residuals(graph, query, parent, certificate, *, canonical=True):
    features = features_of(graph, query, parent, certificate, canonical=canonical)
    rows = constraint_rows(graph)
    body = tuple(x for item in certificate.output for poly in item for x in poly)
    cut_count = len(graph.cuts) * graph.n
    return tuple((_evaluate(row, features, graph.q) - (0 if i < cut_count else body[i-cut_count])) % graph.q
                 for i, row in enumerate(rows))


def verify_exact(graph, query, parent, certificate):
    try:
        return not any(residuals(graph, query, parent, certificate))
    except (TypeError, ValueError, AttributeError):
        return False


def adjoint(rows, weights, feature_count, q):
    if len(rows) != len(weights):
        raise ValueError("Wrong check row")
    result = [0] * feature_count
    for row, weight in zip(rows, weights, strict=True):
        for at, value in row.items():
            result[at] = (result[at] + weight * value) % q
    return tuple(result)


def nullspace_vector(matrix, p):
    """Exact finite-field elimination. Returns one nonzero kernel vector."""
    if not matrix or not is_prime(p) or not matrix[0] or any(len(row) != len(matrix[0]) for row in matrix):
        raise ValueError("Bounded rectangular field matrix required")
    rows, width, pivots = [list(x % p for x in row) for row in matrix], len(matrix[0]), []
    rank = 0
    for column in range(width):
        pivot = next((i for i in range(rank, len(rows)) if rows[i][column]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        inverse = pow(rows[rank][column], -1, p)
        rows[rank] = [value * inverse % p for value in rows[rank]]
        for i in range(len(rows)):
            if i != rank and rows[i][column]:
                value = rows[i][column]
                rows[i] = [(a - value * b) % p for a, b in zip(rows[i], rows[rank], strict=True)]
        pivots.append(column)
        rank += 1
        if rank == len(rows):
            break
    free = next((i for i in range(width) if i not in pivots), None)
    if free is None:
        raise ValueError("No false-witness kernel in this matrix")
    result = [0] * width
    result[free] = 1
    for row, column in zip(rows, pivots, strict=False):
        result[column] = -row[free] % p
    return tuple(result), rank


def false_witness_kernel(graph, query, parent, certificate, prime):
    """Keep final output exact while violating a canonical digit range."""
    from dataclasses import replace
    if (type(prime) is not int or not is_prime(prime) or graph.q % prime
            or gcd(prime, graph.q // prime) != 1):
        raise ValueError("Named prime limb must divide Q coprimely")
    start = 2 * graph.n
    matrix = tuple(tuple(row.get(at, 0) % prime for at in range(start, graph.feature_count))
                   for row in constraint_rows(graph))
    vector, rank = nullspace_vector(matrix, prime)
    old = features_of(graph, query, parent, certificate)[start:]
    at = next(i for i, value in enumerate(vector) if value)
    B = 1 << graph.digit_bits
    if prime <= B:
        raise ValueError("Toy kernel requires prime larger than digit radix")
    scale = (B - old[at]) * pow(vector[at], -1, prime) % prime
    other = graph.q // prime
    # Zero in every other limb, prescribed perturbation in this limb.
    lift = 1 if other == 1 else other * pow(other, -1, prime)
    changed = iter((value + scale * delta * lift) % graph.q for value, delta in zip(old, vector, strict=True))
    split = tuple(tuple(tuple(next(changed) for _ in row) for row in cut.feature_ids) for cut in graph.cuts)
    bad = replace(certificate, cut_digits=split)
    assert not any(residuals(graph, query, parent, bad, canonical=False))
    assert not verify_exact(graph, query, parent, bad)
    return bad, {"rank": rank, "digit_variables": len(vector), "nullity": len(vector)-rank,
                 "affine_only_accepts": True, "canonical_accepts": False,
                 "honest_output_unchanged": bad.output == certificate.output, "prime": prime}


def uniform_field_exhaustion(p=5, dimension=3):
    """Every nonzero residual against every row, bounded independently of HE."""
    if (type(p) is not int or type(dimension) is not int or not 1 <= dimension <= 8
            or not is_prime(p) or p**(2*dimension) > 100000):
        raise ValueError("Exhaustive space too large")
    rows = tuple(product(range(p), repeat=dimension))
    vectors, non_basis, maximum = 0, 0, 0
    for error in rows:
        if not any(error):
            continue
        accepts = sum(sum(x*y for x, y in zip(row, error, strict=True)) % p == 0 for row in rows)
        assert accepts * p == len(rows)
        vectors += 1
        non_basis += sum(x != 0 for x in error) > 1
        maximum = max(maximum, accepts)
    return {"prime": p, "dimension": dimension, "nonzero_errors": vectors,
            "non_basis_errors": non_basis, "uniform_rows": len(rows),
            "checks": vectors * len(rows), "max_accept_count": maximum,
            "exact_one_row_false_residual_probability": [1, p]}


def feedback_exhaustion():
    """First false TRACE accepted in two attempts; hidden rows and one bit."""
    accepted = 0
    for values in product(range(3), repeat=4):
        rows = (values[:2], values[2:])
        first = all(row[0] == 0 for row in rows)
        second = not first and all(row[1] == 0 for row in rows)
        accepted += first or second
    assert Fraction(accepted, 81) <= Fraction(2, 9)
    return {"private_matrices": 81, "first_false_trace_accepts": accepted,
            "union_bound": [2, 9], "durable_lifecycle_implemented": False}


def cost_card(n, columns, replies, q_bits, digit_bits, *, relin=False, rounds=4):
    """Paid dense control counts; no measured latency or approved parameters."""
    factor, ell = 1 << (columns - 1).bit_length(), (q_bits + digit_bits - 1) // digit_bits
    if relin and columns != 1:
        raise ValueError("Separate actual relin and expansion graphs")
    cuts, components = (replies, 2) if relin else (factor - 1, 3)
    features, residual = (2 + cuts * ell) * n, (cuts + components * replies) * n
    def body(entries, bits):
        return (entries * bits + 7) // 8
    return {"n": n, "columns": columns, "replies": replies, "q_bits": q_bits,
            "rounds": rounds, "rounds_are_count_choice_not_security_target": True,
            "digit_bits": digit_bits, "canonical_cuts": cuts,
            "cut_source_body_bytes": body(cuts*n, q_bits),
            "cut_digit_body_bytes": body(cuts*ell*n, digit_bits),
            "cut_digit_body_is_fixed_width_per_digit_upper_bound": True,
            "packed_top_digit_control_body_bytes": body(cuts*n, q_bits),
            "full_output_body_bytes": body(components*replies*n, q_bits),
            "dense_hint_body_bytes": body(rounds*features, q_bits),
            "dense_challenge_body_bytes": body(rounds*residual, q_bits),
            "dense_online_scalar_products": rounds*(features+components*replies*n),
            "online_canonical_range_and_digit_derivation_cost_not_in_scalar_count": True,
            "public_input_cut_features": features, "affine_constraints": residual,
            "canonical_digit_coefficients_derived_or_supplied": cuts*ell*n,
            "new_vs_equally_optimized_generic_control_ratio": [1, 1],
            "registration_dense_compiler_cost_and_runtime_unmeasured": True,
            "source_cut_control_can_derive_digits_locally_too": True,
            "actual_RNS_uint64_wire_bytes_and_full_authentication_excluded": True,
            "output_bodies_are_full_C0_upper_bounds_projected_counts_separate": True,
            "algebraic_soundness_uses_each_prime_limb_not_Q_bit_length": True,
            "model_only_unapproved_parameters": True}
