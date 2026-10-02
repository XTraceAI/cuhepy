"""E83 public finite coded-operator/Merkle controls; no private-key API.

Negacirculant and tensor codes are known ingredients. This tests whether they
preserve the operator generators and what complete authenticated access costs.
Tiny exhaustive distance is never transferred to production ring parameters.
Hash binding and owner-approved registration remain explicit premises.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from itertools import product
import json

from gmpy2 import is_prime


def vector(values, count, prime):
    if (type(prime) is not int or not 3 <= prime <= 65537 or not is_prime(prime)
            or type(values) is not tuple or len(values) != count or not 1 <= count <= 256
            or any(type(x) is not int or not 0 <= x < prime for x in values)):
        raise ValueError("Expected bounded canonical prime-field vector")


def matvec(matrix, values, prime):
    if type(matrix) is not tuple or not 1 <= len(matrix) <= 256 or not matrix[0]:
        raise ValueError("Expected bounded matrix")
    vector(values, len(matrix[0]), prime)
    for row in matrix:
        vector(row, len(values), prime)
    return tuple(sum(a * b for a, b in zip(row, values, strict=True)) % prime for row in matrix)


def ring_product(left, right, prime):
    vector(left, len(left), prime)
    vector(right, len(left), prime)
    if len(left) > 16:
        raise ValueError("Ring oracle exceeds cap")
    result = [0] * len(left)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            result[(i + j) % len(left)] += a * b * (1 if i + j < len(left) else -1)
    return tuple(x % prime for x in result)


def negashift(values, shift, prime):
    vector(values, len(values), prime)
    if type(shift) is not int or not 0 <= shift < len(values):
        raise ValueError("Shift outside ring")
    result = [0] * len(values)
    for i, value in enumerate(values):
        result[(i + shift) % len(values)] = value * (1 if i + shift < len(values) else -1) % prime
    return tuple(result)


def rs_encode(values, points, prime):
    vector(values, len(values), prime)
    vector(points, len(points), prime)
    if len(set(points)) != len(points) or len(points) < len(values):
        raise ValueError("Code points must be distinct and cover dimension")
    return tuple(sum(value * pow(point, i, prime) for i, value in enumerate(values)) % prime
                 for point in points)


def quasi_encode(values, multipliers, prime):
    vector(values, len(values), prime)
    if (type(multipliers) is not tuple or not 1 <= len(multipliers) <= 8
            or multipliers[0] != (1,) + (0,) * (len(values) - 1)):
        raise ValueError("Systematic negacirculant code required")
    return tuple(x for multiplier in multipliers for x in ring_product(multiplier, values, prime))


def tensor_encode(values, n, multipliers, outer_points, prime):
    vector(values, len(values), prime)
    if type(n) is not int or not 1 <= n <= 16 or len(values) % n:
        raise ValueError("Invalid block width")
    blocks = tuple(values[i:i + n] for i in range(0, len(values), n))
    vector(outer_points, len(outer_points), prime)
    if len(set(outer_points)) != len(outer_points) or len(outer_points) < len(blocks):
        raise ValueError("Outer code needs enough distinct points")
    output = []
    for point in outer_points:
        combined = tuple(sum(pow(point, j, prime) * block[i] for j, block in enumerate(blocks)) % prime
                         for i in range(n))
        output.extend(quasi_encode(combined, multipliers, prime))
    return tuple(output)


def exhaustive_distance(dimension, prime, encoder):
    vector((0,) * dimension, dimension, prime)
    if prime ** dimension > 100000:
        raise ValueError("All-error enumeration exceeds oracle cap")
    smallest, witness, checked = None, None, 0
    for error in product(range(prime), repeat=dimension):
        if not any(error):
            continue
        encoded = encoder(error)
        vector(encoded, len(encoded), prime)
        weight = sum(bool(x) for x in encoded)
        if smallest is None or weight < smallest:
            smallest, witness = weight, error
        checked += 1
    return {"dimension": dimension, "field": prime, "errors_checked": checked,
            "minimum_distance": smallest, "witness": witness,
            "code_length": len(encoder((0,) * dimension))}


def encode_matrix(matrix, prime, encoder):
    matvec(matrix, (0,) * len(matrix[0]), prime)
    columns = tuple(encoder(tuple(row[i] for row in matrix)) for i in range(len(matrix[0])))
    return tuple(tuple(column[i] for column in columns) for i in range(len(columns[0])))


@dataclass(frozen=True)
class Registration:
    prime: int
    rows: int
    width: int
    identity: str
    root: bytes


@dataclass(frozen=True)
class Opening:
    index: int
    row: tuple[int, ...]
    siblings: tuple[bytes, ...]


def _leaf(index, row, registration):
    body = json.dumps([registration.prime, registration.rows, registration.width,
                       registration.identity, index, row], separators=(",", ":")).encode()
    return sha256(b"cuhepy-E83-row\x00" + body).digest()


def _node(left, right):
    return sha256(b"cuhepy-E83-node\x00" + left + right).digest()


def register(matrix, prime, identity):
    """OWNER approval of ED is a prerequisite; a root alone does not prove ED."""
    matvec(matrix, (0,) * len(matrix[0]), prime)
    if (type(identity) is not str or len(identity) != 64
            or set(identity) - set("0123456789abcdef")):
        raise ValueError("Expected owner-pinned operator/code/key/epoch identity")
    registration = Registration(prime, len(matrix), len(matrix[0]), identity, b"")
    size = 1 << (len(matrix) - 1).bit_length()
    leaves = tuple(_leaf(i, matrix[i] if i < len(matrix) else (), registration) for i in range(size))
    layers = [leaves]
    while len(layers[-1]) > 1:
        current = layers[-1]
        layers.append(tuple(_node(current[i], current[i + 1]) for i in range(0, len(current), 2)))
    return Registration(prime, len(matrix), len(matrix[0]), identity, layers[-1][0]), tuple(layers)


def open_row(matrix, layers, index):
    if type(index) is not int or not 0 <= index < len(matrix):
        raise ValueError("Row index outside registered matrix")
    cursor, siblings = index, []
    for layer in layers[:-1]:
        siblings.append(layer[cursor ^ 1])
        cursor //= 2
    return Opening(index, matrix[index], tuple(siblings))


def authenticate_row(registration, opening, expected_index):
    if type(registration) is not Registration or type(opening) is not Opening:
        return False
    if (type(expected_index) is not int or type(opening.index) is not int
            or opening.index != expected_index or not 0 <= opening.index < registration.rows
            or len(opening.siblings) != (registration.rows - 1).bit_length()
            or any(type(s) is not bytes or len(s) != 32 for s in opening.siblings)):
        return False
    try:
        vector(opening.row, registration.width, registration.prime)
    except ValueError:
        return False
    digest, cursor = _leaf(opening.index, opening.row, registration), opening.index
    for sibling in opening.siblings:
        digest = _node(sibling, digest) if cursor & 1 else _node(digest, sibling)
        cursor //= 2
    return digest == registration.root


@dataclass(frozen=True)
class FixedAnswer:
    values: tuple[int, ...]
    query: tuple[int, ...]
    registration: Registration


def fix_answer(values, query, registration):
    vector(values, len(values), registration.prime)
    vector(query, registration.width, registration.prime)
    return FixedAnswer(values, query, registration)


def check_rows(fixed, indices, openings, encoder):
    """Public check only. Caller must fix answer before fresh challenge indices.

    This immutable local snapshot tests the interface, not a durable/network
    receiver. Approved encoder, source matrix and original input binding are
    prerequisites; the API cannot certify a server-chosen initial root.
    """
    if (type(fixed) is not FixedAnswer or type(indices) is not tuple or not indices
            or len(indices) > 256 or type(openings) is not tuple or len(indices) != len(openings)):
        return False
    try:
        coded = encoder(fixed.values)
        vector(coded, fixed.registration.rows, fixed.registration.prime)
    except ValueError:
        return False
    for index, opening in zip(indices, openings, strict=True):
        if not authenticate_row(fixed.registration, opening, index):
            return False
        actual = sum(a * b for a, b in zip(opening.row, fixed.query, strict=True)) % fixed.registration.prime
        if coded[index] != actual:
            return False
    return True
