"""E68 implicit full-Q operator, adjoint, digits and public-result controls.

Exact integer/field algebra only: no outer encryption, registration or proof.
Generators retain the public index's negacyclic/subring structure. Digits are
decomposed BEFORE shifts, so signed wraparound retains its correct meaning.
All routines are bounded reference oracles, not a private constant-time API.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.bfv_search_lab import ciphertext_linear_oracle as literal
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import reduction_oracles as integer


@dataclass(frozen=True)
class Operator:
    n: int
    q: int
    replies: int
    degrees: tuple[int, ...]
    # [column][reply * 2 + component][coefficient], centered in the inner Q.
    generators: tuple[tuple[tuple[int, ...], ...], ...]

    @property
    def rows(self):
        return 2 * self.n * self.replies

    @property
    def width(self):
        return sum(self.degrees)


def validate(op):
    if (type(op) is not Operator or type(op.n) is not int or not 2 <= op.n <= 64
            or op.n & (op.n - 1) or type(op.q) is not int or not 3 <= op.q < 1 << 60
            or type(op.replies) is not int or not 1 <= op.replies <= 16
            or type(op.degrees) is not tuple or not op.degrees
            or any(type(d) is not int or d < 1 or op.n % d for d in op.degrees)
            or op.rows * op.width > 1000000 or type(op.generators) is not tuple
            or len(op.generators) != len(op.degrees)
            or any(type(column) is not tuple or len(column) != 2 * op.replies
                   or any(type(p) is not tuple or len(p) != op.n
                          or any(type(x) is not int or abs(x) > op.q // 2 for x in p)
                          for p in column) for column in op.generators)):
        raise ValueError("Invalid bounded structured operator")


def from_index(index, pk):
    masked._context(index.space, pk)
    if len(index.columns) != index.space.columns:
        raise ValueError("Wrong public index column count")
    replies = index.space.layout.cost.response_ciphertexts
    for column in index.columns:
        masked.validate_ciphertexts(column, replies, pk)
    q = int(pk.q)
    generators = tuple(tuple(tuple(int(x) if x <= q // 2 else int(x) - q for x in p)
                             for cipher in column for p in cipher.components)
                       for column in index.columns)
    op = Operator(pk.n, q, replies, index.space.column_degrees, generators)
    validate(op)
    return op


def _vector(values, count):
    if type(values) is not tuple or len(values) != count or any(type(x) is not int for x in values):
        raise ValueError("Incorrect structured operator vector")


def _integer_forward(op, forms):
    result = [0] * op.rows
    cursor = 0
    for degree, column in zip(op.degrees, op.generators, strict=True):
        for k, weight in enumerate(forms[cursor:cursor + degree]):
            shift = k * (op.n // degree)
            for block, poly in enumerate(column):
                for i, coefficient in enumerate(poly):
                    target = i + shift
                    result[block * op.n + target % op.n] += coefficient * weight * (1 if target < op.n else -1)
        cursor += degree
    return tuple(result)


def forward(op, forms):
    validate(op)
    _vector(forms, op.width)
    return tuple(x % op.q for x in _integer_forward(op, forms))


def adjoint(op, challenge):
    """Convolution with beta(X^-1), independent of literal shift columns."""
    validate(op)
    _vector(challenge, op.rows)
    result = []
    for degree, column in zip(op.degrees, op.generators, strict=True):
        total = [0] * op.n
        for block, poly in enumerate(column):
            beta = challenge[block * op.n:(block + 1) * op.n]
            inverse = (beta[0], *tuple(-x for x in reversed(beta[1:])))
            product = integer.ring_product(poly, inverse)
            total = [a + b for a, b in zip(total, product, strict=True)]
        result.extend((total[0] if k == 0 else -total[op.n - k * (op.n // degree)]) % op.q
                      for k in range(degree))
    return tuple(result)


def balanced_digits(value, base):
    if type(value) is not int or type(base) is not int or not 4 <= base <= 65536 or base & (base - 1):
        raise ValueError("Expected bounded power-of-two digit base")
    result = []
    while value:
        digit = value % base
        # Allow both signed ties: this avoids a spurious leading carry digit.
        if digit > base // 2 or (digit == base // 2 and value < 0):
            digit -= base
        result.append(digit)
        value = (value - digit) // base
    return tuple(result) or (0,)


def digit_count(q, base):
    balanced_digits(0, base)
    if type(q) is not int or not 3 <= q < 1 << 60:
        raise ValueError("Expected bounded inner Q")
    count, capacity = 1, base // 2
    while capacity < q // 2:
        capacity = base * capacity + base // 2
        count += 1
    return count


def digit_products(op, forms, base):
    """Return INTEGER digit outputs; reducing them needs an explicit field bound."""
    validate(op)
    _vector(forms, op.width)
    count = digit_count(op.q, base)
    split = tuple(tuple(tuple(balanced_digits(x, base) for x in p) for p in column)
                  for column in op.generators)
    outputs = []
    for j in range(count):
        generators = tuple(tuple(tuple(d[j] if j < len(d) else 0 for d in p) for p in column)
                           for column in split)
        outputs.append(_integer_forward(Operator(op.n, op.q, op.replies, op.degrees, generators), forms))
    return tuple(outputs)


def reconstruct_digit_products(outputs, base, q):
    count = digit_count(q, base)
    if type(outputs) is not tuple or len(outputs) != count or not outputs[0]:
        raise ValueError("Incorrect digit output shape")
    for output in outputs:
        _vector(output, len(outputs[0]))
    return tuple(sum(base**j * output[i] for j, output in enumerate(outputs)) % q for i in range(len(outputs[0])))


def projected_rows(certificate):
    return tuple(i for r, indices in enumerate(certificate.kept_c0)
                 for i in (*tuple(2 * r * certificate.n + k for k in indices),
                           *tuple(range((2 * r + 1) * certificate.n, (2 * r + 2) * certificate.n))))


def project(values, rows):
    _vector(values, len(values))
    if type(rows) is not tuple or tuple(sorted(set(rows))) != rows or any(type(i) is not int or not 0 <= i < len(values) for i in rows):
        raise ValueError("Incorrect public projection")
    return tuple(values[i] for i in rows)


def projection_adjoint(challenge, rows, full_count):
    _vector(challenge, len(rows))
    project((0,) * full_count, rows)
    result = [0] * full_count
    for i, value in zip(rows, challenge, strict=True):
        result[i] = value
    return tuple(result)


def recover_public_input(matrix: literal.Matrix, output):
    """Public Gaussian elimination control; unique full-rank inputs only."""
    _vector(output, len(matrix.rows))
    width, q = len(matrix.rows[0]), matrix.q
    if len(matrix.rows) * width > 1000000:
        raise ValueError("Recovery exceeds bounded oracle")
    augmented = [[*(x % q for x in row), value % q] for row, value in zip(matrix.rows, output, strict=True)]
    pivot = 0
    for column in range(width):
        choice = next((i for i in range(pivot, len(augmented)) if augmented[i][column]), None)
        if choice is None:
            raise ValueError("Public operator does not uniquely determine its input")
        augmented[pivot], augmented[choice] = augmented[choice], augmented[pivot]
        inverse = pow(augmented[pivot][column], -1, q)
        augmented[pivot] = [x * inverse % q for x in augmented[pivot]]
        for i, row in enumerate(augmented):
            if i != pivot:
                factor = row[column]
                augmented[i] = [(x - factor * y) % q for x, y in zip(row, augmented[pivot], strict=True)]
        pivot += 1
    if any(row[-1] for row in augmented[width:]):
        raise ValueError("Inconsistent public result")
    return tuple(row[-1] for row in augmented[:width])


def digit_screen(*, rows, width, columns, q, query_bound, base):
    """Optimistic exact-INTEGER terminal bodies, excluding the outer protocol."""
    count = digit_count(q, base)
    if any(type(x) is not int or x < 1 for x in (rows, width, columns, query_bound)):
        raise ValueError("Invalid bounded resource dimensions")
    bound = width * (base // 2) * query_bound
    minimum_modulus = 2 * bound + 1
    output_bits = count * minimum_modulus.bit_length()
    return {"base": base, "digits": count, "digit_entry_bound": base // 2,
            "integer_digit_product_bound": bound, "minimum_exact_outer_plaintext_modulus": minimum_modulus,
            "minimum_plaintext_bits": minimum_modulus.bit_length(),
            "digit_output_bits_per_inner_residue": output_bits,
            "optimistic_digit_output_body_bytes": (rows * output_bits + 7) // 8,
            "inner_output_body_bytes": (rows * q.bit_length() + 7) // 8,
            "digit_generator_entries": rows * columns * count,
            "literal_digit_entries": rows * width * count,
            "literal_to_generator_expansion": width / columns,
            "outer_ciphertext_proof_setup_and_private_state_included": False,
            "admissible_extracted_norm_correctness_established": False,
            "scope": "Integer no-wrap screening bound only; actual outer parameters, compressed linear release and proof may differ."}
