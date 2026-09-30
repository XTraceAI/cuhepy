"""E47 exact public ciphertext-coefficient matrix, with full-Q lift controls.

An algebra/count oracle, not an outer encryption or verification protocol.
Explicit expansion is bounded before allocation. Secret HE state never enters
this operator: its inputs are the public index and private centered CRT forms.
No off-the-shelf vLHE parameters, composition proof or implicit-matrix support
are assumed. The existing production/research response gates are untouched.
"""

from __future__ import annotations

from dataclasses import dataclass

from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import reduction_oracles as reference
from experiments.bfv_search_lab import shallow_bgv as bgv


@dataclass(frozen=True)
class Matrix:
    rows: tuple[tuple[int, ...], ...]
    q: int
    n: int
    replies: int


def shape(s: space.Space) -> tuple[int, int]:
    space.validate(s)
    return 2 * s.layout.cost.response_ciphertexts * s.layout.context.n, sum(s.column_degrees)


def cost(s: space.Space, q: int) -> dict[str, int | bool | str]:
    rows, columns = shape(s)
    if type(q) is not int or not 3 <= q < 1 << 60:
        raise ValueError("Invalid inner word modulus")
    bits = q.bit_length()
    return {"output_residues": rows, "matrix_columns": columns,
            "literal_entries": rows * columns,
            "literal_packed_body_bytes": (rows * columns * bits + 7) // 8,
            "literal_native_word_bytes": rows * columns * 8,
            "implicit_base_packed_body_bytes": (rows * s.columns * bits + 7) // 8,
            "literal_to_base_entry_factor_numerator": columns,
            "literal_to_base_entry_factor_denominator": s.columns,
            "full_q_output_uncompressed_body_bytes": (rows * bits + 7) // 8,
            "centered_database_entry_bound": q // 2,
            "query_entry_bound": s.layout.context.prime // 2,
            "integer_inner_product_absolute_bound": columns * (q // 2) * (s.layout.context.prime // 2),
            "outer_plaintext_modulus_required": q,
            "outer_ciphertext_bytes": "unresolved: depends on reviewed outer parameters/packing",
            "implicit_matrix_supported_by_outer_reference": False,
            "removes_trusted_owner_answer_only_if_composition_is_proved": True}


def matrix(index: masked.Index, pk: bgv.PublicKey, *, entry_limit: int = 1000000) -> Matrix:
    rows, width = shape(index.space)
    if (type(entry_limit) is not int or not 1 <= entry_limit <= 1000000
            or rows * width > entry_limit):
        raise ValueError("Literal ciphertext matrix exceeds oracle work limit")
    if (pk.n, pk.t) != (index.space.layout.context.n, index.space.layout.context.prime):
        raise ValueError("Wrong public index context")
    replies = index.space.layout.cost.response_ciphertexts
    if len(index.columns) != index.space.columns:
        raise ValueError("Wrong index column count")
    for column in index.columns:
        masked.validate_ciphertexts(column, replies, pk)
    output = []
    for r in range(replies):
        for component in range(2):
            for coefficient in range(pk.n):
                row = []
                for column, degree in zip(index.columns, index.space.column_degrees, strict=True):
                    for k in range(degree):
                        # Collapsed/shared columns may use a proper subring
                        # smaller than the final leaf cover. Their true spacing
                        # is N/degree, not the cover's minimum leaf degree.
                        shift = k * (pk.n // degree)
                        value = int(column[r].components[component][(coefficient - shift) % pk.n])
                        value = value if value <= pk.q // 2 else value - int(pk.q)
                        row.append(value if coefficient >= shift else -value)
                output.append(tuple(row))
    return Matrix(tuple(output), int(pk.q), pk.n, replies)


def alpha(s: space.Space, values: tuple[int, ...]) -> tuple[int, ...]:
    """Compute CRT in F_t first, THEN center each resulting coefficient."""
    return tuple(x for row in space.corrections(s, values) for x in row)


def evaluate(operator: Matrix, forms: tuple[int, ...]) -> tuple[int, ...]:
    if (type(forms) is not tuple or len(forms) != len(operator.rows[0])
            or any(type(x) is not int for x in forms)):
        raise ValueError("Incorrect literal private query forms")
    return tuple(sum(a * b for a, b in zip(row, forms, strict=True)) % operator.q for row in operator.rows)


def independent(index: masked.Index, pk: bgv.PublicKey, values: tuple[int, ...]) -> tuple[int, ...]:
    """Independent integer schoolbook ring products, without matrix shifts."""
    corrections = space.corrections(index.space, values)
    result = []
    for r in range(index.space.layout.cost.response_ciphertexts):
        for component in range(2):
            out = [0] * pk.n
            for column, short in zip(index.columns, corrections, strict=True):
                product = reference.ring_product(tuple(map(int, column[r].components[component])),
                                                 tuple(space.expand(index.space, short)))
                out = [a + b for a, b in zip(out, product, strict=True)]
            result.extend(x % int(pk.q) for x in out)
    return tuple(result)
