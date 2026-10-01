"""E69 ideal RANDOM-matrix triple to fixed private matrix correlation control.

An ideal source, not a PCG/MAC implementation. All values below stay inside
the trusted owner in this control. The correction (M-B)r still needs a dense
product; declaring Br 'offline' does not eliminate it or fresh HE encryption.
"""

from __future__ import annotations

from dataclasses import dataclass

from gmpy2 import is_prime


@dataclass(frozen=True)
class Triple:
    matrix: tuple[tuple[int, ...], ...]
    mask: tuple[int, ...]
    product: tuple[int, ...]
    prime: int


def matrix_valid(matrix, prime):
    if (type(prime) is not int or not 3 <= prime <= 65537 or not is_prime(prime)
            or type(matrix) is not tuple or not 1 <= len(matrix) <= 128
            or type(matrix[0]) is not tuple or not 1 <= len(matrix[0]) <= 32
            or any(type(row) is not tuple or len(row) != len(matrix[0])
                   or any(type(x) is not int or not 0 <= x < prime for x in row) for row in matrix)):
        raise ValueError("Invalid bounded private matrix")


def product(matrix, mask, prime):
    matrix_valid(matrix, prime)
    if type(mask) is not tuple or len(mask) != len(matrix[0]) or any(type(x) is not int or not 0 <= x < prime for x in mask):
        raise ValueError("Incorrect private mask")
    return tuple(sum(a*b for a, b in zip(row, mask, strict=True)) % prime for row in matrix)


def ideal_triple(rows, width, prime, rng):
    if type(rows) is not int or not 1 <= rows <= 128 or type(width) is not int or not 1 <= width <= 32:
        raise ValueError("Ideal correlation exceeds oracle limit")
    matrix = tuple(tuple(rng.randrange(prime) for _ in range(width)) for _ in range(rows))
    mask = tuple(rng.randrange(prime) for _ in range(width))
    return Triple(matrix, mask, product(matrix, mask, prime), prime)


def audit_ideal_triple(triple):
    """Diagnostic recomputation; this is NOT distributed MAC verification."""
    if type(triple) is not Triple or product(triple.matrix, triple.mask, triple.prime) != triple.product:
        raise ValueError("Malformed ideal correlation")


def convert(owner_matrix, triple):
    matrix_valid(owner_matrix, triple.prime)
    if len(owner_matrix) != len(triple.matrix) or len(owner_matrix[0]) != len(triple.mask):
        raise ValueError("Wrong fixed-matrix correlation geometry")
    # A valid triple is an IDEAL prerequisite. Its real distribution,
    # authentication, generation and recipient model need their own protocol.
    correction = tuple(tuple((m-b) % triple.prime for m, b in zip(row, random_row, strict=True))
                       for row, random_row in zip(owner_matrix, triple.matrix, strict=True))
    delta_product = product(correction, triple.mask, triple.prime)
    return tuple((a+b) % triple.prime for a, b in zip(triple.product, delta_product, strict=True))


def cost(rows, width, *, tokens=1, field_bits=8):
    if any(type(x) is not int or x < 1 for x in (rows, width, tokens, field_bits)):
        raise ValueError("Positive count inputs required")
    return {"owner_correction_field_products": rows*width*tokens,
            "direct_fresh_plaintext_field_products": rows*width*tokens,
            "owner_correction_matrix_subtractions": rows*width*tokens,
            "ideal_random_matrix_body_bytes": (rows*width*tokens*field_bits + 7)//8,
            "ideal_mask_and_product_body_bytes": ((rows+width)*tokens*field_bits + 7)//8,
            "fresh_ciphertext_and_full_Q_check_cost_removed": False,
            "real_generator_setup_expansion_authentication_cost_included": False,
            "scope": "Naive dense correction control; structure/batching may alter runtime, not counted as a new protocol here."}
