"""E28 matrix-source/gadget accounting, not an encrypted latency estimator.

All variants here produce the same independent module-vector output format.
No free cross-row response packing, terminal reduction, parameter equivalence
or authentication is assumed. n*k held fixed is only a dimension control.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Variant = Literal["right", "right_symmetric", "left_independent", "left_transpose", "gadget_query"]


@dataclass(frozen=True)
class MatrixCost:
    variant: str
    rank: int
    ring_degree: int
    effective_dimension: int
    output_columns: int
    output_rows: int
    source_values_per_output: int
    distinct_offline_sources: int
    query_gadget_sources: int
    offline_gadget_bytes: int
    offline_gadget_bytes_if_uniform_masks_seeded: int
    query_coefficient_bytes: int
    query_bytes_if_uniform_masks_seeded: int
    index_coefficient_bytes: int
    response_coefficient_bytes: int
    switching_ring_products: int
    ring_product_degree: int
    owner_source_secret_coefficients: int
    owner_output_secret_coefficients: int
    per_output_switch_error_bound: int


def cost(variant: Variant, rank: int, *, effective_dimension: int = 16384,
         columns: int = 1, rows: int = 1, q_bits: int = 120, digit_bits: int = 30,
         t: int = 1153, eta: int = 1) -> MatrixCost:
    """Uncompressed coefficient bodies; query projection drops unused C0 columns.

    A right-oriented query still needs its entire k-by-k random mask even if
    only b plaintext output columns matter. Left-oriented masks are k-by-b.
    The gadget-query body is regenerated per query, not amortized as setup.
    Switching counts omit forming coefficients, NTTs, sums and owner work.
    """
    if (variant not in ("right", "right_symmetric", "left_independent", "left_transpose", "gadget_query")
            or any(type(x) is not int or x < 1 for x in
                   (rank, effective_dimension, columns, rows, q_bits, digit_bits, t))
            or effective_dimension % rank or columns > rank
            or type(eta) is not int or eta < 0):
        raise ValueError("Invalid matrix count-model context")
    n, k, b = effective_dimension // rank, rank, columns
    if n & (n - 1):
        raise ValueError("Underlying ring degree must be a power of two")
    digits, width = (q_bits + digit_bits - 1) // digit_bits, (q_bits + 7) // 8
    ciphertext_bytes = (k + 1) * n * width
    query_sources = 0
    if variant == "right":
        per_output, sources = k * k + k ** 3, k * k + k ** 3 * b
    elif variant == "right_symmetric":
        per_output = k * k + k ** 3 - k * (k - 1) // 2
        selected = k * b
        sources = k * k + k * k * selected - selected * (selected - 1) // 2
    elif variant == "left_independent":
        per_output = sources = 3 * k * k
    elif variant == "left_transpose":
        per_output = sources = k * k + k * (k + 1) // 2
    else:
        per_output, sources, query_sources = 2 * k, 0, 2 * k * b
    if variant.startswith("right"):
        query_bytes = (k * k + k * b) * n * width
    elif variant == "gadget_query":
        query_bytes = query_sources * digits * ciphertext_bytes
    else:
        query_bytes = 2 * k * b * n * width
    # Standard seeded-uniform-component control, not a new codec or measured
    # packet. One public 32-byte seed expands all masks with distinct domains.
    seeded_key = sources * digits * n * width + (32 if sources else 0)
    seeded_query = (query_sources * digits * n * width if query_sources else k * b * n * width) + 32
    return MatrixCost(
        variant, k, n, effective_dimension, b, rows, per_output, sources, query_sources,
        sources * digits * ciphertext_bytes, seeded_key, query_bytes, seeded_query, 2 * rows * k * n * width,
        rows * b * ciphertext_bytes, rows * b * per_output * digits * (k + 1), n,
        k * k * n * (2 if variant == "left_independent" else 1), k * n,
        per_output * digits * n * ((1 << digit_bits) - 1) * t * eta,
    )


def masked_cost(rank: int, *, effective_dimension: int = 16384, rows: int = 1,
                q_bits: int = 120, digit_bits: int = 30, t: int = 65537,
                mask_space: Literal["full", "constant"] = "full") -> dict[str, int | str]:
    """One-use offline/online split with both resident index representations.

    Online fields use the implemented byte-aligned residues; bit packing is a
    separate idealized control. Headers/authentication/runtime memory are extra.
    This is not an amortized reduction in total per-query work or traffic.
    """
    base = cost("gadget_query", rank, effective_dimension=effective_dimension, rows=rows,
                q_bits=q_bits, digit_bits=digit_bits, t=t)
    if mask_space not in ("full", "constant"):
        raise ValueError("Unknown public query subspace")
    n, width, digits = base.ring_degree, (q_bits + 7) // 8, (q_bits + digit_bits - 1) // digit_bits
    cipher_bytes = (rank + 1) * n * width
    query_dimension = rank * (n if mask_space == "full" else 1)
    return {
        "mask_space": mask_space,
        "rank": rank, "ring_degree": n, "effective_dimension": effective_dimension, "output_rows": rows,
        "offline_query_coefficient_bytes_per_token": base.query_coefficient_bytes,
        "offline_query_bytes_if_uniform_masks_seeded": base.query_bytes_if_uniform_masks_seeded,
        "online_delta_coefficient_bytes": query_dimension * ((t.bit_length() + 7) // 8),
        "online_delta_if_bitpacked_bytes": (query_dimension * t.bit_length() + 7) // 8,
        "response_coefficient_bytes": rows * cipher_bytes,
        "server_stored_answer_bytes_per_unused_token": rows * cipher_bytes,
        "original_index_coefficient_bytes": base.index_coefficient_bytes,
        "converted_index_coefficient_bytes": rows * rank * cipher_bytes,
        "total_resident_index_coefficient_bytes": base.index_coefficient_bytes + rows * rank * cipher_bytes,
        "one_time_linear_key_bytes": rank * rank * digits * cipher_bytes,
        "one_time_index_conversion_ring_products": rows * rank * rank * digits * (rank + 1),
        "offline_switch_ring_products_per_token": base.switching_ring_products,
        "online_plaintext_ciphertext_ring_products": rows * rank * (rank + 1) if mask_space == "full" else 0,
        "online_scalar_coefficient_multiplications": rows * rank * (rank + 1) * n if mask_space == "constant" else 0,
        "online_switches": 0,
        "owner_mask_seed_bytes_per_token": 32,
        "local_epoch_and_token_id_bytes": 48,
        "owner_mask_field_body_bytes": query_dimension * ((t.bit_length() + 7) // 8),
        "oracle_expanded_mask_polynomial_coefficients": rank * n,
    }


def published_naive_relinearization_body(rank: int, degree: int, q_bits: int = 120,
                                       digit_bits: int = 30) -> int:
    """Literal k^4 full matrix masks per digit, before other conversions.

    This is a different output representation from cost(), so is a size
    reference only, not an apples-to-apples speed comparison to our oracle.
    """
    if any(type(x) is not int or x < 1 for x in (rank, degree, q_bits, digit_bits)):
        raise ValueError("Expected positive dimensions/widths")
    return 2 * rank ** 6 * degree * ((q_bits + digit_bits - 1) // digit_bits) * ((q_bits + 7) // 8)


def lookup_rank_bound(dimension: int, supports: tuple[tuple[int, ...], ...]) -> dict[str, int]:
    """E25 small structural control for a fixed support-class dictionary.

    Within a class whose possible private addresses are J, q -> q_j includes
    an |J|-by-|J| identity submatrix on singleton queries. Any exact separated
    scalar bilinear encoding needs |J| features (|J|-1 with a query-only
    offset). This says nothing about arbitrary HE circuits or ring packing.
    Hiding the selected class still needs a priced encrypted selector.
    """
    if (type(dimension) is not int or dimension < 1 or not supports
            or any(not group or len(set(group)) != len(group)
                   or any(type(j) is not int or not 0 <= j < dimension for j in group)
                   for group in supports)):
        raise ValueError("Invalid private residual support classes")
    union = {j for group in supports for j in group}
    return {"classes": len(supports), "distinct_possible_addresses": len(union),
            "sum_class_features": sum(map(len, supports)),
            "worst_class_features": max(map(len, supports)),
            "hidden_class_joint_features": len(union),
            "hidden_class_with_query_offset_features": max(0, len(union) - 1)}
