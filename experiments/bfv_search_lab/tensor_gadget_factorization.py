"""Q70 known-control factorization: group radix cross terms by a+b.

The digit dimension is an ordinary polynomial convolution. Shared composite
keys replace a sufficient but expensive per-node public query matrix. This is
small public exact arithmetic and a resource model, not a native verifier or
new cryptographic primitive. A generic control receives the same factorization.
"""

from __future__ import annotations

from experiments.bfv_search_lab import propagated_gadget_bgv as gadget
from experiments.bfv_search_lab import tensor_gadget_seed as seed


def power_rows(q, bits):
    ell = (q.bit_length() + bits - 1) // bits
    return tuple(
        tuple(
            row[0] for row in gadget.canonical_digits((pow(1 << bits, r, q),), q, bits)
        )
        for r in range(2 * ell - 1)
    )


def cross_sums(query, indexed, q, bits):
    """T_r = sum_(a+b=r),alpha dq_alpha[a]*dI_(1-alpha)[b]."""
    dq = tuple(gadget.canonical_digits(p, q, bits) for p in query)
    di = tuple(gadget.canonical_digits(p, q, bits) for p in indexed)
    return digit_cross_sums(dq, di)


def digit_cross_sums(dq, di):
    """Bivariate integer product, also for signed derived input families."""
    n, ell = len(dq[0][0]), len(dq[0])
    out = [[0] * n for _ in range(2 * ell - 1)]
    for alpha in range(2):
        for a in range(ell):
            for b in range(ell):
                product = gadget.integer_product(dq[alpha][a], di[1 - alpha][b])
                out[a + b] = [x + y for x, y in zip(out[a + b], product, strict=True)]
    return tuple(tuple(p) for p in out)


def grouped_seed(query, indexed, relin_digits, relin_a, q, bits):
    """Exact signed integer E, identical to the unfactored reference."""
    n, ell = len(query[0]), (q.bit_length() + bits - 1) // bits
    out = [[0] * n for _ in range(ell)]
    for row, product in zip(
        power_rows(q, bits), cross_sums(query, indexed, q, bits), strict=True
    ):
        for j, scalar in enumerate(row):
            out[j] = [x + scalar * y for x, y in zip(out[j], product, strict=True)]
    for d, a in zip(relin_digits, relin_a, strict=True):
        for j, da in enumerate(gadget.canonical_digits(a, q, bits)):
            product = gadget.integer_product(d, da)
            out[j] = [x + y for x, y in zip(out[j], product, strict=True)]
    return tuple(tuple(p) for p in out)


def composite_keys(relin_a, rotation_key, exponent, q, bits):
    """Shared L_(r,k)=sum_j gamma_(r,j)*K_(j,k), R_(c,k)."""
    n = len(relin_a[0])
    linear = tuple(
        tuple(
            tuple(
                sum(scalar * rotation_key[j][k][i] for j, scalar in enumerate(row)) % q
                for i in range(n)
            )
            for k in range(2)
        )
        for row in power_rows(q, bits)
    )
    relin = []
    for a in relin_a:
        row = []
        da = gadget.canonical_digits(a, q, bits)
        for k in range(2):
            out = [0] * n
            for j, digits in enumerate(da):
                product = gadget.integer_product(
                    gadget.permute(digits, exponent), rotation_key[j][k]
                )
                out = [(x + y) % q for x, y in zip(out, product, strict=True)]
            row.append(tuple(out))
        relin.append(tuple(row))
    return linear, tuple(relin)


def fused_first_switch(
    left, right, query, relin_a, rotation_key, exponent, shift, product_shift, q, bits
):
    """Known composite-key control for one first unary/binary rotation.

    left/right are (public index pair, canonical C2 digits). Original tensor
    C0/plus work, relinearization work and terminal conversion remain additional.
    """
    linear, relin = composite_keys(relin_a, rotation_key, exponent, q, bits)
    n, out = len(query[0]), [[0] * len(query[0]) for _ in range(2)]

    def family(a, b):
        shifted = gadget.permute(a, shift=product_shift)
        other = (
            (0,) * n if b is None else gadget.permute(b, shift=product_shift + shift)
        )
        return gadget.permute(
            tuple(x - y for x, y in zip(shifted, other, strict=True)), exponent
        )

    dq = tuple(
        tuple(
            gadget.permute(row, exponent) for row in gadget.canonical_digits(p, q, bits)
        )
        for p in query
    )
    di = []
    for alpha in range(2):
        left_digits = gadget.canonical_digits(left[0][alpha], q, bits)
        right_digits = (
            None if right is None else gadget.canonical_digits(right[0][alpha], q, bits)
        )
        di.append(
            tuple(
                family(row, None if right_digits is None else right_digits[a])
                for a, row in enumerate(left_digits)
            )
        )
    # Combine siblings before multiplication. Canonicalizing the combined
    # digits would change the chosen common lift and invalidate this identity.
    combined_cross = digit_cross_sums(dq, tuple(di))
    for r, keys in enumerate(linear):
        common = combined_cross[r]
        for k in range(2):
            product = gadget.integer_product(common, keys[k])
            out[k] = [(x + y) % q for x, y in zip(out[k], product, strict=True)]
    for c, keys in enumerate(relin):
        common = family(left[1][c], None if right is None else right[1][c])
        for k in range(2):
            product = gadget.integer_product(common, keys[k])
            out[k] = [(x + y) % q for x, y in zip(out[k], product, strict=True)]
    return tuple(tuple(p) for p in out)


def resource_models(geometry, bits):
    """Sufficient RNS state and pointwise counts; never ring-convolution times."""
    n, d = geometry["N"], geometry["D"]
    q, ell30 = int(geometry["Q_hex"], 16), 4
    ell, limb_bytes = (q.bit_length() + bits - 1) // bits, n * 2 * 8
    shared = 2 * (2 * ell - 1) + 2 * ell30
    cards = []
    models = seed.source_models(geometry, bits)
    for vectors in geometry["vectors"]:
        tiles = (vectors + n // d - 1) // (n // d)
        nodes = sum(min(d // 2, min(d, tiles - start)) for start in range(0, tiles, d))
        body = next(
            m
            for m in models
            if m["vectors"] == vectors and m["rule"] == "tensor_seed_first_rotation"
        )
        cards.append(
            {
                "vectors": vectors,
                "tiles": tiles,
                "first_nodes": nodes,
                "all_guards_pass": body["all_guards_pass"],
                "full_source_and_terminal_Q_body_bytes": body[
                    "full_source_and_terminal_Q_body_bytes"
                ],
                "shared_L_R_polynomials": shared,
                "shared_L_R_RNS_word_bytes": shared * limb_bytes,
                "L_setup_word_multiply_accumulates": 2 * (2 * ell - 1) * ell * n * 2,
                "R_setup_ring_product_equivalents": 2 * ell30 * ell,
                "cached_index_digit_RNS_word_bytes": 2 * ell * tiles * limb_bytes,
                "cached_index_setup_forward_prime_NTTs": 2 * ell * tiles * 2,
                "cached_combined_first_family_RNS_word_bytes": 2
                * ell
                * nodes
                * limb_bytes,
                "combined_family_setup_forward_prime_NTTs": 2 * ell * nodes * 2,
                "index_canonical_polynomials_decomposed": 2 * tiles,
                "streamed_index_pair_digit_RNS_word_bytes": 4 * ell * limb_bytes,
                "shared_query_digit_RNS_word_bytes": 2 * ell * limb_bytes,
                "query_forward_prime_NTTs": 2 * ell * 2,
                "streamed_index_per_query_forward_prime_NTTs": 2 * ell * tiles * 2,
                "streamed_combined_family_per_query_forward_prime_NTTs": 2
                * ell
                * nodes
                * 2,
                "cross_term_poly_word_products_per_query": 2 * ell**2 * nodes,
                "L_R_poly_word_products_per_query": shared * nodes,
                "factorized_total_word_products_per_query": (2 * ell**2 + shared)
                * nodes
                * n
                * 2,
                "expanded_query_matrix_RNS_word_bytes": body[
                    "compiled_query_matrix_RNS_word_bytes"
                ],
                "expanded_matrix_setup_poly_word_products": 4 * ell**2 * nodes,
                "expanded_online_word_products_per_query": (4 * ell + 2 * ell30)
                * nodes
                * n
                * 2,
                "scope": "Sufficient first-rotation correction state/count model. Existing input/index/keys, tensor C0/C2/relinearization/plus work, digit CRT, transforms/permutations, all later rotations, verification state, terminal conversion, allocation/scratch and update/lifecycle costs are additional. Counts are not complete service totals, latency or state lower bounds. No fresh functional secret-key family. Generic known-method control receives identical body, guards and factorization.",
            }
        )
    return cards
