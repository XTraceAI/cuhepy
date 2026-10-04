"""Independent public aggregate references: small schoolbook and saved GMP.

Neither reference is an admission authority. No secret/encryption/decryption,
native control call or change to the earlier small-reference guard is used.
"""

from __future__ import annotations

from gmpy2 import mpz

from experiments.bfv_search_lab import native_boundary_oracle as schoolbook
from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab import shared_query_bgv as shared
from experiments.bfv_search_lab import shared_query_gmp as gmp


def _small_switch(source, key, q):
    total = [(0,) * len(source), (0,) * len(source)]
    for digit, column in enumerate(key):
        values = tuple((x >> (30 * digit)) & ((1 << 30) - 1) for x in source)
        for component in range(2):
            total[component] = schoolbook.add(
                total[component], schoolbook.multiply(values, column[component], q), q
            )
    return tuple(total)


def small_aggregates(context):
    if type(context) is not shared.Context or context.profile.n > 64:
        raise ValueError("Independent schoolbook reference is bounded to N<=64")
    p = context.profile
    if p.policy != "canonical30" or p.index_mode != "owner":
        raise ValueError("Selected owner canonical profile required")
    p.require_safe()
    frontier = [context.query]
    for level, (exponent, key) in enumerate(context.rotations):
        even, odd = [], []
        for pair in frontier:
            rotated = tuple(schoolbook.automorphism(row, exponent, p.q) for row in pair)
            switched = _small_switch(rotated[1], key, p.q)
            rotated = (schoolbook.add(rotated[0], switched[0], p.q), switched[1])
            even.append(
                tuple(schoolbook.add(a, b, p.q) for a, b in zip(pair, rotated, strict=True))
            )
            odd.append(
                tuple(
                    schoolbook.monomial(schoolbook.add(a, b, p.q, -1), -(1 << level), p.q)
                    for a, b in zip(pair, rotated, strict=True)
                )
            )
        frontier = even + odd
    rows = []
    for group in range(context.groups):
        total = [(0,) * p.n for _ in range(3)]
        for feature in range(p.dimension):
            x, y = frontier[feature], context.index[group * p.dimension + feature]
            terms = (
                schoolbook.multiply(x[0], y[0], p.q),
                schoolbook.add(
                    schoolbook.multiply(x[0], y[1], p.q), schoolbook.multiply(x[1], y[0], p.q), p.q
                ),
                schoolbook.multiply(x[1], y[1], p.q),
            )
            total = [schoolbook.add(a, b, p.q) for a, b in zip(total, terms, strict=True)]
        rows.extend(total)
    return native.pack_common(tuple(rows), p.n, p.q)


def from_saved_transcript(metadata, key_body, full_body):
    """Recover the aggregate using only a previously validated public tape.

    Saved C2 is the genuine pre-relinearization aggregate; saved final outputs
    are C0/C1 plus key-switch(C2). Subtracting an independent whole-Q GMP switch
    recovers the other two components. The caller must separately authenticate
    and pin the original tape's independent correctness provenance.
    """
    if type(metadata) is not native.PublicMetadata:
        raise ValueError("Bounded public metadata required")
    metadata.__post_init__()
    p = metadata.profile
    gmp._validate_buffer(key_body, (p.levels + 1) * 8, p.n, p.q)
    gmp._validate_buffer(full_body, metadata.sources + 2 * metadata.groups, p.n, p.q)
    stride = p.n * native.COMMON_WIDTH
    key = tuple(
        tuple(gmp._row(key_body, (2 * digit + c) * stride, p.n) for c in range(2))
        for digit in range(4)
    )
    rows = []
    for group in range(metadata.groups):
        c2 = gmp._row(full_body, (p.padded - 1 + group) * stride, p.n)
        switched = gmp._switch(c2, key, mpz(p.q))
        rows.extend(
            gmp._add(
                gmp._row(full_body, (metadata.sources + 2 * group + c) * stride, p.n),
                switched[c],
                mpz(p.q),
                -1,
            )
            for c in range(2)
        )
        rows.append(c2)
    return b"".join(gmp._row_bytes(row) for row in rows)
