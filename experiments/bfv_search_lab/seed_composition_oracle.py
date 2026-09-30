"""E53 negative oracle: PUBLIC zero seed breaks homomorphic pad correlations.

Own tiny research contexts only. Recover centered CRT forms from the public C1
matrix and a deliberately disclosed rerandomizer seed. No secret key or private
map enters recovery. This is a conditional linear-algebra obstruction to a
naive E48/E49 composition, not an attack on the implemented Factory (which
keeps that seed private), not a general RLWE break or a novelty claim.
"""

from __future__ import annotations

from gmpy2 import is_prime

from experiments.bfv_search_lab import ciphertext_linear_oracle as outer
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as crt
from experiments.bfv_search_lab import owner_bgv as owner


def solve(rows, rhs, q):
    """Exact overdetermined field solve; fail closed on deficient/inconsistent rank."""
    if (type(q) is not int or not 3 <= q < 1 << 60 or not is_prime(q)
            or not rows or len(rows) != len(rhs) or not 1 <= len(rows[0]) <= 64
            or len(rows) > 512 or any(len(row) != len(rows[0]) for row in rows)):
        raise ValueError("Negative oracle exceeds tiny matrix bounds")
    width = len(rows[0])
    work = [[int(x) % q for x in row] + [int(y) % q] for row, y in zip(rows, rhs, strict=True)]
    for j in range(width):
        pivot = next((i for i in range(j, len(work)) if work[i][j]), None)
        if pivot is None:
            raise ValueError("Public C1 operator lacks full column rank")
        work[j], work[pivot] = work[pivot], work[j]
        inverse = pow(work[j][j], -1, q)
        work[j] = [x * inverse % q for x in work[j]]
        for i in range(len(work)):
            if i != j and work[i][j]:
                factor = work[i][j]
                work[i] = [(a - factor * b) % q for a, b in zip(work[i], work[j], strict=True)]
    if any(row[-1] for row in work[width:]):
        raise ValueError("Disclosed zero seed is inconsistent with the public correlation")
    return tuple(work[j][-1] for j in range(width))


def recover(index, pk, answer, request, zero_seeds):
    s, count = index.space, index.space.layout.cost.response_ciphertexts
    masked.validate_request(request)
    masked.validate_ciphertexts(answer.ciphertexts, count, pk)
    if (answer.space != s or request.space != s or answer.epoch != index.epoch
            or request.epoch != index.epoch or request.token_id != answer.token_id
            or type(zero_seeds) is not tuple or len(zero_seeds) != count
            or any(type(seed) is not bytes or len(seed) != 32 for seed in zero_seeds)):
        raise ValueError("Invalid deliberately disclosed seed transcript")
    operator = outer.matrix(index, pk, entry_limit=32768)
    rows = tuple(row for r in range(count) for row in operator.rows[(2 * r + 1) * pk.n:(2 * r + 2) * pk.n])
    rhs = tuple(int(a - b) % int(pk.q) for cipher, seed in zip(answer.ciphertexts, zero_seeds, strict=True)
                for a, b in zip(cipher.components[1], owner._uniform_bulk(seed, pk), strict=True))
    lifted = solve(rows, rhs, int(pk.q))
    centered = tuple(x if x <= pk.q // 2 else x - int(pk.q) for x in lifted)
    if any(abs(x) > pk.t // 2 for x in centered):
        raise ValueError("Recovered coefficients are not centered plaintext CRT forms")
    maps = [[None] * d for d in s.dimensions]
    start = 0
    for j, degree in enumerate(s.column_degrees):
        short = centered[start:start + degree]
        start += degree
        pieces = crt.decode(s.layout.context, [x % pk.t for x in space.expand(s, short)])
        for i, piece in zip(s.map_ids, pieces, strict=True):
            if any(piece[1:]) or (j >= s.dimensions[i] and piece[0]):
                raise ValueError("Recovered polynomial is not a component-constant form")
            if j < s.dimensions[i]:
                old = maps[i][j]
                if old is not None and old != piece[0]:
                    raise ValueError("Replicated component has inconsistent recovered mask")
                maps[i][j] = piece[0]
    if s.coordinate_ids:
        pad = [None] * s.dimension
        for weights, identifiers in zip(maps, s.coordinate_ids, strict=True):
            for value, identifier in zip(weights, identifiers, strict=True):
                if pad[identifier] is not None and pad[identifier] != value:
                    raise ValueError("Shared coordinate recovery is inconsistent")
                pad[identifier] = value
    else:
        if any(weights[:s.shared] != maps[0][:s.shared] for weights in maps):
            raise ValueError("Recovered common prefix is inconsistent")
        pad = maps[0][:s.shared] + [x for weights in maps for x in weights[s.shared:]]
    if any(x is None for x in pad):
        raise ValueError("Incomplete recovered private mask")
    weights = tuple((delta + r) % pk.t for delta, r in zip(request.delta, pad, strict=True))
    return tuple(pad), weights
