"""E07 reference: encrypted constant query features, accumulate before switching.

Each index polynomial stores ONE signed feature across N rows. Each query
ciphertext encrypts one signed constant, so multiplying adds no plaintext
cross-row correlations. Sum all three-component products, then relinearize
once per response polynomial. No rotations are necessary.

The obvious cost is D query ciphertexts rather than one. This reference makes
that tradeoff measurable before attempting encrypted query expansion. All
arithmetic is homemade; this is a local fixture, not an authenticated protocol.
"""

from __future__ import annotations

from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import butterfly_bgv as butterfly


def encode(query: list[int], rows: list[list[int]], n: int) -> tuple[list[list[int]], list[list[list[int]]]]:
    if (type(n) is not int or not 8 <= n <= 32768 or n & (n - 1)
        or not 1 <= len(query) <= min(n // 2, 512) or len(rows) > 64 * n
        or any(type(x) is not int or x not in (0, 1) for x in query)
        or any(len(row) != len(query) or any(type(x) is not int or x not in (0, 1) for x in row) for row in rows)):
        raise ValueError("Invalid feature-major binary layout")
    queries = [[1 - 2 * bit] + [0] * (n - 1) for bit in query]
    groups = []
    for start in range(0, len(rows), n):
        part = rows[start:start + n]
        groups.append([[1 - 2 * row[j] for row in part] + [0] * (n - len(part)) for j in range(len(query))])
    return queries, groups


def search(queries: list[bgv.Ciphertext], groups: list[list[bgv.Ciphertext]],
           pk: bgv.PublicKey, keys: trace.EvaluationKeys, *, delayed: bool = True) -> list[bgv.Ciphertext]:
    butterfly.validate_keys(pk, keys)
    if (keys.padded != 1 or type(delayed) is not bool or not 1 <= len(queries) <= min(pk.n // 2, 512)
        or pk.t <= 2 * len(queries) or len(groups) > 64 or any(len(group) != len(queries) for group in groups)):
        raise ValueError("Invalid feature-major query/index/key layout")
    for cipher in queries + [c for group in groups for c in group]:
        bgv._validate(cipher, pk)
        if len(cipher.components) != 2:
            raise ValueError("Feature-major input requires two components")

    def relinearize(cipher: bgv.Ciphertext) -> bgv.Ciphertext:
        switched = trace._switch(cipher.components[2], keys.relin, pk, keys.digit_bits)
        components = tuple(tuple((a + b) % pk.q for a, b in zip(cipher.components[j], switched[j], strict=True)) for j in range(2))
        return trace._bounded(components, cipher.phase_bound + keys.switch_error_bound, pk)

    output = []
    for group in groups:
        bound = sum(pk.n * q.phase_bound * c.phase_bound for q, c in zip(queries, group, strict=True))
        bound += keys.switch_error_bound * (1 if delayed else len(queries))
        if 2 * bound >= pk.q:
            raise ValueError("Feature-major no-wrap bound exceeded")
        accumulated = None
        for query, tile in zip(queries, group, strict=True):
            product = bgv.multiply(query, tile, pk)
            if not delayed:
                product = relinearize(product)
            accumulated = product if accumulated is None else trace._add(accumulated, product, pk)
        assert accumulated is not None
        output.append(relinearize(accumulated) if delayed else accumulated)
    return output


def decode(plaintexts: list[list[int]], count: int, dimension: int, pk: bgv.PublicKey) -> list[int]:
    if (type(count) is not int or not 0 <= count <= 64 * pk.n or type(dimension) is not int
        or not 1 <= dimension <= min(pk.n // 2, 512) or pk.t <= 2 * dimension
        or len(plaintexts) != (count + pk.n - 1) // pk.n):
        raise ValueError("Invalid feature-major response shape")
    distances: list[int] = []
    for plain in plaintexts:
        if len(plain) != pk.n or any(type(c) is not int or not 0 <= c < pk.t for c in plain):
            raise ValueError("Noncanonical feature-major plaintext")
        for value in plain[:min(pk.n, count - len(distances))]:
            correlation = value if value <= pk.t // 2 else value - pk.t
            if abs(correlation) > dimension or (dimension - correlation) % 2:
                raise ValueError("Invalid feature-major correlation")
            distances.append((dimension - correlation) // 2)
    return distances


def costs(count: int, dimension: int, n: int, q_bits: int = 120) -> dict[str, int]:
    if any(type(x) is not int or x < 1 for x in (count, dimension, n, q_bits)) or n & (n - 1) or dimension > n // 2:
        raise ValueError("Invalid feature-major cost model")
    groups = (count + n - 1) // n
    return {"query_ciphertexts": dimension, "seeded_query_coefficient_bytes": dimension * ((n * q_bits + 7) // 8),
            "index_ciphertexts": groups * dimension, "ciphertext_products": groups * dimension,
            "eager_key_switches": groups * dimension, "delayed_key_switches": groups,
            "rotations": 0, "response_ciphertexts": groups}
