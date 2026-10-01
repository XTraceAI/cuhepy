"""E70 exact polynomial quotient/NTT-point certificate screening.

Known polynomial identity testing, not a new proof system or HE protocol.
The pure toy oracle has no private key, encrypted-query adapter or receiver.
Secret-point reuse requires a full hidden-state/feedback argument; publicly
sampled points require commitment/opening order, not this bare equality test.
"""

from __future__ import annotations

from dataclasses import dataclass

from gmpy2 import is_prime

from experiments.bfv_search_lab import reduction_oracles as integer


@dataclass(frozen=True)
class Certificate:
    output: tuple[int, ...]
    quotient: tuple[int, ...]


def validate(pairs, q):
    if (type(q) is not int or not 3 <= q < 1 << 64 or not is_prime(q)
            or type(pairs) is not tuple or not 1 <= len(pairs) <= 64
            or type(pairs[0]) is not tuple or len(pairs[0]) != 2 or type(pairs[0][0]) is not tuple):
        raise ValueError("Expected bounded prime-field products")
    n = len(pairs[0][0])
    if (not 2 <= n <= 64 or n & (n - 1) or len(pairs)*n*n > 1000000
            or any(type(pair) is not tuple or len(pair) != 2
                   or any(type(p) is not tuple or len(p) != n
                          or any(type(x) is not int or not 0 <= x < q for x in p) for p in pair) for pair in pairs)):
        raise ValueError("Invalid bounded polynomial factors")
    return n


def evaluate(poly, point, q):
    result = 0
    for x in reversed(poly):
        result = (result*point + x) % q
    return result


def certify(pairs, q):
    n = validate(pairs, q)
    full = [0]*(2*n-1)
    for a, b in pairs:
        for i, x in enumerate(a):
            for j, y in enumerate(b):
                full[i+j] += x*y
    quotient = tuple(x % q for x in full[n:])
    output = tuple((full[i] - (full[i+n] if i+n < len(full) else 0)) % q for i in range(n))
    return Certificate(output, quotient)


def cyclic_quotient_control(pairs, q):
    """Independent cyclic/negacyclic difference, h=(cyclic-negacyclic)/2."""
    n = validate(pairs, q)
    cyclic, negative = [0]*n, [0]*n
    for a, b in pairs:
        for i, x in enumerate(a):
            for j, y in enumerate(b):
                cyclic[(i+j) % n] += x*y
        product = integer.ring_product(a, b)
        negative = [a+b for a, b in zip(negative, product, strict=True)]
    inverse = pow(2, -1, q)
    assert (cyclic[-1] - negative[-1]) % q == 0
    return Certificate(tuple(x % q for x in negative),
                       tuple((a-b)*inverse % q for a, b in zip(cyclic[:-1], negative[:-1], strict=True)))


def verify_at_point(pairs, certificate, point, q):
    n = validate(pairs, q)
    if (type(certificate) is not Certificate or type(certificate.output) is not tuple
            or type(certificate.quotient) is not tuple or len(certificate.output) != n
            or len(certificate.quotient) != n-1 or type(point) is not int or not 0 <= point < q
            or any(type(x) is not int or not 0 <= x < q for x in (*certificate.output, *certificate.quotient))):
        raise ValueError("Noncanonical coefficient-field certificate")
    expected = sum(evaluate(a, point, q)*evaluate(b, point, q) for a, b in pairs) % q
    actual = (evaluate(certificate.output, point, q)
              + (pow(point, n, q)+1)*evaluate(certificate.quotient, point, q)) % q
    return actual == expected


def negacyclic_roots(n, q):
    if (type(n) is not int or not 2 <= n <= 64 or n & (n - 1)
            or type(q) is not int or not 3 <= q <= 65537 or not is_prime(q) or (q-1) % (2*n)):
        raise ValueError("Expected bounded NTT-root control")
    for candidate in range(2, q):
        psi = pow(candidate, (q-1)//(2*n), q)
        if pow(psi, n, q) == q-1:
            return tuple(pow(psi, 2*i+1, q) for i in range(n))
    raise AssertionError("Missing root for the validated toy prime")


def vanishing_polynomial(points, q):
    if (type(points) is not tuple or not 1 <= len(points) <= 63 or type(q) is not int or not is_prime(q)
            or any(type(x) is not int or not 0 <= x < q for x in points)):
        raise ValueError("Invalid bounded disclosed-point control")
    poly = [1]
    for point in points:
        new = [0]*(len(poly)+1)
        for j, x in enumerate(poly):
            new[j] = (new[j]-point*x) % q
            new[j+1] = (new[j+1]+x) % q
        poly = new
    return tuple(poly)


def rounds_for(q, degree, budget, target_bits):
    """Exact inequality B*(degree/q)^rounds <= 2^-target, algebra only."""
    if (any(type(x) is not int for x in (q, degree, budget, target_bits))
            or not is_prime(q) or not 1 <= degree < q or budget < 1 or not 1 <= target_bits <= 512):
        raise ValueError("Invalid polynomial soundness count")
    rounds = 1
    while budget * degree**rounds * (1 << target_bits) > q**rounds:
        rounds += 1
        if rounds > 1024:
            raise ValueError("No useful bounded repetition count")
    return rounds


def cost(*, n, q, replies, columns, width, budget=1024, target_bits=128):
    if any(type(x) is not int or x < 1 for x in (n, replies, columns, width)) or n & (n-1):
        raise ValueError("Invalid coefficient certificate geometry")
    rounds = rounds_for(q, 2*n-2, budget, target_bits)
    dense_rounds = rounds_for(q, 1, budget, target_bits)
    bits = q.bit_length()
    return {"known_identity_degree_bound": 2*n-2, "attempt_budget_count_only": budget,
            "algebraic_target_bits_not_parameter_assurance": target_bits,
            "point_rounds": rounds, "matched_dense_field_rounds": dense_rounds,
            "secret_points_body_bytes": (rounds*bits+7)//8,
            "point_index_hint_body_bytes": (rounds*columns*2*replies*bits+7)//8,
            "dense_subring_fingerprint_body_bytes": (dense_rounds*width*bits+7)//8,
            "per_answer_point_hint_body_bytes": (rounds*2*replies*bits+7)//8,
            "per_answer_dense_hint_body_bytes": (dense_rounds*bits+7)//8,
            "full_reply_body_bytes": (2*replies*n*bits+7)//8,
            "quotient_body_bytes": (2*replies*(n-1)*bits+7)//8,
            "owner_fresh_answer_factory_removed": False,
            "query_encryption_or_complete_release_protocol_implemented": False,
            "scope": "Direct masked public-polynomial arithmetic primitive control. Known private-point identity test with full quotient bodies; no compact commitment, batching, proof generation timing or security review."}
