"""Independent plaintext-product and exact encrypted coefficient-layout checks."""

from dataclasses import replace
from itertools import product
import random

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import shallow_bgv as bgv


def plain_product(a, b, modulus):
    # Quadratic schoolbook oracle; no library polynomial helper or transform.
    result = [0] * len(a)
    for i, left in enumerate(a):
        for j, right in enumerate(b):
            at = i + j
            result[at % len(a)] += left * right * (1 if at < len(a) else -1)
    return [x % modulus for x in result]


@pytest.mark.parametrize("n,t,q_bits", [(8, 17, 60), (16, 1031, 90), (64, 65537, 120)])
def test_full_polynomial_product_and_public_bound(n, t, q_bits):
    pk, sk = bgv.key_gen(n, t, q_bits)
    rng = random.Random(22)
    for _ in range(5):
        a = [rng.randrange(t) for _ in range(n)]
        b = [rng.randrange(t) for _ in range(n)]
        lhs, rhs = bgv.encrypt(a, pk), bgv.encrypt(b, pk)
        assert bgv.decrypt(lhs, pk, sk) == a
        multiplied = bgv.multiply(lhs, rhs, pk)
        assert multiplied == bgv.multiply(lhs, rhs, pk, karatsuba=True)
        assert bgv.decrypt(multiplied, pk, sk) == plain_product(a, b, t)
        assert multiplied.phase_bound == n * pk.fresh_bound**2 < pk.q // 2
        with pytest.raises(ValueError, match="Only one"):
            bgv.multiply(multiplied, lhs, pk)
    assert bgv.encrypt(a, pk) != bgv.encrypt(a, pk)


@pytest.mark.parametrize("dimension,n", [(1, 8), (3, 16), (5, 64), (16, 16)])
def test_encrypted_coefficient_hamming_including_negacyclic_wrap(dimension, n):
    pk, sk = bgv.key_gen(n)
    capacity = n // (1 << (dimension - 1).bit_length())
    rng = random.Random(dimension)
    queries = (
        list(product((0, 1), repeat=dimension))
        if dimension <= 3
        else [[0] * dimension, [1] * dimension, [rng.randrange(2) for _ in range(dimension)]]
    )
    for query_tuple in queries:
        query = list(query_tuple)
        vectors = [query, [1 - bit for bit in query]]
        vectors += [[rng.randrange(2) for _ in range(dimension)] for _ in range(2 * capacity + 1)]
        for count in sorted({0, 1, capacity, capacity + 1, len(vectors)}):
            qp, tiles = bgv.coefficient_inputs(query, vectors[:count], n)
            encrypted_query = bgv.encrypt(qp, pk)
            polynomials = [
                bgv.decrypt(bgv.multiply(encrypted_query, bgv.encrypt(tile, pk), pk), pk, sk)
                for tile in tiles
            ]
            assert bgv.decode_coefficients(polynomials, count, dimension, n, pk.t) == [
                sum(a != b for a, b in zip(query, row, strict=True)) for row in vectors[:count]
            ]


def test_wrong_context_noncanonical_ciphertext_and_bounds():
    pk, sk = bgv.key_gen(16)
    other, other_sk = bgv.key_gen(16)
    ct = bgv.encrypt([0] * 16, pk)
    for malformed in (
        replace(ct, key_id=other.key_id),
        replace(ct, components=ct.components[:1]),
        replace(ct, components=((pk.q,) + ct.components[0][1:], ct.components[1])),
        replace(ct, components=((mpz(-1),) + ct.components[0][1:], ct.components[1])),
        replace(ct, phase_bound=int(pk.q)),
    ):
        with pytest.raises(ValueError):
            bgv.decrypt(malformed, pk, sk)
        with pytest.raises(ValueError):
            bgv.multiply(malformed, ct, pk)
    with pytest.raises(ValueError, match="Wrong"):
        bgv.decrypt(ct, pk, other_sk)
    with pytest.raises(ValueError, match="bound"):
        bgv.key_gen(16384, 65537, 60)
    for args in ((0,), (12,), (16, 2), (16, 1031, 32), (True,), (16, 1031, 300)):
        with pytest.raises(ValueError):
            bgv.key_gen(*args)


def test_coefficient_layout_rejects_invalid_shapes_and_scores():
    for query, rows, n in (([], [], 16), ([2], [], 16), ([0, 1], [[0]], 16), ([0] * 17, [], 16)):
        with pytest.raises(ValueError):
            bgv.coefficient_inputs(query, rows, n)
    for polys, count, d, n, t in (
        ([], 1, 3, 16, 1031),
        ([], 0, 0, 16, 1031),
        ([], 0, 3, 17, 1031),
        ([[0] * 16], 1, 3, 16, 5),
        ([[0] * 15], 1, 3, 16, 1031),
        ([[0] * 16], 1, 3, 16, 1031),  # parity: odd dimension cannot have zero dot product
        ([[0, 0, 0, 100] + [0] * 12], 1, 3, 16, 1031),
    ):
        with pytest.raises(ValueError):
            bgv.decode_coefficients(polys, count, d, n, t)
