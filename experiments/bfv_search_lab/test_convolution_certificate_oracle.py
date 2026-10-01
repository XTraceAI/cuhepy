"""Polynomial identity, root-domain, quotient and exposed-point controls."""

from dataclasses import replace
import itertools
import random

import pytest

from experiments.bfv_search_lab import convolution_certificate_oracle as certificate


def test_all_tiny_products_and_all_field_points_match_integer_identity():
    vectors = tuple(tuple(x % 17 for x in p) for p in itertools.product((-1, 0, 1), repeat=2))
    for a, b in itertools.product(vectors, repeat=2):
        pairs = ((a, b),)
        result = certificate.certify(pairs, 17)
        assert result == certificate.cyclic_quotient_control(pairs, 17)
        assert result.quotient == (a[1]*b[1] % 17,)
        assert result.output == ((a[0]*b[0]-a[1]*b[1]) % 17, (a[0]*b[1]+a[1]*b[0]) % 17)
        assert all(certificate.verify_at_point(pairs, result, point, 17) for point in range(17))


@pytest.mark.parametrize("n,q", ((8, 97), (16, 193), (32, 257)))
def test_batched_products_match_independent_cyclic_control(n, q):
    rng = random.Random(70000+n)
    pairs = tuple((tuple(rng.randrange(q) for _ in range(n)), tuple(rng.randrange(q) for _ in range(n))) for _ in range(3))
    result = certificate.certify(pairs, q)
    assert result == certificate.cyclic_quotient_control(pairs, q)
    assert all(certificate.verify_at_point(pairs, result, point, q) for point in range(q))


def test_a_deliberate_frequency_error_passes_seven_of_eight_NTT_points():
    q, n = 97, 8
    pairs = (((1, 2, 3, 4, 5, 6, 7, 8), (8, 7, 6, 5, 4, 3, 2, 1)),)
    honest = certificate.certify(pairs, q)
    roots = certificate.negacyclic_roots(n, q)
    error = certificate.vanishing_polynomial(roots[:-1], q)
    forged = replace(honest, output=tuple((a+b) % q for a, b in zip(honest.output, error, strict=True)))
    assert forged.output != honest.output
    assert sum(certificate.verify_at_point(pairs, forged, point, q) for point in roots) == 7
    assert sum(certificate.verify_at_point(pairs, forged, point, q) for point in range(q)) == 7
    # Ordinary evaluation without quotient is not even complete off the roots.
    assert certificate.evaluate(honest.output, 2, q) != certificate.evaluate(pairs[0][0], 2, q)*certificate.evaluate(pairs[0][1], 2, q) % q


def test_disclosing_then_reusing_points_permits_an_exact_interpolation_forgery():
    pairs = (((1,)*8, (2,)*8),)
    honest = certificate.certify(pairs, 97)
    points = (2, 3)
    error = (*certificate.vanishing_polynomial(points, 97), 0, 0, 0, 0, 0)
    forged = replace(honest, output=tuple((a+b) % 97 for a, b in zip(honest.output, error, strict=True)))
    assert forged.output != honest.output
    assert all(certificate.verify_at_point(pairs, forged, point, 97) for point in points)
    with pytest.raises(ValueError, match="Noncanonical"):
        certificate.verify_at_point(pairs, replace(honest, quotient=(97,)*7), 2, 97)


def test_boolean_ring_identity_does_not_force_a_constant_bit_in_split_NTT_ring():
    roots = certificate.negacyclic_roots(8, 97)
    polynomial = certificate.vanishing_polynomial(roots[:-1], 97)
    inverse = pow(certificate.evaluate(polynomial, roots[-1], 97), -1, 97)
    e = tuple(x*inverse % 97 for x in polynomial)
    assert e not in ((0,)*8, (1, 0, 0, 0, 0, 0, 0, 0))
    assert certificate.certify(((e, e),), 97).output == e
    assert tuple(certificate.evaluate(e, point, 97) for point in roots) == (0, 0, 0, 0, 0, 0, 0, 1)
    # Domain control for adapting ring bit constraints, NOT an attack on a
    # paper instantiated over a different/local coefficient ring.


def test_lifetime_and_degree_counts_are_exact_and_do_not_claim_a_protocol():
    c = certificate.cost(n=16384, q=4294955009, replies=1, columns=32, width=1024)
    assert c["point_rounds"] == 9 and c["matched_dense_field_rounds"] == 5
    assert c["point_index_hint_body_bytes"] < c["dense_subring_fingerprint_body_bytes"]
    assert c["quotient_body_bytes"] == 131064
    assert not c["owner_fresh_answer_factory_removed"]
    with pytest.raises(ValueError):
        certificate.rounds_for(17, 18, 1024, 128)
