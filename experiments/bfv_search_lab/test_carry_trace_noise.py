"""E105 carry identity, exact kernels, full CBD mass and actual graph regressions."""

from collections import Counter
from itertools import product
from random import Random

import pytest

from experiments.bfv_search_lab import carry_trace_noise as lab
from experiments.bfv_search_lab import finite_lifetime_noise as noise
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.test_finite_lifetime_noise import schoolbook, synthetic_context


def make_graph(index_mask, query_mask):
    pk, sk, keys, errors, secret = synthetic_context(8, 2)
    _, tiles = bgv.coefficient_inputs([0, 0], [[0, 0], [0, 1], [1, 0]], 8)
    error = tuple((i+1) % 3-1 for i in range(8))
    return lab.Graph(pk, sk, keys, errors, secret, tuple(tiles[0]), error, index_mask, query_mask)


@pytest.fixture(scope="module")
def graph():
    # Fixed supported test diagnostics, distinct from the runner's frozen OS draw.
    rng, q = Random(10501), (1 << 61)-1
    return make_graph(tuple(rng.randrange(q) for _ in range(8)), tuple(rng.randrange(q) for _ in range(8)))


@pytest.mark.parametrize("q", (17, 97))
def test_all_scalar_canonical_wrap_and_borrow_states_match_literal_digits(q):
    for a, b in product(range(q), repeat=2):
        beta, delta = (a,)+(0,)*7, (b,)+(0,)*7
        expected = lab.digit_columns(((a+b) % q,)+(0,)*7)
        wrap, carries = lab.carries(beta, delta, q, lab.digit_columns(beta), lab.digit_columns(delta), expected)
        assert wrap[0] == int(a+b >= q)
        for j in range(16):
            reconstructed = ((a >> (4*j)) & 15)+((b >> (4*j)) & 15)-wrap[0]*((q >> (4*j)) & 15)+carries[j][0]-16*carries[j+1][0]
            assert reconstructed == expected[j][0]


def test_full_literal_CBD1_coin_distribution_matches_weighted_unique_support():
    literal = Counter(tuple(bits[2*j]-bits[2*j+1] for j in range(8)) for bits in product((0, 1), repeat=16))
    assert dict(literal) == dict(lab.cbd_states())
    assert len(literal) == 6561 and sum(literal.values()) == 65536


@pytest.mark.parametrize("kernel", (
    (0,)*8, (1, 0, -1, 1, 0, -1, 1, 0), (-2, 3, 7, -4, 0, 1, 2, 9),
    (16, -16, 0, 16, -16, 0, 16, -16),
))
def test_signed_orbit_normalization_and_chunk_cache_preserve_integer_convolution(kernel):
    memo, rng = lab.Memo(), Random(10502)
    for _ in range(40):
        poly = tuple(rng.randrange(-1, 16) for _ in range(8))
        assert memo.apply(kernel, poly) == schoolbook(kernel, poly)
        assert memo.apply(kernel, poly) == schoolbook(kernel, poly)  # Genuine reused exact entry.
    assert memo.snapshot()["resident_memory_and_elapsed_time_measured"] is False


def test_equivalent_signed_rotated_kernels_receive_identical_cache_pool():
    kernel = (1, 2, -3, 0, 5, 0, 2, 4)
    poly, memo = (2, -1, 0, 1, 0, 0, 3, 1), lab.Memo()
    for shift in range(16):
        moved = lab.monomial(tuple(7*x for x in kernel), shift)
        assert memo.apply(moved, poly) == schoolbook(moved, poly)
    assert memo.snapshot()["compiled_distinct_primitive_orbits"] == 1


def test_chunk_positions_share_public_monomial_pool_and_zero_chunks_do_not_store():
    kernel, memo = (1, -2, 0, 3, 4, 1, 0, 7), lab.Memo()
    first, second = (1, 2, 3, 4, 0, 0, 0, 0), (0, 0, 0, 0, 1, 2, 3, 4)
    assert memo.apply(kernel, first) == schoolbook(kernel, first)
    assert memo.apply(kernel, second) == schoolbook(kernel, second)
    assert memo.snapshot()["cache_entries"] == 1
    assert memo.snapshot()["zero_chunk_skips"] == 2


@pytest.mark.parametrize("bits", tuple(product((0, 1), repeat=2)))
def test_representations_and_actual_trace_API_preserve_same_error_joint_phase(graph, bits):
    query = graph.query(bits)
    direct, binary, carry = lab.Direct(graph.errors[1]), lab.Binary(graph.errors[1]), lab.Carry(graph.errors[1], graph.q)
    selected = [graph.states[i] for i in (0, 1, 17, 129, 2001, 3280, 6001, 6560)]
    for state in selected:
        canonical, digits = graph.canonical(query, state)
        values = direct.functional(digits), binary.functional(digits), carry.functional(query, state, digits)
        independently = tuple(sum(schoolbook(d, e)[k] for d, e in zip(digits, graph.errors[1], strict=True)) for k in range(8))
        assert values == (independently,)*3
        source = tuple(a+b for a, b in zip(query.original_mean, state.original_noise, strict=True))
        maintenance = tuple(a+graph.t*b for a, b in zip(graph.fixed_maintenance, values[0], strict=True))
        expected = tuple(a+b for a, b in zip(source, maintenance, strict=True))
        actual, distances = graph.actual(query, state)
        assert actual == tuple(x % graph.q for x in expected)
        assert distances == tuple(sum(a != b for a, b in zip(bits, row, strict=True)) for row in ((0, 0), (0, 1), (1, 0)))
        # Local stable score/ID adapter only; production ranking is not invoked.
        # Nonpositional IDs make the two equal-distance cases meaningful.
        ids = (20, 40, 10)
        ranked = tuple(record_id for _, record_id in sorted(zip(distances, ids, strict=True)))
        assert ranked == {(0, 0): (20, 10, 40), (0, 1): (40, 20, 10),
                          (1, 0): (10, 20, 40), (1, 1): (10, 40, 20)}[bits]
        assert max(map(abs, maintenance)) <= max(map(abs, graph.fixed_maintenance))+noise.uniform_switch_cap(graph.errors[1], 16, 5)
        assert canonical == tuple((a+b) % graph.q for a, b in zip(query.beta, state.delta, strict=True))


def test_actual_affine_map_has_verified_modular_inverse_and_full_digit_states_do_not_merge(graph):
    matrix = tuple(tuple(column[i] % graph.q for column in graph.mask_columns) for i in range(8))
    inverse = lab.unit_inverse(matrix, graph.q)
    assert inverse is not None
    assert len({s.delta for s in graph.states}) == 6561
    for bits in product((0, 1), repeat=2):
        query = graph.query(bits)
        canonical = {tuple((a+b) % graph.q for a, b in zip(query.beta, state.delta, strict=True)) for state in graph.states}
        assert len(canonical) == 6561  # Same masks/weights, no fresh setup IID premise.


def test_decoder_projection_loses_information_but_full_tensor_injectivity_is_distinct():
    one = (0, 1, 0, 0, 0, 0, 0, 0)
    two = (0, 0, 0, 1, 0, 0, 0, 0)
    assert lab.projection(one) != lab.projection(two)
    assert lab.projection((1, 0, 0, 0, 0, 0, 0, 0)) == (0,)*8


def test_carry_coherence_is_registered_Q61_only_not_arbitrary_canonical_Q(graph):
    # For Q17, a wrapped sum can have a POSITIVE low carry. General-Q sign
    # coherence would therefore give an unjustified narrow grouped bound.
    beta, delta = (8,)+(0,)*7, (15,)+(0,)*7
    wrap, rows = lab.carries(beta, delta, 17, lab.digit_columns(beta), lab.digit_columns(delta),
                             lab.digit_columns((6,)+(0,)*7))
    assert wrap[0] == 1 and rows[1][0] == 1
    with pytest.raises(ValueError, match="Registered Q61"):
        lab.Carry(graph.errors[1], 17)


@pytest.mark.parametrize("matrix,modulus,expected", (
    (((1, 0), (0, 1)), 9, True), (((2, 0), (0, 2)), 9, True),
    (((3, 0), (0, 1)), 9, False), (((1, 1), (1, 1)), 97, False),
))
def test_exact_unit_inverse_certificates_not_assumed_uniform_field_rank(matrix, modulus, expected):
    assert (lab.unit_inverse(matrix, modulus) is not None) is expected


@pytest.mark.parametrize("matrix,modulus", (((), 17), (((1,), (2,)), 17), (((True,),), 17), (((1,),), True)))
def test_refuses_malformed_inverse_certificate_requests(matrix, modulus):
    with pytest.raises(ValueError):
        lab.unit_inverse(matrix, modulus)
