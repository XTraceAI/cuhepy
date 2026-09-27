"""E21 exact identities, stable ties, field aliasing and representation limits."""

from itertools import product
import random

import pytest

from experiments.bfv_search_lab import answer_oracles as oracle


def expected_histogram(query, rows):
    result = [0] * (len(query) + 1)
    for row in rows:
        result[sum(a != b for a, b in zip(query, row, strict=True))] += 1
    return result


@pytest.mark.parametrize("dimension", [1, 2, 3])
def test_three_histogram_constructions_exhaust_all_queries_and_two_row_databases(dimension):
    vectors = list(product((0, 1), repeat=dimension))
    for query, a, b in product(vectors, repeat=3):
        rows, q = [list(a), list(b)], list(query)
        expected = expected_histogram(q, rows)
        for method in (oracle.factor_histogram, oracle.evaluation_histogram, oracle.walsh_histogram):
            assert method(q, rows, 17) == expected


@pytest.mark.parametrize("dimension", [4, 5, 8])
def test_larger_histograms_duplicates_empty_database_and_degree_tail(dimension):
    rng = random.Random(dimension)
    q = [rng.randrange(2) for _ in range(dimension)]
    for rows in ([], [q] * 19, [[1 - bit for bit in q]] * 7,
                 [[rng.randrange(2) for _ in q] for _ in range(31)]):
        expected = expected_histogram(q, rows)
        for method in (oracle.factor_histogram, oracle.evaluation_histogram, oracle.walsh_histogram):
            assert method(q, rows, 257) == expected


def test_stable_prefix_recovery_exhausts_small_distance_lists_and_all_k():
    for count in range(7):
        for distances in product(range(3), repeat=count):
            histogram = [distances.count(i) for i in range(3)]
            expected = sorted((d, i) for i, d in enumerate(distances))
            for k in range(count + 2):
                def count_prefix(d, lo, hi, values=distances):
                    return sum(x == d for x in values[lo:hi])
                actual, transcript = oracle.recover_topk(histogram, count, k, count_prefix)
                assert actual == expected[:k]
                assert len(transcript) <= min(k, count) * max(0, (count - 1).bit_length())


def test_three_moments_do_not_recover_the_first_three_ids_in_a_large_tie():
    # Prouhet/Thue-Morse fixture: equal counts and moments through degree three.
    a = [i for i in range(16) if i.bit_count() % 2 == 0]
    b = [i for i in range(16) if i.bit_count() % 2 == 1]
    assert [sum(i**j for i in a) for j in range(4)] == [sum(i**j for i in b) for j in range(4)]
    assert a[:3] != b[:3]
    for ids in (a, b):
        distances = [0 if i in ids else 1 for i in range(16)]
        recovered, _ = oracle.recover_topk([8, 8], 16, 3,
                                          lambda d, lo, hi, values=distances: sum(x == d for x in values[lo:hi]))
        assert recovered == [(0, i) for i in ids[:3]]


def test_counts_cannot_wrap_and_interpolation_points_must_be_distinct():
    for prime, query, rows in ((7, [0], [[0]] * 7), (7, [0] * 7, []),
                                (9, [0], []), (2, [0], []), (True, [0], [])):
        for method in (oracle.factor_histogram, oracle.evaluation_histogram, oracle.walsh_histogram):
            with pytest.raises(ValueError):
                method(query, rows, prime)
    for query, rows in (([], []), ([0], [[2]]), ([False], []), ([0, 1], [[1]])):
        with pytest.raises(ValueError):
            oracle.factor_histogram(query, rows, 17)


@pytest.mark.parametrize("dimension", [1, 2, 3, 4, 5, 6])
def test_generic_hamming_kernel_has_full_exponential_rank(dimension):
    # K(z) is the d-fold tensor power of [[1,z],[z,1]]. Its base determinant
    # is 1-z*z. Only z=+/-1 loses rank over an odd prime field.
    for point in (0, 2, 3, 7):
        assert oracle.kernel_rank(dimension, point, 17) == 1 << dimension
    for point in (1, 16):
        assert oracle.kernel_rank(dimension, point, 17) == 1


def test_histogram_without_ids_and_inconsistent_prefix_reply_are_insufficient():
    assert expected_histogram([0], [[0], [1]]) == expected_histogram([0], [[1], [0]])
    for reply in (-1, 2, True):
        with pytest.raises(ValueError):
            oracle.recover_topk([1, 1], 2, 1, lambda _d, _lo, _hi, reply=reply: reply)
    with pytest.raises(ValueError):
        oracle.recover_topk([1], 2, 1, lambda _d, _lo, _hi: 0)


def test_cost_model_is_scalar_and_charges_depth_and_cached_outputs():
    model = oracle.scalar_cost(8192, 512)
    assert model["factor_multiplicative_depth"] == 10
    assert model["cached_row_field_elements"] == 8192 * 513
    assert model["exact_separated_features"] == 2**512
    assert model["factor_products"] > model["mismatch_products"]
