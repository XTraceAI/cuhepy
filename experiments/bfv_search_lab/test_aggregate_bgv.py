"""Complete homemade encrypted factor circuit on deliberately small fixtures."""

from dataclasses import replace
from itertools import product

import pytest

from experiments.bfv_search_lab import aggregate_bgv as aggregate
from experiments.bfv_search_lab import answer_oracles as oracle
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


def scalar(cipher, pk, sk):
    plain = bgv.decrypt(cipher, pk, sk)
    assert not any(plain[1:])
    return plain[0]


@pytest.mark.parametrize("dimension", [1, 2, 3, 4])
def test_encrypted_histogram_and_adaptive_stable_ids_match_plaintext(dimension):
    pk, sk = bgv.key_gen(8, t=257, q_bits=180, eta=1)
    keys = trace.evaluation_keys(pk, sk, padded=1, digit_bits=12)
    rows = [list(bits) for bits in product((0, 1), repeat=dimension)]
    rows += [rows[0], rows[0]]
    query = [i % 2 for i in range(dimension)]
    encrypted, index = aggregate.encrypt_inputs(query, rows, pk)
    result = aggregate.search(encrypted, index, pk, keys)
    histogram = [scalar(ct, pk, sk) for ct in result.histogram]
    assert histogram == oracle.factor_histogram(query, rows, pk.t)
    distances = [sum(a != b for a, b in zip(query, row, strict=True)) for row in rows]
    for row, distance in zip(result.row_polynomials, distances, strict=True):
        assert [scalar(ct, pk, sk) for ct in row] == [int(j == distance) for j in range(dimension + 1)]
    for k in (0, 1, 3, len(rows) + 1):
        recovered, transcript = oracle.recover_topk(histogram, len(rows), k,
            lambda d, lo, hi: scalar(aggregate.prefix_count(result, d, lo, hi, pk), pk, sk))
        assert recovered == sorted((distance, i) for i, distance in enumerate(distances))[:k]
        assert all(0 <= probe.start < probe.stop <= len(rows) for probe in transcript)
    model = oracle.scalar_cost(len(rows), dimension)
    assert result.product_calls == model["factor_products"]
    assert result.max_depth == model["factor_multiplicative_depth"]


def test_empty_index_and_public_prefix_bounds():
    pk, sk = bgv.key_gen(8, t=17, q_bits=180, eta=1)
    keys = trace.evaluation_keys(pk, sk, 1, 12)
    encrypted, index = aggregate.encrypt_inputs([0], [], pk)
    result = aggregate.search(encrypted, index, pk, keys)
    assert [scalar(ct, pk, sk) for ct in result.histogram] == [0, 0]
    assert result.product_calls == result.max_depth == 0
    assert scalar(aggregate.prefix_count(result, 0, 0, 0, pk), pk, sk) == 0
    for args in ((-1, 0, 0), (0, -1, 0), (0, 0, 1), (0, False, 0)):
        with pytest.raises(ValueError):
            aggregate.prefix_count(result, *args, pk)


def test_wrong_context_nonbinary_fixture_field_alias_and_excessive_depth_rejected():
    pk, sk = bgv.key_gen(8, t=17, q_bits=120, eta=1)
    keys = trace.evaluation_keys(pk, sk, 1, 12)
    encrypted, index = aggregate.encrypt_inputs([0], [[1]], pk)
    for bad in (replace(encrypted[0], key_id="bad"),
                replace(encrypted[0], components=encrypted[0].components * 2)):
        with pytest.raises(ValueError):
            aggregate.search([bad], index, pk, keys)
    with pytest.raises(ValueError):
        aggregate.encrypt_inputs([0], [[0]] * 17, pk)
    with pytest.raises(ValueError):
        aggregate.encrypt_inputs([2], [[0]], pk)
    with pytest.raises(ValueError):
        aggregate.search(encrypted, [[]], pk, keys)
    # No silently exhausted modulus: the complete public bound must fit Q/2.
    query, index = aggregate.encrypt_inputs([0] * 16, [[1] * 16], pk)
    with pytest.raises(ValueError, match="bound"):
        aggregate.search(query, index, pk, keys)
