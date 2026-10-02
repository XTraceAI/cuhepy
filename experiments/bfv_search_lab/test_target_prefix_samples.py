"""Independent uniformity/equation tests, not an executed cryptanalytic attack."""

from collections import Counter
from itertools import product

import pytest

from experiments.bfv_search_lab import target_prefix_samples as lab
from experiments.bfv_search_lab.test_source_phase_budget import cyclic_reference


@pytest.mark.parametrize("n,prefix", ((2, 1), (2, 2), (4, 1), (4, 2), (4, 3), (4, 4), (8, 2), (8, 4), (8, 8)))
def test_chosen_public_windows_are_disjoint_and_jointly_uniform(n, prefix):
    indices = tuple(tuple(k-j for j in range(prefix)) for k in lab.positions(n, prefix))
    flat = tuple(i for row in indices for i in row)
    assert len(flat) == len(set(flat)) == prefix * (n // prefix)
    assert all(0 <= i < n for i in flat)
    counts = Counter()
    for mask in product(range(3), repeat=n):
        samples = lab.extract(mask, (0,)*n, 3, prefix)
        counts[tuple(a for a, _ in samples)] += 1
    assert len(counts) == 3**len(flat)
    assert set(counts.values()) == {3**(n-len(flat))}
    assert lab.sample_count(n, prefix, 4096) == (n//prefix)*4096


def exact_small_equations():
    cases, equations = 0, 0
    for short, mask, error in product(product((-1, 0, 1), repeat=2),
                                      product(range(3), repeat=4), product((-1, 0, 1), repeat=4)):
        secret = (*short, 0, 0)
        poly = cyclic_reference(mask, secret)
        body = tuple((e-x) % 3 for e, x in zip(error, poly, strict=True))
        for k, (a, b) in zip(lab.positions(4, 2), lab.extract(mask, body, 3, 2), strict=True):
            assert (b - sum(x*s for x, s in zip(a, short, strict=True)) + error[k]) % 3 == 0
            equations += 1
        cases += 1
    return {"N4_p2_Q3_secret_mask_error_cases": cases, "independent_row_equations": equations,
            "selected_positions": [1, 3], "known_zero_suffix_required": True,
            "production_secret_recovery_executed": False}


def test_disjoint_rows_match_integer_negacyclic_encryption_equations():
    assert exact_small_equations()["independent_row_equations"] == 118098


def test_noise_sign_symmetry_and_distinct_coin_indices():
    counts = Counter(a-b for a, b in product((0, 1), repeat=2))
    assert counts == Counter({-1: 1, 0: 2, 1: 1})
    assert counts == Counter({-x: count for x, count in counts.items()})
    assert len(set(lab.positions(8, 2))) == 4


def test_full_rotations_are_not_claimed_independent():
    windows = tuple(tuple((k-j) % 8 for j in range(2)) for k in range(8))
    flat = tuple(i for w in windows for i in w)
    assert len(flat) == 16 and len(set(flat)) == 8
    assert len(lab.positions(8, 2)) == 4


def test_nonzero_suffix_breaks_the_declared_reduced_dimension_relation():
    mask, secret = (1, 2, 0, 1), (1, 0, 1, 0)
    body = tuple(-x % 5 for x in cyclic_reference(mask, secret))
    rows = lab.extract(mask, body, 5, 2)
    assert any(b != sum(x*s for x, s in zip(a, secret[:2], strict=True)) % 5 for a, b in rows)


@pytest.mark.parametrize("n,prefix,life", ((True, 2, 1), (4, True, 1), (3, 1, 1), (4, 5, 1),
                                         (4, 0, 1), (4, 2, True), (4, 2, 0)))
def test_noncanonical_dimensions_and_lifetimes_reject(n, prefix, life):
    with pytest.raises(ValueError):
        lab.sample_count(n, prefix, life)
