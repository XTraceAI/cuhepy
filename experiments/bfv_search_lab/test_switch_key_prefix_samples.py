"""Independent complete row/sample equations and scaled-CBD mass checks."""

from collections import Counter
from dataclasses import replace
from fractions import Fraction
from itertools import product
from random import Random

import pytest

from experiments.bfv_search_lab import switch_key_prefix_samples as lab
from experiments.bfv_search_lab.test_committed_precision_epoch import make_keys
from experiments.bfv_search_lab.test_partial_packed_switch import multiply


def exact_formal_pair():
    q, radix, cases, equations, weighted = 3, 3, 0, 0, 0
    all_vectors = tuple(product(range(q), repeat=2))
    all_errors = tuple(product((-1, 0, 1), repeat=2))
    # Unknown prefix1; the known zero suffix is essential for these rows.
    for target0, source, a, a2, e, e2 in product((-1, 0, 1), product((-1, 0, 1), repeat=2),
                                              all_vectors, all_vectors, all_errors, all_errors):
        target = (target0, 0)
        body = tuple((s-v+err) % q for s, v, err in zip(source, multiply(a, target), e, strict=True))
        body2 = tuple((radix*s-v+err) % q for s, v, err in zip(source, multiply(a2, target), e2, strict=True))
        mask, out = lab.row_pair(a, body, a2, body2, q, radix)
        for (row, rhs), i in zip(lab.extract(mask, out, q, 1), (0, 1), strict=True):
            assert (rhs-row[0]*target0-(radix*e[i]-e2[i])) % q == 0
            equations += 1
        weighted += 2**sum(x == 0 for x in (*e, *e2))
        cases += 1
    assert weighted == 3*9*81*2**8
    return {"formal_N2_Q3_radix3_secret_source_mask_error_cases": cases,
            "independent_row_equations": equations,
            "exact_CBD1_coin_weighted_cases": weighted,
            "formal_pair_not_a_full_Q3_gadget_context": True,
            "actual_secret_recovery_or_lattice_reduction_executed": False}


def test_uniform_pair_masks_and_disjoint_sample_rows():
    for radix in (3, 5):
        counts = Counter()
        for a, b in product(product(range(3), repeat=4), repeat=2):
            mask = tuple((y-radix*x) % 3 for x, y in zip(a, b, strict=True))
            rows = tuple(row for row, _ in lab.extract(mask, (0,)*4, 3, 2))
            counts[rows] += 1
        assert len(counts) == 3**4 and set(counts.values()) == {3**4}


@pytest.mark.parametrize("n", (2, 4, 8))
def test_actual_full_key_contexts_cancel_source_and_derived_square(n):
    for q in (97, 1009):
        levels = lab.context(q, 3)
        for skip in range(levels+1):
            rng = Random(98001+n+q+skip)
            source = tuple(rng.randrange(-1, 2) for _ in range(n))
            target = (1, -1)+(0,)*(n-2)
            keys, errors = make_keys(q, 3, source, target, 2, skip, rng)
            pairs = lab.from_keys(keys)
            assert len(pairs) == levels//2+(levels-skip)//2
            used = set()
            for pair in pairs:
                f, (j, j2) = pair.family, pair.levels
                assert (f, j) not in used and (f, j2) not in used
                used.update(((f, j), (f, j2)))
                start = skip if f else 0
                e1, e2 = errors[f][j-start], errors[f][j2-start]
                hidden = multiply(pair.mask, target)
                assert all((body+term-noise2+3*noise1) % q == 0
                           for body, term, noise1, noise2 in zip(pair.body, hidden, e1, e2, strict=True))
                for (row, rhs), k in zip(pair.samples, range(1, n, 2), strict=True):
                    assert (rhs-sum(x*s for x, s in zip(row, target[:2], strict=True))-(3*e1[k]-e2[k])) % q == 0
            assert sum(len(p.samples) for p in pairs) == lab.sample_count(n, 2, q, 3, skip)


def test_exact_scaled_CBD_law_matches_all_Bernoulli_coins():
    counts = Counter()
    for bits in product((0, 1), repeat=4):
        counts[(bits[2]-bits[3])-3*(bits[0]-bits[1])] += 1
    got, total = lab.error_distribution(1, 3)
    assert got == counts and total == 16


def test_actual_eta21_radix257_law_has_gaps_and_exact_summary():
    counts, total = lab.error_distribution(21, 257)
    assert len(counts) == 1849 and min(counts) == -5418 and max(counts) == 5418
    assert Fraction(sum(x*x*c for x, c in counts.items()), total) == 693525
    assert 22 not in counts and 0 in counts
    assert all(counts[x] == counts[-x] for x in counts)


def test_same_switching_keys_downloaded_again_do_not_add_samples():
    rng = Random(98002)
    keys, _ = make_keys(1009, 3, (1, -1, 0, 1), (1, -1, 0, 0), 2, 1, rng)
    first = lab.from_keys(keys)
    assert first == lab.from_keys(keys)
    assert len({(row, rhs) for p in first for row, rhs in p.samples}) <= sum(len(p.samples) for p in first)


@pytest.mark.parametrize("field", ("q", "radix", "target_prefix", "skipped_c2_levels", "values"))
def test_noncanonical_key_contexts_reject(field):
    keys, _ = make_keys(1009, 3, (1, -1), (1, 0), 1, 0, Random(98003))
    bad = replace(keys, **{field: True})
    with pytest.raises(ValueError):
        lab.from_keys(bad)


@pytest.mark.parametrize("args", ((True, 257), (21, True), (21, 2), (0, 257)))
def test_noncanonical_error_contexts_reject(args):
    with pytest.raises(ValueError):
        lab.error_distribution(*args)
