"""E121 tiny regressions; the registered N4 joint cohort is not run here."""

from collections import Counter
from dataclasses import replace
from fractions import Fraction
from itertools import product
from math import prod

import gmpy2
import pytest

from experiments.bfv_search_lab import cyclic_window as lab


@pytest.fixture(scope="module")
def tiny_image():
    return lab.enumerate_image(lab.Context(2, 13, 5, (-5, 1), 1))


def schoolbook(secret, mask, q):
    result = [0] * len(secret)
    for i, a in enumerate(secret):
        for j, b in enumerate(mask):
            position = i + j
            result[position % len(secret)] += a * b * (-1 if position >= len(secret) else 1)
    return tuple(x % q for x in result)


@pytest.mark.parametrize("field", ("n", "q", "root", "window_length"))
@pytest.mark.parametrize("alias", (True, 2.0, "2", gmpy2.mpz(2)))
def test_context_rejects_numeric_aliases(field, alias):
    with pytest.raises(ValueError):
        replace(lab.Context(2, 13, 5, (-5, 1), 1), **{field: alias}).validate()


@pytest.mark.parametrize("context", (
    lab.Context(2, 9, 2, (-2, 1), 1),
    lab.Context(2, 7, 2, (-2, 1), 1),
    lab.Context(2, 13, 1, (-5, 1), 1),
    lab.Context(2, 13, 5, (0, 0), 1),
    lab.Context(2, 13, 5, (False, 1), 1),
    lab.Context(2, 13, 5, [-5, 1], 1),
    lab.Context(2, 13, 5, (-5, 1), 0),
    lab.Context(2, 13, 5, (-5, 1), 3),
))
def test_context_rejects_false_contracts(context):
    with pytest.raises(ValueError):
        context.validate()


def test_wrapped_windows_keep_literal_positions_and_signs():
    ctx = lab.Context(4, 17, 2, (1, 1, 0, 0), 3)
    assert ctx.windows == ((0, 1, 2), (1, 2, 3), (2, 3, 0), (3, 0, 1))
    expected_columns = [schoolbook(ctx.secret, tuple(int(i == j) for i in range(4)), 17)
                        for j in range(4)]
    assert tuple(tuple(value % 17 for value in row) for row in ctx.matrix) == tuple(
        tuple(column[i] for column in expected_columns) for i in range(4))
    assert lab.window_ranks(ctx) == (3, 3, 3, 3)


@pytest.mark.parametrize("cover", (
    ((0,),), ((0, 0), (1,)), ((False,), (1,)), (([0],), (1,)),
    ((0,), (2,)), ((), (1,)), [[0], [1]], (),
))
def test_cover_rejects_omissions_duplicates_and_aliases(cover):
    with pytest.raises(ValueError):
        lab.regular_cover(2, cover)


def test_regular_cover_allows_overlap_without_independence():
    assert lab.regular_cover(4, lab.cyclic_windows(4, 3)) == 3


def test_independent_fullmask_image_fibres(tiny_image):
    ctx = tiny_image.context
    fullmask = Counter(schoolbook(ctx.secret, mask, ctx.q)
                       for mask in product(range(ctx.q), repeat=ctx.n))
    assert set(fullmask) == set(tiny_image.points)
    assert set(fullmask.values()) == {13}
    assert tiny_image.rank == 1


@pytest.mark.parametrize("mutation", ("missing", "duplicate", "outside", "alias", "wrong_basis"))
def test_image_cache_requires_actual_complete_image(tiny_image, mutation):
    points = tiny_image.points
    if mutation == "missing":
        bad = replace(tiny_image, points=points[:-1])
    elif mutation == "duplicate":
        bad = replace(tiny_image, points=points[:-1] + (points[0],))
    elif mutation == "outside":
        bad = replace(tiny_image, points=points[:-1] + ((0, 1),))
    elif mutation == "alias":
        bad = replace(tiny_image, points=((False, 0),) + points[1:])
    else:
        bad = replace(tiny_image, basis_indices=(0, 1))
    with pytest.raises(ValueError):
        bad.validate()


def test_no_n8_image_cohort():
    with pytest.raises(ValueError):
        lab.enumerate_image(lab.Context(8, 17, 3, (1, 0, 0, 0, 0, 0, 0, 0), 7))


def test_same_error_coset_law_matches_independent_literal_fullmask(tiny_image):
    #Independent mask enumeration and literal scalar reconstruction do not
    #use the image cache, joint loop or quantizer added_error helper.
    ctx = tiny_image.context
    law = lab.QuantizerLaw(13, 3, 2)
    message, weights = (1, -1), (1, -2)
    joint = lab.joint_law(tiny_image, message, weights, law)
    full, windows = Counter(), [Counter(), Counter()]
    for error in product((-1, 0, 1), repeat=2):
        mass = prod(2 if e == 0 else 1 for e in error)
        for mask in product(range(13), repeat=2):
            image = schoolbook(ctx.secret, mask, 13)
            c = tuple((a + 3 * e - v) % 13
                      for a, e, v in zip(message, error, image, strict=True))
            z = tuple(e - (coefficient % 4) // 3 for e, coefficient in zip(error, c, strict=True))
            y = tuple(w * value for w, value in zip(weights, z, strict=True))
            full[sum(y)] += mass
            for j in range(2):
                windows[j][2 * y[j]] += mass
    denominator = 4 ** 2 * 13 ** 2
    assert joint.denominator == 4 ** 2 * 13
    assert joint.compare()["full_moment"] == lab.moment(tuple(full.items()), denominator)
    expected = tuple(lab.moment(tuple(count.items()), denominator) for count in windows)
    assert joint.compare()["window_moments"] == expected
    assert expected == lab.factored_window_moments(ctx, weights, law)
    assert joint.compare()["holder_holds"]
    assert joint.tuple_visits == 9 * 13


def test_cbd_masses_match_literal_coins():
    counts = Counter((a - b, c - d) for a, b, c, d in product((0, 1), repeat=4))
    assert dict(lab.cbd_one_states(2)) == counts
    assert sum(counts.values()) == 4 ** 2


def test_translated_windows_uniform_but_full_coset_changes(tiny_image):
    ctx = tiny_image.context
    first = lab.translated_histograms(tiny_image, (1, -1), (0, 0), 3)
    second = lab.translated_histograms(tiny_image, (1, -1), (1, 0), 3)
    assert first == second
    assert all(len(histogram) == 13 and {mass for _, mass in histogram} == {1}
               for histogram in first)
    original = {((1 - a) % 13, (-1 - b) % 13) for a, b in tiny_image.points}
    shifted = {((4 - a) % 13, (-1 - b) % 13) for a, b in tiny_image.points}
    assert original != shifted
    assert all(point[1] == 5 * point[0] % ctx.q for point in tiny_image.points)


def test_untranslated_indicator_rejects_fake_full_iid():
    image = lab.enumerate_image(lab.Context(2, 5, 2, (-2, 1), 1))
    result = lab.indicator_control(image, (0, 1))
    assert result["direct_moment"] == Fraction(8, 5)
    assert result["fake_iid_moment"] == Fraction(6, 5) ** 2
    assert result["direct_moment"] != result["fake_iid_moment"]
    assert result["ordinary_holder_equality"]


@pytest.mark.parametrize("counts,denominator", (
    (((0, True),), 1), (((False, 1),), 1), (((0, 0),), 1),
    (((0, 1), (0, 1)), 2), (((0, 1),), 2), (((4097, 1),), 1),
))
def test_exponent_law_requires_exact_normalized_counts(counts, denominator):
    with pytest.raises(ValueError):
        lab.moment(counts, denominator)


@pytest.mark.parametrize("base", (2, 2.0, Fraction(1), Fraction(17), True))
def test_moment_rejects_exponent_base_aliases(base):
    with pytest.raises(ValueError):
        lab.moment(((0, 1),), 1, base)


def test_non_surjective_window_cannot_get_factored_rhs():
    ctx = lab.Context(2, 13, 5, (-5, 1), 2)
    with pytest.raises(ValueError):
        lab.factored_window_moments(ctx, (1, 1), lab.QuantizerLaw(13, 3, 2))


def test_formal_small_codec_matches_literal_wholeq_reconstruction():
    law = lab.QuantizerLaw(13, 3, 2)
    histogram = Counter()
    for c in range(13):
        high, low = divmod(c, 4)
        reconstructed = (4 * high + low % 3) % 13
        centered = (reconstructed - c + 6) % 13 - 6
        assert law.literal_map(c) == (3 * high + low % 3, reconstructed)
        assert law.added_error(c) == centered
        histogram[centered // 3] += 1
    assert tuple(sorted(histogram.items())) == tuple(sorted(law.pmf()))
    assert law.mean_units() == Fraction(-3, 13)


def test_joint_counter_mutation_is_rejected(tiny_image):
    joint = lab.joint_law(tiny_image, (1, -1), (1, -2), lab.QuantizerLaw(13, 3, 2))
    with pytest.raises(ValueError):
        replace(joint, tuple_visits=joint.tuple_visits - 1).compare()


@pytest.mark.parametrize("field", ("error_vectors", "image_points", "tuple_visits",
                                    "scalar_lookups", "window_sums", "scalar_cache_entries"))
@pytest.mark.parametrize("alias_kind", ("float", "bool", "mpz"))
def test_joint_counter_aliases_are_rejected(tiny_image, field, alias_kind):
    joint = lab.joint_law(tiny_image, (1, -1), (1, -2), lab.QuantizerLaw(13, 3, 2))
    value = getattr(joint, field)
    alias = {"float": float, "bool": bool, "mpz": gmpy2.mpz}[alias_kind](value)
    with pytest.raises(ValueError):
        replace(joint, **{field: alias}).compare()


@pytest.mark.parametrize("cache_entries", (0, 12, 17))
def test_joint_scalar_cache_cannot_be_omitted_or_detached(tiny_image, cache_entries):
    joint = lab.joint_law(tiny_image, (1, -1), (1, -2), lab.QuantizerLaw(13, 3, 2))
    with pytest.raises(ValueError):
        replace(joint, scalar_cache_entries=cache_entries).compare()


def test_joint_outer_law_tuple_is_required(tiny_image):
    joint = lab.joint_law(tiny_image, (1, -1), (1, -2), lab.QuantizerLaw(13, 3, 2))
    with pytest.raises(ValueError):
        replace(joint, window_exponents=list(joint.window_exponents)).compare()
