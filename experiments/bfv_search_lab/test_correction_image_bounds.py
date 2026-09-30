"""Independent exact image and CRT checks for E36 norm bounds."""

import itertools

import pytest

from experiments.bfv_search_lab import correction_image_bounds as bounds
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import dyadic_crt as tree


@pytest.mark.parametrize("p", (3, 5, 7, 11, 17))
def test_sum_triangle_has_exact_maximum_p(p):
    image = bounds.Image(p, ((1, 0), (0, 1), (1, 1)))
    maximum, value = bounds.exact(image)
    assert maximum == p == bounds.norm(image, value)
    report = bounds.describe(image)
    assert report["proved_upper"] == report["proved_lower"] == p
    assert report["cube_bound"] == 3 * (p // 2)


def test_projective_and_zero_cover_matches_independent_enumeration():
    for p in (3, 5, 7):
        image = bounds.Image(p, ((1, 0), (2, 0), (0, 1), (0, 0)))
        maximum = max(sum(min(v := (a * x + b * y) % p, p - v) for a, b in image.forms)
                      for x, y in itertools.product(range(p), repeat=2))
        upper, groups = bounds.projective(image)
        assert upper == maximum
        assert len(groups) == 2
        assert bounds.describe(image)["nonzero_forms"] == 3


@pytest.mark.parametrize("shared,scheduled", ((0, False), (1, False), (0, True)))
def test_generators_match_existing_corrections_and_full_crt(shared, scheduled):
    ctx = tree.context(32, ("0", "10", "11"), 17)
    layout = tree.layout(ctx, (2, 2, 2), (2, 2, 2))
    s = crt.space(layout, (0, 1, 0), shared=shared,
                  coordinate_ids=((0, 1), (0, 2)) if scheduled else ())
    generated = bounds.generators(s)
    for coordinate in range(s.dimension):
        basis = tuple(int(i == coordinate) for i in range(s.dimension))
        reference = crt.corrections(s, basis)
        for j, (variables, image) in enumerate(generated):
            actual = tuple(row[variables.index(coordinate)] if coordinate in variables else 0 for row in image.forms)
            assert actual == tuple(x % ctx.prime for x in reference[j])
        groups = crt.split(s, basis)
        for j, short in enumerate(reference):
            full = tree.encode(ctx, [[groups[group][j]] + [0] * (leaf.degree - 1)
                                    for leaf, group in zip(ctx.leaves, s.map_ids, strict=True)])
            assert [x % ctx.prime for x in full] == [x % ctx.prime for x in crt.expand(s, short)]
    report = bounds.space_bounds(s)
    actual_max = max(sum(map(abs, (x for col in crt.corrections(s, v) for x in col)))
                     for v in itertools.product(range(ctx.prime), repeat=s.dimension))
    assert report["uniform_norm_lower"] <= actual_max <= report["uniform_norm_upper"]


def test_search_is_a_lower_witness_not_an_upper_certificate():
    image = bounds.Image(257, ((1, 0, 0), (0, 1, 0), (0, 0, 1), (1, 1, 1)))
    report = bounds.describe(image)
    assert bounds.norm(image, tuple(report["witness"])) == report["witness_norm"]
    assert report["proved_lower"] <= report["proved_upper"]
    with pytest.raises(ValueError, match="budget"):
        bounds.exact(image)


def test_reject_invalid_images():
    for image in (bounds.Image(4, ((1,),)), bounds.Image(3, ((3,),)), bounds.Image(3, ()),
                  bounds.Image(3, ((1,), (1, 2)))):
        with pytest.raises(ValueError):
            bounds.validate(image)
