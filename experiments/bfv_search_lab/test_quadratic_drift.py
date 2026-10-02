"""Independent complete small-matrix/secret and integer-certificate controls."""

from dataclasses import replace
from itertools import product
from random import Random

import pytest

from experiments.bfv_search_lab import quadratic_drift as lab


def multiply(left, right):
    n, result = len(left), [0] * len(left)
    for i in range(n):
        for j in range(n):
            k = i + j
            result[k % n] += left[i] * right[j] * (-1 if k >= n else 1)
    return tuple(result)


def matmul(left, right):
    n = len(left)
    return tuple(tuple(sum(left[i][k] * right[k][j] for k in range(n)) for j in range(n)) for i in range(n))


def transpose(matrix):
    return tuple(zip(*matrix, strict=True))


def convolution_matrix(poly):
    n = len(poly)
    return tuple(tuple(poly[(i - j) % n] * (1 if i >= j else -1) for j in range(n)) for i in range(n))


def quadratic_matrix(poly, k):
    n = len(poly)
    return tuple(tuple(poly[(k - i - j) % n] * (-1 if ((k - i - j) // n) % 2 else 1)
                       for j in range(n)) for i in range(n))


def matrix_trace(matrix):
    return sum(matrix[i][i] for i in range(len(matrix)))


def phase(components, secret):
    a = multiply(components[1], secret)
    b = multiply(components[2], multiply(secret, secret))
    return tuple(x + y + z for x, y, z in zip(components[0], a, b, strict=True))


def test_complete_small_signed_kronecker_products():
    for n in (2, 4):
        space = tuple(product((-1, 0, 1), repeat=n))
        for left, right in product(space, repeat=2):
            assert lab.ring_product(left, right) == multiply(left, right)
    rng = Random(91001)
    for n in (2, 8, 32, 128):
        for _ in range(8):
            left = tuple(rng.randrange(-(1 << 70), 1 << 70) for _ in range(n))
            right = tuple(rng.randrange(-(1 << 66), 1 << 66) for _ in range(n))
            assert lab.ring_product(left, right) == multiply(left, right)


def test_entire_small_matrix_moment_space_all_output_positions():
    for n in (2, 4):
        for poly in product((-1, 0, 1), repeat=n):
            c = convolution_matrix(poly)
            gram, powers = matmul(c, transpose(c)), lab.moments(poly)
            for k in range(n):
                h = quadratic_matrix(poly, k)
                assert h == transpose(h)
                assert matmul(h, h) == gram
            current = gram
            for moment in powers:
                if moment.power > 1:
                    current = matmul(current, current)
                assert matrix_trace(current) == moment.trace
                assert moment.trace == n * moment.polynomial[0]
                assert moment.root_upper ** (2 * moment.power) >= moment.trace
                assert moment.root_upper == 0 or (moment.root_upper - 1) ** (2 * moment.power) < moment.trace


def test_complete_small_ternary_source_bounds_include_squared_dependence():
    for n in (2, 4):
        space = tuple(product((-1, 0, 1), repeat=n))
        for poly in space:
            norms = lab.moments(poly)
            for prefix in range(1, n + 1):
                bound = min(lab.quadratic_box(poly, prefix), prefix * min(x.root_upper for x in norms))
                for part in product((-1, 0, 1), repeat=prefix):
                    secret = (*part, *((0,) * (n - prefix)))
                    assert max(map(abs, multiply(poly, multiply(secret, secret)))) <= bound


def test_complete_tiny_rounding_phase_law_and_total_bound():
    n, q, target = 2, 3, 4
    for values in product(range(q), repeat=3 * n):
        components = tuple(values[j:j + n] for j in range(0, len(values), n))
        for prefix in (1, 2):
            approved = lab.Approved(q, target, prefix, components, "toy-context", "toy-keys", "epoch", 1 << 80)
            cert = lab.build(approved)
            raw = tuple(tuple((2 * target * x + q) // (2 * q) for x in poly) for poly in components)
            for part in product((-1, 0, 1), repeat=prefix):
                secret = (*part, *((0,) * (n - prefix)))
                drift = phase(cert.drift, secret)
                before, after = phase(components, secret), phase(raw, secret)
                assert tuple(q * a - target * b for a, b in zip(after, before, strict=True)) == drift
                assert max(map(abs, drift)) <= cert.total_bound


def test_complete_linear_prefix_box_and_all_pair_quadratic_box_controls():
    for n in (2, 4):
        for poly in product((-1, 0, 1), repeat=n):
            for prefix in range(1, n + 1):
                maximum = 0
                for part in product((-1, 1), repeat=prefix):
                    secret = (*part, *((0,) * (n - prefix)))
                    maximum = max(maximum, max(map(abs, multiply(poly, secret))))
                assert lab.linear_bound(poly, prefix) == maximum
                pair_control = max(sum(abs(poly[(k - i - j) % n])
                                       for i in range(prefix) for j in range(prefix)) for k in range(n))
                assert lab.quadratic_box(poly, prefix) == pair_control


def test_cropped_orbit_invariance_is_false():
    poly = (0, 1, 0, 0)
    h0, h1 = quadratic_matrix(poly, 0), quadratic_matrix(poly, 1)
    assert h0[0][0] ** 2 == 0 and h1[0][0] ** 2 == 1
    assert multiply(poly, multiply((1, 0, 0, 0), (1, 0, 0, 0)))[1] == 1


def test_wrong_star_modular_trace_and_floor_roots_are_not_certificates():
    poly = (1, 1)
    correct = lab.moments(poly)[1]
    assert correct.trace == 8 and correct.root_upper == 2
    assert correct.trace > 1 ** 4
    assert multiply(poly, poly) != multiply(poly, lab.star(poly))
    assert (correct.trace % 5) != correct.trace


def example():
    return lab.Approved(65537, 8192, 4, ((1, 1901, 39007, 65001), (17, 26001, 33, 61013),
                                      (12001, 29001, 15099, 63001)), "local-context", "local-key", "epoch-1", 1 << 100)


def test_paid_receiver_and_public_insufficient_budget_before_callback():
    approved, called = example(), []
    cert = lab.build(approved)
    assert lab.verify_and_release(approved, cert, lambda value: called.append(value) or "accepted") == "accepted"
    assert called == [cert]
    changed = replace(approved, drift_budget_numerator=0)
    with pytest.raises(ValueError):
        lab.verify_and_release(changed, lab.build(changed), lambda value: called.append(value))
    assert called == [cert]


@pytest.mark.parametrize("change", ("anchor", "rounded", "drift", "poly", "trace", "root", "floor_root",
                                    "moment", "power", "body_bound", "linear_bound", "box", "total", "bool"))
def test_corrupt_certificate_rejects_before_callback(change):
    approved, called = example(), []
    good = lab.build(approved)
    bad = good
    if change == "anchor":
        bad = replace(good, anchor="0" * 64)
    elif change in ("rounded", "drift"):
        arrays = getattr(good, change)
        bad = replace(good, **{change: ((arrays[0][0] + 1, *arrays[0][1:]), *arrays[1:])})
    elif change in ("poly", "trace", "root", "floor_root", "power", "bool"):
        moment = good.moments[0]
        fields = {"poly": {"polynomial": (moment.polynomial[0] + 1, *moment.polynomial[1:])},
                  "trace": {"trace": moment.trace + 1}, "root": {"root_upper": moment.root_upper + 1},
                  "floor_root": {"root_upper": moment.root_upper - 1}, "power": {"power": 2},
                  "bool": {"power": True}}
        bad = replace(good, moments=(replace(moment, **fields[change]), *good.moments[1:]))
    elif change == "moment":
        bad = replace(good, moments=good.moments[:-1])
    else:
        field = {"body_bound": "body_bound", "linear_bound": "linear_bound", "box": "quadratic_box_bound", "total": "total_bound"}[change]
        bad = replace(good, **{field: getattr(good, field) + 1})
    with pytest.raises(ValueError):
        lab.verify_and_release(approved, bad, lambda value: called.append(value))
    assert not called


@pytest.mark.parametrize("field", ("epoch", "key_id", "context_id", "prefix", "target"))
def test_source_context_substitutions_reject(field):
    approved, called = example(), []
    value = {"prefix": 2, "target": 4096}.get(field, "other")
    with pytest.raises(ValueError):
        lab.verify_and_release(replace(approved, **{field: value}), lab.build(approved), lambda x: called.append(x))
    assert not called


@pytest.mark.parametrize("field,value", (("q", 64), ("target", 63), ("prefix", True), ("prefix", 5)))
def test_invalid_rounding_context_rejects(field, value):
    with pytest.raises(ValueError):
        lab.build(replace(example(), **{field: value}))
