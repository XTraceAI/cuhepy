"""Independent exact mixed-source/target phases and full public checks."""

from dataclasses import replace
from itertools import product
from random import Random, SystemRandom

import pytest

from experiments.bfv_search_lab import partial_packed_switch as lab


def multiply(left, right):
    n, result = len(left), [0] * len(left)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            result[(i + j) % n] += a * b * (1 if i + j < n else -1)
    return tuple(result)


def add(*polys):
    return tuple(sum(values) for values in zip(*polys, strict=True))


def source_phase(components, secret):
    return add(components[0], multiply(components[1], secret),
               multiply(components[2], multiply(secret, secret)))


def make_keys(q, radix, source, target, target_prefix, skip, rng=None, eta=1):
    # Deterministic toy RNG is allowed in tests only; the fresh local fixture
    # explicitly supplies SystemRandom. No key distribution is approved here.
    rng = SystemRandom() if rng is None else rng
    rows, errors, n = [], [], len(source)
    for family, secret in enumerate((source, multiply(source, source))):
        key_family, error_family = [], []
        for level in range(skip if family else 0, lab.context(q, radix)):
            mask = tuple(rng.randrange(q) for _ in range(n))
            error = tuple(rng.randrange(-eta, eta + 1) for _ in range(n))
            product_mask = multiply(mask, target)
            body = tuple((radix ** level * s + e - a) % q for s, e, a in
                         zip(secret, error, product_mask, strict=True))
            key_family.append((mask, body))
            error_family.append(error)
        rows.append(tuple(key_family))
        errors.append(tuple(error_family))
    return lab.Keys(q, radix, target_prefix, skip, tuple(rows)), tuple(errors)


def example(*, n=4, q=97, radix=3, skip=1, target=4, source_prefix=4,
            target_prefix=2, components=None, rng=None):
    rng = Random(92001) if rng is None else rng
    source = (1, -1, 1, 0)[:source_prefix] + (0,) * (n - source_prefix)
    destination = (1, -1, 0, 1)[:target_prefix] + (0,) * (n - target_prefix)
    components = (tuple(tuple(rng.randrange(q) for _ in range(n)) for _ in range(3))
                  if components is None else components)
    keys, errors = make_keys(q, radix, source, destination, target_prefix, skip, rng)
    approved = lab.Approved(components, keys, source_prefix, target, 1, 1 << 200,
                           False, "unit-toy", "source-S", "independent-target-T", "epoch-1")
    return approved, source, destination, errors


def literal_switch(approved):
    all_digits, residual = lab.decomposition(approved)
    digit_families = (all_digits[0], all_digits[1][approved.keys.skipped_c2_levels:])
    body = approved.components[0]
    mask = (0,) * len(body)
    for digit_family, key_family in zip(digit_families, approved.keys.values, strict=True):
        for digit, row in zip(digit_family, key_family, strict=True):
            body, mask = add(body, multiply(digit, row[1])), add(mask, multiply(digit, row[0]))
    return tuple(tuple(x % approved.keys.q for x in poly) for poly in (body, mask)), residual


def key_error(approved, errors):
    all_digits, _ = lab.decomposition(approved)
    families = (all_digits[0], all_digits[1][approved.keys.skipped_c2_levels:])
    terms = [multiply(digit, error) for digit_family, error_family in zip(families, errors, strict=True)
             for digit, error in zip(digit_family, error_family, strict=True)]
    return add(*terms)


def check_phase(approved, source, target, errors):
    cert, q, b = lab.build(approved), approved.keys.q, approved.target
    expected, residual = literal_switch(approved)
    assert cert.output == expected and cert.residual == residual
    error = key_error(approved, errors)
    original = source_phase(approved.components, source)
    retained = add(cert.output[0], multiply(cert.output[1], target))
    hidden = multiply(residual, multiply(source, source))
    assert all((x + y - z - e) % q == 0 for x, y, z, e in zip(retained, hidden, original, error, strict=True))
    after = add(cert.rounded[0], multiply(cert.rounded[1], target))
    drift = add(cert.drift[0], multiply(cert.drift[1], target),
                tuple(b * (e - h) for e, h in zip(error, hidden, strict=True)))
    assert all((q * out - b * before - d) % (q * b) == 0
               for out, before, d in zip(after, original, drift, strict=True))
    assert max(map(abs, error)) <= cert.key_error_bound
    assert max(map(abs, drift)) <= cert.total_bound
    return cert


def test_whole_small_balanced_residues_and_zero_mask_boundary():
    for q, radix in product((3, 5, 7, 9, 17, 97), (3, 5)):
        for skip in range(lab.context(q, radix) + 1):
            for x in range(q):
                residual = lab.residual_bound(x, q, radix, skip)
                for target in (2, 4, 16, 64, 1 << 64):
                    zero = lab.round_integer(residual, q, target) == 0
                    assert zero == (2 * target * abs(residual) < q)
                    if target == 1 << 64:
                        assert zero == (residual == 0)


def test_whole_small_two_secret_classes_and_all_component_phases():
    n, q, radix = 2, 7, 3
    space = tuple(product((-1, 0, 1), repeat=n))
    for skip in range(lab.context(q, radix) + 1):
        for source, target in product(space, repeat=2):
            rng = Random(92002)
            components = tuple(tuple(rng.randrange(q) for _ in range(n)) for _ in range(3))
            keys, errors = make_keys(q, radix, source, target, n, skip, rng)
            approved = lab.Approved(components, keys, n, 16, 1, 1 << 100,
                                   False, "toy-unit", "S", "T", "epoch")
            check_phase(approved, source, target, errors)


def test_source_and_target_prefixes_have_separate_all_key_bounds():
    approved, _, _, _ = example(source_prefix=4, target_prefix=1)
    cert = lab.build(approved)
    for source in product((-1, 0, 1), repeat=4):
        hidden = multiply(cert.residual, multiply(source, source))
        for t in (-1, 0, 1):
            target = (t, 0, 0, 0)
            drift = add(cert.drift[0], multiply(cert.drift[1], target),
                        tuple(-approved.target * x for x in hidden))
            assert max(map(abs, drift)) <= cert.total_bound


def test_candidate_outputs_are_strictly_contained_in_known_approximate_control():
    approved, _, _, _ = example()
    control = lab.build(approved)
    candidate = lab.build(replace(approved, require_zero_residual_mask=True))
    assert candidate.output == control.output and candidate.rounded == control.rounded
    assert candidate.total_bound == control.total_bound
    assert candidate.residual_mask_zero
    for a, cert in ((approved, control), (replace(approved, require_zero_residual_mask=True), candidate)):
        assert lab.verify_and_release(a, cert, lambda _: "opaque-control") == "opaque-control"
    large = replace(approved, target=1 << 64)
    control = lab.build(large)
    assert not control.residual_mask_zero
    assert lab.verify_and_release(large, control, lambda _: "known") == "known"
    restrictive = replace(large, require_zero_residual_mask=True)
    with pytest.raises(ValueError, match="zero rounded"):
        lab.verify_and_release(restrictive, lab.build(restrictive), lambda _: pytest.fail("private work"))


def test_zero_rounded_residual_does_not_remove_original_secret_phase():
    residual, source = (1, 0), (1, 1)
    assert lab.round_integer(1, 97, 4) == 0
    assert multiply(residual, multiply(source, source)) == (0, 2)
    assert multiply(residual, multiply((1, 0), (1, 0))) == (1, 0)


def test_unit_conversion_must_precede_low_digit_choice():
    q, t, radix = 17, 3, 3
    before = lab.residual_bound(1, q, radix, 1)
    after = lab.residual_bound(pow(t, -1, q), q, radix, 1)
    assert before == 1 and after == 0
    assert (before * pow(t, -1, q)) % q == 6


def test_small_target_prefix_cannot_bound_full_source_squared_secret():
    residual, source = (1, 0, 0, 0), (1, 1, 1, 1)
    assert max(map(abs, multiply(residual, multiply(source, source)))) == 4
    assert lab.quadratic_box(residual, 1) == 1
    assert lab.quadratic_box(residual, 4) >= 4


def test_missing_extra_and_noncanonical_key_rows_reject():
    approved, _, _, _ = example()
    keys = approved.keys
    broken = (replace(keys, values=keys.values[:-1]),
              replace(keys, values=(keys.values[0][:-1], keys.values[1])),
              replace(keys, values=(keys.values[0], (*keys.values[1], keys.values[0][0]))),
              replace(keys, skipped_c2_levels=True), replace(keys, target_prefix=0))
    for bad in broken:
        with pytest.raises(ValueError):
            lab.build(replace(approved, keys=bad))


@pytest.mark.parametrize("field", ("output", "residual", "rounded", "drift", "moments", "body_bound",
                                   "linear_bound", "residual_box_bound", "residual_moment_bound",
                                   "key_error_bound", "total_bound", "anchor", "residual_mask_zero"))
def test_malformed_complete_certificates_reject_before_callback(field):
    approved, _, _, _ = example()
    cert = lab.build(approved)
    value = getattr(cert, field)
    if field in ("output", "rounded", "drift"):
        value = ((value[0][0] + 1, *value[0][1:]), *value[1:])
    elif field == "residual":
        value = (value[0] + 1, *value[1:])
    elif field == "moments":
        value = (replace(value[0], trace=value[0].trace + 1), *value[1:])
    elif field == "anchor":
        value = "0" * 64
    elif field == "residual_mask_zero":
        value = int(value)
    else:
        value += 1
    with pytest.raises(ValueError):
        lab.verify_and_release(approved, replace(cert, **{field: value}), lambda _: pytest.fail("private work"))


@pytest.mark.parametrize("change", ({"source_prefix": 0}, {"target": 3}, {"source_key_id": "independent-target-T"},
                                    {"require_zero_residual_mask": 1}, {"key_error_coefficient_bound": -1},
                                    {"epoch": ""}))
def test_invalid_approved_contexts_reject(change):
    approved, _, _, _ = example()
    with pytest.raises(ValueError):
        lab.build(replace(approved, **change))


def test_wrong_source_target_epoch_keys_and_budget_do_not_release():
    approved, _, _, _ = example()
    cert = lab.build(approved)
    for changed in (replace(approved, source_prefix=1), replace(approved, epoch="epoch-2"),
                    replace(approved, keys=replace(approved.keys, target_prefix=1)),
                    replace(approved, drift_budget_numerator=cert.total_bound - 1)):
        with pytest.raises(ValueError):
            lab.verify_and_release(changed, cert, lambda _: pytest.fail("private work"))
    too_small = replace(approved, drift_budget_numerator=cert.total_bound - 1)
    with pytest.raises(ValueError, match="budget"):
        lab.verify_and_release(too_small, lab.build(too_small), lambda _: pytest.fail("private work"))
