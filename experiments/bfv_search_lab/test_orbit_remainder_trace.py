"""Independent finite integer, orbit, phase and fail-before-callback oracles."""

from dataclasses import replace
from itertools import product
import random

import pytest

from experiments.bfv_search_lab import orbit_remainder_trace as lab


def profile(b=64, targets=(4, 4)):
    return lab.Profile(b, targets, "local-test-context", "local-key-context", "epoch-1")


def reference(value, p):
    # Independent nearest-integer quotient, then its exact integer residual.
    current, modulus, result = value, p.modulus, []
    for target in p.targets:
        modulus //= target
        quotient = (2 * current + modulus) // (2 * modulus)
        residual = current - modulus * quotient
        result.append(lab.Step(quotient, residual, int(abs(residual) * 2 == modulus)))
        current = residual
    return tuple(result)


def integer_product(left, right):
    # Full independent negacyclic product before any modular reduction.
    n, result = len(left), [0] * len(left)
    for i in range(n):
        for j in range(n):
            exponent = i + j
            result[exponent % n] += left[i] * right[j] * (-1 if exponent >= n else 1)
    return tuple(result)


def check_blocks(approved, secrets=None):
    built, n, phase_checks = lab.build(approved), len(approved.components[0]), 0
    for block in built.blocks:
        literal_masks = tuple(tuple((poly[(j + block.start) % n] *
                                    (1 if j + block.start < n else -1)) % approved.profile.modulus
                                    for j in range(n)) for poly in approved.components[1:])
        literal = tuple(tuple(reference(x, approved.profile) for x in poly) for poly in literal_masks)
        assert literal == block.masks
        assert block.bodies == tuple(reference(x, approved.profile)
                                     for x in approved.components[0][block.start:block.start + block.width])
        if secrets is None:
            continue
        for k in range(block.width):
            rows = tuple(tuple(s[(k - j) % n] * (1 if j <= k else -1) for j in range(n))
                         for s in secrets)
            previous = approved.components[0][block.start + k] + sum(
                sum(x * s for x, s in zip(mask, row, strict=True))
                for mask, row in zip(literal_masks, rows, strict=True))
            modulus = approved.profile.modulus
            for stage, target in enumerate(approved.profile.targets):
                modulus //= target
                quo = block.bodies[k][stage].quotient + sum(
                    sum(t[stage].quotient * s for t, s in zip(mask, row, strict=True))
                    for mask, row in zip(block.masks, rows, strict=True))
                rem = block.bodies[k][stage].remainder + sum(
                    sum(t[stage].remainder * s for t, s in zip(mask, row, strict=True))
                    for mask, row in zip(block.masks, rows, strict=True))
                assert previous == modulus * quo + rem
                previous = rem
                phase_checks += 1
    return phase_checks


def test_full_small_signed_multistage_laws():
    for power in range(2, 9):
        b = 1 << power
        for stages in range(1, min(power - 1, 4) + 1):
            p = profile(b, (2,) * stages)
            for value in range(b):
                original = lab.scalar_trace(value, p)
                assert original == reference(value, p)
                for sign in (-1, 1):
                    assert lab.signed_trace(value, original, sign, p) == reference(
                        value if sign == 1 else (-value) % b, p)


def test_all_tiny_public_components_full_source_secret_powers():
    p = profile(4, (2,))
    for families in (2, 3):
        for values in product(range(4), repeat=2 * families):
            components = tuple(tuple(values[2 * j:2 * j + 2]) for j in range(families))
            approved = lab.Approved(p, components, ((0, 1), (1, 1)))
            for secret in product((-1, 0, 1), repeat=2):
                secrets = (secret,) if families == 2 else (secret, integer_product(secret, secret))
                assert check_blocks(approved, secrets) == 2


def test_seeded_all_block_starts_widths_and_integer_phases():
    rng = random.Random(90021)
    for n, stages, families in product((2, 4, 8, 16), (1, 2, 3), (2, 3)):
        p = profile(1024, (2,) * stages)
        components = tuple(tuple(rng.randrange(p.modulus) for _ in range(n)) for _ in range(families))
        secret = tuple(rng.choice((-1, 0, 1)) for _ in range(n))
        secrets = (secret,) if families == 2 else (secret, integer_product(secret, secret))
        for start in range(n):
            for width in range(1, n - start + 1):
                assert check_blocks(lab.Approved(p, components, ((start, width),)), secrets) == width * stages


def test_every_small_odd_source_grid_count_and_sharp_zero_condition():
    for q in range(3, 130, 2):
        for power in range(2, 10):
            b = 1 << power
            for a_power in range(1, power):
                a, length = 1 << a_power, b // (1 << a_power)
                actual = sum(lab.rounded_grid(x, q, b) % length == length // 2 for x in range(q))
                assert actual == lab.grid_tie_count(q, b, a)
                assert (actual == 0) == (q < length)


def test_stage_half_tie_sets_disjoint_not_independent():
    p = profile(256, (4, 4, 2))
    for q in range(3, 66, 2):
        sets = [set() for _ in p.targets]
        for value in range(q):
            trace = lab.scalar_trace(lab.rounded_grid(value, q, p.modulus), p)
            for i, step in enumerate(trace):
                if step.half:
                    sets[i].add(value)
        # Half residues at a larger dyadic modulus become zero at a smaller one.
        assert all(not (sets[i] & sets[j]) for i in range(len(sets)) for j in range(i))


def test_half_bits_previous_stage_and_canonical_lift_are_necessary():
    p = profile()
    trace = lab.scalar_trace(8, p)
    neg = lab.scalar_trace(56, p)
    assert trace[0].half == 1 and neg[0].remainder != -trace[0].remainder
    assert neg[1].quotient != -trace[1].quotient + trace[1].half
    end = lab.scalar_trace(63, p)[0]
    assert end.quotient == 4 and end.remainder == -1
    assert (end.quotient % 4) * 16 + end.remainder != 63


def test_grid_formula_does_not_cover_even_sources():
    q, b, a = 6, 8, 2
    count = sum(((2 * b * x + q) // (2 * q)) % (b // a) == b // a // 2 for x in range(q))
    assert count == 0 and 2 * ((q + b // a) // (2 * (b // a))) == 2
    with pytest.raises(ValueError):
        lab.grid_tie_count(q, b, a)


def approved_example():
    return lab.Approved(profile(), ((0, 8, 17, 63), (8, 0, 2, 63), (3, 7, 8, 9)), ((0, 2), (2, 2)))


def test_complete_receiver_accepts_before_callback():
    approved = approved_example()
    good, called = lab.build(approved), []
    assert lab.verify_and_release(approved, good, lambda value: called.append(value) or "released") == "released"
    assert called == [good]


@pytest.mark.parametrize("change", ("bit", "quotient", "remainder", "bool", "stage", "family",
                                    "coefficient", "block", "block_order", "mask", "body", "anchor"))
def test_corrupt_complete_transcript_rejects_without_callback(change):
    approved = approved_example()
    good, called = lab.build(approved), []
    first, bad = good.original[0][0][0], good
    if change in ("bit", "quotient", "remainder", "bool"):
        step = replace(first, **{"bit": {"half": 1}, "quotient": {"quotient": first.quotient + 4},
                                  "remainder": {"remainder": 1}, "bool": {"half": False}}[change])
        poly = ((step, *good.original[0][0][1:]), *good.original[0][1:])
        bad = replace(good, original=(poly, *good.original[1:]))
    elif change == "stage":
        bad = replace(good, original=((good.original[0][0][:-1], *good.original[0][1:]), *good.original[1:]))
    elif change == "family":
        bad = replace(good, original=good.original[:-1])
    elif change == "coefficient":
        bad = replace(good, original=(good.original[0][:-1], *good.original[1:]))
    elif change == "block":
        bad = replace(good, blocks=good.blocks[:-1])
    elif change == "block_order":
        bad = replace(good, blocks=good.blocks[::-1])
    elif change in ("mask", "body"):
        block = good.blocks[0]
        block = replace(block, **({"masks": block.masks[:-1]} if change == "mask" else {"bodies": block.bodies[:-1]}))
        bad = replace(good, blocks=(block, *good.blocks[1:]))
    else:
        bad = replace(good, anchor="0" * 64)
    with pytest.raises(ValueError):
        lab.verify_and_release(approved, bad, lambda value: called.append(value))
    assert not called


@pytest.mark.parametrize("field", ("epoch", "context_id", "key_id"))
def test_replay_wrong_public_context_rejects_without_callback(field):
    approved, called = approved_example(), []
    good = lab.build(approved)
    changed = replace(approved, profile=replace(approved.profile, **{field: "other"}))
    with pytest.raises(ValueError):
        lab.verify_and_release(changed, good, lambda value: called.append(value))
    assert not called


def test_original_component_substitution_and_duplicate_coverage():
    approved = approved_example()
    altered = replace(approved, components=((1, *approved.components[0][1:]), *approved.components[1:]))
    with pytest.raises(ValueError):
        lab.verify_and_release(altered, lab.build(approved), lambda _: None)
    with pytest.raises(ValueError):
        lab.build(replace(approved, blocks=((0, 2), (1, 1))))


@pytest.mark.parametrize("p", (profile(63), profile(64, (True,)), profile(64, (3,)),
                               profile(64, (8, 8)), profile(64, (2, 2, 2, 2, 2))))
def test_unsupported_profiles_reject(p):
    with pytest.raises(ValueError):
        lab.divisors(p)
