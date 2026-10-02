"""Independent phase/noise and adversarial public-receiver checks for E87."""

from dataclasses import replace
from itertools import product
from random import Random

import pytest

from experiments.bfv_search_lab import batched_score_bridge as bridge


def product_reference(left, right, q):
    # Ordinary full product followed by X^N=-1; independent of bridge loops.
    n = len(left)
    full = [sum(left[j] * right[k - j] for j in range(n) if 0 <= k - j < n)
            for k in range(2 * n - 1)] + [0]
    return tuple((full[k] - full[k + n]) % q for k in range(n))


def powers_reference(source, count, q):
    return (source,) if count == 2 else (source, product_reference(source, source, q))


def phase_reference(components, source, q):
    terms = [components[0]] + [product_reference(poly, secret, q) for poly, secret in
                              zip(components[1:], powers_reference(source, len(components), q), strict=True)]
    return tuple(sum(values) % q for values in zip(*terms, strict=True))


def make_keys(source, target, q, radix, count, rng):
    """Local toy fixtures: independent random masks, explicit secret/error data."""
    n, levels = len(source), bridge.context(q, radix)
    column, column_errors, packed, packed_errors = [], [], [], []
    padded = target + (0,) * (n - len(target))
    for secret in powers_reference(source, count, q):
        family, errors = [], []
        for value in secret:
            row, noise_row = [], []
            for level in range(levels):
                mask, error = tuple(rng.randrange(q) for _ in target), rng.choice((-1, 0, 1))
                body = (radix**level * value + error - sum(a * s for a, s in zip(mask, target, strict=True))) % q
                row.append(bridge.Scalar(mask, body))
                noise_row.append(error)
            family.append(tuple(row))
            errors.append(tuple(noise_row))
        column.append(tuple(family))
        column_errors.append(tuple(errors))
        family, errors = [], []
        for level in range(levels):
            mask = tuple(rng.randrange(q) for _ in source)
            noise = tuple(rng.choice((-1, 0, 1)) for _ in source)
            mask_phase = product_reference(mask, padded, q)
            body = tuple((radix**level * s + e - a) % q for s, e, a in zip(secret, noise, mask_phase, strict=True))
            family.append((mask, body))
            errors.append(noise)
        packed.append(tuple(family))
        packed_errors.append(tuple(errors))
    return (bridge.ColumnKeys(q, radix, tuple(column)), tuple(column_errors),
            bridge.PackedKeys(q, radix, len(target), tuple(packed)), tuple(packed_errors))


def check_phase(components, source, target, column, column_errors, packed, packed_errors):
    q, n = column.q, len(source)
    literal = bridge.literal_switch(components, column)
    assert bridge.column_switch(components, column) == literal
    original = phase_reference(components, source, q)
    for k, sample in enumerate(literal):
        noise = 0
        for poly, family in zip(components[1:], column_errors, strict=True):
            for j in range(n):
                extracted = (poly[(k - j) % n] * (1 if j <= k else -1)) % q
                noise += sum(d * e for d, e in zip(bridge.digits(extracted, q, column.radix), family[j], strict=True))
        assert (sample.b + sum(a * s for a, s in zip(sample.a, target, strict=True))) % q == (original[k] + noise) % q
    switched = bridge.packed_switch(components, packed)
    expected_noise = [0] * n
    for poly, family in zip(components[1:], packed_errors, strict=True):
        for level, errors in enumerate(family):
            digits = tuple(bridge.digits(x, q, packed.radix)[level] for x in poly)
            convolution = product_reference(digits, errors, q)
            expected_noise = [a + b for a, b in zip(expected_noise, convolution, strict=True)]
    for k in range(n):
        sample = bridge.extract_packed(switched, k, len(target), q)
        assert (sample.b + sum(a * s for a, s in zip(sample.a, target, strict=True))) % q == (original[k] + expected_noise[k]) % q
    return n * (len(target) + 1), n


@pytest.mark.parametrize("q,radix", [(3, 3), (5, 3), (17, 3), (17, 5), (19, 9), (51, 3), (257, 17), (323, 257)])
def test_all_residues_exact_unique_negation(q, radix):
    for x in range(q):
        digits = bridge.digits(x, q, radix)
        assert sum(d * radix**level for level, d in enumerate(digits)) == bridge.centered(x, q)
        assert bridge.digits((-x) % q, q, radix) == tuple(-d for d in digits)
        assert all(abs(d) <= radix // 2 for d in digits)


@pytest.mark.parametrize("count", [2, 3])
def test_exhaustive_tiny_all_inputs_source_keys_positions_and_noise(count):
    for source in product(range(3), repeat=2):
        keys = make_keys(source, (1,), 3, 3, count, Random(31 + sum(source)))
        for values in product(range(3), repeat=2 * count):
            components = tuple(values[i:i + 2] for i in range(0, len(values), 2))
            check_phase(components, source, (1,), *keys)


@pytest.mark.parametrize("q,radix,n,count", [(17, 3, 4, 3), (51, 5, 4, 2), (323, 9, 8, 3), (65537, 257, 16, 3)])
def test_seeded_larger_exact_phase_and_errors(q, radix, n, count):
    rng = Random(q + radix + n)
    source, target = tuple(rng.choice((-1, 0, 1)) for _ in range(n)), (1, -1)
    keys = make_keys(source, target, q, radix, count, rng)
    for _ in range(12):
        components = tuple(tuple(rng.randrange(q) for _ in range(n)) for _ in range(count))
        check_phase(components, source, target, *keys)


def test_unsigned_binary_digits_fail_to_commute_with_extraction_sign():
    q, x = 17, 1
    def unsigned(value):
        return tuple((value >> level) & 1 for level in range(q.bit_length()))
    assert unsigned((-x) % q) != tuple(-d for d in unsigned(x))


def test_evaluation_only_cannot_determine_balanced_digits():
    # These coefficient polynomials agree at z=2 but their low digit differs.
    q, radix, point = 17, 3, 2
    left, right = (0, 1), (2, 0)
    assert (left[0] + point * left[1]) % q == (right[0] + point * right[1]) % q
    digit_left, digit_right = (tuple(bridge.digits(x, q, radix)[0] for x in poly) for poly in (left, right))
    assert (digit_left[0] + point * digit_left[1]) % q != (digit_right[0] + point * digit_right[1]) % q


def test_range_and_modular_reconstruction_do_not_force_centered_digits():
    q, radix, value = 17, 3, 9  # centered value -8; alternate integer lift +9.
    canonical, alternate = bridge.digits(value, q, radix), (0, 0, 1)
    assert canonical != alternate and all(abs(d) <= radix // 2 for d in alternate)
    assert sum(d * radix**level for level, d in enumerate(alternate)) % q == value
    assert sum(d * radix**level for level, d in enumerate(canonical)) == -8


def test_disclosed_challenge_allows_adaptive_nonzero_polynomial_error():
    column, _, packed, _ = make_keys((1, 0), (1,), 17, 3, 2, Random(44))
    approved = bridge.register("root-control", ((1, 2), (3, 4)), packed, (0, 1))
    correct, point, q = bridge.recompute(approved), 2, 17
    mask, body = correct.output
    forged_mask = ((mask[0] - point) % q, (mask[1] + 1) % q)
    assert (forged_mask[0] + point * forged_mask[1]) % q == (mask[0] + point * mask[1]) % q
    assert not bridge.verify_recomputation(approved, replace(correct, output=(forged_mask, body)))


def fresh_bgv_differential():
    from experiments.bfv_search_lab import bgv_unit_bridge as unit
    from experiments.bfv_search_lab import shallow_bgv as bgv

    pk, sk = bgv.key_gen(n=8, t=17, q_bits=32, eta=1)
    cipher = bgv.multiply(bgv.encrypt([1, 0, 1, 0, 0, 1, 0, 0], pk),
                          bgv.encrypt([0, 1, 1, 0, 0, 0, 1, 0], pk), pk)
    expected = bgv.decrypt(cipher, pk, sk)
    components = tuple(tuple(int(x) for x in poly) for poly in cipher.components)
    q, source, target = int(pk.q), tuple(int(x) for x in sk.s), (1, -1)
    converted = unit.convert(components, q, pk.t)
    column, errors, packed, packed_errors = make_keys(source, target, q, 257, 3, Random(828))
    check_phase(converted, source, target, column, errors, packed, packed_errors)
    switched = bridge.packed_switch(converted, packed)
    actual = []
    for k in range(pk.n):
        sample = bridge.extract_packed(switched, k, len(target), q)
        phase = (sample.b + sum(a * s for a, s in zip(sample.a, target, strict=True))) % q
        actual.append(unit.scaled_decode_reference(phase, q, pk.t))
    assert actual == expected
    return {"N": pk.n, "Q": q, "t": pk.t, "eta": pk.eta, "radix": 257,
            "target_dimension": len(target), "all_output_coefficients_checked": pk.n,
            "fresh_OS_random_source_keys_and_encryption": True,
            "original_GMP_and_independent_schoolbook_phase": True,
            "unit_then_packed_switch_decode_matched": True,
            "private_decryption_only_local_trusted_fixture": True,
            "secure_parameters_or_production_protocol": False}


def test_fresh_homemade_bgv_product_unit_then_switch_differential():
    assert fresh_bgv_differential()["unit_then_packed_switch_decode_matched"]


@pytest.mark.parametrize("packed_mode", [False, True])
def test_incomplete_key_component_and_digit_shapes_rejected(packed_mode):
    column, _, packed, _ = make_keys((1, -1), (1,), 17, 3, 3, Random(3))
    keys = packed if packed_mode else column
    components = ((1, 2), (3, 4), (5, 6))
    for bad in (replace(keys, values=keys.values[:1]),
                replace(keys, values=(keys.values[0][:-1], keys.values[1]))):
        with pytest.raises(ValueError):
            bridge.register("bad-key", components, bad, (0, 1))
    with pytest.raises(ValueError):
        bridge.register("missing-C2", components[:2], keys, (0, 1))


@pytest.mark.parametrize("packed_mode", [False, True])
def test_full_recomputation_rejects_corruption_before_any_private_work(packed_mode):
    column, _, packed, _ = make_keys((1, -1), (1,), 17, 3, 3, Random(8))
    keys = packed if packed_mode else column
    approved = bridge.register("owner-epoch-7", ((1, 2), (9, 3), (4, 8)), keys, (0, 1))
    correct = bridge.recompute(approved)
    assert bridge.verify_recomputation(approved, correct)
    corrupted = [replace(correct, epoch="owner-epoch-8"), replace(correct, input_digest="0" * 64),
                 replace(correct, positions=(1, 0)), replace(correct, positions=(0,)),
                 replace(correct, positions=(False, 1)), replace(correct, digit_polys=correct.digit_polys[:1]),
                 replace(correct, digit_polys=(correct.digit_polys[0][:-1], correct.digit_polys[1])),
                 replace(correct, output=correct.output[:-1])]
    noncanonical = list(list(list(poly) for poly in family) for family in correct.digit_polys)
    for level, digit in enumerate((0, 0, 1)):
        noncanonical[0][level][0] = digit
    corrupted.append(replace(correct, digit_polys=tuple(tuple(tuple(poly) for poly in family) for family in noncanonical)))
    for index in range(len(correct.output)):
        changed = list(correct.output)
        if packed_mode:
            changed[index] = ((changed[index][0] + 1) % 17, changed[index][1])
        else:
            changed[index] = replace(changed[index], b=(changed[index].b + 1) % 17)
        corrupted.append(replace(correct, output=tuple(changed)))
    alternate_column, _, alternate_packed, _ = make_keys((1, -1), (1,), 17, 3, 3, Random(9))
    altered = bridge.register(approved.epoch, approved.components,
                              alternate_packed if packed_mode else alternate_column, approved.positions)
    corrupted.append(bridge.recompute(altered))
    assert all(not bridge.verify_recomputation(approved, bad) for bad in corrupted)
    # Exact classes/integers matter: Python True == 1 is not a wire codec.
    floating = list(correct.output)
    if packed_mode:
        floating[0] = tuple(float(x) for x in floating[0])
    else:
        floating[0] = replace(floating[0], b=float(floating[0].b))
    assert not bridge.verify_recomputation(approved, replace(correct, output=tuple(floating)))


def test_every_composite_rns_value_and_missing_limb_rejected():
    q, moduli = 51, (3, 17)
    for x in range(q):
        components = ((x, (x + 1) % q), ((2 * x) % q, (3 * x) % q), ((4 * x) % q, 0))
        limbs = tuple(tuple(tuple(x % p for x in poly) for poly in components) for p in moduli)
        assert bridge.from_rns(limbs, moduli) == components
        with pytest.raises(ValueError):
            bridge.from_rns(limbs[:1], moduli)
    for mutated in (((3, 0), (0, 0)), ((0, 0),)):
        with pytest.raises(ValueError):
            bridge.from_rns((mutated, ((0, 0), (0, 0))), moduli)


@pytest.mark.parametrize("q,radix", [(16, 3), (17, 2), (True, 3), (17, True), ((1 << 64) + 1, 3)])
def test_invalid_arithmetic_contexts(q, radix):
    with pytest.raises(ValueError):
        bridge.context(q, radix)


def test_paid_counts_include_different_keys_sparse_work_and_missing_proof():
    from benchmarks.batched_score_bridge_lab import geometry

    profile = {"n": 4, "modeled_Q": 17, "replies": 1, "t": 3, "phase_bound": 1,
               "dataset": "toy", "profile": "toy"}
    card = geometry(profile, 3, 2, False)
    assert card["column_key_coefficients"] == 72  # 2 families *3 levels *4 positions *3 coordinates
    assert card["packed_key_coefficients"] == 48  # 2 families *3 levels *2 polynomials *4 coefficients
    dense = next(m for m in card["execution_modes"] if m["required_coefficients_per_reply"] == 4 and m["query_batches"] == 1)
    sparse = next(m for m in card["execution_modes"] if m["required_coefficients_per_reply"] == 3 and m["query_batches"] == 1)
    assert dense["literal_scalar_multiply_add_contributions"] == 288
    assert sparse["literal_scalar_multiply_add_contributions"] == 216
    assert dense["column_shared_pointwise_products"] == sparse["column_shared_pointwise_products"] == 72
    assert dense["packed_shared_pointwise_products"] == 48
    assert card["compact_digit_original_score_binding_PBS_ID_coverage_prover_verifier_wire_costs"] is None
    assert not card["existing_Q_unit_plus_illustrative_KS_sufficient_radius"]
    relin = geometry(profile, 3, 2, True)
    assert relin["once_relin_additional_key_coefficients_conditional_same_gadget"] == 24
    assert not relin["once_relin_noise_bound_known"]
