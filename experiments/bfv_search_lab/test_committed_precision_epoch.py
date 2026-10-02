"""Independent law/phase/corruption controls; no HE security reduction."""

from collections import Counter
from dataclasses import replace
from fractions import Fraction
from itertools import product
from math import comb
from random import Random, SystemRandom

import pytest

from experiments.bfv_search_lab import committed_precision_epoch as lab
from experiments.bfv_search_lab import partial_packed_switch as packed
from experiments.bfv_search_lab.test_partial_packed_switch import add, multiply


def cbd(rng, eta):
    return sum(rng.randrange(2) - rng.randrange(2) for _ in range(eta))


def make_keys(q, radix, source, target, target_prefix, skip, rng, eta=1):
    """Toy/honest differential generation uses the actual centered-binomial law."""
    families, errors, n = [], [], len(source)
    for f, secret in enumerate((source, multiply(source, source))):
        rows, noise = [], []
        for level in range(skip if f else 0, packed.context(q, radix)):
            a = tuple(rng.randrange(q) for _ in range(n))
            e = tuple(cbd(rng, eta) for _ in range(n))
            a_t = multiply(a, target)
            b = tuple((radix**level * s + error - term) % q
                      for s, error, term in zip(secret, e, a_t, strict=True))
            rows.append((a, b))
            noise.append(e)
        families.append(tuple(rows))
        errors.append(tuple(noise))
    return packed.Keys(q, radix, target_prefix, skip, tuple(families)), tuple(errors)


def fixture(*, q=1009, radix=5, skip=0, rng=None):
    rng = Random(93001) if rng is None else rng
    source, target = (1, -1), (-1, 1)
    c1, c2 = (21, 13), (3, 4)
    c0 = tuple(-x % q for x in add(multiply(c1, source), multiply(c2, multiply(source, source))))
    family = lab.Family(q, 3, 2, 0, "S", "original-query", "original-index", "epoch-1", 8,
                        ((c0, c1, c2),), (lab.View(0, 1, 64, (0, 1), "nearest"),
                                         lab.View(0, -1, 1024, (0, 1), "odd_lut")))
    keys, errors = make_keys(q, radix, source, target, 2, skip, rng)
    epoch = lab.OwnerApprovedEpoch(lab.family_anchor(family), "fresh-T", 1, lab.TERNARY_CBD, keys)
    return family, epoch, source, target, errors


def private_phase_check(family, epoch, source, target, errors):
    """Independent integer phase diagnostic, not the public verifier."""
    certificate = lab.build(family, epoch)
    for view, cert in zip(family.views, certificate.views, strict=True):
        approved = lab.approve_view(family, epoch, view)
        all_digits, residual = packed.decomposition(approved)
        families = (all_digits[0], all_digits[1][epoch.keys.skipped_c2_levels:])
        key_error = add(*(multiply(d, e) for ds, es in zip(families, errors, strict=True)
                          for d, e in zip(ds, es, strict=True)))
        original = add(approved.components[0], multiply(approved.components[1], source),
                       multiply(approved.components[2], multiply(source, source)))
        hidden = multiply(residual, multiply(source, source))
        before_round = add(cert.output[0], multiply(cert.output[1], target))
        assert all((after + h - old - e) % family.q == 0 for after, h, old, e in
                   zip(before_round, hidden, original, key_error, strict=True))
        after_round = add(cert.rounded[0], multiply(cert.rounded[1], target))
        drift = tuple(tuple(family.q * packed.round_integer(x, family.q, view.target) - view.target * x
                            for x in poly) for poly in cert.output)
        z = add(multiply(drift[1], target), tuple(view.target * e for e in key_error))
        numerator = add(drift[0], z, tuple(-view.target * h for h in hidden))
        for event in cert.events:
            k = event.coefficient
            assert (family.q * after_round[k] - view.target * original[k] - numerator[k]) % (family.q * view.target) == 0
            assert abs(z[k]) <= event.deterministic_bound
            assert abs(hidden[k]) <= event.source_residual_bound
    return certificate


def test_independent_signed_rows_reproduce_all_ring_coefficients():
    for n in (2, 4, 8):
        p = tuple(range(-n // 2, n // 2))
        for prefix in range(1, n + 1):
            for secret_short in product((-1, 0, 1), repeat=min(prefix, 4)):
                secret = (*secret_short, *((0,) * (n - len(secret_short))))
                out = multiply(p, secret)
                for k in range(n):
                    assert sum(w * s for w, s in zip(lab.row_weights(p, k, prefix), secret[:prefix], strict=True)) == out[k]


@pytest.mark.parametrize("law,eta", (("ternary", 1), ("centered_binomial", 1), ("centered_binomial", 2)))
def test_exact_distribution_matches_entire_coin_support(law, eta):
    weights = (1, -2, 3)
    counts = Counter()
    if law == "ternary":
        samples = tuple(product((-1, 0, 1), repeat=3))
        for values in samples:
            counts[sum(w * x for w, x in zip(weights, values, strict=True))] += 1
    else:
        samples = tuple(product((0, 1), repeat=6 * eta))
        for bits in samples:
            values = tuple(sum(bits[2 * eta * i + 2 * j] - bits[2 * eta * i + 2 * j + 1]
                               for j in range(eta)) for i in range(3))
            counts[sum(w * x for w, x in zip(weights, values, strict=True))] += 1
    got, denominator = lab.exact_distribution(weights, law=law, eta=eta)
    assert got == counts and sum(got.values()) == denominator == len(samples)


def test_exact_ternary_and_CBD_tails_at_registered_thresholds():
    for weights, eta, kappa, events in product(((1,) * 16, (2, -3, 7, -9), (0,) * 4), (1, 2), (1, 8, 32), (1, 8)):
        twice = 2 * sum(w * w for w in weights)
        threshold = lab.tail_threshold(twice, kappa, events)
        counts, denominator = lab.exact_distribution(weights)
        assert Fraction(sum(count for value, count in counts.items() if abs(value) > threshold), denominator) <= Fraction(1, 2**kappa * events)
        threshold = lab.tail_threshold(eta * sum(w * w for w in weights), kappa, events)
        counts, denominator = lab.exact_distribution(weights, law="centered_binomial", eta=eta)
        assert Fraction(sum(count for value, count in counts.items() if abs(value) > threshold), denominator) <= Fraction(1, 2**kappa * events)


def test_post_key_sign_choice_is_not_a_single_fixed_weight_event():
    n, kappa = 32, 8
    threshold = lab.tail_threshold(2 * n, kappa, 1)
    fixed, denominator = lab.exact_distribution((1,) * n)
    fixed_tail = Fraction(sum(c for v, c in fixed.items() if abs(v) > threshold), denominator)
    adaptive_tail = Fraction(sum(comb(n, k) * 2**k for k in range(threshold + 1, n + 1)), 3**n)
    assert fixed_tail <= Fraction(1, 2**kappa) < adaptive_tail
    # A revealing toy body lets w follow T. It is not a cryptanalytic attack.
    assert lab.tail_threshold(2 * n, kappa, 2**n) >= n


def test_shared_random_variables_must_be_aggregated_before_squaring():
    naive_squares = sum(x * x for x in (1, 1, 1, 1))
    aggregate = lab.aggregate_weights((("same-error", 1),) * 4)
    assert aggregate == (("same-error", 4),)
    assert sum(w * w for _, w in aggregate) == 16 > naive_squares
    assert lab.aggregate_weights((("same-error", 3), ("same-error", -3))) == ()


def test_whole_ring_phase_and_original_source_residual_are_separate():
    for skip in (0, 1, 2):
        family, epoch, source, target, errors = fixture(skip=skip)
        certificate = private_phase_check(family, epoch, source, target, errors)
        assert certificate.whole_family_events == 4
        assert lab.verify_and_release(family, epoch, certificate, (0,), lambda _: "public-control") == "public-control"
        assert (certificate.views[0].events[0].source_residual_bound == 0) == (skip == 0)


def test_mask_and_proxy_ignore_key_bodies_but_epoch_binding_does_not():
    family, epoch, _, _, _ = fixture()
    good = lab.build(family, epoch)
    changed_rows = tuple(tuple((a, tuple((v + 1) % family.q for v in b)) for a, b in rows)
                         for rows in epoch.keys.values)
    changed = replace(epoch, keys=replace(epoch.keys, values=changed_rows))
    other = lab.build(family, changed)
    for old_view, new_view in zip(good.views, other.views, strict=True):
        assert old_view.output[1] == new_view.output[1]
        for a, b in zip(old_view.events, new_view.events, strict=True):
            assert a.twice_proxy == b.twice_proxy and a.statistical_bound == b.statistical_bound
    assert good.epoch_anchor != other.epoch_anchor
    with pytest.raises(ValueError):
        lab.verify_and_release(family, changed, good, (0,), lambda _: pytest.fail("private work"))


@pytest.mark.parametrize("field", ("family_anchor", "epoch_anchor", "whole_family_events", "views"))
def test_root_or_family_framing_corruption_rejects_before_callback(field):
    family, epoch, _, _, _ = fixture()
    cert = lab.build(family, epoch)
    value = {"family_anchor": "wrong", "epoch_anchor": "wrong", "whole_family_events": True,
             "views": cert.views[:-1]}[field]
    with pytest.raises(ValueError):
        lab.verify_and_release(family, epoch, replace(cert, **{field: value}), (0,), lambda _: pytest.fail("private work"))


@pytest.mark.parametrize("field", ("twice_proxy", "statistical_bound", "deterministic_bound", "body_bound",
                                   "source_residual_bound", "total_bound", "coefficient", "sufficient"))
def test_every_event_field_is_recomputed_before_callback(field):
    family, epoch, _, _, _ = fixture()
    cert = lab.build(family, epoch)
    event = cert.views[0].events[0]
    changed = replace(event, **{field: not event.sufficient if field == "sufficient" else getattr(event, field) + 1})
    view = replace(cert.views[0], events=(changed, *cert.views[0].events[1:]))
    bad = replace(cert, views=(view, *cert.views[1:]))
    with pytest.raises(ValueError):
        lab.verify_and_release(family, epoch, bad, (0,), lambda _: pytest.fail("private work"))


@pytest.mark.parametrize("field", ("original_query_root", "original_index_root", "epoch_id", "source_key_id", "source_phase_bound", "source_prefix"))
def test_original_source_and_context_substitution_cannot_reuse_epoch(field):
    family, epoch, _, _, _ = fixture()
    value = 1 if field in ("source_phase_bound", "source_prefix") else "replacement"
    changed = replace(family, **{field: value})
    with pytest.raises(ValueError):
        lab.build(changed, epoch)


@pytest.mark.parametrize("selected", ((), (0, 0), (True,), (2,), ([],)))
def test_unapproved_subset_rejected(selected):
    family, epoch, _, _, _ = fixture()
    with pytest.raises(ValueError):
        lab.verify_and_release(family, epoch, lab.build(family, epoch), selected, lambda _: pytest.fail("private work"))


def test_finite_odd_LUT_budget_includes_grid_quantization():
    family, epoch, _, _, _ = fixture()
    view = lab.View(0, 1, 8, (0,), "odd_lut")
    changed = replace(family, views=(view,))
    epoch = replace(epoch, family_anchor=lab.family_anchor(changed))
    cert = lab.build(changed, epoch)
    assert lab.budget(changed, view) < 0 < Fraction(view.target * family.q, 4 * family.t)
    with pytest.raises(ValueError, match="insufficient"):
        lab.verify_and_release(changed, epoch, cert, (0,), lambda _: pytest.fail("private work"))


def test_small_context_does_not_accept_an_unpaid_residual():
    family, epoch, source, target, errors = fixture(q=101, skip=2)
    cert = private_phase_check(family, epoch, source, target, errors)
    assert any(not e.sufficient for e in cert.views[0].events)
    with pytest.raises(ValueError, match="insufficient"):
        lab.verify_and_release(family, epoch, cert, (0,), lambda _: pytest.fail("private work"))


@pytest.mark.parametrize("law", ("gaussian", "binary", "fixed-weight", "posterior-ternary"))
def test_different_secret_or_error_laws_are_not_interchangeable(law):
    family, epoch, _, _, _ = fixture()
    with pytest.raises(ValueError):
        lab.build(family, replace(epoch, law=law))


def test_fresh_OS_coin_generation_is_a_separate_trusted_premise():
    family, epoch, source, target, errors = fixture(rng=SystemRandom())
    cert = private_phase_check(family, epoch, source, target, errors)
    assert cert.family_anchor == lab.family_anchor(family)
    # This is an arithmetic differential, not proof that a submitted epoch's
    # coins/provenance or timing were honest. No secret is in the certificate.


@pytest.mark.parametrize("bad", ((), ((1,),), ((1, 2, 3),), (((), (), ()),)))
def test_malformed_source_components_have_bounded_rejection(bad):
    family, _, _, _, _ = fixture()
    with pytest.raises(ValueError):
        lab.validate_family(replace(family, sources=bad))
