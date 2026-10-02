"""Independent scalar, phase, exact-tail, provenance and lifecycle controls."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from fractions import Fraction
from itertools import product
from math import comb

import pytest

from experiments.bfv_search_lab import committed_precision_epoch as epoch
from experiments.bfv_search_lab import owner_bound_rounding as lab
from experiments.bfv_search_lab import partial_packed_switch as switch
from experiments.bfv_search_lab.test_committed_precision_epoch import fixture as old_fixture
from experiments.bfv_search_lab.test_partial_packed_switch import add, multiply


def literal_round(x, q, b, u):
    # Independent integer inequality, without production divmod/remainder calls.
    quotient = b*x // q
    return quotient + (q*u < q*b*x-q*q*quotient)


def fixture(*, skip=0):
    family, old, source, target, errors = old_fixture(skip=skip)
    policy = lab.OwnerKeys("reused-T", 1, old.keys)
    coin_id = b"owner-coins-0001"
    assert len(coin_id) == 16
    coins = lab.OwnerCoins(epoch.family_anchor(family), lab.keys_anchor(policy), coin_id.hex(),
                           lab.LAW, (31, 77), (101, 211))
    ledger = lab.OwnerLedger(policy, 8)
    ledger.reserve(family, policy, coin_id)
    ledger.bind(family, policy, coins)
    return family, policy, coins, ledger, source, target, errors


def corruption_cases(cert):
    for field in ("family_anchor", "keys_anchor", "coins_anchor"):
        yield replace(cert, **{field: "wrong"})
    yield replace(cert, whole_family_events=True)
    yield replace(cert, views=cert.views[:-1])
    for vi, view in enumerate(cert.views):
        for field in ("switched", "rounded"):
            for pi, poly in enumerate(getattr(view, field)):
                for ci, value in enumerate(poly):
                    changed = [list(p) for p in getattr(view, field)]
                    changed[pi][ci] = value+1
                    updated = replace(view, **{field: tuple(tuple(p) for p in changed)})
                    yield replace(cert, views=(*cert.views[:vi], updated, *cert.views[vi+1:]))
        for ei, event in enumerate(view.events):
            for field in event.__dataclass_fields__:
                value = not event.sufficient if field == "sufficient" else getattr(event, field)+1
                updated = replace(view, events=(*view.events[:ei], replace(event, **{field: value}), *view.events[ei+1:]))
                yield replace(cert, views=(*cert.views[:vi], updated, *cert.views[vi+1:]))


def private_phase_check(family, policy, coins, source, target, errors):
    certificate = lab.build(family, policy, coins)
    for view, cert in zip(family.views, certificate.views, strict=True):
        approved = lab.approve(family, policy, view)
        ds, residual = switch.decomposition(approved)
        retained = (ds[0], ds[1][policy.keys.skipped_c2_levels:])
        key_error = add(*(multiply(d, e) for digits, es in zip(retained, errors, strict=True)
                          for d, e in zip(digits, es, strict=True)))
        original = add(approved.components[0], multiply(approved.components[1], source),
                       multiply(approved.components[2], multiply(source, source)))
        hidden = multiply(residual, multiply(source, source))
        before = add(cert.switched[0], multiply(cert.switched[1], target))
        assert all((a-o-k+h) % family.q == 0 for a, o, k, h in zip(before, original, key_error, hidden, strict=True))
        us = tuple(tuple(u if view.sign == 1 else family.q-1-u for u in poly)
                   for poly in (coins.body, coins.mask))
        raw = tuple(tuple(literal_round(x, family.q, view.target, u) for x, u in zip(poly, coin, strict=True))
                    for poly, coin in zip(cert.switched, us, strict=True))
        assert tuple(tuple(x % view.target for x in poly) for poly in raw) == cert.rounded
        drift = tuple(tuple(family.q*r-view.target*x for r, x in zip(rs, xs, strict=True))
                      for rs, xs in zip(raw, cert.switched, strict=True))
        phase_error = add(drift[0], multiply(drift[1], target))
        after = add(cert.rounded[0], multiply(cert.rounded[1], target))
        for event in cert.events:
            i = event.coefficient
            numerator = phase_error[i]+view.target*(key_error[i]-hidden[i])
            assert (family.q*after[i]-view.target*original[i]-numerator) % (family.q*view.target) == 0
            assert abs(phase_error[i]) <= event.deterministic_bound
            assert abs(key_error[i]) <= event.old_key_error_bound and abs(hidden[i]) <= event.source_residual_bound
    return certificate


@pytest.mark.parametrize("q", (2, 3, 4, 5, 7, 9, 15))
def test_exact_unbiased_scalar_law_variance_and_signed_coupling(q):
    for b, x in product((2, 4, 8, 16, 32), range(q)):
        errors = []
        for u in range(q):
            got = lab.round_integer(x, q, b, u)
            assert got == literal_round(x, q, b, u)
            error = q*got-b*x
            errors.append(error)
            opposite = lab.round_integer(-x % q, q, b, q-1-u)
            assert (opposite+got) % b == 0
            assert q*opposite-b*(-x % q) == -error
        r = b*x % q
        assert sum(errors) == 0 and sum(e*e for e in errors) == q*r*(q-r)
        assert max(map(abs, errors)) < q


def test_unchanged_sign_coins_and_reused_coefficients_do_not_have_the_claimed_law():
    assert (lab.round_integer(1, 5, 4, 0)+lab.round_integer(4, 5, 4, 0)) % 4 != 0
    # One coin copied into every coefficient forces a non-negligible whole error.
    threshold = lab.uniform_precision(4, 128, 8, 1)[1]
    failures = [abs(128*(4*literal_round(1, 4, 2, u)-2)) > threshold for u in range(4)]
    assert all(failures)


def exact_symmetric_tail():
    threshold = lab.uniform_precision(4, 128, 8, 1)[1]
    numerator = sum(comb(129, k) for k in range(130) if abs(2*(2*k-129)) > threshold)
    return threshold, Fraction(numerator, 2**129)


def exact_post_coin_tail():
    # Choose r=u+1, except u=4 gives r0: errors4,3,2,1,0 after input postselection.
    counts = Counter({0: 1})
    for _ in range(64):
        updated = Counter()
        for value, mass in counts.items():
            for error in range(5):
                updated[value+error] += mass
        counts = updated
    threshold = lab.uniform_precision(5, 64, 8, 1)[1]
    return threshold, Fraction(sum(mass for v, mass in counts.items() if v > threshold), 5**64)


def test_registered_exact_nonzero_tail_and_postselection_falsifier():
    threshold, tail = exact_symmetric_tail()
    assert threshold == 97 and 0 < tail <= Fraction(1, 256)
    threshold, invalid_tail = exact_post_coin_tail()
    assert threshold == 86 and invalid_tail > Fraction(1, 256)
    for u in range(5):
        r = u+1 if u < 4 else 0
        x = r*4 % 5  # inverse of B4 mod Q5.
        assert 5*literal_round(x, 5, 4, u)-4*x == 4-u


def test_public_remainder_variance_is_fixed_input_information_and_nonnegative():
    family, policy, coins, *_ = fixture()
    cert = lab.build(family, policy, coins)
    for view, output in zip(family.views, cert.views, strict=True):
        for event in output.events:
            remainders = [view.target*output.switched[0][event.coefficient] % family.q]
            remainders += [view.target*output.switched[1][(event.coefficient-i) % 2] % family.q for i in range(2)]
            assert event.variance == sum(r*(family.q-r) for r in remainders)
            assert event.active_terms == sum(r != 0 for r in remainders)
            assert event.statistical_bound <= event.active_hoeffding_bound <= event.uniform_bound
    changed = replace(coins, body=(family.q-1, 0), mask=(family.q-1, 0))
    cert2 = lab.build(family, policy, changed)
    for a, b in zip(cert.views, cert2.views, strict=True):
        assert [(e.variance, e.twice_proxy, e.statistical_bound) for e in a.events] == [
            (e.variance, e.twice_proxy, e.statistical_bound) for e in b.events]


def test_zero_remainders_have_zero_rounding_threshold():
    family, policy, coins, *_ = fixture()
    family = replace(family, sources=(((0, 0), (0, 0), (0, 0)),))
    coins = replace(coins, family_anchor=epoch.family_anchor(family))
    cert = lab.build(family, policy, coins)
    assert all(e.variance == e.statistical_bound == e.deterministic_bound == 0
               for v in cert.views for e in v.events)


@pytest.mark.parametrize("skip", (0, 1, 2))
def test_mixed_phase_and_selected_family_release_once(skip):
    family, policy, coins, ledger, source, target, errors = fixture(skip=skip)
    cert = private_phase_check(family, policy, coins, source, target, errors)
    assert lab.verify_and_consume(family, policy, coins, cert, (0,), ledger, lambda _: "checked") == "checked"
    with pytest.raises(RuntimeError):
        lab.verify_and_consume(family, policy, coins, cert, (0,), ledger, lambda _: "replay")


def test_all_public_certificate_corruptions_reject_before_callback():
    family, policy, coins, ledger, *_ = fixture()
    cert, calls = lab.build(family, policy, coins), []
    bads = tuple(corruption_cases(cert))
    assert len(bads) == 77
    for bad in bads:
        with pytest.raises(ValueError):
            lab.verify_and_consume(family, policy, coins, bad, (0,), ledger, calls.append)
    assert not calls
    lab.verify_and_consume(family, policy, coins, cert, (0,), ledger, calls.append)
    assert len(calls) == 1


@pytest.mark.parametrize("field", ("family_anchor", "keys_anchor", "coin_id", "law", "body", "mask"))
def test_malformed_owner_coins_reject(field):
    family, policy, coins, *_ = fixture()
    changed = (True, *getattr(coins, field)[1:]) if field in ("body", "mask") else "wrong"
    with pytest.raises(ValueError):
        lab.build(family, policy, replace(coins, **{field: changed}))


def test_same_id_packet_replacement_rejects_even_self_consistent_arithmetic():
    family, policy, coins, ledger, *_ = fixture()
    other = replace(coins, body=(family.q-1, 0))
    with pytest.raises(RuntimeError):
        lab.verify_and_consume(family, policy, other, lab.build(family, policy, other), (0,), ledger, lambda _: None)
    lab.verify_and_consume(family, policy, coins, lab.build(family, policy, coins), (0,), ledger, lambda _: None)


@pytest.mark.parametrize("selection", ((), (True,), (0, 0), (99,), ([0],)))
def test_malformed_selected_events_reject(selection):
    family, policy, coins, ledger, *_ = fixture()
    with pytest.raises(ValueError):
        lab.verify_and_consume(family, policy, coins, lab.build(family, policy, coins), selection, ledger, lambda _: None)


def test_sampling_follows_reservation_binds_packet_and_has_no_private_witness(monkeypatch):
    family, policy, _, *_ = fixture()
    ledger, nonce, calls = lab.OwnerLedger(policy, 1), b"owner-coins-0002", []
    def uniform(q):
        assert ledger._issued[nonce.hex()][1] is None
        calls.append(q)
        return 2
    monkeypatch.setattr(lab.secrets, "randbelow", uniform)
    coins = lab.generate_owner_coins(family, policy, ledger, nonce)
    assert calls == [family.q]*4 and coins.body == coins.mask == (2, 2)
    assert ledger._issued[nonce.hex()][1] == lab.coins_anchor(coins)
    assert set(coins.__dataclass_fields__) == {"family_anchor", "keys_anchor", "coin_id", "law", "body", "mask"}


def test_failed_sampling_abandoned_slots_and_callback_failure_burn(monkeypatch):
    family, policy, coins, ledger, *_ = fixture()
    def fail(_):
        raise LookupError("diagnostic failure")
    abandoned = lab.OwnerLedger(policy, 1)
    monkeypatch.setattr(lab.secrets, "randbelow", fail)
    with pytest.raises(LookupError):
        lab.generate_owner_coins(family, policy, abandoned, b"owner-coins-0002")
    with pytest.raises(RuntimeError):
        abandoned.reserve(family, policy, b"owner-coins-0003")
    with pytest.raises(LookupError):
        lab.verify_and_consume(family, policy, coins, lab.build(family, policy, coins), (0,), ledger, fail)
    with pytest.raises(RuntimeError):
        ledger.consume(coins)


def test_one_reservation_and_one_callback_are_atomic():
    family, policy, coins, ledger, *_ = fixture()
    fresh = lab.OwnerLedger(policy, 8)
    def reserve(_):
        try:
            fresh.reserve(family, policy, bytes.fromhex(coins.coin_id))
        except RuntimeError:
            return False
        return True
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(reserve, range(16))) == 1
    cert = lab.build(family, policy, coins)
    def release(_):
        try:
            return lab.verify_and_consume(family, policy, coins, cert, (0,), ledger, lambda _: True)
        except RuntimeError:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(release, range(16))) == 1


def test_shape_or_public_seed_relation_does_not_prove_sampling():
    family, policy, coins, *_ = fixture()
    assert lab.validate_coins(family, policy, replace(coins, body=(0, 0), mask=(0, 0))) == (2, 4)
    pairs = tuple(product(range(5), product(range(5), repeat=2)))
    relation = {(seed, (seed, (seed+1) % 5)) for seed in range(5)}
    assert Fraction(sum(pair in relation for pair in pairs), len(pairs)) == Fraction(1, 25)


@pytest.mark.parametrize("args", ((True, 5, 4, 0), (5, 5, 4, 0), (1, True, 4, 0),
                                 (1, 5, True, 0), (1, 5, 4, True), (1, 5, 4, 5)))
def test_noncanonical_scalar_parameters_reject(args):
    with pytest.raises(ValueError):
        lab.round_integer(*args)
