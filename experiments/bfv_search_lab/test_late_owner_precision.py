"""Independent exact fixed-key, phase, ordering and framing controls for E95."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from fractions import Fraction
from itertools import product

import pytest

from experiments.bfv_search_lab import committed_precision_epoch as epoch
from experiments.bfv_search_lab import late_owner_precision as lab
from experiments.bfv_search_lab import partial_packed_switch as switch
from experiments.bfv_search_lab.test_committed_precision_epoch import fixture as old_fixture
from experiments.bfv_search_lab.test_partial_packed_switch import add, multiply


def fixture(*, skip=0):
    family, old, source, target, errors = old_fixture(skip=skip)
    policy = lab.OwnerKeys("reused-T", 1, 1, old.keys)
    mask, error, zero_id = (31, 77), (1, -1), b"test-zero-id-001"
    assert len(zero_id) == 16
    body = tuple((e - x) % family.q for e, x in zip(error, multiply(mask, target), strict=True))
    zero = lab.OwnerZero(epoch.family_anchor(family), lab.keys_anchor(policy), zero_id.hex(), lab.LAW, body, mask)
    ledger = lab.OwnerLedger(policy, 8)
    ledger.reserve(family, policy, zero_id)
    return family, policy, zero, ledger, source, target, errors, error


def corruption_cases(certificate):
    for field in ("family_anchor", "keys_anchor", "zero_anchor"):
        yield replace(certificate, **{field: "wrong"})
    yield replace(certificate, whole_family_events=True)
    yield replace(certificate, views=certificate.views[:-1])
    for vi, view in enumerate(certificate.views):
        for field in ("switched", "added", "rounded"):
            for pi, poly in enumerate(getattr(view, field)):
                for ci, value in enumerate(poly):
                    changed = [list(p) for p in getattr(view, field)]
                    changed[pi][ci] = value + 1
                    updated = replace(view, **{field: tuple(tuple(p) for p in changed)})
                    yield replace(certificate, views=(*certificate.views[:vi], updated, *certificate.views[vi+1:]))
        for ei, event in enumerate(view.events):
            for field in event.__dataclass_fields__:
                value = not event.sufficient if field == "sufficient" else getattr(event, field) + 1
                updated = replace(view, events=(*view.events[:ei], replace(event, **{field: value}), *view.events[ei+1:]))
                yield replace(certificate, views=(*certificate.views[:vi], updated, *certificate.views[vi+1:]))


def private_phase_check(family, policy, zero, source, target, errors, zero_error):
    """Independent integer oracle; private witnesses never enter the certificate."""
    certificate = lab.build(family, policy, zero)
    for view, cert in zip(family.views, certificate.views, strict=True):
        approved = lab.approve(family, policy, view)
        digits, residual = switch.decomposition(approved)
        retained = (digits[0], digits[1][policy.keys.skipped_c2_levels:])
        key_error = add(*(multiply(d, e) for ds, es in zip(retained, errors, strict=True)
                          for d, e in zip(ds, es, strict=True)))
        original = add(approved.components[0], multiply(approved.components[1], source),
                       multiply(approved.components[2], multiply(source, source)))
        hidden = multiply(residual, multiply(source, source))
        before = add(cert.added[0], multiply(cert.added[1], target))
        assert all((new + h - old - k - e) % family.q == 0
                   for new, h, old, k, e in zip(before, hidden, original, key_error, zero_error, strict=True))
        drift = tuple(tuple(family.q * switch.round_integer(x, family.q, view.target) - view.target * x
                            for x in poly) for poly in cert.added)
        z = add(multiply(drift[1], target), tuple(view.target * e for e in zero_error))
        numerator = add(drift[0], z, tuple(view.target * (k - h)
                                         for k, h in zip(key_error, hidden, strict=True)))
        after = add(cert.rounded[0], multiply(cert.rounded[1], target))
        for event in cert.events:
            i = event.coefficient
            assert (family.q * after[i] - view.target * original[i] - numerator[i]) % (family.q * view.target) == 0
            assert abs(z[i]) <= event.deterministic_bound
            assert abs(key_error[i]) <= event.old_key_error_bound
            assert abs(hidden[i]) <= event.source_residual_bound
    return certificate


@pytest.mark.parametrize("q", (3, 5, 7, 9, 15, 31))
def test_odd_coprime_residues_are_uniform_for_every_offset(q):
    for target in (2, 4, 8, 16, 32):
        expected = Counter(range(-(q // 2), q // 2 + 1))
        for offset in range(q):
            residues = Counter(lab.rounding_error((offset + rho) % q, q, target) for rho in range(q))
            assert residues == expected and sum(k * v for k, v in residues.items()) == 0


def test_even_upward_ties_and_noncoprime_target_break_registered_permutation():
    residues = tuple(4 * switch.round_integer(x, 4, 2) - 2 * x for x in range(4))
    assert residues == (0, 2, 0, 2) and sum(residues) != 0
    residues = tuple(9 * switch.round_integer(x, 9, 3) - 3 * x for x in range(9))
    assert Counter(residues) == Counter({-3: 3, 0: 3, 3: 3})
    with pytest.raises(ValueError):
        lab.rounding_error(1, 4, 2)
    with pytest.raises(ValueError):
        lab.rounding_error(1, 9, 3)


def test_fixed_target_supports_do_not_need_a_random_secret_law():
    for target in product((-1, 0, 1), repeat=2):
        for offset in product(range(5), repeat=2):
            # The offset may be an arbitrary function of key/body history.
            counts = Counter()
            for rho in product(range(5), repeat=2):
                drift = tuple(lab.rounding_error((a + r) % 5, 5, 4) for a, r in zip(offset, rho, strict=True))
                counts[multiply(drift, target)[0]] += 1
            assert sum(v * c for v, c in counts.items()) == 0
            assert sum(v * v * c for v, c in counts.items()) == 50 * sum(x*x for x in target)


def test_stages_and_duplicate_views_share_random_variables():
    pairs = tuple((lab.rounding_error(x, 3, 2), lab.rounding_error(x, 3, 4)) for x in range(3))
    assert all(x == -y for x, y in pairs)
    assert sum(x * y for x, y in pairs) == -2
    # For a duplicated event, union probability is p, not independent 1-(1-p)^2.
    p = Fraction(2, 3)
    assert p != 1 - (1 - p)**2


def exact_uniform_error_tail(n=128, kappa=8):
    counts = Counter({0: 1})
    for _ in range(n):
        updated = Counter()
        for v, c in counts.items():
            for x in (-1, 0, 1):
                updated[v + x] += c
        counts = updated
    threshold = lab.precision(3, 2, n, 1, kappa, 1)[1]
    mass = sum(c * w for v, c in counts.items() for e, w in ((-1, 1), (0, 2), (1, 1))
               if abs(v + 2 * e) > threshold)
    return threshold, Fraction(mass, 4 * 3**n)


def test_registered_uniform_CBD_tail_is_nonzero_and_below_target():
    threshold, tail = exact_uniform_error_tail()
    assert threshold == 49 and 0 < tail <= Fraction(1, 256)


def test_post_rho_or_reused_rho_offset_can_force_every_rounding_error():
    n, q, target = 1024, 5, 4
    rho = tuple(i % q for i in range(n))
    chosen_x = next(x for x in range(q) if lab.rounding_error(x, q, target) == q // 2)
    offsets = tuple((chosen_x - r) % q for r in rho)
    errors = tuple(lab.rounding_error((a + r) % q, q, target) for a, r in zip(offsets, rho, strict=True))
    threshold = lab.precision(q, target, n, 1, 8, 1)[1]
    assert sum(errors) == n * (q // 2) > threshold


def test_public_seed_pair_cannot_be_replaced_by_independent_uniform_mask():
    # A toy deterministic expansion has a perfectly testable public relation.
    seeded_pairs = {(seed, tuple((seed + i) % 5 for i in range(2))) for seed in range(5)}
    iid_pairs = tuple(product(range(5), product(range(5), repeat=2)))
    assert len(seeded_pairs) == 5 and sum(pair in seeded_pairs for pair in iid_pairs) == 5
    assert Fraction(5, len(iid_pairs)) == Fraction(1, 25)


@pytest.mark.parametrize("skip", (0, 1, 2))
def test_full_mixed_phase_and_public_certificate_with_reused_keys(skip):
    family, policy, zero, ledger, source, target, errors, error = fixture(skip=skip)
    cert = private_phase_check(family, policy, zero, source, target, errors, error)
    assert cert.whole_family_events == 4
    # The nearest selected view is deliberately sufficient in this tiny fixture.
    assert lab.verify_and_consume(family, policy, zero, cert, (0,), ledger, lambda _: "checked") == "checked"
    with pytest.raises(RuntimeError):
        lab.verify_and_consume(family, policy, zero, cert, (0,), ledger, lambda _: "replay")


def test_all_public_certificate_corruptions_reject_before_callback():
    family, policy, zero, ledger, *_ = fixture()
    cert, calls = lab.build(family, policy, zero), []
    bads = tuple(corruption_cases(cert))
    assert len(bads) == 65
    for bad in bads:
        with pytest.raises(ValueError):
            lab.verify_and_consume(family, policy, zero, bad, (0,), ledger, calls.append)
    assert not calls
    # Rejections do not create a new noise draw or spend a second lifetime slot.
    lab.verify_and_consume(family, policy, zero, cert, (0,), ledger, calls.append)
    assert len(calls) == 1


@pytest.mark.parametrize("change", ("original_query_root", "original_index_root", "epoch_id", "source_phase_bound"))
def test_wrong_original_binding_rejects(change):
    family, policy, zero, ledger, *_ = fixture()
    value = 1 if change == "source_phase_bound" else "other"
    with pytest.raises(ValueError):
        lab.build(replace(family, **{change: value}), policy, zero)


@pytest.mark.parametrize("field", ("family_anchor", "keys_anchor", "zero_id", "law", "body", "mask"))
def test_wrong_owner_zero_or_framing_rejects(field):
    family, policy, zero, ledger, *_ = fixture()
    changed = (True, *getattr(zero, field)[1:]) if field in ("body", "mask") else "wrong"
    with pytest.raises(ValueError):
        lab.build(family, policy, replace(zero, **{field: changed}))


def test_public_shape_is_not_a_proof_of_zero_plaintext_or_honest_coins():
    family, policy, zero, *_ = fixture()
    wrong = replace(zero, body=tuple((x + 20) % family.q for x in zero.body))
    assert lab.validate_zero(family, policy, wrong) == (2, 4)
    # Hence the verifier MUST take an authenticated trusted owner zero, not let
    # the server supply its own claimed owner packet and self-consistent proof.
    assert lab.zero_anchor(wrong) != lab.zero_anchor(zero)


def test_sampling_follows_reservation_and_never_returns_private_errors(monkeypatch):
    family, policy, _, _, _, target, *_ = fixture()
    ledger = lab.OwnerLedger(policy, 1)
    nonce, calls = b"test-zero-id-002", []
    def uniform(q):
        assert nonce.hex() in ledger._issued
        calls.append(q)
        return 2
    monkeypatch.setattr(lab.secrets, "randbelow", uniform)
    monkeypatch.setattr(lab.secrets, "randbits", lambda _: 0)
    zero = lab.generate_owner_zero(family, policy, ledger, nonce, target)
    assert calls == [family.q] * 2
    assert all(x % family.q == 0 for x in add(zero.body, multiply(zero.mask, target)))
    assert set(zero.__dataclass_fields__) == {"family_anchor", "keys_anchor", "zero_id", "law", "body", "mask"}


def test_abandoned_generation_exhaustion_and_callback_failure_burn_slots():
    family, policy, zero, _, *_ = fixture()
    ledger = lab.OwnerLedger(policy, 1)
    ledger.reserve(family, policy, bytes.fromhex(zero.zero_id))
    with pytest.raises(RuntimeError):
        ledger.reserve(family, policy, b"test-zero-id-002")
    def failed(_):
        raise LookupError("opaque callback failed")
    with pytest.raises(LookupError):
        lab.verify_and_consume(family, policy, zero, lab.build(family, policy, zero), (0,), ledger, failed)
    with pytest.raises(RuntimeError):
        ledger.consume(zero)


def test_reservation_is_atomic_for_the_same_owner_zero():
    family, policy, zero, _, *_ = fixture()
    ledger = lab.OwnerLedger(policy, 8)
    def reserve(_):
        try:
            ledger.reserve(family, policy, bytes.fromhex(zero.zero_id))
        except RuntimeError:
            return False
        return True
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(reserve, range(16))) == 1


@pytest.mark.parametrize("args", ((True, 4, 2, 1, 8, 1), (5, 3, 2, 1, 8, 1),
                                 (5, 4, True, 1, 8, 1), (5, 4, 2, True, 8, 1),
                                 (5, 4, 2, 1, True, 1), (5, 4, 2, 1, 8, True)))
def test_noncanonical_law_parameters_reject(args):
    with pytest.raises(ValueError):
        lab.precision(*args)
