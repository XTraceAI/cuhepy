"""Independent exact conditional phases/tails and missing-premise controls."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, replace
from fractions import Fraction
from itertools import product
from math import comb

import pytest

from experiments.bfv_search_lab import adaptive_query_phase as lab
from experiments.bfv_search_lab import committed_precision_epoch as probability
from experiments.bfv_search_lab.test_source_phase_budget import cyclic_reference


def policy(**changes):
    return replace(lab.Policy(2, 3, 1, 1, 1, 1, 1, "S", "index-1"), **changes)


def test_entire_fixed_index_query_message_and_CBD_support():
    bound = lab.derive(policy())
    for index, message, error in product(product(range(-4, 5), repeat=2),
                                         product((-1, 0, 1), repeat=2),
                                         product((-1, 0, 1), repeat=2)):
        actual = cyclic_reference(index, tuple(m + 3 * e for m, e in zip(message, error, strict=True)))
        mean = cyclic_reference(index, message)
        noise = cyclic_reference(index, error)
        assert actual == tuple(m + 3 * e for m, e in zip(mean, noise, strict=True))
        assert max(map(abs, mean)) <= bound.deterministic_mean
        assert max(map(abs, actual)) <= bound.all_support_phase
        assert sum((3 * x)**2 for x in index) <= bound.fresh_query_twice_proxy


def test_nontrivial_exact_conditional_tail_is_not_a_Gaussian_estimate():
    p = policy(n=16, kappa=8)
    b = lab.derive(p)
    counts, denominator = probability.exact_distribution((12,) * 16, law="centered_binomial", eta=1)
    tail = Fraction(sum(c for v, c in counts.items() if abs(v) > b.fresh_query_tail), denominator)
    assert 0 < tail <= Fraction(1, 2**p.kappa * b.events)
    assert b.whole_lifetime_phase < b.all_support_phase


def test_post_error_index_choice_breaks_the_registered_law():
    p = policy(n=1024, kappa=8)
    b = lab.derive(p)
    # Revealing toy transcript, then index_i = 4*sign(E_(k-i)) with the
    # negacyclic sign corrected. It yields 12*sum|E_i| for eta1 CBD.
    cutoff = b.whole_lifetime_phase // 12
    failure = Fraction(sum(comb(p.n, k) for k in range(cutoff + 1, p.n + 1)), 2**p.n)
    assert failure > Fraction(1, 2**p.kappa)
    assert cutoff < p.n // 2


def test_repeated_query_error_requires_aggregated_square_not_N_squares():
    n, weight = 32, 12
    iid_proxy, repeated_proxy = n * weight**2, (n * weight)**2
    threshold = probability.tail_threshold(iid_proxy, 8, 1)
    # eta1 error has absolute value1 with probability1/2.
    assert threshold < n * weight
    assert Fraction(1, 2) > Fraction(1, 256)
    assert repeated_proxy == n * iid_proxy


def test_adaptive_query_message_does_not_need_to_be_independent_of_the_index():
    # Each query message is selected to align with the complete fixed index.
    # Mean is bounded deterministically; only errors enter the MGF.
    b = lab.derive(policy())
    for index in product(range(-4, 5), repeat=2):
        message = tuple(1 if x >= 0 else -1 for x in (index[0], -index[1]))
        assert abs(cyclic_reference(index, message)[0]) <= b.deterministic_mean


@pytest.mark.parametrize("field", tuple(f.name for f in fields(lab.Bound)))
def test_all_public_bound_fields_recomputed(field):
    p, b = policy(), lab.derive(policy())
    with pytest.raises(ValueError):
        lab.verify(p, replace(b, **{field: getattr(b, field) + 1}))
    with pytest.raises(ValueError):
        lab.verify(p, replace(b, **{field: True}))


def test_fresh_query_lifetime_is_not_replenished_by_failure_or_replay():
    p, qid = policy(), bytes(16)
    ledger = lab.FreshQueryLedger(p)
    assert ledger.reserve(qid, p.source_key_id, p.index_epoch) == lab.derive(p)
    # No sampler/result is invoked; an abandoned reserved query remains burned.
    with pytest.raises(RuntimeError, match="already reserved"):
        ledger.reserve(qid, p.source_key_id, p.index_epoch)
    with pytest.raises(RuntimeError, match="exhausted"):
        ledger.reserve((1).to_bytes(16, "little"), p.source_key_id, p.index_epoch)


def test_concurrent_reservation_of_same_original_query_has_one_success():
    p, ledger = policy(max_fresh_queries=8), lab.FreshQueryLedger(policy(max_fresh_queries=8))
    def reserve(_):
        try:
            ledger.reserve(bytes(16), p.source_key_id, p.index_epoch)
            return True
        except RuntimeError:
            return False
    with ThreadPoolExecutor(max_workers=4) as executor:
        assert sum(executor.map(reserve, range(16))) == 1


@pytest.mark.parametrize("key,epoch,qid", (("wrong", "index-1", bytes(16)), ("S", "wrong", bytes(16)),
                                          ("S", "index-1", bytes(15)), ("S", "index-1", True)))
def test_wrong_epoch_or_query_does_not_consume_an_approved_slot(key, epoch, qid):
    p, ledger = policy(), lab.FreshQueryLedger(policy())
    with pytest.raises(ValueError):
        ledger.reserve(qid, key, epoch)
    ledger.reserve(bytes(16), p.source_key_id, p.index_epoch)


@pytest.mark.parametrize("changes", ({"replies": 0}, {"max_fresh_queries": True}, {"kappa": 0},
                                      {"index_epoch": ""}, {"source_key_id": False}, {"eta": 0}))
def test_invalid_lifetime_policy_rejected(changes):
    with pytest.raises(ValueError):
        lab.derive(policy(**changes))
