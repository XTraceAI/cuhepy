"""Independent complete source supports and phase/carry controls for E93A."""

from dataclasses import replace
from itertools import product

import pytest

from experiments.bfv_search_lab import source_phase_budget as lab


def cyclic_reference(a, b):
    # Coefficient-oriented reference, unlike the implementation's scatter.
    n = len(a)
    return tuple(sum(a[i] * b[(k - i) % n] * (1 if i <= k else -1)
                     for i in range(n)) for k in range(n))


def test_entire_N2_message_error_support_and_unit_error_identity():
    vectors = tuple(product((-1, 0, 1), repeat=2))
    bound = lab.envelope(2, 3, 1, 1)
    largest = 0
    for ml, mr, el, er in product(vectors, repeat=4):
        got = lab.expanded_phase((ml,), (mr,), (el,), (er,), 3)
        direct = cyclic_reference(tuple(m + 3 * e for m, e in zip(ml, el, strict=True)),
                                  tuple(m + 3 * e for m, e in zip(mr, er, strict=True)))
        assert got["centered_phase_before_possible_Q_wrap"] == direct
        assert max(map(abs, got["integer_plaintext_product"])) <= bound.message_products
        assert 3 * max(map(abs, got["message_error_cross"])) <= bound.message_error_products
        assert 9 * max(map(abs, got["error_product"])) <= bound.error_products
        assert max(map(abs, direct)) <= bound.centered_phase
        for phi, message in zip(direct, got["centered_plaintext"], strict=True):
            # Exact original phase/Q unit error; no Gaussian or relabeling.
            q, inverse = 101, pow(3, -1, 101)
            k = (3 * inverse - 1) // q
            assert (3 * (phi * inverse % q) - k * q * message - phi) % (3 * q) == 0
        largest = max(largest, *map(abs, direct))
    assert largest == bound.centered_phase == 32


@pytest.mark.parametrize("n,t,eta,columns", ((2, 3, 1, 1), (8, 17, 1, 2), (32, 193, 21, 3)))
def test_message_and_supported_noise_can_attain_the_public_envelope(n, t, eta, columns):
    m, e = t // 2, eta
    # All contributions to coefficient zero have the same sign.
    a, b = (m,) * n, (m,) + (-m,) * (n - 1)
    ea, eb = (e,) * n, (e,) + (-e,) * (n - 1)
    got = lab.expanded_phase((a,) * columns, (b,) * columns,
                             (ea,) * columns, (eb,) * columns, t)
    assert got["centered_phase_before_possible_Q_wrap"][0] == lab.envelope(n, t, eta, columns).centered_phase


def test_owner_public_key_and_phase_error_are_distinct():
    bound = lab.envelope(8, 17, 1, 3)
    assert bound.owner_fresh == 25
    assert bound.ordinary_public_key_fresh == 297
    example = lab.expanded_phase(((1, 1),), ((1, 1),), ((1, 1),), ((1, 1),), 3)
    assert example["integer_plaintext_product"] == (0, 2)
    assert example["plaintext_carry"] == (0, 1)
    assert example["BGV_error_including_plaintext_carry"] == (0, 11)
    assert example["centered_phase_before_possible_Q_wrap"] == (0, 32)
    assert example["centered_plaintext"] == (0, -1)


def test_changed_Q_recomputes_all_terms_without_claiming_security():
    bound = lab.envelope(16384, 1153, 21, 32)
    assert bound.centered_phase == bound.n * bound.columns * bound.owner_fresh**2
    q = lab.ntt_prime_above(bound.n, 2 * bound.centered_phase + 1)
    assert lab.source_margin(q, bound.t, bound.centered_phase, 1 << 64, domain="quarter") < 0
    assert lab.source_margin(q, bound.t, bound.centered_phase, 1 << 64, domain="half") > 0
    enlarged = lab.ntt_prime_above(bound.n, 6 * bound.centered_phase + 1)
    assert lab.source_margin(enlarged, bound.t, bound.centered_phase, 1 << 64, domain="quarter") > 0
    changed_eta = lab.envelope(bound.n, bound.t, 22, bound.columns)
    assert changed_eta != replace(bound, eta=22)


@pytest.mark.parametrize("values", ((0, 3, 1, 1), (3, 3, 1, 1), (2, 4, 1, 1),
                                   (2, 3, 0, 1), (2, 3, 1, 0), (True, 3, 1, 1)))
def test_invalid_source_context_rejected(values):
    with pytest.raises(ValueError):
        lab.envelope(*values)


@pytest.mark.parametrize("q,t,bound,target,domain", ((17, 3, 1, 4, "gaussian"),
                                                    (18, 3, 1, 4, "half"),
                                                    (17, 3, -1, 4, "half"),
                                                    (17, 3, 1, True, "half")))
def test_invalid_margin_context_rejected(q, t, bound, target, domain):
    with pytest.raises(ValueError):
        lab.source_margin(q, t, bound, target, domain=domain)
