"""Independent domain/carry and complete actual-API regressions for E113."""

from math import isqrt

import pytest
import msgpack

from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.one_prime_bounds import (
    Profile, byte_card, challenge_repetitions, complete_bound, maximum_digit_sum,
    prime64, prime_and_root,
)
from experiments.bfv_search_lab.one_prime_oracle import (
    evaluate_fixture, make_fixture, nearest_congruent, phase,
)


@pytest.mark.parametrize("bits", [1, 2, 3, 4, 5])
def test_exact_digit_extremum_by_exhaustive_words(bits):
    radix = 1 << bits
    for q in range(3, 250):
        expected = 0
        for word in range(q):
            rest, score = word, 0
            while rest:
                rest, digit = divmod(rest, radix)
                score += digit
            expected = max(expected, score)
        actual, witness = maximum_digit_sum(q, bits)
        assert actual == expected and 0 <= witness < q
        digits, rest = [], witness
        while rest:
            rest, digit = divmod(rest, radix)
            digits.append(digit)
        assert sum(digits) == actual


@pytest.mark.parametrize("n", [8, 8192, 16384, 32768])
def test_actual_single_prime_and_order(n):
    q, root = prime_and_root(n)
    assert q % (2*n) == 1 and prime64(q)
    assert pow(root, n, q) == q-1 and pow(root, 2*n, q) == 1


@pytest.mark.parametrize("value", [0, 1, True, -7, 341, 561, 73*193, 3215031751, 1 << 64])
def test_prime_diagnostic_rejects_composites_and_types(value):
    assert not prime64(value)


@pytest.mark.parametrize("value", [73, 193, 407521, 299210837])
def test_prime_divisors_of_miller_rabin_bases_are_not_rejected(value):
    # Trial division independently establishes primality, rather than asking
    # another Miller--Rabin implementation to mirror this diagnostic.
    assert all(value % divisor for divisor in range(2, isqrt(value)+1))
    assert any(base % value == 0 for base in (28178, 450775, 9780504, 1795265022))
    assert prime64(value)


def test_raw_success_can_fail_real_terminal_margin():
    result = complete_bound(Profile(16384, 512, 8192, digit_bits=19))
    assert result["raw_admitted"] and not result["terminal_admitted"]
    assert result["raw_margin_twice"] > 0 and result["terminal_margin_twice"] <= 0
    assert not result["owner_bound_feasible"]


def test_general_public_index_and_setup_guard_are_not_owner_bounds():
    profile = Profile(8192, 512, 8192, digit_bits=10)
    owner = complete_bound(profile)
    public = complete_bound(profile, index_mode="public")
    assert owner["owner_bound_feasible"] and not public["owner_bound_feasible"]
    assert not owner["general_keygen_guard_admitted"]
    # The real existing API rejects BEFORE sampling a secret; no guard is changed.
    with pytest.raises(ValueError, match="one-product correctness"):
        bgv.key_gen(profile.n, t=profile.t, eta=profile.eta, q_bits=60, rns_modulus=True)


def test_bounded_alternative_recomposition_and_factor_two_scope():
    profile = Profile(16384, 512, 8192, digit_bits=15)
    result = complete_bound(profile, relaxed=True)
    q, bits = result["q"], profile.digit_bits
    # A genuinely noncanonical integer source with the same modulo-Q source.
    word, rest, digits = q, q, []
    for _ in range(result["levels"]):
        rest, digit = divmod(rest, 1 << bits)
        digits.append(digit)
    assert rest == 0 and sum(d << (j*bits) for j, d in enumerate(digits)) == word
    assert word % q == 0 and all(0 <= d < 1 << bits for d in digits)
    assert result["factor2_verified"]
    assert sum(digits) <= result["relaxed_digit_sum_cap"]
    assert result["switch_bound"] <= 2*complete_bound(profile)["switch_bound"]


def test_signed_secret_and_positive_negative_terminal_carries():
    q, p, t = 1049, 29, 17
    assert q % t == p % t
    negative = nearest_congruent(9, q, p, t)
    positive = nearest_congruent(q-9, q, p, t)
    assert negative < 0 and positive >= p
    for c in range(q):
        y = nearest_congruent(c, q, p, t)
        assert y % t == c % t and 2*abs(q*y-p*c) < q*t
    components = ((7, 2), (3, 5))
    assert phase(components, (q-1, 1), q) == phase(components, (-1, 1), q)
    assert phase(components, (-1, 1), q) == (-1, 0)


@pytest.mark.parametrize("bad", [(True, 3, 9), (16, 9, 9), (16, 3, 0)])
def test_invalid_full_layout_rejected(bad):
    with pytest.raises(ValueError):
        complete_bound(Profile(*bad))


def test_partial_groups_and_complete_packet_byte_ledger():
    profile = Profile(16, 3, 9, 17, 1, 10)
    result = complete_bound(profile, drop=8)
    card = byte_card(profile, result)
    assert result["partial_group_tile_counts"] == (3,)
    header = ["cuhepy-lab-bgv-compact-v1", 16, 17,
              result["p"].to_bytes(4, "little"), bytes(32), 9, 3]
    packet = msgpack.packb([header, [[bytes(64), bytes(64)]]], use_bin_type=True)
    assert len(packet) == card["response_complete_compact_v1_packet_bytes"]
    assert card["rotation_cuts"] == 3 and card["product_cuts"] == 3
    assert card["ordinary_one_limb_control_count_ratio"] == 1
    assert card["response_complete_compact_v1_packet_bytes"] > card["response_coefficient_body_bytes"]


def test_challenge_lifetime_budget_requires_repetition():
    q, _ = prime_and_root(16384)
    k = challenge_repetitions(q)
    assert k == 3 and q**(k-1) <= (1 << 160) < q**k


def test_actual_owner_query_to_all_coefficients_and_stable_ids():
    result = evaluate_fixture(make_fixture())
    assert result["observation_count"] == 16
    assert result["all_original_queries_and_full_packets_checked"]
    zero = next(x for x in result["observations"] if x["query"] == (0, 0, 0) and x["graph"] == "joint")
    assert zero["top3_owner_local_ids"][:2] == [(1, 0), (40, 0)]
    assert all(len(x["distances"]) == 9 for x in result["observations"])
