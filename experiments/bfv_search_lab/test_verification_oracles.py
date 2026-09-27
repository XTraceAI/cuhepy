"""Exact small-field miss counts and integer-relation mutation regressions.

No test demonstrates a complete proof or a safe remote acceptance protocol.
"""

from dataclasses import replace
from itertools import product
import random

import pytest

from cuhepy.bfv.scheme import _ntt
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import verification_oracles as oracle


@pytest.mark.parametrize("p", [3, 5, 7])
def test_exact_one_over_p_miss_rate_for_every_nonzero_error(p):
    a, x = [[1, 2], [2, 0]], [2, 1]
    expected = oracle.matvec(a, x, p)
    challenges = list(product(range(p), repeat=2))
    assert all(oracle.linear_check(a, x, expected, r, p) for r in challenges)
    for error in product(range(p), repeat=2):
        if error == (0, 0):
            continue
        wrong = [(y+e) % p for y, e in zip(expected, error, strict=True)]
        assert sum(oracle.linear_check(a, x, wrong, r, p) for r in challenges) == p


def test_two_limbs_do_not_square_soundness_for_one_corrupted_limb():
    a, x = [[1, 2], [2, 0]], [2, 1]
    first, second = oracle.matvec(a, x, 5), oracle.matvec(a, x, 7)
    first[0] = (first[0]+1) % 5
    accepts = sum(oracle.linear_check(a, x, first, r, 5) and oracle.linear_check(a, x, second, s, 7)
                  for r in product(range(5), repeat=2) for s in product(range(7), repeat=2))
    assert accepts == (5**2 * 7**2)//5
    assert accepts != (5**2 * 7**2)//(5*7)


def test_public_or_reused_known_challenge_allows_a_wrong_output():
    # Algebra counterexample to treating a public fixed checksum as a proof.
    a, x, r, p = [[1, 2], [2, 0]], [2, 1], [2, 3], 7
    good = oracle.matvec(a, x, p)
    bad = [(good[0]+r[1]) % p, (good[1]-r[0]) % p]
    assert bad != good and oracle.linear_check(a, x, bad, r, p)


@pytest.mark.parametrize("n", [2, 4, 8])
def test_vandermonde_and_radix_two_ntt_agree(n):
    p, psi = 17, pow(3, 16//(2*n), 17)
    a = oracle.negacyclic_ntt_matrix(n, psi, p)
    rng = random.Random(n)
    for _ in range(8):
        x = [rng.randrange(p) for _ in range(n)]
        expected = _ntt([v*pow(psi, i, p) % p for i, v in enumerate(x)], psi*psi % p, p)
        assert oracle.matvec(a, x, p) == expected
        r = [rng.randrange(p) for _ in range(n)]
        assert oracle.linear_check(a, x, expected, r, p)


def test_fixed_index_tensor_is_linear_in_both_query_components():
    p = 17
    for index0, index1, query0, query1 in product(range(3), repeat=4):
        a = [[index0, 0], [index1, index0], [0, index1]]
        out = [query0*index0 % p, (query0*index1+query1*index0) % p, query1*index1 % p]
        assert oracle.matvec(a, [query0, query1], p) == out
        assert oracle.linear_check(a, [query0, query1], out, [1, 3, 5], p)


@pytest.mark.parametrize("a,x,y,r,p", [([[1]], [0], [0], [0], 9),
    ([[1]], [0], [0], [0], 65537), ([[1]], [0], [5], [0], 5),
    ([[1]], [True], [0], [0], 5), ([[1]], [0], [0], [], 5),
    ([[1], [1, 2]], [0], [0, 0], [0, 0], 5)])
def test_field_relation_requires_canonical_toy_inputs(a, x, y, r, p):
    with pytest.raises(ValueError):
        oracle.linear_check(a, x, y, r, p)


def test_terminal_exhaustive_small_coefficients_and_wrong_witnesses():
    seen = 0
    for t in (3, 5, 7):
        for q in range(t+3, 101):
            if q % t == 0:
                continue
            for p in range(t+1, q):
                if (q-p) % t:
                    continue
                for c in range(q):
                    w = oracle.terminal_witness(c, q, p, t)
                    assert oracle.terminal_relation(c, w, q, p, t)
                    assert w.output == compact._round_coefficient(c, q, p, t) % p
                    for change in (dict(quotient=w.quotient+1), dict(quotient=w.quotient-1),
                                   dict(residue=w.residue+t), dict(output=w.output+p),
                                   dict(output=(w.output+1) % p)):
                        assert not oracle.terminal_relation(c, replace(w, **change), q, p, t)
                    seen += 1
    assert seen > 100000


def test_negative_quotient_tie_and_proof_field_alias():
    negative = oracle.terminal_witness(4, 97, 17, 5)
    assert negative.quotient == -1
    assert oracle.terminal_relation(4, negative, 97, 17, 5)
    tie = oracle.terminal_witness(7, 14, 5, 3)
    assert tie.quotient == 1 and tie.output == 4  # Exact 2.5, congruent choices 1 and 4.
    assert not oracle.terminal_relation(7, replace(tie, quotient=0, output=1), 14, 5, 3)
    proof_prime = 257
    alias = replace(negative, quotient=negative.quotient+proof_prime*17)
    assert (alias.quotient-negative.quotient) % proof_prime == 0
    assert (alias.quotient*5+alias.residue-alias.output) % 17 == 0
    assert not oracle.terminal_relation(4, alias, 97, 17, 5)


def test_gadget_ranges_integer_aliases_and_crt_canonicality():
    for q in (17, 65, 97, 257):
        for bits in (1, 2, 3, 4):
            base, count = 1 << bits, (q.bit_length()+bits-1)//bits
            for c in range(q):
                digits = [(c >> (j*bits)) % base for j in range(count)]
                assert oracle.gadget_relation(c, digits, q, bits)
                assert not oracle.gadget_relation(c+q, digits, q, bits)
                assert not oracle.gadget_relation(c, [*digits, 0], q, bits)
                if count > 1:
                    alias = digits.copy()
                    alias[0] += base
                    alias[1] -= 1
                    assert sum(d << (j*bits) for j, d in enumerate(alias)) == c
                    assert not oracle.gadget_relation(c, alias, q, bits)
    moduli = (5, 7)
    for c in range(35):
        residues = (c % 5, c % 7)
        assert oracle.crt_relation(c, residues, moduli)
        assert not oracle.crt_relation(c+35, residues, moduli)
        assert not oracle.crt_relation(c, (residues[0]+5, residues[1]), moduli)
        assert not oracle.crt_relation(c, ((residues[0]+1) % 5, residues[1]), moduli)
    with pytest.raises(ValueError):
        oracle.crt_relation(1, (1, 1), (6, 9))


def test_digit_boundary_counts_against_existing_schedule_and_known_workloads():
    for n in (8, 16, 32, 64):
        for padded in (1 << j for j in range(n.bit_length()-1)):
            for count in range(1, 2*n+2):
                model = oracle.digit_boundary_counts(n, padded, count)
                tiles = model["index_tiles"]
                expected = sum(butterfly.schedule(padded, [0]*min(padded, tiles-i), 0)[1]
                               for i in range(0, tiles, padded))
                assert model["butterfly_switches"] == expected
                assert model["switch_input_coefficients"] == (tiles+expected)*n
    small, large = (oracle.digit_boundary_counts(16384, 512, count) for count in (8192, 32768))
    assert (small["native_layout_roundtrip_bytes"], small["ideally_packed_roundtrip_bytes"]) == (1005322240, 376995840)
    assert (large["native_layout_roundtrip_bytes"], large["ideally_packed_roundtrip_bytes"]) == (2681733120, 1005649920)
    assert (small["aligned_words_roundtrip_bytes"], large["aligned_words_roundtrip_bytes"]) == (402128896, 1072693248)
