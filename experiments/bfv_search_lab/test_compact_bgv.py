"""Terminal rounding arithmetic, encrypted correctness and bound refusal."""

from dataclasses import replace
import random

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import butterfly_bgv as butterfly, compact_bgv as compact


@pytest.mark.parametrize("q,p,t", [(1013, 73, 5), (4093, 109, 3), (1009, 151, 11)])
def test_rounding_preserves_residue_and_has_proven_absolute_error(q, p, t):
    assert (q - p) % t == 0
    for c in range(q):
        rounded = compact._round_coefficient(mpz(c), mpz(q), mpz(p), t)
        assert (rounded - c) % t == 0
        assert 2 * abs(q * rounded - p * c) <= q * t


@pytest.mark.parametrize("n,d,bits", [(8, 1, 16), (16, 3, 20), (64, 31, 32)])
def test_compaction_preserves_entire_plaintext_across_response_groups(n, d, bits):
    pk, sk = bgv.key_gen(n, q_bits=96)
    keys = trace.evaluation_keys(pk, sk, 1 << (d - 1).bit_length())
    rng = random.Random(n + d)
    query = [rng.randrange(2) for _ in range(d)]
    rows = [query, [1 - x for x in query]] + [[rng.randrange(2) for _ in range(d)] for _ in range(n + 3)]
    qp, tiles = bgv.coefficient_inputs(query, rows, n)
    query_ct, index = bgv.encrypt(qp, pk), [bgv.encrypt(p, pk) for p in tiles]
    for method in (trace.search, butterfly.search):
        responses = method(query_ct, index, len(rows), pk, keys)
        small = [compact.compact(c, pk, bits) for c in responses]
        expected = [bgv.decrypt(c, pk, sk) for c in responses]
        assert [compact.decrypt(c, pk, sk) for c in small] == expected
        assert all(2 * c.phase_bound < c.modulus for c in small)
        assert len(compact.pack(small, len(rows), d, pk)) < 2 * len(responses) * n * 12 + 100


def test_refuses_unsafe_bounds_moduli_and_secret_contexts():
    pk, sk = bgv.key_gen(64, q_bits=96)
    ct = bgv.encrypt([0] * 64, pk)
    with pytest.raises(ValueError, match="bound"):
        compact.compact(ct, pk, 16)  # Rounding alone exceeds half of any 16-bit P.
    for bits in (True, 0, 96):
        with pytest.raises(ValueError):
            compact.compact(ct, pk, bits)
    good = compact.compact(ct, pk)
    for bad in (replace(good, key_id="bad"), replace(good, modulus=good.modulus - 1),
                replace(good, phase_bound=int(good.modulus)),
                replace(good, components=(tuple([good.modulus] * 64), good.components[1]))):
        with pytest.raises(ValueError):
            compact.decrypt(bad, pk, sk)
    with pytest.raises(ValueError, match="ternary"):
        compact.decrypt(good, pk, replace(sk, s=tuple([mpz(2)] * 64)))
