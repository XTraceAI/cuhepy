"""Independent polynomial identity and encrypted joint-packing regressions."""

from dataclasses import replace
import random

import pytest

from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import butterfly_bgv as butterfly


def permute(poly, multiplier=1, shift=0):
    # Plain integer ring oracle: no production automorphism/monomial helpers.
    n, out = len(poly), [0] * len(poly)
    for i, x in enumerate(poly):
        quotient, target = divmod(i * multiplier + shift, n)
        out[target] += x * (-1 if quotient % 2 else 1)
    return out


@pytest.mark.parametrize("n", [8, 16, 32, 64])
def test_butterfly_identity_for_arbitrary_polynomials_and_every_tail(n):
    rng = random.Random(n)
    for d in (1 << i for i in range(n.bit_length() - 1)):
        for count in range(1, d + 1):
            source = [[rng.randrange(-10, 11) for _ in range(n)] for _ in range(count)]
            expected = [0] * n
            for i, poly in enumerate(source):
                for j in range(0, n, d):
                    expected[j + i] = d * poly[j]
            work, shift, generator = source, d // 2, 1 + 2 * n // d
            for level in range(d.bit_length() - 1):
                merged = []
                for i in range(min(shift, len(work))):
                    right = permute(work[i + shift], shift=shift) if i + shift < len(work) else [0] * n
                    plus = [a + b for a, b in zip(work[i], right, strict=True)]
                    minus = [a - b for a, b in zip(work[i], right, strict=True)]
                    rotated = permute(minus, multiplier=pow(generator, 1 << level, 2 * n))
                    merged.append([a + b for a, b in zip(plus, rotated, strict=True)])
                work, shift = merged, shift // 2
            assert work == [expected]


@pytest.mark.parametrize("n,d", [(8, 1), (16, 3), (32, 8), (64, 5), (64, 31)])
def test_encrypted_full_polynomial_matches_per_tile_trace(n, d):
    pk, sk = bgv.key_gen(n)
    padded = 1 << (d - 1).bit_length()
    keys = trace.evaluation_keys(pk, sk, padded)
    rng = random.Random(n + d)
    query = [rng.randrange(2) for _ in range(d)]
    rows = [query, [1 - x for x in query]] + [[rng.randrange(2) for _ in range(d)] for _ in range(n + 1)]
    qp, tiles = bgv.coefficient_inputs(query, rows, n)
    encrypted = bgv.encrypt(qp, pk)
    index = [bgv.encrypt(tile, pk) for tile in tiles]
    for count in sorted({0, 1, n // padded + 1, n - 1, n, n + 1, len(rows)}):
        chosen = index[:(count + n // padded - 1) // (n // padded)]
        expected = trace.search(encrypted, chosen, count, pk, keys)
        actual = butterfly.search(encrypted, chosen, count, pk, keys)
        plains = [bgv.decrypt(ct, pk, sk) for ct in actual]
        assert plains == [bgv.decrypt(ct, pk, sk) for ct in expected]
        assert trace.decode(plains, count, d, pk) == [sum(a != b for a, b in zip(query, row, strict=True)) for row in rows[:count]]
        assert all(a.phase_bound <= b.phase_bound for a, b in zip(actual, expected, strict=True))


def test_operation_count_and_bounds():
    assert butterfly.schedule(512, [1] * 256, 0) == (512 * 256, 511)
    assert butterfly.schedule(512, [1] * 512, 0) == (512 * 512, 511)
    assert butterfly.schedule(512, [1], 1) == (1023, 9)
    for d in (1, 2, 4, 16, 512):
        bound, rotations = butterfly.schedule(d, [3] * d, 7)
        assert bound == d * d * 3 + 7 * (d * d - 1) // 3
        assert rotations == d - 1


def test_rejects_wrong_schedule_keys_components_and_actual_phase_bound():
    pk, sk = bgv.key_gen(16)
    keys = trace.evaluation_keys(pk, sk, 4)
    ct = bgv.encrypt([0] * 16, pk)
    for bad in (replace(keys, key_id="bad"), replace(keys, rotations=keys.rotations[::-1]),
                replace(keys, switch_error_bound=0), replace(keys, relin=())):
        with pytest.raises(ValueError):
            butterfly.search(ct, [ct], 1, pk, bad)
    for cipher in (replace(ct, phase_bound=int(pk.q // 3)),
                   replace(ct, components=ct.components + (ct.components[0],))):
        with pytest.raises(ValueError):
            butterfly.search(cipher, [ct], 1, pk, keys)
