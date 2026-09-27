"""Independent integer/symbolic support and encrypted E15 regressions."""

from dataclasses import replace
import random

import pytest

from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import butterfly_bgv as butterfly, compact_bgv as compact
from experiments.bfv_search_lab import support_bounds_bgv as support
from experiments.bfv_search_lab.native_bgv import NativeServer


def add(left, right, sign=1):
    out = left.copy()
    for atom, factor in right.items():
        out[atom] = out.get(atom, 0) + sign*factor
        if not out[atom]:
            del out[atom]
    return out


def permute(poly, multiplier=1, shift=0):
    n, out = len(poly), [{} for _ in poly]
    for j, value in enumerate(poly):
        quotient, target = divmod(j*multiplier + shift, n)
        out[target] = add(out[target], value, -1 if quotient % 2 else 1)
    return out


def symbolic_butterfly(n, padded, count):
    # Every initial phase coefficient and every switch-error coefficient is a
    # distinct indeterminate. Combining dicts preserves cancellation of aliases.
    work = [[{("input", i, j): 1} for j in range(n)] for i in range(count)]
    shift, generator = padded//2, 1 + 2*n//padded
    for level in range(padded.bit_length()-1):
        merged = []
        for i in range(min(shift, len(work))):
            right = permute(work[i+shift], shift=shift) if i+shift < len(work) else [{} for _ in range(n)]
            plus = [add(a, b) for a, b in zip(work[i], right, strict=True)]
            minus = [add(a, b, -1) for a, b in zip(work[i], right, strict=True)]
            rotated = permute(minus, multiplier=pow(generator, 1 << level, 2*n))
            merged.append([add(add(a, b), {("switch", level, i, j): 1})
                           for j, (a, b) in enumerate(zip(plus, rotated, strict=True))])
        work, shift = merged, shift//2
    return work[0]


@pytest.mark.parametrize("n", [8, 16, 32, 64])
def test_exact_symbolic_identity_all_tail_shapes(n):
    for padded in (1 << j for j in range(n.bit_length()-1)):
        for count in range(1, padded+1):
            result = symbolic_butterfly(n, padded, count)
            for position, terms in enumerate(result):
                source = {k: v for k, v in terms.items() if k[0] == "input"}
                lane = position % padded
                expected = {("input", lane, position-lane): padded} if lane < count else {}
                assert source == expected
                for level in range(padded.bit_length()-1):
                    degree = padded >> (level+1)
                    node = position % degree
                    active = min(degree, count)
                    expected_error = {("switch", level, node, position-node): degree} if node < active else {}
                    actual_error = {k: v for k, v in terms.items() if k[:2] == ("switch", level)}
                    assert actual_error == expected_error


def test_unequal_bounds_and_correlated_error_extremes():
    rng = random.Random(915)
    for padded in (1, 2, 4, 8, 16):
        for count in range(1, padded+1):
            limits = [rng.randrange(1, 30) for _ in range(count)]
            error = 13
            maximum = 0
            for terms in symbolic_butterfly(32, padded, count):
                row_bound = sum(abs(v)*(limits[k[1]] if k[0] == "input" else error) for k, v in terms.items())
                maximum = max(maximum, row_bound)
                # The bound includes arbitrary coefficient correlations; choose
                # signs that maximize this row, rather than sample small errors.
                extreme = sum(v*((1 if v > 0 else -1)*(limits[k[1]] if k[0] == "input" else error))
                              for k, v in terms.items())
                assert abs(extreme) == row_bound
            tight = support.final_bound(padded, limits, error)
            assert maximum == tight
            assert tight <= butterfly.schedule(padded, limits, error)[0]


@pytest.mark.parametrize("arguments", [(0, [1], 1), (3, [1], 1), (2, [], 1),
    (2, [1, 1, 1], 1), (2, [-1], 1), (2, [True], 1), (2, [1], -1)])
def test_invalid_schedules(arguments):
    with pytest.raises(ValueError):
        support.final_bound(*arguments)


@pytest.mark.parametrize("n,dimension,count", [(16, 1, 33), (32, 3, 39), (64, 9, 71), (128, 31, 129)])
def test_same_complete_ciphertext_and_exact_distances(n, dimension, count):
    pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace")
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    padded = 1 << (dimension-1).bit_length()
    keys = trace.evaluation_keys(pk, sk, padded)
    rng = random.Random(n+count)
    query = [rng.randrange(2) for _ in range(dimension)]
    rows = [query, [1-b for b in query]] + [[rng.randrange(2) for _ in query] for _ in range(count-2)]
    qp, plains = bgv.coefficient_inputs(query, rows, n)
    ciphertext = bgv.encrypt(qp, pk)
    index = [bgv.encrypt(poly, pk) for poly in plains]
    old, new = NativeServer(pk, keys, residue=True), support.SupportBoundServer(pk, keys, residue=True)
    old_index, new_index = old.prepare_index(index, count), new.prepare_index(index, count)
    before, after = old.search(ciphertext, old_index), new.search(ciphertext, new_index)
    assert [c.components for c in before] == [c.components for c in after]
    assert all(a.phase_bound <= b.phase_bound for a, b in zip(after, before, strict=True))
    expected = [sum(a != b for a, b in zip(query, row, strict=True)) for row in rows]
    assert trace.decode([bgv.decrypt(c, pk, sk) for c in after], count, dimension, pk) == expected
    compressed = [compact.compact(c, pk) for c in after]
    assert trace.decode([compact.decrypt(c, pk, sk) for c in compressed], count, dimension, pk) == expected
    with pytest.raises(ValueError, match="joint"):
        new.search(ciphertext, new_index, joint=False)
    with pytest.raises(ValueError, match="index"):
        new.search(ciphertext, old_index)
    with pytest.raises(ValueError, match="Q/2"):
        new.search(replace(ciphertext, phase_bound=int(pk.q)//3), new_index)
    assert new.search(ciphertext, new.prepare_index([], 0)) == []
