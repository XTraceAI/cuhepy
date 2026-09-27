"""Homemade encrypted tests of disjoint mixed-scale output support."""

from dataclasses import replace
import random

import pytest

from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import folded_dictionary as dictionary
from experiments.bfv_search_lab import folded_filter as folded
from experiments.bfv_search_lab import interval_filter as interval
from experiments.bfv_search_lab import linear_packing as packing
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import witness_packing as witness


@pytest.mark.parametrize("count,witness_count", [(1, 1), (55, 7), (64, 8)])
def test_encrypted_fusion_zero_support_scales_partial_tiles_and_two_round_top3(count, witness_count):
    rng = random.Random(2902)
    rows = [rng.getrandbits(32) for _ in range(max(3, count))]
    query = rng.getrandbits(32)
    dictionary_plan = dictionary.prepare(rows, 32, 7).plan
    pk, sk = bgv.key_gen(128, t=257, q_bits=180, eta=1)
    rows = rows[:count]
    qp, tiles, padded, radii = interval.inputs(dictionary_plan, query, rows, pk.n)
    # Repetition is fine here: support/packing must hold even for duplicate witnesses.
    witnesses = [rows[i % count] for i in range(witness_count)]
    full_plan = folded.FoldPlan(32, tuple(range(32)), tuple((i, 0) for i in range(32)), 0)
    wq, wt, wp = folded.inputs(full_plan, query, witnesses, pk.n)
    ciphertexts, plains = [], []
    for q, ts, pad, size in ((qp, tiles, padded, count), (wq, wt, wp, witness_count)):
        keys = trace.evaluation_keys(pk, sk, pad, 12)
        output = butterfly.search(bgv.encrypt(q, pk), [bgv.encrypt(t, pk) for t in ts], size, pk, keys)
        assert len(output) == 1
        cipher = output[0]
        plain = bgv.decrypt(cipher, pk, sk)
        support = set(witness.positions(pk.n, pad, size))
        assert all(x == 0 for i, x in enumerate(plain) if i not in support)
        ciphertexts.append(cipher)
        plains.append(plain)
    plan = witness.place(pk.n, padded, count, wp, witness_count)
    mixed = witness.combine(*ciphertexts, plan, pk)
    assert mixed.phase_bound == sum(c.phase_bound for c in ciphertexts)
    left, right = witness.decode(bgv.decrypt(mixed, pk, sk), plan, pk.t)
    templates = interval.decode_templates(left, 32, pk.t)
    assert templates == [(query ^ folded._template(dictionary_plan, x)).bit_count() for x in rows]
    exact_witness = interval.decode_templates(right, 32, pk.t)
    assert exact_witness == [(query ^ x).bit_count() for x in witnesses]
    lo, hi = interval.intervals(templates, radii, 32)
    # Complete second round also uses homemade encrypted arithmetic.
    exact = [(query ^ x).bit_count() for x in rows]
    ids = list(reversed(range(count)))
    capacity = pk.n // wp
    keys = trace.evaluation_keys(pk, sk, wp, 12)

    def fetch(selected):
        positions = [i for t in selected for i in range(t * capacity, min((t + 1) * capacity, count))]
        q, ts, pad = folded.inputs(full_plan, query, [rows[i] for i in positions], pk.n)
        out = butterfly.search(bgv.encrypt(q, pk), [bgv.encrypt(t, pk) for t in ts], len(positions), pk, keys)
        dots = packing.unpack([bgv.decrypt(c, pk, sk) for c in out], len(positions), pad, pk.n, pk.t)
        return list(zip(positions, folded.decode(full_plan, dots, pk.t), strict=True))

    known = {i % count: d for i, d in enumerate(exact_witness)}
    top, _, _ = interval.refine_once(lo, hi, ids, capacity, fetch, k=min(3, count), known_scores=known)
    assert top == tuple(sorted(zip(exact, ids, strict=True))[:min(3, count)])


def test_support_certificate_refuses_overlap_and_does_not_assume_arbitrary_scatter():
    plan = witness.place(16384, 64, 8192, 512, 256)
    assert plan.shift == 32
    witness.validate(plan)
    with pytest.raises(ValueError):
        witness.validate(replace(plan, shift=0))
    # Two free coefficients remain, but they cannot hold this witness pattern.
    with pytest.raises(ValueError, match="No disjoint"):
        witness.place(16, 2, 14, 8, 2)
    for args in ((16, 3, 1), (16, 2, 17), (16, 2, -1)):
        with pytest.raises(ValueError):
            witness.positions(*args)


def test_fusion_rejects_foreign_keys_wrong_ring_and_unsafe_noise():
    pk, sk = bgv.key_gen(32, t=257, q_bits=120, eta=1)
    other, _ = bgv.key_gen(32, t=257, q_bits=120, eta=1)
    c = bgv.encrypt([0] * pk.n, pk)
    foreign = bgv.encrypt([0] * pk.n, other)
    plan = witness.place(32, 4, 8, 8, 2)
    with pytest.raises(ValueError):
        witness.combine(c, foreign, plan, pk)
    with pytest.raises(ValueError):
        witness.combine(c, c, witness.place(64, 4, 8, 8, 2), pk)
    unsafe = replace(c, phase_bound=pk.q // 3)
    with pytest.raises(ValueError):
        witness.combine(unsafe, unsafe, plan, pk)
