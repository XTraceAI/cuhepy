"""Independent rounding oracle, extreme inputs, bounds and native boundary checks."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import random

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab.native_bgv import NativeServer

pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace")


@pytest.mark.parametrize("q_bits,rns", [(96, False), (120, True), (180, True), (240, True)])
def test_native_rounding_matches_reference_for_random_and_boundary_coefficients(q_bits, rns):
    pk, sk = bgv.key_gen(64, t=17, q_bits=q_bits, rns_modulus=rns)
    server = NativeServer(pk, trace.evaluation_keys(pk, sk, 1), residue=rns)
    rng = random.Random(q_bits)
    for bits in (16, 20, 31, 32, 47, 60):
        p = compact.terminal_modulus(pk.q, pk.t, bits)
        # Arbitrary public coefficients, not a valid encryption. Never decrypt
        # these or treat their synthetic bound as evidence of authenticity.
        choices = [0, 1, pk.q - 1, pk.q // 2, pk.t - 1, pk.t, pk.t + 1]
        # Values surrounding the scaled half-integer rounding thresholds.
        choices += [max(mpz(0), min(pk.q - 1, ((2 * k + 1) * pk.q) // (2 * p) + offset))
                    for k in (0, 1, int(p // 2), int(p - 1)) for offset in (-1, 0, 1)]
        values = choices + [mpz(rng.randrange(int(pk.q))) for _ in range(128 - len(choices))]
        cipher = bgv.Ciphertext((tuple(values[:64]), tuple(values[64:])), pk.key_id, 0)
        actual = server.compact_result(cipher, bits)
        assert actual == compact.compact(cipher, pk, bits)
        for before, after in zip(cipher.components, actual.components, strict=True):
            for c, reduced in zip(before, after, strict=True):
                assert 0 <= reduced < p
                # Lift reduced back near P*c/Q, allowing a single +/-P wrap.
                lifted = min((reduced - p, reduced, reduced + p), key=lambda x: abs(pk.q * x - p * c))
                assert (lifted - c) % pk.t == 0
                assert 2 * abs(pk.q * lifted - p * c) <= pk.q * pk.t


@pytest.mark.parametrize("residue", [False, True])
def test_integrated_native_compaction_matches_separate_steps_and_empty_index(residue):
    pk, sk = bgv.key_gen(64, q_bits=120, rns_modulus=True)
    server = NativeServer(pk, trace.evaluation_keys(pk, sk, 8), residue=residue)
    query = [0, 1, 0, 1, 1]
    rows = [query, [1 - x for x in query]] * 35
    qp, tiles = bgv.coefficient_inputs(query, rows, pk.n)
    ct = bgv.encrypt(qp, pk)
    index = server.prepare_index([bgv.encrypt(tile, pk) for tile in tiles], len(rows))
    for joint in (False, True):
        expected = [compact.compact(c, pk) for c in server.search(ct, index, joint=joint)]
        assert server.search_compact(ct, index, joint=joint) == expected
        assert trace.decode([compact.decrypt(c, pk, sk) for c in expected], len(rows), 5, pk) == [0, 5] * 35
    assert server.search_compact(ct, server.prepare_index([], 0)) == []
    with ThreadPoolExecutor(max_workers=3) as pool:
        outputs = list(pool.map(lambda _: server.search_compact(ct, index), range(3)))
    assert outputs[0] == outputs[1] == outputs[2]


def test_native_compaction_refuses_bad_contexts_bounds_and_parameters():
    pk, sk = bgv.key_gen(64, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 8)
    server, other = NativeServer(pk, keys), NativeServer(pk, keys)
    ct = bgv.encrypt([0] * pk.n, pk)
    index = server.prepare_index([ct], 1)
    with pytest.raises(ValueError, match="context"):
        other.search_compact(ct, index)
    with pytest.raises(ValueError, match="bound"):
        server.search_compact(ct, index, bits=16)
    with pytest.raises(ValueError, match="bound"):
        server.compact_result(replace(ct, phase_bound=int(pk.q // 2 - 1)))
    for level in (True, -1, 4, 1):
        with pytest.raises(ValueError, match="level"):
            NativeServer(pk, keys, cuda_level=level)
    pair = tuple(server._pack(poly) for poly in ct.components)
    p = compact.terminal_modulus(pk.q, pk.t, 32)
    for t, value in ((True, format(p, "x")), (2, format(p, "x")), (pk.t, "f" * 1000),
                     (pk.t, "0" + format(p, "x")), (pk.t, format(p - 1, "x")),
                     (pk.t, "-ffff"), (pk.t, "1\x00ffff")):
        with pytest.raises((ValueError, OverflowError)):
            server._native.compact_result(server._server, pair, t, value)
        with pytest.raises((ValueError, OverflowError)):
            server._native.search_compact(server._server, pair, index.handle, True, t, value)
    bad = pk.q.to_bytes(server.width, "little") * pk.n
    with pytest.raises(ValueError, match="Noncanonical"):
        server._native.compact_result(server._server, (bad, pair[1]), pk.t, format(p, "x"))


@pytest.mark.parametrize("n,minimum_bits", [(2048, 22), (16384, 25)])
def test_terminal_precision_boundary_depends_on_ring_and_plaintext_modulus(n, minimum_bits):
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    server = NativeServer(pk, trace.evaluation_keys(pk, sk, 1), residue=True)
    cipher = bgv.encrypt([0] * n, pk)
    with pytest.raises(ValueError, match="correctness bound"):
        server.compact_result(cipher, minimum_bits - 1)
    small = server.compact_result(cipher, minimum_bits)
    assert small == compact.compact(cipher, pk, minimum_bits)
    assert compact.decrypt(small, pk, sk) == [0] * n
    assert 2 * small.phase_bound < small.modulus
