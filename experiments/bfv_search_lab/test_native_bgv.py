"""Ciphertext-exact native differential tests and defensive boundary checks."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import random

import pytest

from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab.native_bgv import NativeServer

native = pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace")


@pytest.mark.parametrize("n,d,bits", [(8, 1, 96), (16, 3, 96), (64, 8, 180), (64, 31, 96)])
def test_native_exact_ciphertexts_for_both_circuits_and_tails(n, d, bits):
    pk, sk = bgv.key_gen(n, q_bits=bits)
    keys = trace.evaluation_keys(pk, sk, 1 << (d - 1).bit_length())
    server = NativeServer(pk, keys)
    rng = random.Random(n + d)
    query = [rng.randrange(2) for _ in range(d)]
    rows = [[rng.randrange(2) for _ in range(d)] for _ in range(n + 3)]
    qp, tiles = bgv.coefficient_inputs(query, rows, n)
    encrypted, index = bgv.encrypt(qp, pk), [bgv.encrypt(tile, pk) for tile in tiles]
    capacity = n // keys.padded
    for count in sorted({0, 1, capacity + 1, n - 1, n, n + 1, len(rows)}):
        chosen = index[:(count + capacity - 1) // capacity]
        prepared = server.prepare_index(chosen, count)
        for joint, reference in ((False, trace.search), (True, butterfly.search)):
            expected = reference(encrypted, chosen, count, pk, keys)
            assert server.search(encrypted, prepared, joint=joint) == expected
    prepared = server.prepare_index(index, len(rows))
    with ThreadPoolExecutor(max_workers=3) as pool:
        outputs = list(pool.map(lambda _: server.search(encrypted, prepared), range(3)))
    assert outputs[0] == outputs[1] == outputs[2]
    assert trace.decode([bgv.decrypt(ct, pk, sk) for ct in outputs[0]], len(rows), d, pk) == [
        sum(a != b for a, b in zip(query, row, strict=True)) for row in rows
    ]


def test_native_boundary_rejections():
    pk, sk = bgv.key_gen(16, q_bits=96)
    keys = trace.evaluation_keys(pk, sk, 4)
    server, other = NativeServer(pk, keys), NativeServer(pk, keys)
    ct = bgv.encrypt([0] * pk.n, pk)
    index = server.prepare_index([ct], 1)
    with pytest.raises(ValueError, match="context"):
        other.search(ct, index)
    with pytest.raises(ValueError, match="bound"):
        server.search(replace(ct, phase_bound=int(pk.q // 3)), index)
    pair = tuple(server._pack(p) for p in ct.components)
    for malformed in ((b"", b""), pair[:1], (pk.q.to_bytes(server.width, "little") * pk.n, pair[1])):
        with pytest.raises(ValueError):
            native.search(server._server, malformed, index.handle, True)
        with pytest.raises(ValueError):
            native.prepare_index(server._server, (malformed,))
    with pytest.raises(ValueError, match="another"):
        native.search(other._server, pair, index.handle, True)
    for mode in (1, None):
        with pytest.raises(ValueError):
            native.search(server._server, pair, index.handle, mode)
    for n, q, bits, d in ((True, "f" * 24, 30, 4), (16, "0" * 1000, 30, 4),
                          (16, "-" + "f" * 24, 30, 4), (16, "f" * 24, 0, 4),
                          (16, "f" * 24, 30, 3)):
        with pytest.raises(ValueError):
            native.create_server(n, q, bits, d, ())


@pytest.mark.parametrize("n,d,bits", [(8, 1, 120), (64, 5, 120), (64, 31, 180)])
def test_persistent_rns_matches_python_and_auxiliary_native(n, d, bits):
    pk, sk = bgv.key_gen(n, q_bits=bits, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 1 << (d - 1).bit_length())
    query = [i % 2 for i in range(d)]
    rows = [query, [1 - x for x in query]] * (n + 1)
    qp, tiles = bgv.coefficient_inputs(query, rows, n)
    ct, index = bgv.encrypt(qp, pk), [bgv.encrypt(p, pk) for p in tiles]
    for joint, reference in ((False, trace.search), (True, butterfly.search)):
        expected = reference(ct, index, len(rows), pk, keys)
        for residue in (False, True):
            server = NativeServer(pk, keys, residue=residue)
            assert server.search(ct, server.prepare_index(index, len(rows)), joint=joint) == expected
