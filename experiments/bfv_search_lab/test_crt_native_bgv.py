"""Exact optional short-NTT backend against independent GMP and schoolbook."""

from contextlib import closing
from dataclasses import replace
import random
import struct

import pytest

from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import reduction_oracles as reduction
from experiments.bfv_search_lab.test_crt_masked_bgv import EPOCH, SEED, TOKEN

backend = pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")


@pytest.mark.parametrize("n,paths,features,counts", [
    (8, ("",), (1,), (0,)),
    (8, ("",), (3,), (17,)),
    (32, ("0", "10", "11"), (3, 2, 1), (37, 9, 1)),
    (128, tuple(format(i, "06b") for i in range(64)), (2,) * 64, tuple(i % 9 for i in range(64))),
])
def test_native_and_gmp_complete_noisy_ciphertexts_identical(n, paths, features, counts):
    plan = tree.layout(tree.context(n, paths, 257), features, counts)
    s, rng = space.space(plan, tuple(range(len(paths)))), random.Random(7400)
    rows = [[[rng.randrange(-2, 3) for _ in range(f)] for _ in range(c)] for f, c in zip(features, counts, strict=True)]
    pk, sk = masked.key_gen(s, q_bits=40, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, rows, EPOCH, client)
        prepared = native.NativeIndex(index, pk)
        for i in range(4):
            ticket, answer, _ = masked.prepare(s, rows, EPOCH, i.to_bytes(16, "little"), SEED, client)
            request = ticket.consume(tuple(rng.randrange(-257, 258) for _ in range(s.dimension)), EPOCH)
            assert prepared.evaluate(answer, request) == masked.evaluate(index, answer, request, pk)
        with pytest.raises(ValueError, match="mismatch"):
            prepared.evaluate(answer, replace(request, epoch=b"x" * 32))


def test_native_signed_word_extremes_and_coefficient_boundaries():
    n, slots, columns, replies, q, psi = 8, 4, 2, 2, 97, 33
    assert pow(psi, slots, q) == q - 1
    rng = random.Random(7401)
    index = [rng.randrange(q) for _ in range(columns * replies * 2 * n)]
    index[:3] = [0, q - 1, q - 1]
    short = [-(1 << 63), (1 << 63) - 1, -1, 0, 1, q - 1, -q, q]
    saved = [rng.randrange(q) for _ in range(replies * 2 * n)]
    handle = backend.prepare(n, slots, columns, replies, q, psi, struct.pack(f"<{len(index)}Q", *index))
    raw = backend.evaluate(handle, struct.pack(f"<{len(short)}q", *short), struct.pack(f"<{len(saved)}Q", *saved))
    actual = struct.unpack(f"<{len(saved)}Q", raw)
    expected = saved.copy()
    for j in range(columns):
        poly = tuple(short[j * slots + i // (n // slots)] if i % (n // slots) == 0 else 0 for i in range(n))
        for p in range(replies * 2):
            start = (j * replies * 2 + p) * n
            product = reduction.ring_product(tuple(index[start:start + n]), poly)
            for i, value in enumerate(product):
                expected[p * n + i] = (expected[p * n + i] + value) % q
    assert actual == tuple(expected)
    with pytest.raises(ValueError, match="buffer"):
        backend.evaluate(handle, b"", bytes(len(saved) * 8))
    with pytest.raises(ValueError, match="offline"):
        backend.evaluate(handle, bytes(len(short) * 8), struct.pack(f"<{len(saved)}Q", *([q] * len(saved))))
    with pytest.raises(ValueError, match="enrolled"):
        backend.prepare(n, slots, columns, replies, q, psi, struct.pack(f"<{len(index)}Q", *([q] * len(index))))
    with pytest.raises(ValueError, match="context"):
        backend.prepare(n, slots, columns, replies, q, 1, bytes(len(index) * 8))
