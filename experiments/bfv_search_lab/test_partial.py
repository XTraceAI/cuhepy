"""Experimental layouts: exact coefficients, distances, bounds and ownership."""

from concurrent.futures import ThreadPoolExecutor
import random

import pytest

from cuhepy.bfv.cuda import cuda_available
from cuhepy.bfv.private import BFVPrivateDecoder
from cuhepy.hamming.bfv import BFVClient
from experiments.bfv_search_lab.partial import (
    PartialCudaServer,
    PartialLayout,
    PartialNativeServer,
    reference_search,
)


@pytest.fixture(params=[(3, 16, 97), (5, 64, 257)])
def owner(request):
    pytest.importorskip("cuhepy.bfv._cpu_ext._bfv_rns")
    d, n, t = request.param
    return BFVClient(
        d, n, t, 180, 30, response_modulus_bits=40, rns_modulus=True, server_backend="residue"
    )


@pytest.mark.parametrize("gpu", [False, True], ids=["native", "cuda"])
@pytest.mark.parametrize("compact", [False, True])
def test_ciphertexts_and_distances(owner, gpu, compact):
    if gpu and not cuda_available():
        pytest.skip("CUDA device/extension required")
    rng = random.Random(163)
    query = [rng.randrange(2) for _ in range(owner.embed_len)]
    rows = [
        [rng.randrange(2) for _ in query] for _ in range(2 * owner.params.poly_modulus_degree + 1)
    ]
    rows[:3] = [query, [1 - bit for bit in query], [0] * len(query)]
    encrypted = owner.encrypt_vec_one(query)
    index = owner.encrypt_vec_packed(rows)
    capacity = owner.vectors_per_ciphertext
    for partials in (1 << i for i in range(owner.padded_embed_len.bit_length())):
        layout = PartialLayout(owner.params.poly_modulus_degree, owner.embed_len, partials)
        cls = PartialCudaServer if gpu else PartialNativeServer
        server = cls(owner._evaluator()._rns, layout, owner.response_modulus_bits)
        for count in (
            0,
            1,
            capacity - 1,
            capacity,
            capacity + 1,
            layout.n - 1,
            layout.n + 1,
            len(rows),
        ):
            subindex = index[: (count + capacity - 1) // capacity]
            expected = reference_search(owner, encrypted, subindex, count, layout, compact=compact)
            actual = server.search(encrypted, subindex, count, compact=compact)
            assert actual == expected
            assert layout.decode(owner, actual, count) == [
                sum(a != b for a, b in zip(query, row, strict=True)) for row in rows[:count]
            ]
            if partials == 1:
                assert actual == owner.encode_hamming_server_packed(
                    encrypted, subindex, count, compact=compact
                )


def test_prepared_concurrent_and_native_private_decode(owner):
    if not cuda_available():
        pytest.skip("CUDA device/extension required")
    layout = PartialLayout(owner.params.poly_modulus_degree, owner.embed_len, 2)
    server = PartialCudaServer(owner._evaluator()._rns, layout, 40, batch_tiles=1)
    rows = [[0] * owner.embed_len, [1] * owner.embed_len] * 13
    index = server.prepare_index(owner.encrypt_vec_packed(rows), len(rows))
    queries = [owner.encrypt_vec_one([bit] * owner.embed_len) for bit in (0, 1)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda query: server.search_prepared(query, index), queries))
    private = BFVPrivateDecoder(owner)
    try:
        assert layout.decode(owner, responses[0], len(rows), private) == [0, owner.embed_len] * 13
        assert layout.decode(owner, responses[1], len(rows), private) == [owner.embed_len, 0] * 13
    finally:
        private.close()
    other = PartialCudaServer(
        owner._evaluator()._rns, PartialLayout(layout.n, layout.dimension, 1), 40
    )
    with pytest.raises(ValueError, match="another"):
        other.search_prepared(queries[0], index)


@pytest.mark.parametrize("partials", [0, -1, 3, 32, True, 1.0])
def test_layout_rejects_invalid_counts(partials):
    with pytest.raises(ValueError):
        PartialLayout(16, 3, partials)


def test_native_boundary_rejects_invalid_counts(owner):
    arithmetic = owner._evaluator()._rns
    relin = arithmetic._prepare_key(0, owner._pk()["relin_key"])
    for partials in (0, -1, 3, owner.padded_embed_len * 2, True, 1.0):
        with pytest.raises((ValueError, OverflowError)):
            arithmetic._native.create_partial_server(
                relin,
                (),
                owner.padded_embed_len,
                owner.params.plain_modulus,
                "ffffffffff",
                partials,
            )


def test_bad_counts_and_owner_layout(owner):
    layout = PartialLayout(owner.params.poly_modulus_degree, owner.embed_len, 2)
    with pytest.raises(ValueError):
        layout.decode(owner, [], 1)
    with pytest.raises(ValueError):
        layout.decode(owner, [], True)
    with pytest.raises(ValueError):
        PartialLayout(layout.n, owner.embed_len + 1, 1).decode(owner, [], 0)


def test_prime_modulus_native_partial_path():
    pytest.importorskip("cuhepy.bfv._cpu_ext._bfv_rns")
    owner = BFVClient(3, 16, 97, 180, 30, response_modulus_bits=40, server_backend="native")
    query = [1, 0, 1]
    rows = [[0, 0, 0], query, [0, 1, 0]] * 7
    encrypted, index = owner.encrypt_vec_one(query), owner.encrypt_vec_packed(rows)
    for count in (1, 7, len(rows)):
        selected = index[
            : (count + owner.vectors_per_ciphertext - 1) // owner.vectors_per_ciphertext
        ]
        for parts in (1, 2, 4):
            layout = PartialLayout(16, 3, parts)
            server = PartialNativeServer(owner._evaluator()._rns, layout, 40)
            result = server.search(encrypted, selected, count)
            assert result == reference_search(owner, encrypted, selected, count, layout)
            assert (
                layout.decode(owner, result, count)
                == [2, 0, 3] * (count // 3) + [2, 0, 3][: count % 3]
            )
