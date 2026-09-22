"""Exact CUDA/CPU comparisons; small rings below are arithmetic fixtures only."""

from concurrent.futures import ThreadPoolExecutor
import gc
import random

import gmpy2
import pytest

from cuhepy.bfv.cuda import BFVCudaServer, cuda_available
from cuhepy.bfv.scheme import BFV
from cuhepy.hamming.bfv import BFVClient
from cuhepy.hamming.bfv_attested import BFVAttestedServer
from cuhepy.hamming.bfv_verified import BFVProtocolError
from cuhepy.types import BFVCiphertext


@pytest.fixture
def client():
    if not cuda_available():
        pytest.skip("Build the BFV CUDA extension and expose a CUDA device")
    return BFVClient(
        3,
        16,
        97,
        180,
        30,
        response_modulus_bits=40,
        rns_modulus=True,
        server_backend="residue",
    )


def cuda_server(client):
    return BFVCudaServer(
        client._evaluator()._rns, client.padded_embed_len, client.response_modulus_bits
    )


def test_attestation_rejects_cuda_before_setup_or_private_operations():
    with pytest.raises(BFVProtocolError, match="outside.*attestation"):
        BFVAttestedServer(b"", b"", b"", 0, None, backend="cuda")


@pytest.mark.parametrize("compact", [False, True])
def test_partial_tiles_merge_tails_and_multiple_responses(client, compact):
    gpu = cuda_server(client)
    rng = random.Random(73)
    rows = [[rng.randrange(2) for _ in range(3)] for _ in range(37)]
    query = [0, 1, 1]
    encrypted = client.encrypt_vec_one(query)
    for count in (0, 1, 3, 4, 5, 8, 9, 12, 13, 15, 16, 17, 29, 37):
        index = client.encrypt_vec_packed(rows[:count])
        expected = client.encode_hamming_server_packed(encrypted, index, count, compact=compact)
        actual = gpu.search(encrypted, index, count, compact=compact)
        assert actual == expected
        assert client.decode_hamming_client_packed(actual, count) == [
            sum(a != b for a, b in zip(query, row, strict=True)) for row in rows[:count]
        ]


def test_canonical_extremes_and_random_ciphertexts(client):
    # Arbitrary public ciphertext coefficients exercise signed tensor quotients,
    # CRT carry/borrow boundaries, and gadget decomposition beyond valid messages.
    # Compare with the GMP native backend as well as the persistent-residue CPU.
    gpu = cuda_server(client)
    pk, n = client._pk(), client.params.poly_modulus_degree
    q = int(pk["q"])
    rng = random.Random(341)
    values = [0, 1, q - 1, q // 2, (1 << 64) - 1, 1 << 64, (1 << 128) - 1]
    native = BFVClient(skip_key_gen=True, server_backend="native")
    native.public_key = pk
    native.params, native.embed_len, native.response_modulus_bits = client.params, 3, 40
    native._configure_layout()

    def wire(polynomials):
        return BFV.ciphertext_to_ints(
            BFVCiphertext(
                tuple(tuple(gmpy2.mpz(c) for c in p) for p in polynomials), pk["q"], pk["key_id"]
            ),
            pk,
        )

    zero = wire([[0] * n, [0] * n])
    cases = [wire([[v] * n, [v] * n]) for v in values]
    cases += [wire([[rng.randrange(q) for _ in range(n)] for _ in range(2)]) for _ in range(12)]
    for ct in cases:
        expected = native.encode_hamming_server_packed(zero, [ct], 3, compact=False)
        assert gpu.search(zero, [ct], 3, compact=False) == expected
        assert client.encode_hamming_server_packed(zero, [ct], 3, compact=False) == expected


def test_gpu_batch_boundaries_and_public_client_dispatch(client):
    rng = random.Random(17)
    owner = BFVClient(100, 256, 65537, 180, 30, rns_modulus=True, server_backend="residue")
    gpu = BFVClient(
        100, 256, 65537, 180, 30, rns_modulus=True, server_backend="cuda", skip_key_gen=True
    )
    gpu.load_stringified_keys(owner.stringify_pk())
    assert gpu.keys is None
    rows = [[rng.randrange(2) for _ in range(100)] for _ in range(519)]
    query = rows[0]
    encrypted = owner.encrypt_vec_one(query)
    for count in (63, 64, 65, 127, 128, 129, 255, 257, 519):
        index = owner.encrypt_vec_packed(rows[:count])
        actual = gpu.encode_hamming_server_packed(encrypted, index, count)
        assert actual == owner.encode_hamming_server_packed(encrypted, index, count)
        assert owner.decode_hamming_client_packed(actual, count) == [
            sum(a != b for a, b in zip(query, row, strict=True)) for row in rows[:count]
        ]
    prepared = gpu.prepare_cuda_index(index, count)
    assert gpu.encode_hamming_server_prepared(encrypted, prepared) == actual
    # Switching the requested backend creates a new plan, not a stale CUDA plan.
    gpu.server_backend = "residue"
    assert gpu.encode_hamming_server_packed(encrypted, index, count) == actual
    with pytest.raises(ValueError, match="server_backend"):
        gpu.encode_hamming_server_prepared(encrypted, prepared)


def test_reused_plan_concurrent_queries_and_index_mutation(client):
    gpu = cuda_server(client)
    index = client.encrypt_vec_packed([[0, 0, 0], [1, 1, 1], [1, 0, 1]])
    queries = [client.encrypt_vec_one([i & 1, (i >> 1) & 1, 0]) for i in range(4)]
    expected = [client.encode_hamming_server_packed(q, index, 3) for q in queries]
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda q: gpu.search(q, index, 3), queries)) == expected
    index[:] = client.encrypt_vec_packed([[1, 0, 0], [0, 1, 0], [0, 0, 1]])
    assert gpu.search(queries[0], index, 3) == client.encode_hamming_server_packed(
        queries[0], index, 3
    )


def test_malformed_wire_and_native_boundary(client):
    from cuhepy.bfv._gpu_ext import _bfv_cuda as native

    gpu = cuda_server(client)
    q = client.encrypt_vec_one([0, 1, 0])
    modulus = int(client._pk()["q"])
    for offset, value in (
        (0, 0),
        (1, 2),
        (2, 32),
        (3, modulus - 2),
        (4, q[4] + 1),
        (5, 3),
        (6, -1),
        (6, modulus),
    ):
        bad = q[:]
        bad[offset] = value
        with pytest.raises(ValueError):
            gpu.search(q, [bad], 1)
    wire = gpu._wire(q)
    for index, count in (((), 1), ((wire,), -1), ((wire,), 1 << 65), (((b"", b""),), 1)):
        with pytest.raises((ValueError, OverflowError)):
            native.packed_search(gpu._server, wire, index, count, True)
    with pytest.raises(ValueError):
        native.packed_search(client._native()._server, wire, (wire,), 1, True)
    profile = {}
    assert gpu.search(q, [q], 1, profile=profile) == gpu.search(q, [q], 1)
    assert profile["forward_ntt"]["calls"] > 0
    assert profile["inverse_ntt"]["seconds"] > 0
    # Failure must leave the immutable plan usable for later valid requests.
    assert gpu.search(q, [q], 1) == client.encode_hamming_server_packed(q, [q], 1)


def test_unsupported_parameters_fail_without_changing_keys(client):
    for bits, gadget in ((120, 30), (180, 15)):
        other = BFVClient(
            3,
            16,
            97,
            bits,
            gadget,
            rns_modulus=True,
            response_modulus_bits=40,
            server_backend="cuda",
        )
        before = other.stringify_pk()
        q = other.encrypt_vec_one([0, 0, 0])
        with pytest.raises(ValueError, match="CUDA requires"):
            other.encode_hamming_server_packed(q, [q], 1)
        assert other.stringify_pk() == before


@pytest.mark.parametrize("level", [0, 1, 2, 3])
@pytest.mark.parametrize("batch", [1, 3, 32, 64])
def test_kernel_controls_and_prepared_snapshots(client, level, batch):
    server = BFVCudaServer(client._evaluator()._rns, 4, 40, kernel_level=level, batch_tiles=batch)
    rows = [[i % 2, (i // 2) % 2, (i // 4) % 2] for i in range(37)]
    query = client.encrypt_vec_one([0, 1, 0])
    index = client.encrypt_vec_packed(rows)
    expected = client.encode_hamming_server_packed(query, index, len(rows), compact=False)
    prepared = server.prepare_index(index, len(rows))
    assert prepared.device_bytes == len(index) * 6 * client.params.poly_modulus_degree * 8
    assert prepared.vector_count == len(rows)
    assert server.search_prepared(query, prepared, compact=False) == expected
    assert server.search(query, index, len(rows), compact=False) == expected
    index.clear()
    gc.collect()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda _: server.search_prepared(query, prepared, compact=False), range(4))
        )
    assert results == [expected] * 4
    empty = server.prepare_index([], 0)
    assert server.search_prepared(query, empty) == []
    assert empty.device_bytes == 0


def test_prepared_index_context_validation_and_lifetime(client):
    from cuhepy.bfv._gpu_ext import _bfv_cuda as native

    server = cuda_server(client)
    query = client.encrypt_vec_one([1, 0, 1])
    prepared = server.prepare_index([query], 1)
    expected = server.search_prepared(query, prepared)
    other = cuda_server(client)
    with pytest.raises(ValueError, match="another CUDA server"):
        other.search_prepared(query, prepared)
    with pytest.raises(ValueError, match="another CUDA server"):
        native.prepared_search(other._server, other._wire(query), prepared._handle, True)
    handle, plan, wire = prepared._handle, server._server, server._wire(query)
    native_expected = native.prepared_search(plan, wire, handle, True)
    del prepared, server, client
    gc.collect()
    assert native.prepared_search(plan, wire, handle, True) == native_expected
    assert expected


def test_gpu_decoder_rejects_every_packed_coefficient_and_recovers(client):
    server = cuda_server(client)
    query = client.encrypt_vec_one([1, 0, 1])
    q, n = int(client._pk()["q"]), client.params.poly_modulus_degree
    # Exercise every 180-bit alignment, both components, and unused lanes.
    for component in (6, 7):
        for coefficient in range(n):
            bad = query[:]
            shift = coefficient * q.bit_length()
            mask = ((1 << q.bit_length()) - 1) << shift
            bad[component] = (int(bad[component]) & ~mask) | (q << shift)
            with pytest.raises(ValueError, match="Noncanonical"):
                server.prepare_index([bad], 1)
            with pytest.raises(ValueError, match="Noncanonical"):
                server.search(bad, [], 0)
    good = server.prepare_index([query], 1)
    assert client.decode_hamming_client_packed(server.search_prepared(query, good), 1) == [0]


@pytest.mark.parametrize(
    "level,batch", [(True, 32), (-1, 32), (4, 32), (1, 0), (1, 257), (1, True)]
)
def test_invalid_cuda_experiment_controls(client, level, batch):
    with pytest.raises(ValueError):
        BFVCudaServer(client._evaluator()._rns, 4, 40, kernel_level=level, batch_tiles=batch)
