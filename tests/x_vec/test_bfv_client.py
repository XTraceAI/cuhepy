"""Native BFV Hamming interface, packing, persistence and public-only evaluation."""

import json
import random
import subprocess
import sys
from pathlib import Path

import pytest

from xtrace_sdk.x_vec.crypto.bfv_client import BFVClient
from xtrace_sdk.x_vec.crypto.encryption.bfv import BFV
from xtrace_sdk.x_vec.crypto.hamming_client_base import HammingClientBase


def small_client(dimension: int = 3) -> BFVClient:
    # Deliberately insecure parameters: fast tests, not a deployment preset.
    return BFVClient(dimension, 32, 193, 120, 20, response_modulus_bits=40)


def public_server(client: BFVClient, backend: str = "optimized") -> BFVClient:
    server = BFVClient(skip_key_gen=True, server_backend=backend)
    server.load_config(json.loads(client.stringify_config()))
    server.load_stringified_keys(client.stringify_pk())
    assert server.keys is None
    return server


def data(count: int, dimension: int) -> tuple[list[list[int]], list[int], list[int]]:
    rng = random.Random(97 + dimension + count)
    query = [rng.randrange(2) for _ in range(dimension)]
    vectors = [[rng.randrange(2) for _ in range(dimension)] for _ in range(count)]
    if count:
        vectors[0] = query[:]
    if count > 1:
        vectors[1] = [1 - bit for bit in query]
    if count > 2:
        vectors[-1] = query[:]
    return vectors, query, [sum(x != y for x, y in zip(query, v, strict=True)) for v in vectors]


def test_base_interface_and_individual_batch() -> None:
    client = small_client()
    server = public_server(client)
    assert isinstance(client, HammingClientBase)
    vectors, query, expected = data(13, 3)
    index, encrypted_query = client.encrypt_vec_batch(vectors), client.encrypt_vec_one(query)
    assert len(index) == len(vectors)
    response = [server.encode_hamming_server(encrypted_query, ct) for ct in index]
    assert client.decode_hamming_client_batch(response) == expected
    assert client.encrypt_vec_batch([]) == []
    assert client.decode_hamming_client_batch([]) == []
    with pytest.raises(RuntimeError, match="Secret key"):
        server.decode_hamming_client_one(response[0])
    with pytest.raises(RuntimeError, match="Secret key"):
        server.stringify_sk()
    restored = BFVClient(skip_key_gen=True)
    restored.load_config(json.loads(client.stringify_config()))
    restored.load_stringified_keys(client.stringify_pk(), client.stringify_sk())
    assert restored.decode_hamming_client_batch(response) == expected
    # Public-only clients can also encrypt, without access to a secret key.
    fresh_query = server.encrypt_vec_one(query)
    assert (
        client.decode_hamming_client_one(server.encode_hamming_server(fresh_query, index[0])) == 0
    )


@pytest.mark.parametrize("dimension", [1, 3, 9, 16])
def test_packed_tile_row_and_response_boundaries(dimension: int) -> None:
    client = small_client(dimension)
    server = public_server(client)
    c = client.vectors_per_ciphertext
    reference = public_server(client, "reference")
    for count in sorted({0, 1, c - 1, c, c + 1, 31, 32, 33, 67}):
        vectors, query, expected = data(count, dimension)
        index = client.encrypt_vec_packed(vectors)
        assert len(index) == (count + c - 1) // c
        encrypted_query = client.encrypt_vec_one(query)
        result = server.encode_hamming_server_packed(encrypted_query, index, count)
        assert result == reference.encode_hamming_server_packed(encrypted_query, index, count)
        assert len(result) == (count + 31) // 32
        distances = client.decode_hamming_client_packed(result, count)
        assert distances == expected
        assert (
            sorted(range(count), key=lambda i: (distances[i], i))[:3]
            == sorted(range(count), key=lambda i: (expected[i], i))[:3]
        )


def test_partial_tile_padding_is_zero_and_compaction_preserves_distances() -> None:
    client = small_client(9)
    vectors, query, expected = data(13, 9)
    query_ct, index = client.encrypt_vec_one(query), client.encrypt_vec_packed(vectors)
    response = client.encode_hamming_server_packed(query_ct, index, 13, compact=False)
    pk, keys = client._pk(), client._keys()
    ct = BFV.ciphertext_from_ints(response[0], pk)
    slots = BFV.batch_decode(BFV.decrypt(ct, keys), client.params)
    used = set()
    for pos, value in enumerate(expected):
        tile, lane = divmod(pos, client.vectors_per_ciphertext)
        row, column = divmod(lane, client.lanes_per_row)
        slot = row * 16 + tile * client.lanes_per_row + column
        used.add(slot)
        assert slots[slot] == value
    assert all(slots[i] == 0 for i in range(32) if i not in used)
    compact = BFV.ciphertext_to_ints(BFV.modulus_switch(ct, 40, pk), pk)
    assert client.decode_hamming_client_packed([compact], 13) == expected
    reference = public_server(client, "reference")
    assert reference.encode_hamming_server_packed(query_ct, index, 13, compact=False) == response
    assert sum(v.bit_length() for v in compact) < sum(v.bit_length() for v in response[0]) / 2


def test_public_only_evaluator_in_separate_process(tmp_path: Path) -> None:
    client = small_client(9)
    vectors, query, expected = data(35, 9)
    public = json.loads(client.stringify_pk())
    assert set(public) == {"version", "params", "key_id", "b", "a", "relin_key", "galois_keys"}
    packet = {
        "config": json.loads(client.stringify_config()),
        "pk": client.stringify_pk(),
        "query": [format(v, "x") for v in client.encrypt_vec_one(query)],
        "index": [[format(v, "x") for v in ct] for ct in client.encrypt_vec_packed(vectors)],
        "count": len(vectors),
    }
    path = tmp_path / "public.json"
    path.write_text(json.dumps(packet))
    script = """
import json, sys
from pathlib import Path
from xtrace_sdk.x_vec.crypto.bfv_client import BFVClient
p = json.loads(Path(sys.argv[1]).read_text())
s = BFVClient(skip_key_gen=True)
s.load_config(p['config'])
s.load_stringified_keys(p['pk'])
assert s.keys is None
assert not any('tenseal' in name or 'sealapi' in name for name in sys.modules)
response = s.encode_hamming_server_packed(
    [int(v, 16) for v in p['query']],
    [[int(v, 16) for v in row] for row in p['index']], p['count'])
print(json.dumps([[format(v, 'x') for v in row] for row in response]))
"""
    run = subprocess.run(
        [sys.executable, "-c", script, str(path)],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    response = [[int(v, 16) for v in row] for row in json.loads(run.stdout)]
    assert client.decode_hamming_client_packed(response, len(vectors)) == expected


def test_invalid_vectors_keys_configuration_and_counts() -> None:
    client = small_client()
    query = client.encrypt_vec_one([0, 1, 0])
    index = client.encrypt_vec_packed([[0, 1, 0]])
    for vector in ([0], [0, 1, 2], [0, -1, 1], [0, 1, 0.0]):
        with pytest.raises(ValueError):
            client.encrypt_vec_one(vector)
        with pytest.raises(ValueError):
            client.encrypt_vec_packed([vector])
    for count in (-1, 0, 9, True):
        with pytest.raises(ValueError, match="vector_count"):
            client.encode_hamming_server_packed(query, index, count)
    with pytest.raises(ValueError, match="vector_count"):
        client.decode_hamming_client_packed([], 1)
    with pytest.raises(ValueError, match="configuration"):
        BFVClient(skip_key_gen=True).load_stringified_keys(client.stringify_pk())
    with pytest.raises(ValueError, match="empty client"):
        client.load_config({**json.loads(client.stringify_config()), "embed_len": 2})
    with pytest.raises(RuntimeError, match="Keys not initialized"):
        BFVClient(skip_key_gen=True).encrypt_vec_one([0] * 512)
    with pytest.raises(NotImplementedError, match="CPU"):
        BFVClient(device="gpu")
    assert not client.has_gpu()
    with pytest.raises(ValueError, match="server_backend"):
        BFVClient(skip_key_gen=True, server_backend="invalid")
    for dimension in (0, -1, 17):
        with pytest.raises(ValueError, match="embed_len"):
            small_client(dimension)


def test_backend_and_key_reload_reset_public_evaluator() -> None:
    client = small_client()
    server = public_server(client, "reference")
    assert server.server_backend == "reference"
    assert "server_backend" not in json.loads(server.stringify_config())
    query = client.encrypt_vec_one([0, 1, 0])
    reference = server.encode_hamming_server(query, query)
    server.server_backend = "optimized"
    assert server.encode_hamming_server(query, query) == reference
    old_evaluator = server._evaluator()
    assert old_evaluator._switch_keys
    replacement = small_client()
    server.load_stringified_keys(replacement.stringify_pk())
    assert server._server_evaluator is None
    assert server._evaluator() is not old_evaluator
    assert not server._evaluator()._switch_keys
    with pytest.raises(ValueError, match="header or key"):
        server.encode_hamming_server(query, query)
    query = replacement.encrypt_vec_one([0, 1, 0])
    assert replacement.decode_hamming_client_one(server.encode_hamming_server(query, query)) == 0


@pytest.fixture(scope="module")
def default_case() -> tuple[BFVClient, list[list[int]], list[int], list[int]]:
    client = BFVClient()
    vectors, query, expected = data(33, 512)
    index = client.encrypt_vec_packed(vectors)
    encrypted_query = client.encrypt_vec_one(query)
    result = client.encode_hamming_server_packed(encrypted_query, index, len(vectors))
    reference = BFVClient(skip_key_gen=True, server_backend="reference")
    reference.public_key = client._pk()
    assert reference.encode_hamming_server_packed(encrypted_query, index, len(vectors)) == result
    distances = client.decode_hamming_client_packed(result, len(vectors))
    assert distances == expected
    assert BFV.noise_budget(BFV.ciphertext_from_ints(result[0], client._pk()), client._keys()) >= 10
    assert len(index) == 3 and len(result) == 1
    return client, vectors, query, distances


def test_default_parameters_512_bit_vectors(default_case: tuple) -> None:
    client, vectors, query, distances = default_case
    assert client.device == "cpu"
    assert distances[0] == 0 and distances[1] == 512 and distances[-1] == 0
    individual = client.encrypt_vec_batch(vectors[:2])
    encrypted_query = client.encrypt_vec_one(query)
    response = [client.encode_hamming_server(encrypted_query, ct) for ct in individual]
    assert client.decode_hamming_client_batch(response) == [0, 512]


def test_optional_seal_reference(default_case: tuple) -> None:
    # SEAL is only an optional independent oracle in tests. Native code does not
    # use its arithmetic, keys, serialization or slot ordering internally.
    ts = pytest.importorskip(
        "tenseal", reason="Optional sanity check: install experiments/bfv/requirements.txt"
    )
    _, vectors, query, native_distances = default_case
    context = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=8192, plain_modulus=65537)
    context.generate_galois_keys()
    encrypted_query = ts.bfv_vector(context, query)
    for i in (0, 1, 17, 32):
        difference = encrypted_query - ts.bfv_vector(context, vectors[i])
        assert (difference * difference).sum().decrypt() == [native_distances[i]]
