"""Real cryptographic tests; no XTrace account, network, or GPU required."""

import random
import subprocess
import sys
from pathlib import Path

import msgpack
import pytest

pytest.importorskip("tenseal", reason="Install experiments/bfv/requirements.txt")

from packed_hamming import BfvClient, BfvServer, Layout, SLOTS


def vectors_and_query(count: int, dimension: int) -> tuple[list[list[int]], list[int]]:
    rng = random.Random(404 + dimension + count)
    query = [rng.randrange(2) for _ in range(dimension)]
    vectors = [[rng.randrange(2) for _ in range(dimension)] for _ in range(count)]
    if count:
        vectors[0] = query[:]
    if count > 1:
        vectors[1] = [1 - bit for bit in query]
    return vectors, query


def oracle(vectors: list[list[int]], query: list[int], ids: list[int]) -> list[tuple[int, int]]:
    return [(record_id, sum(x != y for x, y in zip(vector, query, strict=True)))
            for record_id, vector in zip(ids, vectors, strict=True)]


def rewrite(payload: bytes, **changes: object) -> bytes:
    packet = msgpack.unpackb(payload, raw=False)
    packet.update(changes)
    return msgpack.packb(packet, use_bin_type=True)


@pytest.fixture(scope="module")
def default_pair() -> tuple[BfvClient, BfvServer]:
    client = BfvClient()
    return client, BfvServer(client.server_bundle())


@pytest.fixture(scope="module")
def default_case(default_pair: tuple[BfvClient, BfvServer]) -> tuple[bytes, list[tuple[int, int]]]:
    client, server = default_pair
    vectors, query = vectors_and_query(45, 512)
    vectors[-1] = query[:]
    ids = list(reversed(range(1000, 1045)))
    response = server.search(client.encrypt_index(vectors, ids), client.encrypt_query(query))
    return response, oracle(vectors, query, ids)


def test_default_exact_distances_and_stable_top_k(default_pair, default_case) -> None:
    client, _ = default_pair
    response, expected = default_case
    assert client.decrypt_distances(response) == expected
    assert client.top_k(response) == sorted(expected, key=lambda pair: (pair[1], pair[0]))[:3]
    assert client.top_k(response, 0) == []
    assert len(client.top_k(response, 100)) == 45
    assert min(client.noise_budgets(response)) >= 10


@pytest.mark.parametrize("dimension", [1, 3, 513, 4096])
def test_dimensions_with_padding_and_extremes(dimension: int) -> None:
    client = BfvClient(dimension)
    server = BfvServer(client.server_bundle())
    vectors, query = vectors_and_query(9, dimension)
    response = server.search(client.encrypt_index(vectors), client.encrypt_query(query))
    assert client.decrypt_distances(response) == oracle(vectors, query, list(range(9)))


@pytest.fixture(scope="module")
def small_dimension_pair() -> tuple[BfvClient, BfvServer]:
    client = BfvClient(4)
    return client, BfvServer(client.server_bundle())


@pytest.mark.parametrize("count", [0, 1, 1025, 2049, SLOTS - 1, SLOTS, SLOTS + 1])
def test_row_tile_and_response_boundaries(small_dimension_pair, count: int) -> None:
    client, server = small_dimension_pair
    vectors, query = vectors_and_query(count, 4)
    response = server.search(client.encrypt_index(vectors), client.encrypt_query(query))
    assert client.decrypt_distances(response) == oracle(vectors, query, list(range(count)))
    assert len(msgpack.unpackb(response, raw=False)["ciphertexts"]) == (count + SLOTS - 1) // SLOTS


@pytest.mark.parametrize("bit", [0, 1])
def test_uniform_vectors_and_zero_distance(default_pair, bit: int) -> None:
    client, server = default_pair
    query = [bit] * 512
    vectors = [query[:], [1 - bit] * 512] * 10
    response = server.search(client.encrypt_index(vectors), client.encrypt_query(query))
    assert client.decrypt_distances(response) == oracle(vectors, query, list(range(20)))


def test_modulus_compaction_preserves_results(default_pair) -> None:
    client, server = default_pair
    vectors, query = vectors_and_query(65, 512)
    index, encrypted_query = client.encrypt_index(vectors), client.encrypt_query(query)
    full = server.search(index, encrypted_query, compact=False)
    compact = server.search(index, encrypted_query)
    assert client.decrypt_distances(full) == client.decrypt_distances(compact)
    assert len(compact) < len(full) / 3
    assert min(client.noise_budgets(full)) > min(client.noise_budgets(compact)) > 0


def test_serialized_server_in_separate_process(default_pair, tmp_path: Path) -> None:
    client, _ = default_pair
    vectors, query = vectors_and_query(19, 512)
    public = client.server_bundle()
    packet = msgpack.unpackb(public, raw=False)
    assert set(packet) == {"protocol", "kind", "dimension", "key_id", "public_key", "relin_keys", "galois_keys"}
    for name, payload in [("keys", public), ("index", client.encrypt_index(vectors)),
                          ("query", client.encrypt_query(query))]:
        (tmp_path / name).write_bytes(payload)
    subprocess.run(
        [sys.executable, "-c",
         "from pathlib import Path; from packed_hamming import BfvServer; "
         "import sys; p=Path(sys.argv[1]); "
         "s=BfvServer((p/'keys').read_bytes()); "
         "(p/'response').write_bytes(s.search((p/'index').read_bytes(), (p/'query').read_bytes()))",
         str(tmp_path)],
        cwd=Path(__file__).parent, check=True, capture_output=True, timeout=60,
    )
    assert client.decrypt_distances((tmp_path / "response").read_bytes()) == oracle(vectors, query, list(range(19)))


def test_encryption_is_randomized(default_pair) -> None:
    client, _ = default_pair
    vector = [0, 1] * 256
    assert client.encrypt_query(vector) != client.encrypt_query(vector)
    assert client.encrypt_index([vector]) != client.encrypt_index([vector])


def test_mismatched_keys_and_malformed_messages(default_pair, default_case) -> None:
    client, server = default_pair
    response, _ = default_case
    query = client.encrypt_query([0] * 512)
    index = client.encrypt_index([[0] * 512])
    with pytest.raises(ValueError, match="different key"):
        server.search(index, rewrite(query, key_id="0" * 64))
    with pytest.raises(ValueError, match="different key"):
        client.decrypt_distances(rewrite(response, dimension=511))
    with pytest.raises(ValueError, match="ciphertexts"):
        server.search(rewrite(index, ciphertexts=[]), query)
    with pytest.raises(ValueError, match="unique"):
        client.decrypt_distances(rewrite(response, ids=[1, 1]))
    with pytest.raises(ValueError, match="Expected"):
        client.decrypt_distances(query)
    with pytest.raises(ValueError):
        client.decrypt_distances(b"not a MessagePack response")


@pytest.mark.parametrize("vector", [[0], [2] * 512, [-1] * 512, [0.5] * 512])
def test_invalid_vectors(default_pair, vector: list[int]) -> None:
    client, _ = default_pair
    with pytest.raises(ValueError):
        client.encrypt_query(vector)
    with pytest.raises(ValueError):
        client.encrypt_index([vector])


def test_invalid_ids_and_k(default_pair, default_case) -> None:
    client, _ = default_pair
    response, _ = default_case
    for ids in [[1, 1], [-1, 2], [1, 2**64], [True, 2], [1]]:
        with pytest.raises(ValueError):
            client.encrypt_index([[0] * 512, [1] * 512], ids)
    for k in [-1, 1.5, True]:
        with pytest.raises(ValueError, match="k must"):
            client.top_k(response, k)


@pytest.mark.parametrize("dimension", [0, -1, 4097, 1.5, True])
def test_invalid_dimensions(dimension: int) -> None:
    with pytest.raises(ValueError):
        Layout(dimension)
