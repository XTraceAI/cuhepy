"""Complete native server: public-only evaluation, wire boundaries and profiling."""

import gc
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from cuhepy.bfv.client import BFVClient
from cuhepy.bfv.rns import BFVRNSArithmetic

native = pytest.importorskip("cuhepy.bfv._cpu_ext._bfv_rns")


@pytest.fixture(params=["native", "residue"])
def client(request) -> BFVClient:
    residue = request.param == "residue"
    return BFVClient(
        3,
        16,
        97,
        180 if residue else 100,
        15,
        response_modulus_bits=40,
        server_backend=request.param,
        rns_modulus=residue,
    )


def test_native_individual_wire_bytes_and_backend_changes(client: BFVClient) -> None:
    query, other = client.encrypt_vec_one([0, 1, 0]), client.encrypt_vec_one([1, 0, 1])
    responses = []
    for backend in ("native", "rns", "reference", "optimized", "native"):
        client.server_backend = backend
        responses.append(client.encode_hamming_server(query, other))
    assert all(response == responses[0] for response in responses)
    assert client.decode_hamming_client_one(responses[0]) == 3
    byte_query = [v.to_bytes((v.bit_length() + 7) // 8, "little") for v in query]
    assert client.encode_hamming_server(byte_query, other) == responses[0]
    client.response_modulus_bits = 45
    changed = client.encode_hamming_server(query, other)
    assert changed[3].bit_length() == 45
    assert client.decode_hamming_client_one(changed) == 3
    client.response_modulus_bits = 10
    with pytest.raises(ValueError, match="target modulus"):
        client.encode_hamming_server(query, other)


def test_complete_search_skips_python_polynomial_conversions(
    client: BFVClient, monkeypatch
) -> None:
    from cuhepy.bfv.scheme import BFV

    query = client.encrypt_vec_one([0, 1, 0])
    vectors = [[0, 1, 0], [1, 0, 1], [0, 0, 0]] * 13
    index = client.encrypt_vec_packed(vectors)
    server = BFVClient(skip_key_gen=True, server_backend=client.server_backend)
    server.load_config(json.loads(client.stringify_config()))
    server.load_stringified_keys(client.stringify_pk())
    assert server.keys is None

    def forbidden(*args, **kwargs):
        raise AssertionError("Server must keep intermediate polynomials in C++")

    with monkeypatch.context() as patch:
        for name in (
            "ciphertext_from_ints",
            "ciphertext_to_ints",
            "batch_encode",
            "modulus_switch",
        ):
            patch.setattr(BFV, name, forbidden)
        response = server.encode_hamming_server_packed(query, index, len(vectors))
    assert client.decode_hamming_client_packed(response, len(vectors)) == [0, 3, 1] * 13
    old_plan = server._native()
    server.load_stringified_keys(client.stringify_pk())
    assert server._native() is not old_plan
    assert server.encode_hamming_server_packed(query, index, len(vectors)) == response


def test_profile_is_transparent_and_thread_local(client: BFVClient) -> None:
    query = client.encrypt_vec_one([0, 1, 0])
    index = client.encrypt_vec_packed([[0, 1, 0], [1, 0, 1]] * 5)
    evaluator = client._native()
    expected = evaluator.search(query, index, 10)

    def evaluate(_: int):
        profile = {}
        result = evaluator.search(query, index, 10, profile=profile)
        assert result == expected
        assert sum(v["seconds"] for v in profile.values()) > 0
        assert all(v["seconds"] >= 0 and v["calls"] >= 0 for v in profile.values())
        assert profile["wire_import"]["calls"] == 2 * (1 + len(index))
        assert profile["wire_export"]["calls"] == 2
        return {name: value["calls"] for name, value in profile.items()}

    with ThreadPoolExecutor(max_workers=2) as pool:
        counts = list(pool.map(evaluate, range(6)))
    assert all(count == counts[0] for count in counts)
    assert evaluator.search(query, index, 10) == expected
    with pytest.raises(ZeroDivisionError):
        native.profile_call(lambda: 1 / 0)
    result, profile = native.profile_call(lambda: evaluator.search(query, index, 10))
    assert result == expected
    assert profile["wire_import"]["calls"] == 2 * (1 + len(index))


def test_native_rejects_malformed_wire(client: BFVClient) -> None:
    query = client.encrypt_vec_one([0, 1, 0])
    q = int(client._pk()["q"])
    packed_bits = 16 * q.bit_length()
    changes = [
        (0, 0),
        (1, 2),
        (2, 32),
        (3, q - 2),
        (4, query[4] + 1),
        (5, 3),
        (6, -1),
        (6, 0.5),
        (6, 1 << packed_bits),
        (6, q << (packed_bits - q.bit_length())),
    ]
    for offset, value in changes:
        malformed = query[:]
        malformed[offset] = value
        with pytest.raises(ValueError):
            client.encode_hamming_server_packed(query, [malformed], 1)
    for count in (-1, True, 1.0, 5):
        with pytest.raises(ValueError):
            client.encode_hamming_server_packed(query, [query], count)
    with pytest.raises(ValueError):
        client.encode_hamming_server(query[:-1], query)
    other = BFVClient(3, 16, 97, 100, 15, response_modulus_bits=40)
    with pytest.raises(ValueError, match="key"):
        client.encode_hamming_server(query, other.encrypt_vec_one([0, 1, 0]))


def test_private_native_boundary_and_plan_lifetime(client: BFVClient) -> None:
    evaluator = client._native()
    arithmetic = evaluator.arithmetic
    pk = client._pk()
    relin = arithmetic._prepare_key(0, pk["relin_key"])
    keys = tuple((g, arithmetic._prepare_key(g, key)) for g, key in pk["galois_keys"].items())
    for padded, t, target in (
        (0, 97, "ffff"),
        (3, 97, "ffff"),
        (32, 97, "ffff"),
        (4, 33, "ffff"),
        (4, 65, "ffff"),
        (4, 97, "0"),
        (4, 97, "!"),
    ):
        with pytest.raises(ValueError):
            native.create_server(relin, keys, padded, t, target)
    with pytest.raises(ValueError, match="Missing"):
        native.create_server(relin, (), 4, 97, "ffff")
    with pytest.raises(ValueError, match="Duplicate"):
        native.create_server(relin, keys + keys[:1], 4, 97, "ffff")
    other = BFVRNSArithmetic(pk)
    other_key = other._prepare_key(0, pk["relin_key"])
    with pytest.raises(ValueError, match="another native ring"):
        native.create_server(relin, ((3, other_key),), 4, 97, "ffff")
    wire = evaluator._wire(client.encrypt_vec_one([0, 1, 0]))
    plan = evaluator._server
    for index, count in (((), 1), ((wire,), -1), ((wire,), 1 << 65), (((b"", b""),), 1)):
        with pytest.raises((ValueError, OverflowError)):
            native.packed_search(plan, wire, index, count, True)
    # Use a fresh ring with no BFVClient owner to test the plan's ownership.
    owned = BFVRNSArithmetic(pk, fast=True, residue=pk["params"].rns_modulus)
    relin = owned._prepare_key(0, pk["relin_key"])
    keys = tuple((g, owned._prepare_key(g, key)) for g, key in pk["galois_keys"].items())
    plan = native.create_server(relin, keys, 4, 97, format(evaluator._target, "x"))
    expected = native.packed_search(plan, wire, (wire,), 1, True)
    del owned, relin, keys
    gc.collect()
    assert native.packed_search(plan, wire, (wire,), 1, True) == expected
