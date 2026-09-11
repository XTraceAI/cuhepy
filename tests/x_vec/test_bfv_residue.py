"""Persistent RNS ciphertexts: compatibility, exact oracles and public-only search."""

import hashlib
import json
from dataclasses import asdict, replace

import gmpy2
import pytest

from xtrace_sdk.x_vec.crypto.bfv_client import BFVClient
from xtrace_sdk.x_vec.crypto.encryption.bfv import BFV, _rns_coefficient_primes
from xtrace_sdk.x_vec.utils.xtrace_types import BFVParameters


def test_default_keys_keep_original_fingerprints_and_serialization() -> None:
    keys = BFV.key_gen(16, 97, 100, 15)
    pk = keys["pk"]
    legacy_params = asdict(pk["params"])
    del legacy_params["rns_modulus"]
    digest = hashlib.sha256(json.dumps(legacy_params, sort_keys=True).encode())
    for poly in (pk["b"], pk["a"]):
        for c in poly:
            digest.update(int(c).to_bytes(13, "little"))
    assert pk["key_id"] == digest.hexdigest()
    encoded = BFV.serialize_public_key(pk)
    assert "rns_modulus" not in json.loads(encoded)["params"]
    assert BFV.deserialize_public_key(encoded) == pk
    client = BFVClient(3, 16, 97, 100, 15, response_modulus_bits=40)
    assert "rns_modulus" not in json.loads(client.stringify_config())


@pytest.mark.parametrize("bits", [60, 120, 180, 480])
def test_rns_modulus_key_roundtrip_and_equal_bit_compaction(bits: int) -> None:
    keys = BFV.key_gen(16, 97, bits, 15, rns_modulus=True)
    pk = keys["pk"]
    assert pk["q"].bit_length() == bits
    primes = _rns_coefficient_primes(16, bits)
    assert len(primes) == bits // 60
    assert len(set(primes)) == len(primes)
    assert all(gmpy2.is_prime(p) and p % 32 == 1 for p in primes)
    product = gmpy2.mpz(1)
    for p in primes:
        product *= p
    assert pk["q"] == product
    encoded = BFV.serialize_public_key(pk)
    assert json.loads(encoded)["params"]["rns_modulus"] is True
    assert BFV.deserialize_public_key(encoded) == pk
    assert BFV.deserialize_secret_key(BFV.serialize_secret_key(keys["sk"]), pk) == keys["sk"]
    slots = list(range(16))
    ct = BFV.encrypt(BFV.batch_encode(slots, pk["params"]), pk)
    assert BFV.modulus_switch(ct, bits, pk) == ct
    assert BFV.batch_decode(BFV.decrypt(ct, keys), pk["params"]) == slots


@pytest.mark.parametrize(
    "changes",
    [
        {"rns_modulus": 1},
        {"rns_modulus": "yes"},
        {"coeff_modulus_bits": 100},
        {"coeff_modulus_bits": 512},
    ],
)
def test_rns_parameter_validation(changes) -> None:
    with pytest.raises(ValueError):
        BFV.validate_parameters(
            replace(BFVParameters(16, 97, 180, 15, rns_modulus=True), **changes)
        )


@pytest.mark.parametrize("bits,gadget", [(60, 4), (120, 15), (180, 30), (180, 61), (480, 127)])
def test_residue_search_matches_every_backend(bits: int, gadget: int) -> None:
    pytest.importorskip("xtrace_sdk.x_vec.crypto.bfv_cpu_ext._bfv_rns")
    client = BFVClient(3, 16, 97, bits, gadget, response_modulus_bits=40, rns_modulus=True)
    # Uneven tile and merge counts, two rows, multiple responses and padding.
    vectors = [[0, 1, 0], [1, 0, 1], [0, 0, 0]] * 13
    query = client.encrypt_vec_one([0, 1, 0])
    index = client.encrypt_vec_packed(vectors)
    results = []
    for backend in ("reference", "optimized", "rns", "native", "residue"):
        server = BFVClient(skip_key_gen=True, server_backend=backend)
        server.load_config(json.loads(client.stringify_config()))
        server.load_stringified_keys(client.stringify_pk())
        assert server.keys is None
        for compact in (False, True):
            result = server.encode_hamming_server_packed(
                query, index, len(vectors), compact=compact
            )
            assert client.decode_hamming_client_packed(result, len(vectors)) == [0, 3, 1] * 13
            results.append(result)
        assert server.encode_hamming_server_packed(query, [], 0) == []
        if backend == "residue":
            info = server._evaluator().cache_info()
            assert info["residue_prime_count"] == info["switch_prime_count"] == bits // 60
    assert all(result == results[0] for result in results[::2])
    assert all(result == results[1] for result in results[1::2])


def test_residue_rejects_existing_prime_modulus_keys() -> None:
    native = pytest.importorskip("xtrace_sdk.x_vec.crypto.bfv_cpu_ext._bfv_rns")
    with pytest.raises(ValueError, match="fresh keys"):
        BFVClient(server_backend="residue")
    client = BFVClient(3, 16, 97, 100, 15, response_modulus_bits=40)
    client.server_backend = "residue"
    query = client.encrypt_vec_one([0, 1, 0])
    with pytest.raises(ValueError, match="fresh keys"):
        client.encode_hamming_server(query, query)
    with pytest.raises(ValueError, match="product"):
        native.create_ring(16, format(client._pk()["q"], "x"), 15, True, True)
