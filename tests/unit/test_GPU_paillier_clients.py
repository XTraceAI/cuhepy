import json
import pickle

import pytest

from cuhepy import keys
from cuhepy.hamming.paillier import PaillierClient
from cuhepy.hamming.paillier_lookup import PaillierLookupClient

_EMBED_LEN = 8
_KEY_LEN = 1024
_VECTORS = [
    [0, 1, 0, 1, 1, 0, 1, 0],
    [1, 1, 0, 0, 1, 0, 0, 1],
    [1, 0, 1, 0, 1, 1, 0, 0],
]

_CLIENTS = [
    pytest.param(PaillierClient, id="paillier"),
    pytest.param(PaillierLookupClient, id="paillier_lookup"),
]


def _hamming(lhs: list[int], rhs: list[int]) -> int:
    return sum(int(a != b) for a, b in zip(lhs, rhs, strict=True))


def _reload(client: object, cls: type, device: str) -> object:
    """Round-trip a client's keys into a fresh client on ``device``."""
    config = json.loads(client.stringify_config())  # type: ignore[attr-defined]
    kwargs = {"embed_len": _EMBED_LEN, "key_len": _KEY_LEN}
    if cls is PaillierLookupClient:
        kwargs["alpha_len"] = config["alpha_len"]
    clone = cls(**kwargs, skip_key_gen=True, device=device)
    clone.load_stringified_keys(
        client.stringify_pk(),  # type: ignore[attr-defined]
        client.stringify_sk(),  # type: ignore[attr-defined]
    )
    if cls is PaillierLookupClient:
        clone.load_config(config, precomputed_tables=client.dump_tables())  # type: ignore[attr-defined]
    else:
        clone.load_config(config)
    return clone


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_consecutive_gpu_clients_generate_distinct_keypairs(client_cls: type) -> None:
    if not client_cls.has_gpu():
        pytest.skip(f"{client_cls.__name__} GPU backend is unavailable on this machine")

    first = client_cls(embed_len=_EMBED_LEN, key_len=_KEY_LEN, device="gpu")
    second = client_cls(embed_len=_EMBED_LEN, key_len=_KEY_LEN, device="gpu")

    assert json.loads(first.stringify_pk()) != json.loads(second.stringify_pk())
    assert json.loads(first.stringify_sk()) != json.loads(second.stringify_sk())


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_gpu_client_encrypt_hamming_and_key_roundtrip(client_cls: type) -> None:
    """Encrypt, evaluate and decode on GPU, then reload the keys and repeat."""
    if not client_cls.has_gpu():
        pytest.skip(f"{client_cls.__name__} GPU backend is unavailable on this machine")

    client = client_cls(embed_len=_EMBED_LEN, key_len=_KEY_LEN, device="gpu")
    assert client.device == "gpu"

    config = json.loads(client.stringify_config())
    assert config["embed_len"] == _EMBED_LEN
    assert config["key_len"] == _KEY_LEN

    cipher_one = client.encrypt_vec_one(_VECTORS[0])
    batch = client.encrypt_vec_batch(_VECTORS)
    assert len(batch) == len(_VECTORS)
    assert len(cipher_one) == len(batch[0]) > 0

    encoded = client.encode_hamming_server(cipher_one, batch[1])
    assert client.decode_hamming_client_one(encoded) == _hamming(_VECTORS[0], _VECTORS[1])

    encoded_batch = [
        client.encode_hamming_server(batch[0], batch[1]),
        client.encode_hamming_server(batch[1], batch[2]),
    ]
    assert client.decode_hamming_client_batch(encoded_batch) == [
        _hamming(_VECTORS[0], _VECTORS[1]),
        _hamming(_VECTORS[1], _VECTORS[2]),
    ]

    clone = _reload(client, client_cls, "gpu")
    clone_encoded = clone.encode_hamming_server(
        clone.encrypt_vec_one(_VECTORS[0]), clone.encrypt_vec_one(_VECTORS[1])
    )
    assert json.loads(clone.stringify_pk()) == json.loads(client.stringify_pk())
    assert json.loads(clone.stringify_sk()) == json.loads(client.stringify_sk())
    assert json.loads(clone.stringify_config()) == config
    assert clone.decode_hamming_client_one(clone_encoded) == _hamming(_VECTORS[0], _VECTORS[1])


@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize(
    ("source_device", "target_device"),
    [pytest.param("cpu", "gpu", id="cpu_to_gpu"), pytest.param("gpu", "cpu", id="gpu_to_cpu")],
)
def test_cross_device_interop(
    client_cls: type, source_device: str, target_device: str
) -> None:
    """Keys are portable: ciphertexts from either backend round-trip through the other."""
    if not client_cls.has_gpu():
        pytest.skip(f"{client_cls.__name__} GPU backend is unavailable on this machine")

    source = client_cls(embed_len=_EMBED_LEN, key_len=_KEY_LEN, device=source_device)
    target = _reload(source, client_cls, target_device)

    assert source.device == source_device
    assert target.device == target_device
    assert json.loads(target.stringify_pk()) == json.loads(source.stringify_pk())

    expected = _hamming(_VECTORS[0], _VECTORS[1])
    src_a = source.encrypt_vec_one(_VECTORS[0])
    src_b = source.encrypt_vec_one(_VECTORS[1])

    # Evaluate on source, decode on target.
    assert target.decode_hamming_client_one(source.encode_hamming_server(src_a, src_b)) == expected
    # Evaluate on target with source's ciphertexts, decode on target.
    assert target.decode_hamming_client_one(target.encode_hamming_server(src_a, src_b)) == expected
    # Reverse: encrypt on target, evaluate on source, decode on source.
    tgt_a = target.encrypt_vec_one(_VECTORS[0])
    tgt_b = target.encrypt_vec_one(_VECTORS[1])
    assert source.decode_hamming_client_one(source.encode_hamming_server(tgt_a, tgt_b)) == expected


def test_paillier_lookup_gpu_pickle_roundtrip() -> None:
    if not PaillierLookupClient.has_gpu():
        pytest.skip("paillier_lookup GPU backend is unavailable on this machine")

    client = PaillierLookupClient(embed_len=_EMBED_LEN, key_len=_KEY_LEN, device="gpu")
    restored = pickle.loads(pickle.dumps(client))

    encoded = restored.encode_hamming_server(
        restored.encrypt_vec_one(_VECTORS[0]), restored.encrypt_vec_one(_VECTORS[1])
    )
    assert restored.decode_hamming_client_one(encoded) == _hamming(_VECTORS[0], _VECTORS[1])


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_keys_save_load_roundtrip(tmp_path, client_cls: type) -> None:
    """cuhepy.keys round-trips a keypair through disk. Runs on CPU."""
    client = client_cls(embed_len=_EMBED_LEN, key_len=_KEY_LEN, device="cpu")
    path = tmp_path / "key.json"
    keys.save(client, path, include_tables=True)

    assert path.stat().st_mode & 0o777 == 0o600

    restored = keys.load(path, device="cpu")
    encoded = restored.encode_hamming_server(
        restored.encrypt_vec_one(_VECTORS[0]), restored.encrypt_vec_one(_VECTORS[1])
    )
    assert restored.decode_hamming_client_one(encoded) == _hamming(_VECTORS[0], _VECTORS[1])
    assert json.loads(restored.stringify_pk()) == json.loads(client.stringify_pk())
