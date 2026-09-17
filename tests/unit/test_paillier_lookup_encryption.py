import json
import random

import pytest
from cuhepy.paillier import lookup as paillier_lookup
from cuhepy.paillier.lookup import (
    DEFAULT_ALPHA_LEN,
    MIN_ALPHA_LEN,
)
from cuhepy.paillier.lookup_client import PaillierLookupClient
from cuhepy.types import PaillierLookupKeyPair

random.seed(42)

@pytest.fixture
def key_pair(key_len:int, alpha_len:int) -> PaillierLookupKeyPair:
    """Fixture to generate a key pair for testing."""
    keys = paillier_lookup.PaillierLookup.key_gen(key_len, alpha_len)
    return keys


@pytest.fixture
def random_numbers(key_len:int, num_runs:int) -> list:
    """Fixture to generate a list of random numbers for testing."""
    return [random.randint(1, 2**key_len) for _ in range(num_runs)]


def test_encrypt_and_decrypt(key_pair: PaillierLookupKeyPair, random_numbers: list) -> None:
    """Test the encryption and decryption process."""
    for num in random_numbers:
        ciphertext = paillier_lookup.PaillierLookup.encrypt(num, key_pair['pk'], key_pair['g_table'], key_pair['noise_table'], key_pair['message_chunks'])
        decrypted_num = paillier_lookup.PaillierLookup.decrypt(ciphertext, key_pair)
        assert decrypted_num == num, f"Decrypted number {decrypted_num} does not match original number {num}."


def test_addition_of_ciphers(key_pair: PaillierLookupKeyPair, random_numbers: list, key_len:int) -> None:
    """Test the addition of encrypted numbers."""
    encrypted_numbers = [paillier_lookup.PaillierLookup.encrypt(num, key_pair['pk'], key_pair['g_table'], key_pair['noise_table'], key_pair['message_chunks']) for num in random_numbers]

    # Add the encrypted numbers

    for i in range(len(encrypted_numbers)):
        random_offset = random.randint(1, 2**key_len)
        enc_offset = paillier_lookup.PaillierLookup.encrypt(random_offset, key_pair['pk'], key_pair['g_table'], key_pair['noise_table'], key_pair['message_chunks'])
        encrypted_sum = paillier_lookup.PaillierLookup.add(enc_offset, encrypted_numbers[i], key_pair['pk'])
        # Decrypt the sum
        decrypted_sum = paillier_lookup.PaillierLookup.decrypt(encrypted_sum, key_pair)
        # Check if the decrypted sum matches the sum of original numbers
        assert decrypted_sum == random_numbers[i]+random_offset, f"Decrypted sum {decrypted_sum} does not match expected sum {random_numbers[i]+random_offset}."

# ── PL-01 regression: the secret exponent must not be brute-forceable ────────

def test_default_alpha_len_is_secure() -> None:
    """The client default must meet the MIN_ALPHA_LEN floor."""
    assert DEFAULT_ALPHA_LEN >= MIN_ALPHA_LEN
    client = PaillierLookupClient(embed_len=64, key_len=512)
    assert client.alpha_len == DEFAULT_ALPHA_LEN


def test_weak_alpha_len_is_rejected_on_keygen() -> None:
    with pytest.raises(ValueError, match="insecure"):
        PaillierLookupClient(embed_len=64, key_len=512, alpha_len=50)


def test_weak_alpha_len_allowed_with_explicit_opt_in() -> None:
    """Cryptanalysis and regressions may still generate weak keys deliberately."""
    client = PaillierLookupClient(
        embed_len=64, key_len=512, alpha_len=50, allow_weak_alpha=True
    )
    assert client.alpha_len == 50


def test_loading_weak_key_warns() -> None:
    """An existing weak keypair still loads, but must warn rather than fail."""
    weak = PaillierLookupClient(
        embed_len=64, key_len=512, alpha_len=50, allow_weak_alpha=True
    )
    loaded = PaillierLookupClient(
        embed_len=64, key_len=512, alpha_len=50, skip_key_gen=True
    )
    loaded.load_stringified_keys(weak.stringify_pk(), weak.stringify_sk())
    with pytest.warns(RuntimeWarning, match="recoverable from the public key"):
        loaded.load_config(json.loads(weak.stringify_config()),
                           precomputed_tables=weak.dump_tables())


def test_hamming_roundtrip_at_default_alpha() -> None:
    """Raising alpha_len must not change Hamming-distance correctness."""
    client = PaillierLookupClient(embed_len=64, key_len=512)
    lhs = [i % 2 for i in range(64)]
    rhs = [(i // 2) % 2 for i in range(64)]
    encoded = client.encode_hamming_server(
        client.encrypt_vec_one(lhs), client.encrypt_vec_one(rhs)
    )
    expected = sum(a ^ b for a, b in zip(lhs, rhs, strict=True))
    assert client.decode_hamming_client_one(encoded) == expected
