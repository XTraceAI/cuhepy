"""Optional native RNS/NTT kernels: independent oracles and boundary validation."""

import gc
import json
import math
import random
from concurrent.futures import ThreadPoolExecutor

import gmpy2
import pytest
from gmpy2 import mpz

from xtrace_sdk.x_vec.crypto.bfv_client import BFVClient
from xtrace_sdk.x_vec.crypto.encryption.bfv import BFV, _poly_product
from xtrace_sdk.x_vec.crypto.encryption.bfv_evaluator import BFVEvaluator
from xtrace_sdk.x_vec.crypto.encryption.bfv_rns import BFVRNSArithmetic
from xtrace_sdk.x_vec.utils.xtrace_types import BFVCiphertext, BFVKeyPair

native = pytest.importorskip(
    "xtrace_sdk.x_vec.crypto.bfv_cpu_ext._bfv_rns", reason="Build the optional BFV CPU extension"
)


def schoolbook(a: tuple, b: tuple) -> tuple:
    result = [mpz(0)] * len(a)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            result[(i + j) % len(a)] += x * y * (1 if i + j < len(a) else -1)
    return tuple(result)


@pytest.mark.parametrize(
    "q_bits,bits",
    [
        (31, 1),
        (100, 15),
        (180, 30),
        (180, 59),
        (180, 60),
        (180, 61),
        (512, 127),
        (512, 1),
        (100, 100),
    ],
)
@pytest.mark.parametrize("fast", [False, True])
def test_rns_switch_and_products_against_integer_oracle(q_bits: int, bits: int, fast: bool) -> None:
    keys = BFV.key_gen(8, 17, q_bits, bits)
    pk, rng = keys["pk"], random.Random(bits)
    q = pk["q"]
    arithmetic = BFVRNSArithmetic(pk, fast=fast)
    maximum = (q - 1,) * 8
    random_poly = tuple(mpz(rng.randrange(q)) for _ in range(8))
    inputs = [(mpz(0),) * 8, maximum, (mpz(0),) * 7 + (q - 1,), random_poly]
    # Maximum gadget keys stress the sum-of-products CRT bound. This oracle
    # uses signed schoolbook convolution, not either implementation's kernels.
    digit_count = len(pk["relin_key"])
    key = tuple((maximum, random_poly) for _ in range(digit_count))
    for poly in inputs:
        expected = [[mpz(0)] * 8 for _ in range(2)]
        for digit, pair in enumerate(key):
            part = tuple((c >> (digit * bits)) & ((1 << bits) - 1) for c in poly)
            for k in range(2):
                for i, value in enumerate(schoolbook(part, pair[k])):
                    expected[k][i] += value
        assert arithmetic.switch(poly, 0, key) == tuple(
            tuple(c % q for c in row) for row in expected
        )
        for other in (maximum, random_poly):
            assert arithmetic.product(poly, other) == tuple(c % q for c in schoolbook(poly, other))
    info = arithmetic.cache_info()
    primes = info["primes"]
    assert len(primes) == len(set(primes))
    assert all(2**59 < p < 2**60 and p % 16 == 1 and gmpy2.is_prime(p) for p in primes)
    modulus = math.prod(primes[: info["switch_prime_count"]])
    assert modulus > 2 * 8 * digit_count * ((1 << bits) - 1) * (q - 1)


@pytest.fixture(scope="module")
def keys() -> BFVKeyPair:
    return BFV.key_gen(16, 97, 100, 15, rotation_steps=[1, -1, 2, 4])


def test_exact_signed_tensor_scaling_and_multiple_levels(keys: BFVKeyPair) -> None:
    pk, rng = keys["pk"], random.Random(20)
    arithmetic = BFVRNSArithmetic(pk)
    evaluator = BFVEvaluator(pk, "rns")
    maximum = (pk["q"] - 1,) * 16
    for components in (
        (maximum, maximum),
        ((mpz(0),) * 16, maximum),
        tuple(tuple(mpz(rng.randrange(pk["q"])) for _ in range(16)) for _ in range(2)),
    ):
        ct = BFVCiphertext(components, pk["q"], pk["key_id"])
        assert (
            arithmetic.multiply(components, components, 97)
            == BFV.multiply(ct, ct, pk, relinearize=False).components
        )
    a, b = list(range(16)), [96 - i for i in range(16)]
    ca, cb = (BFV.encrypt(BFV.batch_encode(v, pk["params"]), pk) for v in (a, b))
    product = evaluator.multiply(ca, cb)
    assert product == BFV.multiply(ca, cb, pk)
    product = evaluator.multiply(product, ca)
    assert BFV.batch_decode(BFV.decrypt(product, keys), pk["params"]) == [
        x * y * x % 97 for x, y in zip(a, b, strict=True)
    ]


def test_native_buffers_capsules_and_parameter_bounds(keys: BFVKeyPair) -> None:
    pk = keys["pk"]
    arithmetic = BFVRNSArithmetic(pk)
    ring, poly = arithmetic._ring, arithmetic._pack(pk["a"])
    for wrong in (poly[:-1], poly + b"\0", arithmetic._pack((pk["q"],) * 16)):
        with pytest.raises(ValueError):
            native.ring_product(ring, wrong, poly)
    with pytest.raises(TypeError):
        native.ring_product(ring, [0] * len(poly), poly)
    with pytest.raises(ValueError):
        native.ring_product(None, poly, poly)
    for n, q, bits in (
        (7, "11", 1),
        (2**32 + 8, "11", 1),
        (8, "-1", 1),
        (8, "bad!", 1),
        (8, "11", 0),
        (8, "11", 513),
        (8, "11", 2**32 + 1),
    ):
        with pytest.raises((ValueError, OverflowError)):
            native.create_ring(n, q, bits)
    for t in (-1, -(1 << 64) + 17, 1 << 64, 1 << 63, 0, 1):
        with pytest.raises((ValueError, OverflowError)):
            native.multiply(ring, (poly, poly), None, t)
    with pytest.raises(ValueError):
        native.multiply(ring, (poly,), None, 97)
    with pytest.raises(ValueError):
        native.compile_key(ring, ())
    key = arithmetic._prepare_key(0, pk["relin_key"])
    for exponent in (0, 2, 32, -1, 1 << 64):
        with pytest.raises((ValueError, OverflowError)):
            native.rotate_rows(key, (poly, poly), exponent)
    other = BFVRNSArithmetic(pk)
    other_key = other._prepare_key(0, pk["relin_key"])
    with pytest.raises(ValueError, match="another native ring"):
        native.hamming_tile(key, (poly, poly), (poly, poly), ((3, other_key),), poly, 97)
    # The key owns a shared reference to its native plan after Python owners die.
    expected = native.apply_key(key, poly)
    del arithmetic, ring
    gc.collect()
    assert native.apply_key(key, poly) == expected


def test_public_server_cache_reload_and_concurrent_searches() -> None:
    client = BFVClient(9, 32, 193, 120, 20, response_modulus_bits=40)
    server = BFVClient(skip_key_gen=True, server_backend="rns")
    server.load_config(json.loads(client.stringify_config()))
    server.load_stringified_keys(client.stringify_pk())
    assert server.keys is None
    query = client.encrypt_vec_one([0, 1, 0] * 3)
    vectors = [[0, 1, 0] * 3, [1, 0, 1] * 3, [0] * 9] * 13
    index = client.encrypt_vec_packed(vectors)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda _: server.encode_hamming_server_packed(query, index, len(vectors)), range(6)
            )
        )
    assert all(result == results[0] for result in results)
    assert client.decode_hamming_client_packed(results[0], len(vectors)) == [0, 9, 3] * 13
    info = server._evaluator().cache_info()
    assert info["switch_keys"] <= len(client._pk()["galois_keys"]) + 1
    assert info["key_payload_bytes"] > 0
    server.load_stringified_keys(client.stringify_pk())
    assert server._evaluator().cache_info()["switch_keys"] == 0
    assert server.encode_hamming_server_packed(query, index, len(vectors)) == results[0]


def test_default_parameters_match_gmp() -> None:
    client = BFVClient()
    rng = random.Random(1337)
    query = [rng.getrandbits(1) for _ in range(512)]
    vectors = [[rng.getrandbits(1) for _ in range(512)] for _ in range(33)]
    vectors[0] = query[:]
    vectors[1] = [1 - bit for bit in query]
    encrypted_query, index = client.encrypt_vec_one(query), client.encrypt_vec_packed(vectors)
    original = client.encode_hamming_server_packed(encrypted_query, index, 33, compact=False)
    client.server_backend = "rns"
    assert (
        client.encode_hamming_server_packed(encrypted_query, index, 33, compact=False) == original
    )
    response = client.encode_hamming_server_packed(encrypted_query, index, 33)
    assert client.decode_hamming_client_packed(response, 33) == [
        sum(x != y for x, y in zip(v, query, strict=True)) for v in vectors
    ]
