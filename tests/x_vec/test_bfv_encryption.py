"""BFV algebra tests use deliberately insecure small rings to exercise boundaries cheaply."""

import json
import random
from dataclasses import replace

import pytest
from gmpy2 import mpz

from xtrace_sdk.x_vec.crypto.encryption.bfv import BFV, _poly_product, _round_div
from xtrace_sdk.x_vec.utils.xtrace_types import BFVCiphertext, BFVKeyPair, BFVParameters


@pytest.fixture(scope="module")
def keys() -> BFVKeyPair:
    return BFV.key_gen(16, 97, 100, 15, rotation_steps=[1, -1, 2, 4])


def schoolbook(lhs: list[int], rhs: list[int]) -> list[int]:
    """Independent O(N^2) integer oracle, including the sign from X^N = -1."""
    result = [0] * len(lhs)
    for i, a in enumerate(lhs):
        for j, b in enumerate(rhs):
            result[(i + j) % len(lhs)] += a * b * (1 if i + j < len(lhs) else -1)
    return result


@pytest.mark.parametrize("bits", [1, 17, 180, 512])
def test_gmp_polynomial_product_against_integer_oracle(bits: int) -> None:
    rng = random.Random(bits)
    for n in (8, 16, 32):
        for a, b in [
            ([0] * n, [0] * n),
            ([2**bits - 1] * n, [2**bits - 1] * n),
            ([rng.getrandbits(bits) for _ in range(n)], [rng.getrandbits(bits) for _ in range(n)]),
        ]:
            assert _poly_product(tuple(map(mpz, a)), tuple(map(mpz, b))) == tuple(schoolbook(a, b))


def test_signed_exact_rounding() -> None:
    assert [_round_div(mpz(v), mpz(2)) for v in range(-5, 6)] == [
        -2,
        -2,
        -1,
        -1,
        0,
        0,
        1,
        1,
        2,
        2,
        3,
    ]
    value = (mpz(1) << 400) + 123
    assert _round_div(value * 7 - 3, mpz(7)) == value
    assert _round_div(-value * 7 + 3, mpz(7)) == -value


def test_batching_is_ring_crt_not_just_a_roundtrip(keys: BFVKeyPair) -> None:
    params = keys["pk"]["params"]
    a, b = list(range(16)), [96 - i for i in range(16)]
    pa, pb = BFV.batch_encode(a, params), BFV.batch_encode(b, params)
    product = tuple(mpz(c % 97) for c in schoolbook(list(map(int, pa)), list(map(int, pb))))
    assert BFV.batch_decode(product, params) == [x * y % 97 for x, y in zip(a, b, strict=True)]
    assert BFV.batch_decode(BFV.batch_encode([96, 0, 1], params), params) == [96, 0, 1] + [0] * 13
    assert BFV.batch_decode(BFV.batch_encode([], params), params) == [0] * 16


def test_encrypt_decrypt_and_randomization(keys: BFVKeyPair) -> None:
    pk = keys["pk"]
    for values in ([0] * 16, [96] * 16, list(range(16))):
        plaintext = BFV.batch_encode(values, pk["params"])
        ct1, ct2 = BFV.encrypt(plaintext, pk), BFV.encrypt(plaintext, pk)
        assert ct1 != ct2
        assert BFV.decrypt(ct1, keys) == plaintext
        assert BFV.decrypt(ct2, keys) == plaintext
        assert BFV.noise_budget(ct1, keys) > 0


def test_encrypted_arithmetic_and_relinearization(keys: BFVKeyPair) -> None:
    pk, rng = keys["pk"], random.Random(103)
    params = pk["params"]
    for _ in range(5):
        a, b = [rng.randrange(97) for _ in range(16)], [rng.randrange(97) for _ in range(16)]
        pa, pb = BFV.batch_encode(a, params), BFV.batch_encode(b, params)
        ca, cb = BFV.encrypt(pa, pk), BFV.encrypt(pb, pk)
        operations = [
            (BFV.add(ca, cb, pk), [(x + y) % 97 for x, y in zip(a, b, strict=True)]),
            (BFV.subtract(ca, cb, pk), [(x - y) % 97 for x, y in zip(a, b, strict=True)]),
            (BFV.add_plain(ca, pb, pk), [(x + y) % 97 for x, y in zip(a, b, strict=True)]),
            (BFV.multiply_plain(ca, pb, pk), [x * y % 97 for x, y in zip(a, b, strict=True)]),
        ]
        quadratic = BFV.multiply(ca, cb, pk, relinearize=False)
        linear = BFV.relinearize(quadratic, pk)
        assert len(quadratic.components) == 3
        assert len(linear.components) == 2
        expected = [x * y % 97 for x, y in zip(a, b, strict=True)]
        operations.extend(
            [(quadratic, expected), (linear, expected), (BFV.multiply(ca, cb, pk), expected)]
        )
        # A second multiplication exercises the scale and relinearization noise
        # together; it would fail if the tensor product were reduced prematurely.
        operations.append(
            (BFV.multiply(linear, ca, pk), [x * y * x % 97 for x, y in zip(a, b, strict=True)])
        )
        for ct, expected in operations:
            assert BFV.batch_decode(BFV.decrypt(ct, keys), params) == expected


@pytest.mark.parametrize("steps", [0, 1, -1, 2, 4, 9])
def test_row_rotations(keys: BFVKeyPair, steps: int) -> None:
    pk = keys["pk"]
    a = list(range(16))
    ct = BFV.encrypt(BFV.batch_encode(a, pk["params"]), pk)
    expected = [a[row * 8 + (column + steps) % 8] for row in range(2) for column in range(8)]
    assert (
        BFV.batch_decode(BFV.decrypt(BFV.rotate_rows(ct, steps, pk), keys), pk["params"])
        == expected
    )


def test_binary_xor_and_terminal_modulus_switch(keys: BFVKeyPair) -> None:
    pk, params = keys["pk"], keys["pk"]["params"]
    a, b = [0, 0, 1, 1] * 4, [0, 1, 0, 1] * 4
    ca, cb = (BFV.encrypt(BFV.batch_encode(values, params), pk) for values in (a, b))
    full = BFV.xor(ca, cb, pk)
    compact = BFV.modulus_switch(full, 40, pk)
    assert BFV.batch_decode(BFV.decrypt(compact, keys), params) == [
        x ^ y for x, y in zip(a, b, strict=True)
    ]
    assert BFV.decrypt(full, keys) == BFV.decrypt(compact, keys)
    assert compact.modulus.bit_length() == 40
    assert BFV.noise_budget(full, keys) > BFV.noise_budget(compact, keys) > 0
    with pytest.raises(ValueError, match="original modulus"):
        BFV.multiply(compact, compact, pk)
    with pytest.raises(ValueError, match="original modulus"):
        BFV.rotate_rows(compact, 1, pk)
    with pytest.raises(ValueError):
        BFV.add(full, compact, pk)
    with pytest.raises(ValueError):
        BFV.modulus_switch(compact, 50, pk)


def test_key_and_ciphertext_serialization(keys: BFVKeyPair) -> None:
    pk = BFV.deserialize_public_key(BFV.serialize_public_key(keys["pk"]))
    sk = BFV.deserialize_secret_key(BFV.serialize_secret_key(keys["sk"]), pk)
    assert {"pk": pk, "sk": sk} == keys
    for values in ([0] * 16, [96] * 16):
        ct = BFV.encrypt(BFV.batch_encode(values, pk["params"]), pk)
        for candidate in (
            ct,
            BFV.multiply(ct, ct, pk, relinearize=False),
            BFV.modulus_switch(ct, 40, pk),
        ):
            wire = BFV.ciphertext_to_ints(candidate, pk)
            assert BFV.ciphertext_from_ints(wire, pk) == candidate
            as_bytes = [v.to_bytes((v.bit_length() + 7) // 8, "little") for v in wire]
            assert BFV.ciphertext_from_ints(as_bytes, pk) == candidate


def test_reject_missing_evaluation_keys() -> None:
    keys = BFV.key_gen(16, 97, 100, 15, relinearization=False)
    pk = keys["pk"]
    ct = BFV.encrypt(BFV.batch_encode([1], pk["params"]), pk)
    assert (
        BFV.batch_decode(
            BFV.decrypt(BFV.multiply(ct, ct, pk, relinearize=False), keys), pk["params"]
        )
        == [1] + [0] * 15
    )
    with pytest.raises(ValueError, match="relinearization key"):
        BFV.multiply(ct, ct, pk)
    with pytest.raises(ValueError, match="rotation key"):
        BFV.rotate_rows(ct, 1, pk)


def test_reject_mixed_keys_and_bad_wire(keys: BFVKeyPair) -> None:
    pk = keys["pk"]
    ct = BFV.encrypt(BFV.batch_encode([1], pk["params"]), pk)
    other = BFV.key_gen(16, 97, 100, 15)
    with pytest.raises(ValueError, match="different BFV key"):
        BFV.decrypt(ct, other)
    with pytest.raises(ValueError):
        BFV.decrypt(replace(ct, components=(ct.components[0][:-1], ct.components[1])), keys)
    wire = BFV.ciphertext_to_ints(ct, pk)
    malformed = [
        wire[:-1],
        [-1, *wire[1:]],
        [*wire[:1], 2, *wire[2:]],
        [*wire[:3], 97, *wire[4:]],
        [*wire[:4], 0, *wire[5:]],
        [*wire[:6], 1 << (16 * 100), wire[7]],
        [*wire[:6], int(pk["q"]), wire[7]],
    ]
    for value in malformed:
        with pytest.raises(ValueError):
            BFV.ciphertext_from_ints(value, pk)


def test_reject_corrupted_keys(keys: BFVKeyPair) -> None:
    data = json.loads(BFV.serialize_public_key(keys["pk"]))
    data["b"][0] = "0" if data["b"][0] != "0" else "1"
    with pytest.raises(ValueError, match="fingerprint"):
        BFV.deserialize_public_key(json.dumps(data))
    sk = json.loads(BFV.serialize_secret_key(keys["sk"]))
    sk["s"][0] = 0 if sk["s"][0] else 1
    with pytest.raises(ValueError, match="does not match"):
        BFV.deserialize_secret_key(json.dumps(sk), keys["pk"])
    for value in ("{}", "null", "[]"):
        with pytest.raises(ValueError):
            BFV.deserialize_public_key(value)


@pytest.mark.parametrize(
    "changes",
    [
        {"poly_modulus_degree": 12},
        {"poly_modulus_degree": 4},
        {"plain_modulus": 33},
        {"plain_modulus": 101},
        {"coeff_modulus_bits": 12},
        {"decomposition_bits": 0},
        {"error_eta": 0},
        {"error_eta": 65},
        {"poly_modulus_degree": True},
    ],
)
def test_reject_invalid_parameters(changes: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        BFV.validate_parameters(replace(BFVParameters(16, 97, 100, 15), **changes))


def test_reject_invalid_plaintext(keys: BFVKeyPair) -> None:
    pk = keys["pk"]
    for slots in ([97], [-1], [0] * 17, [1.5]):
        with pytest.raises(ValueError):
            BFV.batch_encode(slots, pk["params"])
    with pytest.raises(ValueError, match="exactly N"):
        BFV.encrypt((mpz(0),), pk)
