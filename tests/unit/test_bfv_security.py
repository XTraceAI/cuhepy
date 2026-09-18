"""Security boundaries and malformed-input regressions for experimental BFV.

Some tests deliberately demonstrate attacks against hypothetical integrations.
Their success records a limitation; it does NOT mean the attack was prevented.
All keys/data are generated locally for the tests. No service is contacted.
"""

import hashlib
import json
import random
from dataclasses import replace

import gmpy2
import pytest
from gmpy2 import mpz

from cuhepy.hamming.bfv import BFVClient
from cuhepy.bfv import scheme as bfv
from cuhepy.bfv.scheme import BFV
from cuhepy.bfv.evaluator import BFVEvaluator
from cuhepy.types import BFVCiphertext


@pytest.fixture(scope="module")
def client() -> BFVClient:
    # Insecure small ring for fast, reproducible algebra/security-contract tests.
    return BFVClient(3, 16, 97, 120, 15, response_modulus_bits=40, rns_modulus=True)


def public_server(client: BFVClient, backend="residue", level=None) -> BFVClient:
    server = BFVClient(skip_key_gen=True, server_backend=backend)
    server.load_config(json.loads(client.stringify_config()))
    server.load_stringified_keys(client.stringify_pk())
    if level is not None:
        server._server_evaluator = BFVEvaluator(server._pk(), backend, kernel_level=level)
        server._evaluator_public_key = server._pk()
    assert server.keys is None
    return server


def test_decryption_oracle_would_reveal_secret_key(client: BFVClient) -> None:
    """Releasing one raw chosen decryption can disclose every ternary coefficient."""
    pk, keys = client._pk(), client._keys()
    n, t = client.params.poly_modulus_degree, client.params.plain_modulus
    delta = pk["q"] // t
    forged = BFVCiphertext(((mpz(0),) * n, (delta,) + (mpz(0),) * (n - 1)), pk["q"], pk["key_id"])
    wire = BFV.ciphertext_to_ints(forged, pk)
    # Syntax validation cannot distinguish this from an encryption's origin.
    observed = BFV.decrypt(BFV.ciphertext_from_ints(wire, pk), keys)
    recovered = tuple(c if c <= t // 2 else c - t for c in observed)
    assert recovered == keys["sk"]["s"]


def test_valid_distance_range_does_not_authenticate_answer(client: BFVClient) -> None:
    pk, n = client._pk(), client.params.poly_modulus_degree
    zero = BFVCiphertext(((mpz(0),) * n,) * 2, pk["q"], pk["key_id"])
    assert client.decode_hamming_client_one(BFV.ciphertext_to_ints(zero, pk)) == 0
    # Anyone with the public key can also forge a nontransparent plausible
    # response. Rejecting all-zero ciphertexts would not solve authenticity.
    forged = BFV.encrypt(BFV.batch_encode([1] * n, client.params), pk)
    assert client.decode_hamming_client_one(BFV.ciphertext_to_ints(forged, pk)) == 1


def test_response_is_not_bound_to_query(client: BFVClient) -> None:
    index = client.encrypt_vec_one([0, 0, 0])
    old = client.encode_hamming_server(client.encrypt_vec_one([0, 0, 0]), index)
    current = client.encode_hamming_server(client.encrypt_vec_one([1, 1, 1]), index)
    assert client.decode_hamming_client_one(current) == 3
    assert client.decode_hamming_client_one(old) == 0  # Replay is still accepted.


def test_key_fingerprint_does_not_authenticate_evaluation_keys(client: BFVClient) -> None:
    original = client.stringify_pk()
    data = json.loads(original)
    data["relin_key"][0][0][0] = format(
        (mpz(data["relin_key"][0][0][0], 16) + client._pk()["q"] // 2) % client._pk()["q"], "x"
    )
    modified = json.dumps(data)
    loaded = BFV.deserialize_public_key(modified)
    assert loaded["key_id"] == client._pk()["key_id"]
    assert loaded["relin_key"] != client._pk()["relin_key"]
    assert hashlib.sha256(original.encode()).digest() != hashlib.sha256(modified.encode()).digest()


def test_randomized_encryption_and_public_only_evaluation(client: BFVClient, monkeypatch) -> None:
    query = client.encrypt_vec_one([0, 1, 0])
    encrypted = [client.encrypt_vec_one([1, 1, 1]) for _ in range(12)]
    assert len({tuple(value) for value in encrypted}) == len(encrypted)
    server = public_server(client, "optimized")

    def private_operation_forbidden(*args, **kwargs):
        raise AssertionError("Server touched secret-key arithmetic")

    with monkeypatch.context() as guard:
        guard.setattr(BFV, "_phase", private_operation_forbidden)
        responses = [server.encode_hamming_server(query, value) for value in encrypted]
    assert client.decode_hamming_client_batch(responses) == [2] * len(responses)
    with pytest.raises(RuntimeError, match="public-only"):
        server.decode_hamming_client_one(responses[0])


def test_randomness_failure_does_not_fall_back_to_predictable_values(client, monkeypatch) -> None:
    def unavailable(*args):
        raise OSError("Synthetic OS entropy failure")

    monkeypatch.setattr(bfv.secrets, "randbelow", unavailable)
    with pytest.raises(OSError, match="entropy"):
        BFV.key_gen(16, 97, 100, 15)
    with pytest.raises(OSError, match="entropy"):
        client.encrypt_vec_one([0, 1, 0])


def test_sampler_bounds_and_signed_binomial_mapping(monkeypatch) -> None:
    bits = iter([0, 7, 7, 0, 7, 7, 0, 0])
    monkeypatch.setattr(bfv.secrets, "randbits", lambda eta: next(bits))
    assert bfv._small_poly(4, 3, mpz(97)) == (94, 3, 0, 0)
    ternary = iter([0, 1, 2])
    monkeypatch.setattr(bfv.secrets, "randbelow", lambda bound: next(ternary))
    assert bfv._ternary_poly(3, mpz(97)) == (96, 0, 1)


@pytest.mark.parametrize("entry", range(8))
def test_wire_zero_padding_is_bounded_before_integer_conversion(client, entry) -> None:
    wire = client.encrypt_vec_one([0, 1, 0])
    n, bits = client.params.poly_modulus_degree, client._pk()["q"].bit_length()
    limits = [4, 1, (n.bit_length() + 7) // 8, (bits + 7) // 8, 32, 1, n * bits // 8, n * bits // 8]
    wire[entry] = wire[entry].to_bytes(limits[entry], "little") + b"\0"
    with pytest.raises(ValueError, match="byte limit"):
        BFV.ciphertext_from_ints(wire, client._pk())
    pytest.importorskip("cuhepy.bfv._cpu_ext._bfv_rns")
    with pytest.raises(ValueError, match="byte limit"):
        public_server(client)._native()._wire(wire)


@pytest.mark.parametrize("value", [True, 1.0, bytearray(b"\1"), -1, 1 << 256])
def test_wire_rejects_ambiguous_or_out_of_bounds_values(client, value) -> None:
    wire = client.encrypt_vec_one([0, 1, 0])
    wire[1] = value
    with pytest.raises(ValueError):
        BFV.ciphertext_from_ints(wire, client._pk())


@pytest.mark.parametrize("quadratic", [False, True])
def test_response_shape_checked_before_decryption(client, monkeypatch, quadratic) -> None:
    pk = client._pk()
    ct = BFV.ciphertext_from_ints(client.encrypt_vec_one([0, 1, 0]), pk)
    if quadratic:
        ct = replace(ct, components=(*ct.components, (mpz(0),) * 16))
    else:
        ct = BFV.modulus_switch(ct, 35, pk)  # Valid raw BFV, wrong negotiated response modulus.
    wire = BFV.ciphertext_to_ints(ct, pk)
    monkeypatch.setattr(BFV, "decrypt", lambda *args: pytest.fail("Unexpected private operation"))
    with pytest.raises(ValueError, match="Unexpected BFV response"):
        client.decode_hamming_client_one(wire)


@pytest.mark.parametrize("private", [False, True])
def test_key_json_size_limit_checked_before_parser(client, monkeypatch, private) -> None:
    encoded = client.stringify_sk() if private else client.stringify_pk()
    loader = (
        (lambda s, **kw: BFV.deserialize_secret_key(s, client._pk(), **kw))
        if private
        else BFV.deserialize_public_key
    )
    with monkeypatch.context() as guard:
        guard.setattr(
            bfv.json, "loads", lambda *args, **kwargs: pytest.fail("Oversized JSON was parsed")
        )
        with pytest.raises(ValueError, match="character limit"):
            loader(encoded, max_chars=len(encoded) - 1)
    assert loader(encoded, max_chars=len(encoded))


@pytest.mark.parametrize("private", [False, True])
@pytest.mark.parametrize(
    "bad", ['{"version":1,"version":1}', "[" * 1100 + "0" + "]" * 1100, "null", "[]"]
)
def test_key_json_duplicate_fields_and_nesting_rejected(client, private, bad) -> None:
    with pytest.raises(ValueError):
        if private:
            BFV.deserialize_secret_key(bad, client._pk())
        else:
            BFV.deserialize_public_key(bad)


@pytest.mark.parametrize("private", [False, True])
def test_boolean_key_version_rejected(client, private) -> None:
    data = json.loads(client.stringify_sk() if private else client.stringify_pk())
    data["version"] = True
    with pytest.raises(ValueError, match="version"):
        if private:
            BFV.deserialize_secret_key(json.dumps(data), client._pk())
        else:
            BFV.deserialize_public_key(json.dumps(data))


@pytest.mark.parametrize(
    "coefficient", ["", "00", "+1", "-0", "0x1", " 1", "1_0", "F", "0" * 10000]
)
def test_key_coefficients_have_bounded_canonical_hex(client, coefficient) -> None:
    data = json.loads(client.stringify_pk())
    data["a"][0] = coefficient
    with pytest.raises(ValueError, match="key polynomial"):
        BFV.deserialize_public_key(json.dumps(data))


@pytest.mark.parametrize("exponent", ["03", "+3", "3_0", "٣", "0" * 10000, "2", "33"])
def test_galois_names_do_not_alias_or_escape_ring(client, exponent) -> None:
    data = json.loads(client.stringify_pk())
    data["galois_keys"] = {exponent: next(iter(data["galois_keys"].values()))}
    with pytest.raises(ValueError, match="Galois"):
        BFV.deserialize_public_key(json.dumps(data))


def test_failed_key_load_preserves_client_state(client) -> None:
    fresh = public_server(client, "optimized")
    before = fresh._pk()
    with pytest.raises(ValueError):
        fresh.load_stringified_keys(client.stringify_pk(), '{"s":[]}')
    assert fresh._pk() is before and fresh.keys is None


@pytest.mark.parametrize("text", ["0" * 10000 + "3", "f" * 129, "+3", " 3", "3\0", "0x3"])
def test_native_modulus_text_bounded_before_gmp(client, text) -> None:
    native = pytest.importorskip("cuhepy.bfv._cpu_ext._bfv_rns")
    with pytest.raises(ValueError, match="modulus"):
        native.create_ring(16, text, 15)
    server = public_server(client)._native()
    with pytest.raises(ValueError, match="modulus"):
        native.create_server(
            server.arithmetic._prepare_key(0, client._pk()["relin_key"]), (), 4, 97, text
        )


@pytest.mark.parametrize("level", [0, 1, 2])
def test_mutated_wire_corpus_agrees_with_reference(client, level) -> None:
    """Bounded mutation fuzzing, including arbitrary valid attacker ciphertexts."""
    pytest.importorskip("cuhepy.bfv._cpu_ext._bfv_rns")
    server = public_server(client, level=level)
    reference = public_server(client, "reference")
    wire = client.encrypt_vec_one([0, 1, 0])
    rng = random.Random(20260910)
    for sample in range(150):
        candidate = wire[:]
        at = rng.randrange(8)
        candidate[at] ^= 1 << rng.randrange(max(1, candidate[at].bit_length() + 2))
        if sample % 3 == 0:
            candidate[at] = candidate[at].to_bytes((candidate[at].bit_length() + 7) // 8, "little")
        try:
            expected = reference.encode_hamming_server(candidate, wire)
        except ValueError:
            with pytest.raises(ValueError):
                server.encode_hamming_server(candidate, wire)
        else:
            assert server.encode_hamming_server(candidate, wire) == expected


def test_native_coefficient_bounds_before_kernels(client) -> None:
    native = pytest.importorskip("cuhepy.bfv._cpu_ext._bfv_rns")
    server = public_server(client)._native()
    arithmetic, q = server.arithmetic, client._pk()["q"]
    zero = bytes(arithmetic.n * arithmetic.width)
    rng = random.Random(6421)
    for sample in range(100):
        coefficients = [mpz(rng.randrange(int(q))) for _ in range(arithmetic.n)]
        if sample % 2:
            coefficients[sample % arithmetic.n] = q  # Must not be silently reduced.
        data = gmpy2.pack(coefficients, 8 * arithmetic.width).to_bytes(len(zero), "little")
        if sample % 2:
            with pytest.raises(ValueError, match="Noncanonical"):
                native.ring_product(arithmetic._ring, data, zero)
        else:
            assert native.ring_product(arithmetic._ring, data, zero) == zero


def test_direct_ciphertext_rejects_noninteger_modulus(client) -> None:
    pk = client._pk()
    ct = BFV.ciphertext_from_ints(client.encrypt_vec_one([0, 1, 0]), pk)
    ct = replace(ct, modulus=float(pk["q"] // 2))
    with pytest.raises(ValueError, match="integer"):
        BFV.decrypt(ct, client._keys())
    with pytest.raises(ValueError, match="integer"):
        BFVEvaluator(pk).add(ct, ct)


def test_default_rns_circuit_structured_inputs_across_fresh_keys() -> None:
    """Exercise real defaults and extreme plaintext patterns; no failure-rate claim."""
    pytest.importorskip("cuhepy.bfv._cpu_ext._bfv_rns")
    rng = random.Random(314159)
    patterns = [
        [0] * 512,
        [1] * 512,
        [0, 1] * 256,
        [1] + [0] * 511,
        [0] * 511 + [1],
        [rng.randrange(2) for _ in range(512)],
    ]
    vectors = (patterns * 6)[:33]  # Full tiles plus a partial tile and merge.
    for _ in range(2):
        private = BFVClient(rns_modulus=True)
        server = BFVClient(skip_key_gen=True, rns_modulus=True, server_backend="residue")
        server.public_key = private._pk()  # Trusted generated PK; contains no secret.
        index = private.encrypt_vec_packed(vectors)
        for query in patterns:
            response = server.encode_hamming_server_packed(
                private.encrypt_vec_one(query), index, len(vectors)
            )
            expected = [sum(a != b for a, b in zip(query, v, strict=True)) for v in vectors]
            assert private.decode_hamming_client_packed(response, len(vectors)) == expected
            assert (
                BFV.noise_budget(
                    BFV.ciphertext_from_ints(response[0], private._pk()), private._keys()
                )
                > 0
            )
        assert server.keys is None
