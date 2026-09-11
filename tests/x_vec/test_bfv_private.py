"""Independent arithmetic and ownership tests for the private terminal decoder."""

import random
import os
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from gmpy2 import mpz

from xtrace_sdk.x_vec.crypto.bfv_client import BFVClient
from xtrace_sdk.x_vec.crypto.encryption.bfv import (
    BFV,
    _coefficient_modulus,
    _rns_coefficient_primes,
)
from xtrace_sdk.x_vec.crypto.encryption.bfv_private import BFVPrivateDecoder
from xtrace_sdk.x_vec.utils.xtrace_types import BFVCiphertext


@pytest.fixture(scope="module")
def native():
    return pytest.importorskip("xtrace_sdk.x_vec.crypto.bfv_cpu_ext._bfv_private")


def pack(values):
    return b"".join(int(v).to_bytes(8, "little") for v in values)


def slots(encoded):
    return [int.from_bytes(encoded[i : i + 4], "little") for i in range(0, len(encoded), 4)]


def independent_slots(c0, c1, secret, q, t):
    n = len(secret)
    phase = [
        (c0[i] + sum(c1[j] * (secret[i - j] if i >= j else -secret[n + i - j]) for j in range(n)))
        % q
        for i in range(n)
    ]
    plaintext = [((2 * t * value + q) // (2 * q)) % t for value in phase]
    candidate = 2
    while True:
        psi = pow(candidate, (t - 1) // (2 * n), t)
        if pow(psi, n, t) == t - 1:
            break
        candidate += 1
    exponents = [pow(3, i, 2 * n) for i in range(n // 2)]
    exponents += [(-e) % (2 * n) for e in exponents]
    return [sum(m * pow(psi, e * j, t) for j, m in enumerate(plaintext)) % t for e in exponents]


@pytest.mark.parametrize("n,t", [(8, 17), (16, 97), (32, 193)])
def test_dense_chosen_components_match_schoolbook_and_direct_evaluation(native, n, t):
    rng = random.Random(931 + n)
    q = int(_coefficient_modulus(40))
    for _ in range(15):
        secret = [rng.randrange(-1, 2) for _ in range(n)]
        context = native.create_decoder(
            n, q, t, *_rns_coefficient_primes(n, 120), bytes(s & 255 for s in secret)
        )
        c0, c1 = ([rng.randrange(q) for _ in range(n)] for _ in range(2))
        assert slots(native.decode_slots(context, pack(c0), pack(c1))) == independent_slots(
            c0, c1, secret, q, t
        )
        native.close_decoder(context)


def test_every_plaintext_rounding_boundary(native):
    n, t, q = 8, 17, int(_coefficient_modulus(40))
    secret = [1, -1, 0, 1, 0, -1, 1, 0]
    context = native.create_decoder(
        n, q, t, *_rns_coefficient_primes(n, 120), bytes(s & 255 for s in secret)
    )
    for message in range(t):
        for offset in (-2, -1, 0, 1, 2):
            c0 = [(q * (2 * message + 1) // (2 * t) + offset) % q] * n
            c1 = [0] * n
            assert slots(native.decode_slots(context, pack(c0), pack(c1))) == independent_slots(
                c0, c1, secret, q, t
            )


@pytest.mark.parametrize("n", [8192, 16384, 32768])
def test_worst_supported_signed_convolution_matches_gmp(native, n):
    # Known synthetic secret and extremal PUBLIC components, not generated production keys.
    raw = BFVClient(3, n, 65537, 180, 30, rns_modulus=True)
    q = int(_coefficient_modulus(50))
    secret = (mpz(1),) * n
    raw.keys["sk"]["s"] = secret
    decoder = BFVPrivateDecoder(raw)
    for c0_value, c1_value in ((q - 1, q - 1), (0, q - 1), (q - 1, 0)):
        ct = BFVCiphertext(((mpz(c0_value),) * n, (mpz(c1_value),) * n), q, raw._pk()["key_id"])
        expected = BFV.batch_decode(BFV.decrypt(ct, raw._keys()), raw.params)
        assert decoder.decode_slots(BFV.ciphertext_to_ints(ct, raw._pk())) == expected
    decoder.close()


@pytest.mark.parametrize("bad", [b"", b"\x02" * 16, b"\x80" * 16, b"\x00" * 17])
def test_invalid_secret_encoding_rejected(native, bad):
    with pytest.raises((ValueError, TypeError)):
        native.create_decoder(
            16, int(_coefficient_modulus(40)), 97, *_rns_coefficient_primes(16, 120), bad
        )


@pytest.mark.parametrize(
    "field,value", [(0, True), (0, 65536), (1, 1 << 50), (2, 1 << 30), (3, 1), (4, 1)]
)
def test_private_parameters_rejected_before_transform(native, field, value):
    args = [16, int(_coefficient_modulus(40)), 97, *_rns_coefficient_primes(16, 120), b"\x00" * 16]
    args[field] = value
    with pytest.raises((ValueError, TypeError, OverflowError)):
        native.create_decoder(*args)


def test_noncanonical_ciphertexts_and_closed_context(native):
    q = int(_coefficient_modulus(40))
    context = native.create_decoder(16, q, 97, *_rns_coefficient_primes(16, 120), b"\x01" * 16)
    for value in (b"", b"\x00" * 127, pack([q] + [0] * 15), b"\xff" * 128):
        with pytest.raises(ValueError):
            native.decode_slots(context, value, b"\x00" * 128)
    native.close_decoder(context)
    native.close_decoder(context)
    with pytest.raises(RuntimeError, match="closed"):
        native.decode_slots(context, b"\x00" * 128, b"\x00" * 128)


def test_close_and_decode_do_not_deadlock_or_use_wiped_key(native):
    q = int(_coefficient_modulus(40))
    context = native.create_decoder(128, q, 257, *_rns_coefficient_primes(128, 120), b"\x01" * 128)

    def run():
        try:
            return native.decode_slots(context, b"\x00" * 1024, b"\x00" * 1024)
        except RuntimeError:
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(run) for _ in range(10)]
        pool.submit(native.close_decoder, context).result(timeout=10)
        for future in futures:
            assert future.result(timeout=10) in (None, b"\x00" * 512)


def test_missing_or_wrong_private_extension_never_falls_back(monkeypatch):
    import xtrace_sdk.x_vec.crypto.bfv_cpu_ext as package

    raw = BFVClient(3, 16, 97, 120, 15, response_modulus_bits=40, rns_modulus=True)
    monkeypatch.setattr(package, "_bfv_private", SimpleNamespace(ABI_VERSION=0), raising=False)
    with pytest.raises(RuntimeError, match="ABI 1"):
        BFVPrivateDecoder(raw)


def test_memory_lock_failure_has_no_unlocked_fallback(native):
    if "asan" in os.environ.get("LD_PRELOAD", ""):
        pytest.skip("ASan intercepts mlock; exercise the real OS limit in the release suite")
    # Change the limit only in an isolated child, loading the exact tested binary.
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            textwrap.dedent("""
                import importlib.util
                import resource
                import sys
                spec = importlib.util.spec_from_file_location("_bfv_private", sys.argv[1])
                native = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(native)
                resource.setrlimit(resource.RLIMIT_MEMLOCK, (0, 0))
                try:
                    native.create_decoder(16, 1125899906842597, 97,
                        1152921504606830593, 1152921504606748673, bytes(16))
                except RuntimeError as error:
                    assert "locking failed" in str(error)
                else:
                    raise AssertionError("Private key accepted without memory locking")
            """),
            native.__file__,
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
