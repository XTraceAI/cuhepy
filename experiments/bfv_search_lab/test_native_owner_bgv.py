"""Private native arithmetic checked against independent Python/GMP fixtures."""

from concurrent.futures import ThreadPoolExecutor
import os
import random
import struct

import gmpy2
from gmpy2 import mpz
import pytest

from cuhepy.bfv.scheme import _ring_product
from experiments.bfv_search_lab import shallow_bgv as bgv, compact_bgv as compact
from experiments.bfv_search_lab import owner_bgv as owner, seeded_bgv as seeded
from experiments.bfv_search_lab.native_owner_bgv import NativeTernaryProduct

native = pytest.importorskip("experiments.bfv_search_lab._owner._bgv_owner")


@pytest.mark.parametrize("n,bits", [(8, 93), (64, 240), (2048, 120), (16384, 120), (32768, 240)])
@pytest.mark.parametrize("rns", [False, True])
def test_native_product_exact_for_random_and_extreme_coefficients(n, bits, rns):
    pk, sk = bgv.key_gen(n, q_bits=bits)
    rng = random.Random(n + bits)
    plan = NativeTernaryProduct(sk.s, pk.q, rns=rns)
    for q in (pk.q, compact.terminal_modulus(pk.q, pk.t, 25), compact.terminal_modulus(pk.q, pk.t, 32)):
        secret = tuple(mpz(q - 1) if c == pk.q - 1 else c for c in sk.s)
        a = tuple(mpz(rng.randrange(int(q))) for _ in range(n))
        assert plan.multiply(a, q) == _ring_product(a, secret, q)
        assert plan.multiply((mpz(q - 1),) * n, q) == _ring_product((mpz(q - 1),) * n, secret, q)
    if n == 8:
        for value in (-1, 0, 1):
            special = NativeTernaryProduct((mpz(value % pk.q),) * n, pk.q, rns=rns)
            assert special.multiply(a, q) == _ring_product(a, (mpz(value % q),) * n, q)
    plan.clear()
    with pytest.raises(RuntimeError, match="closed"):
        plan.multiply(a, q)


@pytest.mark.parametrize("eta", [1, 7, 8, 21, 32, 63, 64])
@pytest.mark.parametrize("rns", [False, True])
def test_native_encryption_matches_reference_with_identical_seed_and_error_bits(monkeypatch, eta, rns):
    pk, sk = bgv.key_gen(64, q_bits=120, eta=eta, rns_modulus=True)
    client = owner.OwnerClient(pk, sk, native=True, rns=rns)
    entropy = bytes(i % 256 for i in range(pk.n * ((2 * eta + 7) // 8)))
    errors = owner._errors_from_bytes(entropy, pk.n, eta)
    monkeypatch.setattr(owner.secrets, "token_bytes", lambda count: b"s" * 32 if count == 32 else entropy)
    monkeypatch.setattr(seeded, "_small_poly", lambda n, eta, q: tuple(mpz(e % q) for e in errors))
    message = [(i - 40) * pk.t + i * 29 for i in range(pk.n)]
    wire = client.encrypt(message)
    assert wire == seeded.encrypt(message, pk, sk)
    cipher = compact.compact(seeded.expand(wire, pk), pk, 25)
    assert client.decrypt_compact(cipher) == compact.decrypt(cipher, pk, sk) == [x % pk.t for x in message]
    client.close()
    with pytest.raises(RuntimeError):
        client.decrypt_compact(cipher)


@pytest.mark.parametrize("rns", [False, True])
def test_raw_native_boundary_rejections_and_concurrent_lifecycle(rns):
    n, q = 16, mpz((1 << 93) - 25)
    handle = native.create(n, b"\x01" * n, rns)
    packed = bytes((n * q.bit_length() + 7) // 8)
    good = format(q, "x")
    for degree, secret in ((True, b""), (7, b"\x01" * 7), (16, b"\x03" * 16), (65536, b"")):
        with pytest.raises((ValueError, OverflowError)):
            native.create(degree, secret)
    for value in ("", "0" + good, "-ffff", "f" * 1000, "1\x00fff", "1", True):
        with pytest.raises(ValueError):
            native.prepare(handle, value)
    noncanonical = gmpy2.pack([q] * n, q.bit_length()).to_bytes(len(packed), "little")
    for data in (b"", packed + b"x", noncanonical, bytearray(packed)):
        with pytest.raises(ValueError):
            native.multiply(handle, data, good)
    for t, eta, message, error in ((True, 21, bytes(n * 4), bytes(n * 6)),
                                   (1031, 0, bytes(n * 4), b""),
                                   (1031, 21, struct.pack(f"<{n}I", *([1031] * n)), bytes(n * 6)),
                                   (1031, 21, bytes(n * 4), b"")):
        with pytest.raises(ValueError):
            native.encrypt(handle, packed, message, error, good, t, eta)
    with pytest.raises(ValueError):
        native.decrypt(handle, packed, packed, good, 2)
    with pytest.raises(ValueError, match="encryption fields"):
        native.encrypt(handle, bytes(n * 11 // 8), bytes(n * 4), bytes(n * 6), "407", 1031, 21)
    with pytest.raises(ValueError):
        native.multiply(object(), packed, good)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: native.multiply(handle, packed, good), range(12)))
    assert results == [packed] * 12
    # Raw calls (without the Python owner lock) are serialized with close too.
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(native.multiply, handle, packed, good) for _ in range(8)]
        pool.submit(native.close, handle).result()
        for future in futures:
            try:
                assert future.result() == packed
            except RuntimeError as error:
                assert "closed" in str(error)
    native.close(handle)
    with pytest.raises(RuntimeError, match="closed"):
        native.prepare(handle, good)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork is unavailable")
def test_native_cache_rejects_actual_fork_without_using_inherited_mutex():
    handle = native.create(8, b"\x01" * 8)
    pid = os.fork()
    if pid == 0:
        try:
            native.prepare(handle, "10001")
        except RuntimeError:
            os._exit(0)
        except BaseException:
            os._exit(2)
        os._exit(1)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    native.prepare(handle, "10001")
