"""Independent BGV private arithmetic, native admission and lifecycle regressions."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import copy
import os
import pickle
import random
import struct
import subprocess
import sys
import textwrap
from types import SimpleNamespace

import gmpy2
from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import shallow_bgv as bgv, compact_bgv as compact
from experiments.bfv_search_lab.private_bgv import PrivateDecoder


@pytest.fixture(scope="module")
def native():
    return pytest.importorskip("experiments.bfv_search_lab._owner._bgv_private")


@pytest.mark.parametrize("n", [8, 16, 128, 16384, 32768])
@pytest.mark.parametrize("bits", [25, 32, 50, 60])
def test_independent_gmp_oracle(native, n, bits):
    # Fresh keys cover positive/negative CRT phases without sharing decoder code.
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    p = compact.terminal_modulus(pk.q, pk.t, bits)
    randomizer = random.Random(n + bits)
    boundary = [0, 1, p // 2, p // 2 + 1, p - 1]
    components = tuple(tuple(mpz(randomizer.choice(boundary) if i % 2 else randomizer.randrange(int(p)))
                             for i in range(n)) for _ in range(2))
    cipher = compact.CompactCiphertext(components, pk.key_id, p, 0)
    with PrivateDecoder(pk, sk, bits=bits) as decoder:
        expected = [compact.decrypt(cipher, pk, sk)] * 2
        assert decoder.decode([cipher, cipher]) == expected
        packed = tuple(gmpy2.pack(list(poly), bits).to_bytes(n * bits // 8, "little") for poly in components)
        assert decoder.decode_packed((packed, packed)) == expected


@pytest.mark.parametrize("packed", [False, True])
def test_native_validates_whole_batch_before_any_secret_product(native, packed):
    pk, sk = bgv.key_gen(16, q_bits=120, rns_modulus=True)
    decoder = PrivateDecoder(pk, sk, bits=32)
    bits = 32 if packed else 64
    zero = bytes(bits * pk.n // 8)
    invalid = gmpy2.pack([decoder.modulus] * pk.n, bits).to_bytes(len(zero), "little")
    decode = native.decode_packed_many if packed else native.decode_many
    # A closed decoder would raise RuntimeError if the first valid pair were
    # decrypted. Later public canonical validation must win before that happens.
    native.close_decoder(decoder._handle)
    with pytest.raises(ValueError, match="Noncanonical"):
        decode(decoder._handle, ((zero, zero), (zero, invalid)))
    with pytest.raises(RuntimeError, match="closed"):
        decode(decoder._handle, ((zero, zero),))


def test_native_ownership_and_concurrent_close(native):
    pk, sk = bgv.key_gen(128, q_bits=120, rns_modulus=True)
    decoder = PrivateDecoder(pk, sk)
    cipher = compact.compact(bgv.encrypt([1] * pk.n, pk), pk, 25)
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(decoder)
    with ThreadPoolExecutor(4) as pool:
        assert all(result == [[1] * pk.n] for result in pool.map(lambda _: decoder.decode([cipher]), range(8)))
        futures = [pool.submit(decoder.decode, [cipher]), pool.submit(decoder.close)]
        for future in futures:
            try:
                future.result(timeout=10)
            except RuntimeError as error:
                assert "closed" in str(error)
    with pytest.raises(RuntimeError, match="closed"):
        decoder.decode([cipher])


@pytest.mark.parametrize("field,value", [(0, True), (0, 0), (1, 1 << 60), (2, 0), (3, 7), (4, 7)])
def test_invalid_native_parameters(native, field, value):
    args = [16, 33554039, 1031, 1152921504606830593, 1152921504606748673, bytes(16)]
    args[field] = value
    with pytest.raises((ValueError, OverflowError)):
        native.create_decoder(*args)


def test_no_abi_fallback(native, monkeypatch):
    import experiments.bfv_search_lab._owner as package
    pk, sk = bgv.key_gen(16, q_bits=120, rns_modulus=True)
    monkeypatch.setattr(package, "_bgv_private", SimpleNamespace(ABI_VERSION=0), raising=False)
    with pytest.raises(RuntimeError, match="Rebuild"):
        PrivateDecoder(pk, sk)


@pytest.mark.parametrize("mode", ["lock", "fork"])
def test_os_guards_in_isolated_child(native, mode):
    if mode == "lock" and "asan" in os.environ.get("LD_PRELOAD", ""):
        pytest.skip("ASan intercepts mlock; run OS admission on the release extension")
    script = textwrap.dedent('''
        import importlib.util, os, resource, sys
        spec = importlib.util.spec_from_file_location("_bgv_private", sys.argv[1])
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        if sys.argv[2] == "lock":
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (0, 0))
            try:
                native.create_decoder(16, 33554039, 1031,
                    1152921504606830593, 1152921504606748673, bytes(16))
            except RuntimeError as error:
                assert "locking failed" in str(error)
            else:
                raise AssertionError("Unlocked fallback")
        else:
            decoder = native.create_decoder(16, 33554039, 1031,
                1152921504606830593, 1152921504606748673, bytes(16))
            pid = os.fork()
            if pid == 0:
                try:
                    native.decode_many(decoder, ((bytes(128), bytes(128)),))
                except RuntimeError as error:
                    os._exit(0 if "fork" in str(error) else 2)
                os._exit(3)
            _, status = os.waitpid(pid, 0)
            assert status == 0
            native.close_decoder(decoder)
    ''')
    run = subprocess.run([sys.executable, "-c", script, native.__file__, mode],
                         capture_output=True, text=True, timeout=15)
    assert run.returncode == 0, run.stderr
