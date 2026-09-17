"""Exact coefficient comparisons and boundary oracles for optimized BFV evaluation."""

import random
import builtins
from dataclasses import replace

import numpy as np
import pytest
from gmpy2 import mpz

from xtrace_sdk.x_vec.crypto.encryption.bfv import BFV
from xtrace_sdk.x_vec.crypto.encryption.bfv_evaluator import BFVEvaluator, _PackedSwitchKey
from xtrace_sdk.x_vec.utils.xtrace_types import BFVCiphertext, BFVKeyPair


@pytest.fixture(scope="module")
def keys() -> BFVKeyPair:
    # Insecure toy ring; only the arithmetic is under test.
    return BFV.key_gen(16, 97, 100, 15, rotation_steps=[1, -1, 2, 4])


@pytest.mark.parametrize(
    "q_bits,digit_bits", [(31, 1), (100, 15), (180, 30), (512, 127), (100, 100)]
)
def test_fused_switch_against_schoolbook(q_bits: int, digit_bits: int) -> None:
    n, q = 8, (mpz(1) << q_bits) - 1
    digits = (q_bits + digit_bits - 1) // digit_bits
    rng = random.Random(q_bits + digit_bits)
    # All-maximum keys stress the bound on the *sum* of digit convolutions.
    for key in (
        tuple(((q - 1,) * n, (q - 1,) * n) for _ in range(digits)),
        tuple(
            tuple(tuple(mpz(rng.randrange(q)) for _ in range(n)) for _ in range(2))
            for _ in range(digits)
        ),
    ):
        compiled = _PackedSwitchKey.compile(key, n, q, digit_bits)
        for poly in (
            (mpz(0),) * n,
            (q - 1,) * n,
            (mpz(0),) * (n - 1) + (q - 1,),
            tuple(mpz(rng.randrange(q)) for _ in range(n)),
        ):
            expected = [[0] * n for _ in range(2)]
            # Independent O(N^2) signed negacyclic convolution and digit sum.
            # No pack/unpack or optimized/reference polynomial helper is used.
            for i, pair in enumerate(key):
                for j, coefficient in enumerate(poly):
                    digit = (int(coefficient) >> (i * digit_bits)) % (1 << digit_bits)
                    for component in range(2):
                        for k, value in enumerate(pair[component]):
                            sign = 1 if j + k < n else -1
                            expected[component][(j + k) % n] += sign * digit * int(value)
            actual = compiled.apply(poly, q, digit_bits)
            assert actual == tuple(tuple(value % q for value in row) for row in expected)


@pytest.mark.parametrize("backend", ["optimized", "rns", "native"])
def test_operations_identical_to_reference(keys: BFVKeyPair, backend: str) -> None:
    if backend in ("rns", "native"):
        pytest.importorskip("xtrace_sdk.x_vec.crypto.bfv_cpu_ext._bfv_rns")
    pk, rng = keys["pk"], random.Random(20)
    evaluator = BFVEvaluator(pk, backend)
    for _ in range(3):
        pa, pb = (
            BFV.batch_encode([rng.randrange(97) for _ in range(16)], pk["params"]) for _ in range(2)
        )
        ca, cb = BFV.encrypt(pa, pk), BFV.encrypt(pb, pk)
        assert evaluator.add(ca, cb) == BFV.add(ca, cb, pk)
        assert evaluator.subtract(ca, cb) == BFV.subtract(ca, cb, pk)
        assert evaluator.multiply_plain(ca, pb) == BFV.multiply_plain(ca, pb, pk)
        assert evaluator.multiply(ca, cb) == BFV.multiply(ca, cb, pk)
        assert evaluator.xor(ca, cb) == BFV.xor(ca, cb, pk)
        quadratic = BFV.multiply(ca, cb, pk, relinearize=False)
        assert evaluator.relinearize(quadratic) == BFV.relinearize(quadratic, pk)
        assert evaluator.relinearize(ca) is ca
        assert evaluator.add(quadratic, quadratic) == BFV.add(quadratic, quadratic, pk)
        for step in (0, 1, -1, 2, 4, 9):
            assert evaluator.rotate_rows(ca, step) == BFV.rotate_rows(ca, step, pk)
        compact = BFV.modulus_switch(ca, 40, pk)
        assert evaluator.add(compact, compact) == BFV.add(compact, compact, pk)
        assert evaluator.subtract(compact, compact) == BFV.subtract(compact, compact, pk)


@pytest.mark.parametrize("backend", ["optimized", "rns", "native"])
def test_reject_malformed_ciphertexts_and_keep_integral_support(
    keys: BFVKeyPair, backend: str
) -> None:
    if backend in ("rns", "native"):
        pytest.importorskip("xtrace_sdk.x_vec.crypto.bfv_cpu_ext._bfv_rns")
    pk = keys["pk"]
    evaluator = BFVEvaluator(pk, backend)
    ct = BFV.encrypt(BFV.batch_encode([1], pk["params"]), pk)
    malformed = [
        replace(ct, key_id="wrong"),
        replace(ct, modulus=mpz(97)),
        replace(ct, modulus=pk["q"] + 1),
        replace(ct, components=ct.components[:1]),
        replace(ct, components=(ct.components[0][:-1], ct.components[1])),
    ]
    for value in (-1, pk["q"], 0.0, "0", None):
        malformed.append(replace(ct, components=((value, *ct.components[0][1:]), ct.components[1])))
    for bad in malformed:
        for validate in (evaluator._validate, lambda value: BFV.validate_ciphertext(value, pk)):
            with pytest.raises(ValueError):
                validate(bad)
        for operation in (evaluator.add, evaluator.subtract, evaluator.multiply):
            with pytest.raises(ValueError):
                operation(ct, bad)
        with pytest.raises(ValueError):
            evaluator.rotate_rows(bad, 1)
        with pytest.raises(ValueError):
            evaluator.relinearize(bad)
        with pytest.raises(ValueError):
            evaluator.hamming_tile(ct, bad, [1], BFV.batch_encode([1], pk["params"]))
    for value in (0, False, np.int64(0)):
        candidate = replace(ct, components=((value, *ct.components[0][1:]), ct.components[1]))
        assert evaluator.add(ct, candidate) == BFV.add(ct, candidate, pk)
    quadratic = BFV.multiply(ct, ct, pk, relinearize=False)
    compact = BFV.modulus_switch(ct, 40, pk)
    for incompatible in (quadratic, compact):
        with pytest.raises(ValueError):
            evaluator.add(ct, incompatible)
        with pytest.raises(ValueError):
            evaluator.subtract(ct, incompatible)
        with pytest.raises(ValueError):
            evaluator.multiply(incompatible, incompatible)
        with pytest.raises(ValueError):
            evaluator.rotate_rows(incompatible, 1)
    with pytest.raises(ValueError):
        evaluator.relinearize(BFV.modulus_switch(quadratic, 40, pk))


def test_missing_keys_and_snapshot_cache(keys: BFVKeyPair) -> None:
    pk = {**keys["pk"], "galois_keys": dict(keys["pk"]["galois_keys"])}
    ct = BFV.encrypt(BFV.batch_encode([1], pk["params"]), pk)
    evaluator = BFVEvaluator(pk)
    assert not evaluator._switch_keys
    first = evaluator.rotate_rows(ct, 1)
    prepared = evaluator._switch_keys[3]
    assert evaluator.rotate_rows(ct, 9) == first
    assert evaluator._switch_keys[3] is prepared
    assert len(evaluator._switch_keys) == 1
    # Mutation of the caller's dictionary cannot leave a stale mixed cache.
    pk["galois_keys"].clear()
    assert evaluator.rotate_rows(ct, 1) == first
    missing = BFVEvaluator({**pk, "relin_key": ()})
    with pytest.raises(ValueError, match="rotation key"):
        missing.rotate_rows(ct, 1)
    with pytest.raises(ValueError, match="relinearization key"):
        missing.multiply(ct, ct)
    reference = BFVEvaluator(keys["pk"], "reference")
    assert reference.rotate_rows(ct, 1) == first
    assert not reference._switch_keys
    with pytest.raises(ValueError, match="server_backend"):
        BFVEvaluator(keys["pk"], "invalid")


def test_unavailable_native_extension_keeps_gmp_fallback(
    keys: BFVKeyPair, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_import = builtins.__import__

    def without_native(name: str, *args, **kwargs):
        if name == "xtrace_sdk.x_vec.crypto.bfv_cpu_ext":
            raise ImportError("Native module intentionally unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_native)
    with pytest.raises(ImportError, match="Build it with"):
        BFVEvaluator(keys["pk"], "rns")
    pk = keys["pk"]
    ct = BFV.encrypt(BFV.batch_encode([1], pk["params"]), pk)
    assert BFVEvaluator(pk).multiply(ct, ct) == BFV.multiply(ct, ct, pk)
