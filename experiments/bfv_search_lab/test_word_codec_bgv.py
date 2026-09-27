"""Fixed-word public codecs, GMP fallback and canonical parsing boundaries.

Synthetic coefficients test the representation only, never private decryption.
All drop positions exercise byte offsets, partial bins and the 120-bit cutoff.
"""

import random

import gmpy2
from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab.compressed_query_bgv import coefficient_encoding

native = pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace")


def packed(values, bits):
    return gmpy2.pack(values, bits).to_bytes(len(values) * bits // 8, "little")


@pytest.mark.parametrize(
    "bits", [16, 17, 25, 31, 32, 33, 59, 60, 63, 64, 65, 95, 119, 120, 121, 127, 128, 239, 240]
)
def test_all_precisions_match_python_and_retained_gmp(bits):
    rng = random.Random(bits + 20260925)
    for q in (mpz((1 << bits) - 1), mpz((1 << (bits - 1)) + 3)):
        values = [mpz(0), mpz(1), q - 1, q - 2] + [mpz(rng.randrange(int(q))) for _ in range(4)]
        raw = packed(values, bits)
        assert native.validate_coefficients(raw, 8, format(q, "x")) is None
        for t in (3, 1031, (1 << min(29, bits - 2)) - 1):
            for drop in range(1, bits):
                e = coefficient_encoding(q, t, drop)
                mask = (mpz(1) << drop) - 1
                words = [(v >> drop) * t + (v & mask) % t for v in values]
                expected = packed(words, e.coefficient_bits)
                args = (8, format(q, "x"), t, drop)
                assert native.compress_query_coefficients(raw, *args) == expected
                assert native.compress_query_coefficients_gmp(raw, *args) == expected
                decoded = [((w // t << drop) + w % t + e.center) % q for w in words]
                original = packed(decoded, bits)
                assert native.expand_query_coefficients(expected, *args) == original
                assert native.expand_query_coefficients_gmp(expected, *args) == original


@pytest.mark.parametrize("bits", [16, 25, 65, 120, 121, 240])
def test_word_and_gmp_paths_reject_noncanonical_coefficients_and_holes(bits):
    q, t = mpz((1 << (bits - 1)) + 3), 1031
    for position in (0, 7):
        coefficients = [mpz(0)] * 8
        coefficients[position] = q
        raw = packed(coefficients, bits)
        with pytest.raises(ValueError, match="Noncanonical"):
            native.validate_coefficients(raw, 8, format(q, "x"))
        for function in (
            native.compress_query_coefficients,
            native.compress_query_coefficients_gmp,
        ):
            with pytest.raises(ValueError, match="Noncanonical"):
                function(raw, 8, format(q, "x"), t, 1)
    for drop in (1, bits - 2):
        e = coefficient_encoding(q, t, drop)
        # Residue 2 has no R=2 preimage; residue 3 has no final-bin preimage.
        hole = mpz(2) if drop == 1 else ((q - 1) >> drop) * t + 3
        encoded = packed([hole] + [mpz(0)] * 7, e.coefficient_bits)
        for function in (native.expand_query_coefficients, native.expand_query_coefficients_gmp):
            with pytest.raises(ValueError, match="Noncanonical|preimage"):
                function(encoded, 8, format(q, "x"), t, drop)


@pytest.mark.parametrize(
    "position,value",
    [
        (0, None),
        (0, bytearray(120)),
        (0, bytes(119)),
        (0, bytes(121)),
        (1, True),
        (1, -8),
        (1, 7),
        (1, 12),
        (1, 65536),
        (2, ""),
        (2, "0" * 30),
        (2, "F" * 30),
        (2, "f" * 61),
        (2, "7fff"),
        (2, "f" * 29 + "e"),
        (2, "f" * 29 + "\x00"),
    ],
)
def test_native_validation_bounds_the_complete_input(position, value):
    args = [bytes(120), 8, "f" * 30]
    args[position] = value
    with pytest.raises((ValueError, TypeError, OverflowError)):
        native.validate_coefficients(*args)
