"""Public native codec equivalence and bounds, including unaligned coefficient widths."""

from concurrent.futures import ThreadPoolExecutor
import random

import gmpy2
from gmpy2 import mpz
import msgpack
import pytest

from experiments.bfv_search_lab import compressed_query_bgv as codec, shallow_bgv as bgv
from experiments.bfv_search_lab import seeded_bgv as seeded

native = pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace")


def seeded_packet(coefficients, pk):
    body = gmpy2.pack(coefficients, pk.q.bit_length()).to_bytes(
        pk.n * pk.q.bit_length() // 8, "little"
    )
    return msgpack.packb(
        [seeded._TAG, bytes.fromhex(pk.key_id), bytes(32), body], use_bin_type=True
    )


@pytest.mark.parametrize(
    "n,bits,t",
    [(8, 33, 3), (16, 61, 9), (2048, 120, 1031), (16384, 120, 1031), (8, 240, (1 << 30) - 1)],
)
def test_native_matches_reference_at_boundaries_and_multiple_precisions(n, bits, t):
    # A codec needs no prime modulus or encryption key. Public synthetic inputs
    # cover Q edges that are unlikely to occur in honestly encrypted test data.
    pk = bgv.PublicKey(n, t, mpz((1 << bits) - 1), 1, (), (), "a" * 64)
    rng = random.Random(n + bits + t)
    values = [mpz(rng.randrange(int(pk.q))) for _ in range(n)]
    values[:4] = [mpz(0), mpz(1), pk.q - 1, pk.q - 2]
    for coefficients in (values, [mpz(0)] * n):
        original = seeded_packet(coefficients, pk)
        for drop in (1, bits // 3, bits // 2, bits - 2):
            reference = codec.compress(original, pk, dropped_bits=drop)
            packed = codec.compress(original, pk, dropped_bits=drop, backend="native")
            assert packed == reference
            assert codec.expand(packed, pk, dropped_bits=drop, backend="native") == codec.expand(
                reference, pk, dropped_bits=drop
            )


@pytest.mark.parametrize("bits,drop,t", [(33, 8, 17), (120, 1, 1031), (240, 200, 9)])
def test_native_rejects_noncanonical_raw_and_compressed_coefficients(bits, drop, t):
    pk = bgv.PublicKey(8, t, mpz((1 << (bits - 1)) + 3), 1, (), (), "0" * 64)
    with pytest.raises(ValueError, match="Noncanonical"):
        codec.compress(seeded_packet([pk.q] * 8, pk), pk, dropped_bits=drop, backend="native")
    encoding = codec.parameters(pk, drop)
    packet = codec.compress(seeded_packet([mpz(0)] * 8, pk), pk, dropped_bits=drop)
    # The first unused residue in the last partial bin or in an R<t bin.
    hole = (((pk.q - 1) >> drop) * t + 3) if drop > 1 else mpz(2)
    for word in (hole, mpz(encoding.max_word + 1)):
        if word.bit_length() > encoding.coefficient_bits:
            continue
        fields = msgpack.unpackb(packet)
        fields[-1] = gmpy2.pack([word] + [mpz(0)] * 7, encoding.coefficient_bits).to_bytes(
            encoding.body_bytes, "little"
        )
        malformed = msgpack.packb(fields, use_bin_type=True)
        for backend in ("python", "native"):
            with pytest.raises(ValueError, match="Noncanonical|preimage"):
                codec.expand(malformed, pk, dropped_bits=drop, backend=backend)


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
        (1, 8.0),
        (2, ""),
        (2, "0" * 30),
        (2, "F" * 30),
        (2, "f" * 61),
        (2, "7fffffff"),
        (2, "f" * 29 + "e"),
        (2, "f" * 29 + "\x00"),
        (3, True),
        (3, 2),
        (3, -3),
        (3, 1 << 30),
        (4, False),
        (4, -1),
        (4, 0),
        (4, 120),
        (4, 240),
    ],
)
def test_raw_native_entry_points_bound_inputs(position, value):
    for function in (native.compress_query_coefficients, native.expand_query_coefficients):
        arguments = [bytes(120), 8, "f" * 30, 1031, 58]
        if function == native.expand_query_coefficients:
            pk = bgv.PublicKey(8, 1031, mpz((1 << 120) - 1), 1, (), (), "0" * 64)
            arguments[0] = bytes(codec.parameters(pk, 58).body_bytes)
        arguments[position] = value
        with pytest.raises((ValueError, TypeError, OverflowError)):
            function(*arguments)


def test_independent_concurrent_codec_calls_match_and_backend_is_explicit():
    pk = bgv.PublicKey(2048, 1031, mpz((1 << 120) - 1), 21, (), (), "0" * 64)
    original = seeded_packet([mpz(i**4) for i in range(pk.n)], pk)
    expected = codec.compress(original, pk, dropped_bits=58)
    expected_cipher = codec.expand(expected, pk, dropped_bits=58)

    def run(_):
        packet = codec.compress(original, pk, dropped_bits=58, backend="native")
        assert packet == expected
        assert codec.expand(packet, pk, dropped_bits=58, backend="native") == expected_cipher

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(run, range(12)))
    for function, packet in ((codec.compress, original), (codec.expand, expected)):
        with pytest.raises(ValueError, match="python or native"):
            function(packet, pk, dropped_bits=58, backend="cuda")
