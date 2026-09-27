"""Coefficient identities, parser boundaries and exact encrypted search after rounding."""

from contextlib import closing
from dataclasses import replace
import random

import gmpy2
from gmpy2 import mpz
import msgpack
import pytest

from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import butterfly_bgv as butterfly, compact_bgv as compact
from experiments.bfv_search_lab import (
    compressed_query_bgv as codec,
    owner_bgv as owner,
    seeded_bgv as seeded,
)


def packet_from_coefficients(values, pk):
    body = gmpy2.pack(values, pk.q.bit_length()).to_bytes(pk.n * pk.q.bit_length() // 8, "little")
    return msgpack.packb(
        [seeded._TAG, bytes.fromhex(pk.key_id), bytes(32), body], use_bin_type=True
    )


@pytest.mark.parametrize("t", [3, 5, 9, 17])
def test_exhaustive_rounding_identity_bound_and_fixed_width(t):
    # No encrypted fixture or security assumption is needed for this identity.
    pk = bgv.PublicKey(8, t, mpz((1 << 40) + 3), 1, (), (), "0" * 64)
    for drop in range(1, 9):
        e = codec.parameters(pk, drop)
        radius = 1 << drop
        for start in range(0, 3 * radius, pk.n):
            values = [mpz(c) for c in range(start, start + pk.n)]
            packet = codec.compress(packet_from_coefficients(values, pk), pk, dropped_bits=drop)
            parsed = codec.expand(packet, pk, dropped_bits=drop)
            for c, rounded in zip(values, parsed.components[0], strict=True):
                delta = int(rounded - c)
                assert delta % t == 0
                assert abs(delta) <= e.added_bound
                assert rounded == (c // radius) * radius + (c % radius) % t + e.center
            assert len(msgpack.unpackb(packet)[-1]) == e.body_bytes


@pytest.mark.parametrize("n,drop", [(8, 1), (8, 32), (16, 64), (64, 100), (64, 119)])
def test_fresh_encrypted_query_preserves_every_plaintext_coefficient(n, drop):
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    rng = random.Random(n + drop)
    message = [rng.randrange(-pk.t // 2, pk.t // 2 + 1) for _ in range(n)]
    with closing(owner.OwnerClient(pk, sk)) as client:
        first = client.encrypt(message)
        second = client.encrypt(message)
        assert first != second
        for packet in (first, second):
            original = owner.expand(packet, pk)
            compressed = codec.compress(packet, pk, dropped_bits=drop)
            expanded = codec.expand(compressed, pk, dropped_bits=drop)
            assert expanded.components[1] == original.components[1]
            assert (
                expanded.phase_bound
                == original.phase_bound + codec.parameters(pk, drop).added_bound
            )
            assert bgv.decrypt(expanded, pk, sk) == [x % pk.t for x in message]
            # No private input enters compression; applying it to the same public
            # packet is deterministic and does not sample replacement error.
            assert codec.compress(packet, pk, dropped_bits=drop) == compressed


def test_reconstruction_wraps_mod_q_and_checks_the_last_partial_bin():
    pk = bgv.PublicKey(8, 17, mpz((1 << 40) + 3), 1, (), (), "0" * 64)
    values = [pk.q - 1, pk.q - 2, pk.q - 3, mpz(0), mpz(1), mpz(16), mpz(17), mpz(255)]
    packet = codec.compress(packet_from_coefficients(values, pk), pk, dropped_bits=8)
    result = codec.expand(packet, pk, dropped_bits=8)
    e = codec.parameters(pk, 8)
    assert result.components[0][0] < e.center  # The reconstructed integer crossed Q.
    for original, rounded in zip(values, result.components[0], strict=True):
        delta = (rounded - original) % pk.q
        if delta > pk.q // 2:
            delta -= pk.q
        assert delta % pk.t == 0 and abs(delta) <= e.added_bound
    fields = msgpack.unpackb(packet)
    illegal = ((pk.q - 1) >> 8) * pk.t + 3
    fields[-1] = gmpy2.pack([illegal] + [mpz(0)] * 7, e.coefficient_bits).to_bytes(
        e.body_bytes, "little"
    )
    with pytest.raises(ValueError, match="Noncanonical|preimage"):
        codec.expand(msgpack.packb(fields), pk, dropped_bits=8)


def test_parser_rejects_wrong_context_precision_types_lengths_and_holes():
    pk, sk = bgv.key_gen(8, q_bits=120, rns_modulus=True)
    packet = codec.compress(seeded.encrypt([0] * 8, pk, sk), pk, dropped_bits=1)
    bad = [
        b"",
        packet[:-1],
        packet + b"x",
        bytearray(packet),
        b"x" * 4096,
        msgpack.packb({}),
        msgpack.packb([[]] * 6),
        msgpack.packb([[[]]]),
        msgpack.packb("bad"),
    ]
    for position, value in (
        (0, b"bad"),
        (1, bytes(32)),
        (2, bytes(31)),
        (2, bytes(33)),
        (3, True),
        (3, 2),
        (4, b""),
        (4, "bad"),
    ):
        fields = msgpack.unpackb(packet)
        fields[position] = value
        bad.append(msgpack.packb(fields, use_bin_type=True))
    # With R=2 and t=1031, residue 2 cannot represent an original coefficient.
    fields = msgpack.unpackb(packet)
    e = codec.parameters(pk, 1)
    fields[-1] = gmpy2.pack([mpz(2)] + [mpz(0)] * 7, e.coefficient_bits).to_bytes(
        e.body_bytes, "little"
    )
    bad.append(msgpack.packb(fields, use_bin_type=True))
    for value in bad:
        with pytest.raises(ValueError):
            codec.expand(value, pk, dropped_bits=1)
    for drop in (False, 0, -1, 120, 1000, 1.0):
        with pytest.raises(ValueError):
            codec.parameters(pk, drop)
    for invalid in (
        replace(pk, n=7),
        replace(pk, t=2),
        replace(pk, eta=0),
        replace(pk, q=mpz(2)),
        replace(pk, key_id="x" * 64),
    ):
        with pytest.raises(ValueError):
            codec.parameters(invalid, 1)


@pytest.mark.parametrize("n,dimension,count", [(16, 3, 35), (64, 9, 67)])
@pytest.mark.parametrize("owner_index", [False, True])
def test_exact_search_with_public_or_owner_index_and_terminal_reduction(
    n, dimension, count, owner_index
):
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 1 << (dimension - 1).bit_length())
    rng = random.Random(n + dimension)
    query = [rng.randrange(2) for _ in range(dimension)]
    rows = [[rng.randrange(2) for _ in query] for _ in range(count)]
    rows[:3] = [query[:], query[:], [1 - b for b in query]]
    query_plain, index_plain = bgv.coefficient_inputs(query, rows, n)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index = [
            owner.expand(client.encrypt(p), pk) if owner_index else bgv.encrypt(p, pk)
            for p in index_plain
        ]
        packet = client.encrypt(query_plain)
        encoded = codec.compress(packet, pk, dropped_bits=72)
        expanded = codec.expand(encoded, pk, dropped_bits=72)
        result = butterfly.search(expanded, index, count, pk, keys)
        reduced = [compact.compact(c, pk, 25) for c in result]
        finished = client.finish(reduced, count, dimension, method="sort")
        expected = tuple(sum(a != b for a, b in zip(row, query, strict=True)) for row in rows)
        assert finished.distances == expected
        assert finished.top == tuple(sorted(enumerate(expected), key=lambda p: (p[1], p[0]))[:3])
        # Query decryption alone works at this precision, but the whole circuit
        # must refuse it before evaluating a product with an excessive bound.
        unsafe = codec.expand(codec.compress(packet, pk, dropped_bits=119), pk, dropped_bits=119)
        assert bgv.decrypt(unsafe, pk, sk) == [x % pk.t for x in query_plain]
        with pytest.raises(ValueError, match="bound"):
            butterfly.search(unsafe, index, count, pk, keys)
