"""Bounded local wire parser and independently checked feature-major circuit."""

import io
import random
import struct

import gmpy2
import msgpack
import pytest

from experiments.bfv_search_lab import compact_bgv as compact, shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import feature_major_bgv as feature, transport_bgv as transport


class Reader:
    def __init__(self, value):
        self.value = io.BytesIO(value)

    def recv(self, length):
        return self.value.read(min(3, length))


def test_framing_limits_and_truncation():
    assert transport.receive(Reader(struct.pack("!I", 5) + b"hello")) == b"hello"
    for value in (b"", b"123", struct.pack("!I", 5) + b"abc"):
        with pytest.raises(EOFError):
            transport.receive(Reader(value))
    for length in (0, transport.MAX_FRAME + 1, 0xffffffff):
        with pytest.raises(ValueError):
            transport.receive(Reader(struct.pack("!I", length)))


def test_fixture_gate_rejects_modified_replayed_and_wrong_type_before_decryption():
    expected = b"this request's canonical ciphertext"
    assert transport.require_expected_fixture(expected, expected) is None
    for value in (b"previous request", expected + b"x", expected[:-1], bytearray(expected)):
        with pytest.raises(ValueError, match="pinned fixture"):
            transport.require_expected_fixture(value, expected)


def test_application_pacing_and_invalid_links(monkeypatch):
    now, writes = [0.0], []
    monkeypatch.setattr(transport.time, "perf_counter", lambda: now[0])
    monkeypatch.setattr(transport.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))

    class Writer:
        def sendall(self, data):
            writes.append(data)

    transport.send(Writer(), b"x" * 20000, mbps=10, delay_ms=20)
    assert b"".join(writes) == struct.pack("!I", 20000) + b"x" * 20000
    assert now[0] == pytest.approx(0.02 + 8 * 20004 / 1e7)
    for rate in (-1, float("nan"), float("inf")):
        with pytest.raises(ValueError):
            transport.send(Writer(), b"a", mbps=rate)


def test_response_parser_pins_context_and_rejects_malformed_coefficients():
    pk, sk = bgv.key_gen(16, q_bits=120, rns_modulus=True)
    cipher = compact.compact(bgv.encrypt([1] * pk.n, pk), pk, 25)
    packet = compact.pack([cipher], 7, 3, pk)
    kwargs = dict(count=7, dimension=3, modulus=cipher.modulus, bounds=[cipher.phase_bound])
    assert transport.unpack_fixture(packet, pk, **kwargs) == [cipher]
    assert compact.decrypt(cipher, pk, sk) == [1] * pk.n
    corrupt = [b"", packet[:-1], packet + b"x", msgpack.packb({"bad": True}), msgpack.packb([[], []])]
    for position, value in ((0, "wrong"), (1, 32), (2, True), (4, b"wrong"), (5, 8), (6, 4)):
        header, body = msgpack.unpackb(packet)
        header[position] = value
        corrupt.append(msgpack.packb([header, body]))
    for bad in (b"", b"x" * 10000,
                gmpy2.pack([cipher.modulus] * pk.n, cipher.modulus.bit_length()).to_bytes(pk.n * cipher.modulus.bit_length() // 8, "little")):
        header, body = msgpack.unpackb(packet)
        body[0][0] = bad
        corrupt.append(msgpack.packb([header, body]))
    for value in corrupt:
        with pytest.raises((ValueError, msgpack.UnpackException)):
            transport.unpack_fixture(value, pk, **kwargs)


@pytest.mark.parametrize("n,dimension,count", [(16, 1, 1), (16, 3, 35), (64, 9, 67)])
def test_feature_major_delayed_switch_preserves_all_exact_distances(n, dimension, count):
    pk, sk = bgv.key_gen(n, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, 1)
    rng = random.Random(n + dimension)
    query = [rng.randrange(2) for _ in range(dimension)]
    rows = [[rng.randrange(2) for _ in query] for _ in range(count)]
    rows[0] = query[:]
    if count > 1:
        rows[1] = [1 - b for b in query]
    queries, groups = feature.encode(query, rows, n)
    encrypted_queries = [bgv.encrypt(p, pk) for p in queries]
    encrypted_groups = [[bgv.encrypt(p, pk) for p in group] for group in groups]
    expected = [sum(a != b for a, b in zip(row, query, strict=True)) for row in rows]
    for delayed in (False, True):
        result = feature.search(encrypted_queries, encrypted_groups, pk, keys, delayed=delayed)
        assert feature.decode([bgv.decrypt(c, pk, sk) for c in result], count, dimension, pk) == expected
        reduced = [compact.compact(c, pk, 25) for c in result]
        assert feature.decode([compact.decrypt(c, pk, sk) for c in reduced], count, dimension, pk) == expected
    costs = feature.costs(count, dimension, n)
    assert costs["delayed_key_switches"] * dimension == costs["eager_key_switches"]
    assert costs["query_ciphertexts"] == dimension


def test_feature_major_rejects_invalid_shapes_and_parameters():
    for query, rows, n in (([], [], 16), ([1], [[2]], 16), ([True], [], 16), ([1], [[1, 0]], 16), ([1], [], 7)):
        with pytest.raises(ValueError):
            feature.encode(query, rows, n)
    with pytest.raises(ValueError):
        feature.costs(1, 0, 16)
