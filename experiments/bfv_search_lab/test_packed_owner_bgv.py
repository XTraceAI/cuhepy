"""Packed fixture finishing preserves the pre-private gate and all-input validation."""

from contextlib import closing

import gmpy2
import msgpack
import pytest

from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import butterfly_bgv as butterfly, compact_bgv as compact
from experiments.bfv_search_lab import owner_bgv as owner, transport_bgv as wire


@pytest.fixture
def case():
    pytest.importorskip("experiments.bfv_search_lab._owner._bgv_owner")
    pk, sk = bgv.key_gen(16, q_bits=120, rns_modulus=True)
    query, rows = [1, 0, 1], [[1, 0, 1], [1, 0, 1], [0, 1, 0], [0, 0, 1]] * 5
    message, tiles = bgv.coefficient_inputs(query, rows, pk.n)
    keys = trace.evaluation_keys(pk, sk, 4)
    with closing(owner.OwnerClient(pk, sk, native=True, rns=True)) as client:
        response = butterfly.search(owner.expand(client.encrypt(message), pk),
                                    [bgv.encrypt(p, pk) for p in tiles], len(rows), pk, keys)
        reduced = [compact.compact(c, pk, 25) for c in response]
        packet = compact.pack(reduced, len(rows), len(query), pk)
        yield client, reduced, packet, len(rows), len(query)


@pytest.mark.parametrize("all_distances", [False, True])
@pytest.mark.parametrize("k", [0, 1, 3, 20])
def test_packed_native_finish_matches_all_existing_result_paths(case, all_distances, k):
    client, response, packet, count, dimension = case
    expected = client.finish(response, count, dimension, k=k, all_distances=all_distances)
    bounds = [c.phase_bound for c in response]
    assert client.finish_packed_fixture(packet, packet, count, dimension, bits=25,
                                       bounds=bounds, k=k, all_distances=all_distances) == expected
    assert wire.unpack_fixture(packet, client.pk, count=count, dimension=dimension,
                               modulus=response[0].modulus, bounds=bounds) == response


def test_gate_precedes_envelope_parse_and_private_call(case, monkeypatch):
    client, response, packet, count, dimension = case
    entered = []

    def unexpected(*args, **kwargs):
        entered.append(True)
        raise AssertionError("Private code must not run")

    monkeypatch.setattr(client._product, "finish_packed", unexpected)
    bounds = [c.phase_bound for c in response]
    for corrupted in (b"", packet[:-1], packet + b"x", bytearray(packet)):
        with pytest.raises(ValueError, match="pinned fixture"):
            client.finish_packed_fixture(corrupted, packet, count, dimension, bits=25, bounds=bounds)
    for actual_count, actual_dim, actual_bounds in ((count+1, dimension, bounds),
                                                  (count, dimension+1, bounds),
                                                  (count, dimension, [True]*len(bounds)),
                                                  (count, dimension, [int(client.pk.q)]*len(bounds))):
        with pytest.raises(ValueError):
            client.finish_packed_fixture(packet, packet, actual_count, actual_dim,
                                         bits=25, bounds=actual_bounds)
    assert not entered


def test_native_validates_later_ciphertext_before_private_work_on_first(case):
    client, response, packet, count, dimension = case
    p = response[0].modulus
    header, body = msgpack.unpackb(packet)
    # A zero first ciphertext cannot encode an odd-dimensional valid score.
    # If the implementation decrypts/decodes it before vetting the second
    # ciphertext, it fails with an invalid-distance error instead.
    body[0] = [bytes(len(body[0][0])), bytes(len(body[0][1]))]
    body[1][1] = gmpy2.pack([p]*client.pk.n, p.bit_length()).to_bytes(len(body[1][1]), "little")
    malformed = msgpack.packb([header, body], use_bin_type=True)
    with pytest.raises(ValueError, match="Noncanonical owner coefficient"):
        client.finish_packed_fixture(malformed, malformed, count, dimension, bits=25,
                                     bounds=[c.phase_bound for c in response])
    client.close()
    with pytest.raises(RuntimeError, match="closed"):
        client.finish_packed_fixture(packet, packet, count, dimension, bits=25,
                                     bounds=[c.phase_bound for c in response])
