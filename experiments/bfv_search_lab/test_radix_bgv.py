"""Integer carry oracles, complete encrypted results, framing and private-work gates."""

from contextlib import closing
from itertools import product
import random

import msgpack
import pytest

from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, owner_bgv as owner
from experiments.bfv_search_lab import compressed_query_bgv as query_codec
from experiments.bfv_search_lab import compressed_response_bgv as response_codec
from experiments.bfv_search_lab import joint_precision_bgv as planner
from experiments.bfv_search_lab.radix_bgv import Layout, plans
from experiments.bfv_search_lab.radix_client_bgv import RadixClient
from experiments.bfv_search_lab.support_bounds_bgv import SupportBoundServer


@pytest.mark.parametrize("mode", ["balanced", "distance"])
@pytest.mark.parametrize("group", [1, 2, 3])
def test_all_small_distance_digits_and_tail_groups(mode, group):
    for d in range(1, 9):
        layout = Layout(d, group, mode)
        t = layout.plaintext_modulus(minimum=3)
        for active in range(1, group+1):
            for distances in product(range(d+1), repeat=active):
                signed = sum((d-2*h)*layout.base**j for j, h in enumerate(distances))
                assert layout.decode_value(signed % t, t, active) == list(distances)


def test_distance_modular_halving_handles_wrapped_signed_values():
    layout = Layout(512, 3)
    t = layout.plaintext_modulus()
    assert t < 1 << 30
    for distances in ((0, 0, 0), (512, 512, 512), (0, 512, 0), (511, 1, 512)):
        signed = sum((512-2*h)*layout.base**j for j, h in enumerate(distances))
        assert layout.decode_value(signed % t, t, 3) == list(distances)
    with pytest.raises(ValueError, match=r"t<2\^30"):
        Layout(512, 3, "balanced").plaintext_modulus()
    assert Layout(512, 2).plaintext_modulus() < Layout(512, 2, "balanced").plaintext_modulus()//3


def ring_product(a, b):
    n, result = len(a), [0]*len(a)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            at = i+j
            result[at % n] += x*y*(-1 if at >= n else 1)
    return result


@pytest.mark.parametrize("mode", ["balanced", "distance"])
def test_exhaustive_binary_layout_and_negacyclic_boundaries(mode):
    # Independent integer schoolbook product; no HE or existing packing helpers.
    for d in (1, 2, 3):
        vectors = list(product((0, 1), repeat=d))
        for group in (1, 2, 3):
            layout = Layout(d, group, mode)
            n, t = 8, layout.plaintext_modulus(minimum=3)
            for query in vectors:
                for rows in product(vectors, repeat=group):
                    qp, tiles = layout.inputs(list(query), [list(row) for row in rows], n)
                    selected = ring_product(qp, tiles[0])[layout.padded-1]
                    expected = [sum(a != b for a, b in zip(query, row, strict=True)) for row in rows]
                    assert layout.decode_value(selected % t, t, group) == expected
    rng = random.Random(916)
    for d, n, group in ((3, 16, 2), (5, 32, 3), (13, 64, 3)):
        layout = Layout(d, group, mode)
        count = (n+5)*group-1  # Multiple response groups and an incomplete radix digit group.
        query = [rng.randrange(2) for _ in range(d)]
        rows = [[rng.randrange(2) for _ in query] for _ in range(count)]
        qp, tiles = layout.inputs(query, rows, n)
        plaintexts = [[0]*n for _ in range((layout.groups(count)+n-1)//n)]
        t, capacity = layout.plaintext_modulus(), n//layout.padded
        for i, tile in enumerate(tiles):
            correlations = ring_product(qp, tile)
            for lane in range(capacity):
                plaintexts[i//layout.padded][lane*layout.padded+i % layout.padded] = (
                    layout.padded*correlations[lane*layout.padded+layout.padded-1]) % t
        assert layout.decode(plaintexts, count, n, t) == [
            sum(a != b for a, b in zip(query, row, strict=True)) for row in rows]


@pytest.mark.parametrize("mode,group", [("balanced", 1), ("balanced", 2), ("balanced", 3),
                                           ("distance", 1), ("distance", 2), ("distance", 3)])
def test_encrypted_cpu_frontier_and_complete_private_gate(mode, group, monkeypatch):
    pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace")
    layout, n, count = Layout(5, group, mode), 32, 3*32+5
    pk, sk = bgv.key_gen(n, t=layout.plaintext_modulus(), q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, layout.padded)
    rng = random.Random(group)
    query = [rng.randrange(2) for _ in range(layout.dimension)]
    rows = [query[:], [1-b for b in query], query[:]]
    rows += [[rng.randrange(2) for _ in query] for _ in range(count-3)]
    qp, tiles = layout.inputs(query, rows, n)
    server = SupportBoundServer(pk, keys, residue=True)
    with closing(RadixClient(pk, sk, native=True, rns=True)) as client:
        encrypted = [bgv.encrypt(p, pk) for p in tiles]
        index = server.prepare_index(encrypted, layout.groups(count))
        frontier = plans(server, index, layout, count)
        fresh = client.encrypt(qp)
        for plan in {planner.select(frontier, up, down) for up, down in ((1, 1), (10, 100), (100, 10))}:
            packet = fresh if plan.query_drop is None else query_codec.compress(
                fresh, pk, dropped_bits=plan.query_drop, backend="native")
            outer = layout.wrap(packet, count, "query")
            assert len(outer) == layout.packet_size(len(packet), count, "query")
            packet = layout.unwrap(outer, count, "query")
            ct = owner.expand(packet, pk) if plan.query_drop is None else query_codec.expand(
                packet, pk, dropped_bits=plan.query_drop, backend="native")
            response = server.search_compact(ct, index, bits=plan.terminal_bits)
            assert tuple(c.phase_bound for c in response) == plan.terminal_bounds
            raw = compact.pack(response, layout.groups(count), layout.dimension, pk)
            if plan.response_drop is not None:
                raw = response_codec.compress(raw, pk, count=layout.groups(count), dimension=layout.dimension,
                    bits=plan.terminal_bits, bounds=list(plan.terminal_bounds),
                    dropped_bits=plan.response_drop, backend="native")
            assert len(raw) == plan.response_bytes
            raw = layout.wrap(raw, count, "response")
            expected = tuple(sum(a != b for a, b in zip(query, row, strict=True)) for row in rows)
            result = client.finish_radix_fixture(raw, raw, count, layout, plan)
            assert result.distances == expected
            assert result.top == tuple(sorted(enumerate(expected), key=lambda x: (x[1], x[0]))[:3])
        def private_forbidden(*args):
            pytest.fail("A malformed or unpinned response reached private arithmetic")
        monkeypatch.setattr(client, "decrypt_compact", private_forbidden)
        with pytest.raises(ValueError, match="pinned"):
            client.finish_radix_fixture(raw+b"bad", raw, count, layout, plan)
        # A trusted-fixture mistake must still parse every response before decryption.
        malformed = layout.wrap(b"bad", count, "response")
        with pytest.raises(ValueError):
            client.finish_radix_fixture(malformed, malformed, count, layout, plan)


def test_envelope_context_count_direction_types_and_bounds():
    layout = Layout(13, 2)
    packet = layout.wrap(b"example", 77, "query")
    assert layout.unwrap(packet, 77, "query") == b"example"
    malformed = [b"", packet[:-1], packet+b"extra", bytearray(packet)]
    for i, wrong in ((0, b"bad"), (1, "response"), (2, "balanced"), (3, True), (4, 78), (5, 12), (6, [])):
        fields = msgpack.unpackb(packet)
        fields[i] = wrong
        malformed.append(msgpack.packb(fields, use_bin_type=True))
    for wrong in malformed:
        with pytest.raises(ValueError):
            layout.unwrap(wrong, 77, "query")
    for n, t, count in ((16, 1031, 7), (32, 3, 7), (32, 1031, True), (32, 1031, 0)):
        with pytest.raises(ValueError):
            layout.validate(n, t, count)
    with pytest.raises(ValueError):
        layout.decode_value(0, 17, 2)
