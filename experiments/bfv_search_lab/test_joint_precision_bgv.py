"""Joint public bound planning, exact coefficient maps and encrypted search."""

from contextlib import closing

import gmpy2
from gmpy2 import mpz
import msgpack
import pytest

from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, owner_bgv as owner
from experiments.bfv_search_lab import compressed_query_bgv as query_codec
from experiments.bfv_search_lab import compressed_response_bgv as response_codec
from experiments.bfv_search_lab import joint_precision_bgv as planner, transport_bgv as wire
from experiments.bfv_search_lab.native_bgv import NativeServer


@pytest.mark.parametrize("bits,drop", [(16, 12), (25, 20), (32, 25), (59, 45)])
def test_response_codec_native_reference_identity_and_byte_model(bits, drop):
    pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace")
    pk, _ = bgv.key_gen(16, q_bits=120, rns_modulus=True)
    p = compact.terminal_modulus(pk.q, pk.t, bits)
    c0 = tuple([mpz(0), mpz(1), p - 1, p - 2] * 4)
    ct = compact.CompactCiphertext((c0, tuple([mpz(0)] * pk.n)), pk.key_id, p, 0)
    # Synthetic coefficient fixture: the claimed phase bound is used only to
    # test the map and parser, never to decrypt this arbitrary polynomial.
    packet = compact.pack([ct], 13, 3, pk)
    kwargs = dict(count=13, dimension=3, bits=bits, bounds=[0], dropped_bits=drop)
    compressed = response_codec.compress(packet, pk, **kwargs)
    assert response_codec.compress(packet, pk, backend="native", **kwargs) == compressed
    assert response_codec.compress(packet, pk, backend="native-gmp", **kwargs) == compressed
    unpacked, bounds = response_codec.expand(compressed, pk, **kwargs)
    assert response_codec.expand(compressed, pk, backend="native", **kwargs) == (unpacked, bounds)
    assert response_codec.expand(compressed, pk, backend="native-gmp", **kwargs) == (
        unpacked,
        bounds,
    )
    result = wire.unpack_fixture(unpacked, pk, count=13, dimension=3, modulus=p, bounds=bounds)[0]
    extra = query_codec.coefficient_encoding(p, pk.t, drop).added_bound
    assert bounds == [extra]
    for before, after in zip(c0, result.components[0], strict=True):
        delta = (after - before) % p
        if delta > p // 2:
            delta -= p
        assert delta % pk.t == 0 and abs(delta) <= extra
    assert result.components[1] == ct.components[1]
    assert len(packet) == response_codec.packet_size(pk, 13, 3, bits, None)
    assert len(compressed) == response_codec.packet_size(pk, 13, 3, bits, drop)


@pytest.mark.parametrize("owner_index", [False, True])
def test_joint_planner_sizes_bounds_and_exact_encrypted_search(owner_index):
    pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace")
    pk, sk = bgv.key_gen(64, q_bits=120, rns_modulus=True)
    query = [1, 0, 1, 1, 0, 1, 0]
    rows = [query[:], [1 - x for x in query], [0] * len(query)] * 44
    message, tiles = bgv.coefficient_inputs(query, rows, pk.n)
    keys = trace.evaluation_keys(pk, sk, 8)
    server = NativeServer(pk, keys, residue=True)
    with closing(owner.OwnerClient(pk, sk, native=True, rns=True)) as client:
        index = [
            owner.expand(client.encrypt(p), pk) if owner_index else bgv.encrypt(p, pk)
            for p in tiles
        ]
        prepared = server.prepare_index(index, len(rows))
        plans = planner.enumerate_plans(server, prepared, len(query), terminal_bits=(16, 25, 32))
        frontier = planner.pareto(plans)
        assert frontier and all(
            a.query_bytes < b.query_bytes and a.response_bytes > b.response_bytes
            for a, b in zip(frontier, frontier[1:], strict=False)
        )
        for point in frontier:
            assert not any(
                p.query_bytes <= point.query_bytes
                and p.response_bytes <= point.response_bytes
                and p.total_bytes < point.total_bytes
                for p in plans
            )
        selected = {
            planner.select(frontier, up, down) for up, down in ((1, 1), (10, 100), (100, 10))
        }
        selected.add(
            next(
                p
                for p in plans
                if p.query_drop is None and p.response_drop is None and p.terminal_bits == 25
            )
        )
        fresh = client.encrypt(message)
        for plan in selected:
            packet = (
                fresh
                if plan.query_drop is None
                else query_codec.compress(fresh, pk, dropped_bits=plan.query_drop, backend="native")
            )
            expanded = (
                owner.expand(packet, pk)
                if plan.query_drop is None
                else query_codec.expand(packet, pk, dropped_bits=plan.query_drop, backend="native")
            )
            assert len(packet) == plan.query_bytes
            response = server.search_compact(expanded, prepared, bits=plan.terminal_bits)
            raw = compact.pack(response, len(rows), len(query), pk)
            bounds = list(plan.terminal_bounds)
            if plan.response_drop is not None:
                kwargs = dict(
                    count=len(rows),
                    dimension=len(query),
                    bits=plan.terminal_bits,
                    bounds=bounds,
                    dropped_bits=plan.response_drop,
                    backend="native",
                )
                packed = response_codec.compress(raw, pk, **kwargs)
                assert len(packed) == plan.response_bytes
                raw, bounds = response_codec.expand(packed, pk, **kwargs)
            else:
                assert len(raw) == plan.response_bytes
            assert bounds == list(plan.final_bounds)
            result = client.finish_packed_fixture(
                raw, raw, len(rows), len(query), bits=plan.terminal_bits, bounds=bounds
            )
            expected = tuple(sum(a != b for a, b in zip(row, query, strict=True)) for row in rows)
            assert result.distances == expected
            assert result.top == tuple(sorted(enumerate(expected), key=lambda x: (x[1], x[0]))[:3])
        for link in ((0, 1), (1, float("inf")), (float("nan"), 1)):
            with pytest.raises(ValueError):
                planner.select(frontier, *link)


@pytest.mark.parametrize("backend", ["python", "native", "native-gmp"])
def test_response_codec_rejects_wrong_headers_holes_coefficients_and_bounds(backend):
    pytest.importorskip("experiments.bfv_search_lab._native._bgv_trace")
    pk, _ = bgv.key_gen(16, q_bits=120, rns_modulus=True)
    p = compact.terminal_modulus(pk.q, pk.t, 25)
    ct = compact.CompactCiphertext((tuple([mpz(0)] * pk.n),) * 2, pk.key_id, p, 0)
    original = compact.pack([ct], 13, 3, pk)
    kwargs = dict(count=13, dimension=3, bits=25, bounds=[0], dropped_bits=1, backend=backend)
    packet = response_codec.compress(original, pk, **kwargs)
    malformed = [
        b"",
        packet[:-1],
        packet + b"x",
        bytearray(packet),
        msgpack.packb({}),
        msgpack.packb([[[]]]),
    ]
    for position, value in ((0, "bad"), (1, True), (3, b""), (4, bytes(32)), (5, 12), (7, True)):
        fields = msgpack.unpackb(packet)
        fields[0][position] = value
        malformed.append(msgpack.packb(fields, use_bin_type=True))
    for component in (0, 1):
        fields = msgpack.unpackb(packet)
        if component == 0:
            e = query_codec.coefficient_encoding(p, pk.t, 1)
            # R=2<t: residue 2 cannot represent a canonical original coefficient.
            fields[1][0][0] = gmpy2.pack(
                [mpz(2)] + [mpz(0)] * (pk.n - 1), e.coefficient_bits
            ).to_bytes(len(fields[1][0][0]), "little")
        else:
            fields[1][0][1] = gmpy2.pack([p] * pk.n, p.bit_length()).to_bytes(
                len(fields[1][0][1]), "little"
            )
        malformed.append(msgpack.packb(fields, use_bin_type=True))
    for bad in malformed:
        with pytest.raises(ValueError):
            response_codec.expand(bad, pk, **kwargs)
    for drop, bound in ((24, int(p) // 3), (25, 0), (True, 0), (1, -1), (1, True)):
        with pytest.raises(ValueError):
            response_codec.compress(
                original, pk, **{**kwargs, "dropped_bits": drop, "bounds": [bound]}
            )
