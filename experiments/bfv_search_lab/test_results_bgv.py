"""Independent result layouts, exhaustive residues, ties and native boundaries."""

from dataclasses import replace
import random
import struct

import pytest

from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, owner_bgv as owner
from experiments.bfv_search_lab import results_bgv as results


def fixture(n, t, dimension, distances):
    # Scatter D-scaled signed correlations directly, independently of the decoder.
    rng = random.Random(n + dimension)
    polys = [[rng.randrange(t) for _ in range(n)] for _ in range((len(distances) + n - 1) // n)]
    padded = 1 << (dimension - 1).bit_length()
    for i, distance in enumerate(distances):
        group, position = divmod(i, n)
        tile, lane = divmod(position, n // padded)
        polys[group][lane * padded + tile] = (padded * (dimension - 2 * distance)) % t
    return polys


def native_result(polys, pk, count, dimension, k, all_distances=True):
    native = pytest.importorskip("experiments.bfv_search_lab._owner._bgv_owner")
    data = native.finish_plaintexts(tuple(struct.pack(f"<{pk.n}I", *p) for p in polys),
                                    pk.n, pk.t, count, dimension, k, all_distances)
    return results.from_native(data, count, k, all_distances)


@pytest.mark.parametrize("n,dimension,t", [(8, 1, 9), (16, 3, 15), (64, 31, 1031),
                                         (2048, 512, 1031), (16384, 512, 1031)])
@pytest.mark.parametrize("native", [False, True])
def test_lookup_heap_native_match_independent_layout_with_tails_and_ties(n, dimension, t, native):
    pk, _ = bgv.key_gen(n, t=t, q_bits=120)
    rng = random.Random(n + t)
    for count in (0, 1, 2, n - 1, n, n + 7):
        distances = [rng.randrange(dimension + 1) for _ in range(count)]
        if count > 6:
            distances[:6] = [0, dimension, 0, dimension, 0, 0]
        polys = fixture(n, t, dimension, distances)
        assert trace.decode(polys, count, dimension, pk) == distances
        for k in (0, 1, 3, 64):
            for all_distances in (False, True):
                expected = results.SearchResult(
                    tuple((i, distances[i]) for i in sorted(range(count), key=lambda i: (distances[i], i))[:k]),
                    tuple(distances) if all_distances else None,
                )
                for method in ("sort", "heap", "lookup"):
                    assert results.finish(polys, count, dimension, pk, k=k, all_distances=all_distances, method=method) == expected
                if native:
                    assert native_result(polys, pk, count, dimension, k, all_distances) == expected


@pytest.mark.parametrize("dimension", [1, 2, 3, 4])
@pytest.mark.parametrize("native", [False, True])
def test_every_residue_acceptance_matches_original_decoder(dimension, native):
    pk, _ = bgv.key_gen(16, t=2 * dimension + 3, q_bits=120)
    for residue in range(pk.t):
        polys = [[0] * pk.n]
        polys[0][0] = residue
        try:
            original = trace.decode(polys, 1, dimension, pk)
        except ValueError:
            with pytest.raises(ValueError, match="correlation"):
                results.decode_lookup(polys, 1, dimension, pk)
            if native:
                with pytest.raises(ValueError, match="correlation"):
                    native_result(polys, pk, 1, dimension, 1)
        else:
            assert results.decode_lookup(polys, 1, dimension, pk) == original
            if native:
                assert native_result(polys, pk, 1, dimension, 1).distances == tuple(original)


def test_native_large_odd_plaintext_modulus_uses_bounded_arithmetic_fallback():
    pk, _ = bgv.key_gen(64, t=65539, q_bits=120)
    distances = list(range(32)) * 3
    polys = fixture(pk.n, pk.t, 31, distances)
    assert native_result(polys, pk, len(distances), 31, 3) == results.finish(polys, len(distances), 31, pk, method="sort")
    with pytest.raises(ValueError, match="caps"):
        results.decode_lookup(polys, len(distances), 31, pk)


@pytest.mark.parametrize("native,rns", [(False, False), (True, False), (True, True)])
def test_encrypted_owner_finish_matches_full_reference_and_validates_lifecycle(native, rns):
    if native:
        pytest.importorskip("experiments.bfv_search_lab._owner._bgv_owner")
    pk, sk = bgv.key_gen(64, q_bits=120, rns_modulus=True)
    client = owner.OwnerClient(pk, sk, native=native, rns=rns)
    distances = [i % 4 for i in range(129)]
    polys = fixture(pk.n, pk.t, 3, distances)
    ciphertexts = [compact.compact(owner.expand(client.encrypt(p), pk), pk, 25) for p in polys]
    expected = results.finish(polys, len(distances), 3, pk, method="sort")
    methods = ("sort", "heap", "lookup", "native") if native else ("sort", "heap", "lookup")
    for method in methods:
        assert client.finish(ciphertexts, len(distances), 3, method=method) == expected
        assert client.finish(ciphertexts, len(distances), 3, method=method, all_distances=False) == replace(expected, distances=None)
        assert client.finish([], 0, 3, method=method).top == ()
    if not native:
        with pytest.raises(ValueError, match="native owner"):
            client.finish(ciphertexts, len(distances), 3)
    bad = ciphertexts.copy()
    bad[-1] = replace(bad[-1], key_id="bad")
    with pytest.raises(ValueError):
        client.finish(bad, len(distances), 3, method=methods[-1])
    client.close()
    with pytest.raises(RuntimeError, match="closed"):
        client.finish(ciphertexts, len(distances), 3)


def test_invalid_unselected_correlations_and_padding_are_not_skipped():
    pk, _ = bgv.key_gen(16, t=15, q_bits=120)
    for count in (4, 17):
        polys = fixture(pk.n, pk.t, 3, [0] * count)
        # Even after the first three best scores, a later bad correlation rejects.
        last = count - 1
        group, at = divmod(last, pk.n)
        tile, lane = divmod(at, pk.n // 4)
        polys[group][lane * 4 + tile] = 0  # odd dimension cannot have dot = 0
        for method in ("sort", "heap", "lookup"):
            with pytest.raises(ValueError, match="correlation"):
                results.finish(polys, count, 3, pk, method=method, all_distances=False)
        with pytest.raises(ValueError, match="correlation"):
            native_result(polys, pk, count, 3, 3, False)
    polys = fixture(pk.n, pk.t, 3, [0])
    polys[0][-1] = pk.t  # Noncanonical UNUSED coefficient must still reject.
    with pytest.raises(ValueError):
        results.decode_lookup(polys, 1, 3, pk)
    with pytest.raises(ValueError):
        native_result(polys, pk, 1, 3, 1)


def test_raw_native_finish_boundaries_and_closed_handle():
    native = pytest.importorskip("experiments.bfv_search_lab._owner._bgv_owner")
    good = [(), 8, 15, 0, 3, 3, True]
    for index, value in ((0, []), (1, True), (1, 0), (2, 2), (3, 513), (4, 0), (5, 65), (6, 1)):
        args = good.copy()
        args[index] = value
        with pytest.raises((ValueError, OverflowError)):
            native.finish_plaintexts(*args)
    for bad in (b"", bytes(33), bytearray(32)):
        with pytest.raises(ValueError):
            native.finish_plaintexts((bad,), 8, 15, 1, 3, 3, True)
    handle = native.create(8, b"\x01" * 8)
    with pytest.raises(ValueError):
        native.finish(handle, ((bytes(8),),), "10001", 15, 1, 3, 3, True)
    with pytest.raises(ValueError):
        native.finish(handle, ((b"", b""),), "10001", 15, 1, 3, 3, True)
    native.close(handle)
    with pytest.raises(RuntimeError, match="closed"):
        native.finish(handle, (), "10001", 15, 0, 3, 3, True)
