"""Public binary fixture oracle checks; no HE keys, private work or native code."""

import pytest

from benchmarks import source_shared_query_lab as source


@pytest.mark.parametrize("query_number,top", ((0, (0, 1, 2)), (1, (3, 4, 5))))
def test_registered_public_fixture_has_nontrivial_rows_and_stable_exact_ties(query_number, top):
    rows, queries = source.synthetic_rows()
    assert len(rows) == 32768 * 64
    distances = source.plaintext_distances(rows, 32768, queries[query_number])
    assert len(distances) == 32768
    assert sorted(range(len(distances)), key=lambda i: (distances[i], i))[:3] == list(top)
    assert all(distances[i] == 0 for i in top)
    assert distances[:6] == (
        (0, 0, 0, 384, 384, 384) if query_number == 0 else (384, 384, 384, 0, 0, 0)
    )
    for count in source.COUNTS:
        assert source.plaintext_distances(rows, count, queries[query_number]) == distances[:count]
    for at in (8223, 8224, 16383, 16384, 32767):
        raw = rows[at * 64 : (at + 1) * 64]
        assert raw != bytes(64)
        assert distances[at] == sum(
            (a ^ b).bit_count()
            for a, b in zip(raw, queries[query_number].to_bytes(64, "little"), strict=True)
        )
