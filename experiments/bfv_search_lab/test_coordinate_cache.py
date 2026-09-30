"""Cache controls retain all exact scores and stable ID ties without HE."""

from dataclasses import replace

import pytest

from experiments.bfv_search_lab import coordinate_cache as cache
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def fixture():
    w = Workload((0, 1, 2, 3, 8, 9, 10, 11), (99, 41, 8, 2, 19, 18, 17, 16), 4)
    choice = oracle.choices(w, oracle.median_tree(w, 1), 17)[-1]
    return oracle.compile_choice(w, choice, Profile(32, 17, eta=1), (1, 1))


@pytest.mark.parametrize("mode", ("packed", "expanded", "raw", "zlib"))
def test_all_binary_queries_scores_and_stable_top3(mode):
    p = fixture()
    if mode in ("packed", "expanded"):
        c = cache.Coordinates(p.candidate, p.groups, p.workload.ids, mode=mode)
        assert not hasattr(c, "rows")
    else:
        kind = cache.RawRows if mode == "raw" else cache.CompressedRows
        c = kind(p.workload.rows, p.workload.ids, p.workload.dimension)
    for word in range(16):
        result = c.query(word)
        assert result.scores == p.workload.expected(word)
        assert result.top3 == p.workload.top_k(result.scores)


def test_one_bit_pivots_and_constant_blocks_need_no_coordinates():
    w = Workload((5, 5, 5), (9, 1, 8), 4)
    p = oracle.compile_choice(w, oracle.choices(w, oracle.median_tree(w, 0), 17)[1], Profile(32, 17), (1,))
    for mode in ("packed", "expanded"):
        c = cache.Coordinates(p.candidate, p.groups, w.ids, mode=mode)
        assert c.coordinate_body_bytes == 0
        assert c.query(0).top3 == ((2, 1), (2, 8), (2, 9))
    p = fixture()
    c = cache.Coordinates(p.candidate, p.groups, p.workload.ids)
    expected = sum((len(b.positions) * b.mapping.rank + 7) // 8 for b in p.candidate.blocks)
    assert c.coordinate_body_bytes == expected


def test_incomplete_coverage_and_malformed_coords_reject_before_int8_wrap():
    p = fixture()
    malformed = replace(p.candidate, blocks=(replace(p.candidate.blocks[0], positions=()), *p.candidate.blocks[1:]))
    with pytest.raises(ValueError, match="coverage"):
        cache.Coordinates(malformed, p.groups, p.workload.ids)
    groups = [[list(row) for row in group] for group in p.groups]
    groups[0][0][0] = 256
    with pytest.raises(ValueError, match="binary coordinates"):
        cache.Coordinates(p.candidate, groups, p.workload.ids)
    with pytest.raises(ValueError, match="unique"):
        cache.Coordinates(p.candidate, p.groups, (1,) * len(p.workload.ids))


def test_detached_coordinate_cache_does_not_call_row_oracle(monkeypatch):
    p = fixture()
    c = cache.Coordinates(p.candidate, p.groups, p.workload.ids)
    def forbidden(*args):
        raise AssertionError("cache consulted detached plaintext oracle")
    monkeypatch.setattr(Workload, "expected", forbidden)
    assert c.query(0).scores == (0, 1, 1, 2, 1, 2, 2, 3)


@pytest.mark.parametrize("word", (-1, 16, True))
def test_invalid_query_rejected(word):
    p = fixture()
    for c in (cache.Coordinates(p.candidate, p.groups, p.workload.ids),
              cache.CompressedRows(p.workload.rows, p.workload.ids, 4),
              cache.RawRows(p.workload.rows, p.workload.ids, 4)):
        with pytest.raises(ValueError):
            c.query(word)
