"""Known cell mismatches preserve the exact metric; malformed rows reject."""

import pytest

from experiments.bfv_search_lab import connect4_fixture as fixture


def test_indicator_distance_is_twice_cell_mismatch_and_ignores_outcome():
    a, b = ["b"] * 42, ["b"] * 42
    a[0], a[17], b[1], b[17] = "x", "o", "o", "x"
    rows = fixture.parse(",".join(a + ["win"]) + "\n" + ",".join(b + ["draw"]))
    assert (rows[0] ^ rows[1]).bit_count() == 2 * sum(x != y for x, y in zip(a, b, strict=True)) == 6
    assert all(row.bit_count() == 42 for row in rows)
    assert fixture.parse(",".join(a + ["loss"])) == (rows[0],)
    for text in (",".join(a), ",".join(["z"] + a[1:] + ["win"]), ",".join(a + ["bad"])):
        with pytest.raises(ValueError):
            fixture.parse(text)
