"""Mixed key lowering cannot use a retained state across the radix boundary."""

from dataclasses import replace

import pytest

from experiments.bfv_search_lab import noise_cut_lowering as lowering
from experiments.bfv_search_lab import noise_cut_planner as planner
from experiments.bfv_search_lab.test_noise_cut_planner import profile


@pytest.mark.parametrize("bits", [14, 18, 30])
@pytest.mark.parametrize("seeded", [False, True])
def test_lowering_preserves_cuts_and_prices_every_level(bits, seeded):
    p = profile(n=16, d=8, bits=bits)
    value = planner.select(planner.frontier(p, 5, seeded)[0])
    lowered, ledger, rows = lowering.lower(p, value.plan)
    assert max(rows) == lowered.peak and lowered.removed == value.removed
    assert (
        ledger["source_and_terminal_Q_body_bytes"]
        == planner.ledger(p, value)["source_and_terminal_Q_body_bytes"]
    )
    last = ledger["last_state_or_derived_level"]
    assert all(b == 30 for b in ledger["rotation_radix_bits_by_level"][last + 1 :])
    assert (
        ledger["rotation_key_Q_body_bytes"]
        <= planner.ledger(p, value)["rotation_key_Q_body_bytes"]
    )
    assert lowered.work <= value.work


def test_no_retained_or_derived_state_uses_all_canonical30_keys():
    p = profile(n=16, d=8, bits=14)

    def opaque(level, count):
        if not count:
            return planner.Plan(level, 0, "zero", False)
        if level == -1:
            return planner.Plan(-1, 1, "plain", False)
        return planner.Plan(
            level,
            count,
            "canonical",
            False,
            opaque(level - 1, (count + 1) // 2),
            opaque(level - 1, count // 2),
        )

    _, ledger, _ = lowering.lower(p, opaque(2, 5))
    assert ledger["rotation_radix_bits_by_level"] == (30, 30, 30)
    assert ledger["additional_rotation_key_Q_body_bytes_vs30"] == 0
    with pytest.raises(ValueError):
        lowering.lower(p, replace(opaque(2, 5), left=object()))
