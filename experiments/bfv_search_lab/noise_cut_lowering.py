"""Known canonical30 suffix lowering, with an explicit radix-state boundary.

The original exact planner optimizes a uniform-rotation-radix grammar. This
replays one selected plan under a different, fully priced per-level key
schedule; it never claims an optimum over mixed-radix plans.
"""

from dataclasses import replace

from experiments.bfv_search_lab import noise_cut_oracle as oracle
from experiments.bfv_search_lab import noise_cut_planner as planner


def lower(profile, plan):
    original = planner.replay(profile, plan)
    actions = []

    def inspect(value):
        if value.mode == "zero" or value.level == -1:
            return
        actions.append(value)
        inspect(value.left)
        inspect(value.right)

    inspect(plan)
    last = max(
        (v.level for v in actions if v.retain or v.mode == "derived"), default=-1
    )
    widths = tuple(
        profile.bits if level <= last else 30
        for level in range(profile.d.bit_length() - 1)
    )

    def replay(value):
        if value.mode == "zero":
            return planner.Label(0, 0, 0, 0, 0, 0, value)
        if value.level == -1:
            return planner.leaf(profile, True, value.mode == "seed")
        if value.level > last and (value.mode != "canonical" or value.retain):
            raise ValueError("No state or derived action allowed beyond radix boundary")
        p = replace(profile, bits=widths[value.level])
        return planner.node(
            p,
            value.level,
            value.count,
            replay(value.left),
            replay(value.right),
            value.mode,
            value.retain,
        )

    value = replay(plan)
    # Independent full residue reconstruction: only the errors after the last
    # state/derived node change. Input boxes and all original digit lifts remain.
    _, inputs, errors = oracle.plan_boxes(profile, plan)
    canonical = replace(profile, bits=30)
    changed = {
        (level, node): canonical.canonical_error if level > last else error
        for (level, node), error in errors.items()
    }
    rows = tuple(
        profile.d * inputs.get(lane, 0)
        + sum(
            (profile.d >> (level + 1))
            * changed.get((level, lane % (profile.d >> (level + 1))), 0)
            for level in range(len(widths))
        )
        for lane in range(profile.d)
    )
    assert max(rows) == value.peak
    assert (value.removed, value.seeds, value.digit_key_levels) == (
        original.removed,
        original.seeds,
        original.digit_key_levels,
    )
    body = planner.ledger(profile, value)
    qpoly = (profile.n * profile.q.bit_length() + 7) // 8
    columns = sum((profile.q.bit_length() + bits - 1) // bits for bits in widths)
    ell30 = (profile.q.bit_length() + 29) // 30
    body.update(
        rotation_key_Q_body_bytes=2 * columns * qpoly,
        additional_rotation_key_Q_body_bytes_vs30=2
        * (columns - ell30 * len(widths))
        * qpoly,
        rotation_radix_bits_by_level=widths,
        rotation_columns_by_level=[
            (profile.q.bit_length() + bits - 1) // bits for bits in widths
        ],
        last_state_or_derived_level=last,
        exact_optimization_scope="No mixed-radix optimization; legal lowering of one uniform-grammar selected plan",
        scope="Known state-boundary suffix lowering. Same source/terminal-Q body and public digit state; changed key/correction work and full envelope are repriced. No complete admission, memory/scratch/transform/update/lifecycle or timing result.",
    )
    return value, body, rows
