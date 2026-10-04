"""Independent exhaustive/symbolic control for the Q70 finite cut grammar.

No Pareto pruning or memoized frontier is used for the exhaustive control. Its
per-residue boxes are explicitly interleaved. The symbolic butterfly oracle
comes from the preserved E15 tests and combines signed aliases before norms.
"""

from dataclasses import dataclass
from functools import lru_cache

from experiments.bfv_search_lab.noise_cut_planner import Label, Plan
from experiments.bfv_search_lab.test_support_bounds_bgv import symbolic_butterfly


@dataclass(frozen=True)
class BoxLabel:
    state: int | None
    residues: tuple[int, ...]
    removed: int
    seeds: int
    work: int
    keys: int
    plan: Plan


def exhaustive(profile, count, allow_seed, cap=4194304):
    """Complete generic enumeration within the same finite grammar."""
    q, b, n = profile.q, 1 << profile.bits, profile.n
    ell = (q.bit_length() + profile.bits - 1) // profile.bits
    produced = 0

    @lru_cache(None)
    def visit(level, present):
        nonlocal produced
        length = 1 << (level + 1)
        if not present:
            return (
                BoxLabel(0, (0,) * length, 0, 0, 0, 0, Plan(level, 0, "zero", False)),
            )
        if level == -1:
            return tuple(
                BoxLabel(
                    profile.seed_bound if option else None,
                    (profile.d * profile.product_bound,),
                    0,
                    int(option),
                    (2 * ell**2 + 4 * ell) if option else 0,
                    0,
                    Plan(-1, 1, "seed" if option else "plain", option),
                )
                for option in (False, True)
                if allow_seed or not option
            )
        values = []
        for a in visit(level - 1, (present + 1) // 2):
            for c in visit(level - 1, present // 2):
                common = (
                    None if a.state is None or c.state is None else a.state + c.state
                )
                for mode in ("canonical", "derived"):
                    if mode == "derived" and common is None:
                        continue
                    for retain in (False, True):
                        if (
                            retain
                            and mode == "canonical"
                            and c.plan.count
                            and common is None
                        ):
                            continue
                        source = common if mode == "derived" else b - 1
                        error = (
                            (profile.d >> (level + 1))
                            * profile.t
                            * profile.eta
                            * n
                            * ell
                            * source
                        )
                        rows = tuple(
                            x + error
                            for pair in zip(a.residues, c.residues, strict=True)
                            for x in pair
                        )
                        state = None
                        if retain:
                            if mode == "derived":
                                state = common * (1 + n * ell * (b - 1))
                            elif c.plan.count == 0:
                                state = (b - 1) * (1 + n * ell * (b - 1))
                            else:
                                state = common + n * ell * (b - 1) ** 2
                        values.append(
                            BoxLabel(
                                state,
                                rows,
                                a.removed + c.removed + (mode == "derived"),
                                a.seeds + c.seeds,
                                a.work + c.work + 2 * ell + (ell**2 if retain else 0),
                                a.keys | c.keys | ((1 << level) if retain else 0),
                                Plan(level, present, mode, retain, a.plan, c.plan),
                            )
                        )
                        produced += 1
                        if produced > cap:
                            raise RuntimeError("Independent exhaustive cap exceeded")
        return tuple(values)

    rows = visit(profile.d.bit_length() - 2, count)
    safe = [r for r in rows if profile.safe(max(r.residues))]
    if not safe:
        raise ValueError("No safe independent plan")
    best = min(
        safe,
        key=lambda r: (
            -r.removed,
            r.work,
            r.seeds,
            r.keys.bit_count(),
            max(r.residues),
        ),
    )
    return Label(
        None,
        max(best.residues),
        best.removed,
        best.seeds,
        best.work,
        best.keys,
        best.plan,
    ), {
        "enumerated_subproblem_labels": produced,
        "complete_root_plans": len(rows),
        "safe_root_plans": len(safe),
        "complete_no_dominance_pruning": True,
    }


def plan_boxes(profile, plan):
    """Explicit active-node error boxes and final residue rows, no HE secret."""
    errors, inputs = {}, {}
    b, ell = 1 << profile.bits, profile.ell

    def walk(value, offset, stride):
        if value.mode == "zero":
            return 0
        if value.level == -1:
            inputs[offset] = profile.product_bound
            return profile.seed_bound if value.mode == "seed" else None
        a = walk(value.left, offset, stride * 2)
        c = walk(value.right, offset + stride, stride * 2)
        common = None if a is None or c is None else a + c
        source = common if value.mode == "derived" else b - 1
        if source is None:
            raise ValueError("Unknown source in oracle")
        errors[value.level, offset] = profile.t * profile.eta * profile.n * ell * source
        if not value.retain:
            return None
        if value.mode == "derived":
            return common * (1 + profile.n * ell * (b - 1))
        if value.right.count == 0:
            return (b - 1) * (1 + profile.n * ell * (b - 1))
        if common is None:
            raise ValueError("No plus lift for retained binary output")
        return common + profile.n * ell * (b - 1) ** 2

    walk(plan, 0, 1)
    rows = []
    for lane in range(profile.d):
        row = profile.d * inputs.get(lane, 0)
        for level in range(profile.d.bit_length() - 1):
            weight = profile.d >> (level + 1)
            row += weight * errors.get((level, lane % weight), 0)
        rows.append(row)
    return tuple(rows), inputs, errors


def symbolic_box_peak(profile, plan):
    rows, inputs, errors = plan_boxes(profile, plan)
    result = symbolic_butterfly(profile.n, profile.d, plan.count)
    maxima = []
    for position, terms in enumerate(result):
        bound = sum(
            abs(weight)
            * (
                inputs.get(atom[1], 0)
                if atom[0] == "input"
                else errors.get((atom[1], atom[2]), 0)
            )
            for atom, weight in terms.items()
        )
        assert bound == rows[position % profile.d]
        maxima.append(bound)
    return max(maxima), len(maxima)
