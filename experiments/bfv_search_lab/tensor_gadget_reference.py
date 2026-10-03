"""Q70 small homemade encrypted evaluator for two known-gadget follow-ups.

An exact public replay tests mixed14 and tensor18 semantics. No native/proof
performance or production admission is supplied. Phase assumptions come from
trusted owner metadata; observed private errors never select a policy.
"""

from __future__ import annotations

from gmpy2 import mpz

from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import propagated_gadget_bgv as gadget
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import tensor_gadget_seed as seed


def make_trace(query, index, count, dimension, pk, canonical, alternate, rule):
    if rule not in ("mixed14", "tensor18") or pk.n > 128 or canonical.digit_bits != 30:
        raise ValueError("Registered small follow-up rule required")
    bits = 14 if rule == "mixed14" else 18
    if alternate.digit_bits != bits or alternate.padded != canonical.padded:
        raise ValueError("Wrong alternate key schedule")
    butterfly.validate_keys(pk, canonical)
    butterfly.validate_keys(pk, alternate)
    n, q, d = pk.n, int(pk.q), canonical.padded
    if (
        d < 8
        or not 1 <= dimension <= d
        or (1 << (dimension - 1).bit_length()) != d
        or pk.t <= 2 * dimension
    ):
        raise ValueError("Wrong small follow-up dimension")
    if (
        type(count) is not int
        or count < 1
        or len(index) != (count + n // d - 1) // (n // d)
    ):
        raise ValueError("Wrong index coverage")
    for c in (query, *index):
        bgv._validate(c, pk)
        if len(c.components) != 2:
            raise ValueError("Two-component inputs required")
    bounds, active = [], []
    lseed = seed.seed_bound(n, q, bits)
    ell = (q.bit_length() + bits - 1) // bits
    for start in range(0, len(index), d):
        group = index[start : start + d]
        size, product = (
            len(group),
            n * int(query.phase_bound) * max(int(c.phase_bound) for c in group),
        )
        selected = rule == "tensor18" or size <= d // 2
        if rule == "mixed14" and selected:
            small = gadget.model(
                n,
                q,
                pk.t,
                pk.eta,
                d,
                size,
                bits,
                int(query.phase_bound),
                max(int(c.phase_bound) for c in group),
                propagated_stages=2,
            )
            bound = d * (product + canonical.switch_error_bound) + sum(
                r["suffix_support_weight"]
                * (
                    r["switch_error_bound"]
                    if r["level"] < 3
                    else canonical.switch_error_bound
                )
                for r in small["stages"]
            )
        elif rule == "tensor18":
            bound = (
                d * (product + canonical.switch_error_bound)
                + (d // 2)
                * pk.t
                * pk.eta
                * n
                * ell
                * lseed
                * (2 if size > d // 2 else 1)
                + (d // 2 - 1) * canonical.switch_error_bound
            )
        else:
            bound = (
                d * (product + canonical.switch_error_bound)
                + (d - 1) * canonical.switch_error_bound
            )
        p = compact.terminal_modulus(pk.q, pk.t, 16)
        compact.reduced_bound(bound, pk, p)  # Full Q/P guard before any evaluator work.
        bounds.append(bound)
        active.append(selected)
    cuts, output = [], []
    for group, start in enumerate(range(0, len(index), d)):
        work, states = [], []
        for node, tile in enumerate(index[start : start + d]):
            product = bgv.multiply(query, tile, pk, karatsuba=True)
            source = tuple(map(int, product.components[2]))
            digits = gadget.canonical_digits(source, q, 30)
            cuts.append(gadget.Cut(group, -1, node, "canonical30", source, digits))
            correction = gadget.switched(digits, canonical.relin, q)
            pair = tuple(
                tuple((int(x) + y) % q for x, y in zip(poly, corr, strict=True))
                for poly, corr in zip(product.components[:2], correction, strict=True)
            )
            pair = tuple(
                tuple(x % q for x in gadget.permute(poly, shift=1 - d)) for poly in pair
            )
            work.append(pair)
            if rule == "tensor18":
                state = seed.c1_seed(
                    tuple(tuple(map(int, p)) for p in query.components),
                    tuple(tuple(map(int, p)) for p in tile.components),
                    digits,
                    tuple(tuple(map(int, pair[1])) for pair in canonical.relin),
                    q,
                    bits,
                )
                state = tuple(gadget.permute(row, shift=1 - d) for row in state)
                assert gadget.recompose(state, bits, q) == pair[1]
                states.append(state)
        shift = d // 2
        for level, (exponent, standard_key) in enumerate(canonical.rotations):
            use_small = active[group] and (
                level < 3 if rule == "mixed14" else level == 0
            )
            key = alternate.rotations[level][1] if use_small else standard_key
            width = bits if use_small else 30
            merged, next_states = [], []
            key_a = (
                gadget.public_a_digits(key, q, bits)
                if rule == "mixed14" and active[group] and level < 2
                else None
            )
            for node in range(min(shift, len(work))):
                has_right = node + shift < len(work)
                right = (
                    tuple(gadget.permute(p, shift=shift) for p in work[node + shift])
                    if has_right
                    else ((0,) * n,) * 2
                )
                plus = tuple(
                    tuple((x + y) % q for x, y in zip(a, b, strict=True))
                    for a, b in zip(work[node], right, strict=True)
                )
                minus = tuple(
                    tuple((x - y) % q for x, y in zip(a, b, strict=True))
                    for a, b in zip(work[node], right, strict=True)
                )
                c0, source = (
                    tuple(x % q for x in gadget.permute(p, exponent)) for p in minus
                )
                derived = use_small and (rule == "tensor18" or level > 0)
                if derived:
                    right_state = states[node + shift] if has_right else None
                    digits = gadget.source_state(
                        states[node], right_state, shift, exponent
                    )
                    if rule == "tensor18":
                        limit = lseed * (2 if has_right else 1)
                    else:
                        limit = (
                            ((1 << bits) - 1)
                            * (1 + ell * n * ((1 << bits) - 1)) ** level
                            * (2**level)
                        )
                    gadget.validate_digits(source, digits, width, q, limit)
                else:
                    digits = gadget.canonical_digits(source, q, width)
                cuts.append(
                    gadget.Cut(
                        group,
                        level,
                        node,
                        rule if derived else f"canonical{width}",
                        source,
                        digits,
                    )
                )
                b, a = gadget.switched(digits, key, q)
                pair = (
                    tuple(
                        (x + y + z) % q for x, y, z in zip(plus[0], c0, b, strict=True)
                    ),
                    tuple((x + y) % q for x, y in zip(plus[1], a, strict=True)),
                )
                merged.append(pair)
                if key_a is not None:
                    state = (
                        gadget.unary_state(digits, exponent, key_a)
                        if level == 0
                        else gadget.next_state(
                            states[node],
                            states[node + shift] if has_right else None,
                            shift,
                            digits,
                            key_a,
                        )
                    )
                    assert gadget.recompose(state, bits, q) == pair[1]
                    next_states.append(state)
            work, states, shift = merged, next_states, shift // 2
        output.append(work[0])
    ciphers = [
        bgv.Ciphertext(tuple(tuple(map(mpz, p)) for p in pair), pk.key_id, bound)
        for pair, bound in zip(output, bounds, strict=True)
    ]
    packet = compact.pack(
        [compact.compact(c, pk, 16) for c in ciphers], count, dimension, pk
    )
    return gadget.Transcript(
        rule,
        pk.key_id,
        count,
        dimension,
        tuple(cuts),
        tuple(output),
        tuple(bounds),
        packet,
    )


def check_trace(
    query, index, count, dimension, pk, canonical, alternate, rule, supplied
):
    """Strict immutable complete public replay, no private operations."""
    try:

        def integers(row):
            return (
                type(row) is tuple
                and len(row) == pk.n
                and all(type(x) is int for x in row)
            )

        if (
            type(supplied) is not gadget.Transcript
            or type(supplied.response) is not bytes
            or type(supplied.count) is not int
            or type(supplied.dimension) is not int
            or type(supplied.policy) is not str
            or type(supplied.key_id) is not str
            or type(supplied.full_output) is not tuple
            or type(supplied.cuts) is not tuple
            or type(supplied.bounds) is not tuple
            or any(type(x) is not int for x in supplied.bounds)
        ):
            return False
        for pair in supplied.full_output:
            if (
                type(pair) is not tuple
                or len(pair) != 2
                or not all(integers(p) for p in pair)
            ):
                return False
        for cut in supplied.cuts:
            if (
                type(cut) is not gadget.Cut
                or type(cut.kind) is not str
                or any(type(x) is not int for x in (cut.group, cut.level, cut.node))
                or not integers(cut.source)
                or type(cut.digits) is not tuple
                or not all(integers(p) for p in cut.digits)
            ):
                return False
        return supplied == make_trace(
            query, index, count, dimension, pk, canonical, alternate, rule
        )
    except (ValueError, TypeError, IndexError, AttributeError):
        return False
