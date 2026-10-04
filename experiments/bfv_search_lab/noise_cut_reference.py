"""Q70 small public encrypted replay of the registered per-node cut grammar.

This uses homemade Python/GMP BGV arithmetic. Plans change the evaluator's
digit relation, so complete ciphertext bytes may differ from canonical30.
All guards precede evaluation and use trusted owner phase metadata. Diagnostic
traces retain every cut; this is not a compact proof or efficient admission.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json

from gmpy2 import mpz

from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import noise_cut_planner as planner
from experiments.bfv_search_lab import propagated_gadget_bgv as gadget
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import tensor_gadget_seed as seed


def profiles(query, index, count, dimension, pk, canonical, rotations):
    """Trusted input context; no response metadata may supply these bounds."""
    if (
        pk.n > 128
        or canonical.digit_bits != 30
        or rotations.digit_bits not in (14, 18, 30)
        or rotations.padded != canonical.padded
        or type(dimension) is not int
        or not 1 <= dimension <= pk.n // 2
        or (1 << (dimension - 1).bit_length()) != canonical.padded
        or pk.t <= 2 * canonical.padded
        or type(count) is not int
        or count < 1
        or len(index)
        != (count + pk.n // canonical.padded - 1) // (pk.n // canonical.padded)
    ):
        raise ValueError("Wrong registered small encrypted context")
    butterfly.validate_keys(pk, canonical)
    butterfly.validate_keys(pk, rotations)
    for cipher in (query, *index):
        bgv._validate(cipher, pk)
        if len(cipher.components) != 2 or type(cipher.phase_bound) is not int:
            raise ValueError(
                "Two-component inputs with trusted integer bounds required"
            )
    d = canonical.padded
    p = int(compact.terminal_modulus(pk.q, pk.t, 16))
    return tuple(
        planner.Profile(
            pk.n,
            d,
            int(pk.q),
            p,
            pk.t,
            pk.eta,
            rotations.digit_bits,
            pk.n
            * query.phase_bound
            * max(c.phase_bound for c in index[start : start + d])
            + canonical.switch_error_bound,
        )
        for start in range(0, len(index), d)
    )


def policy(contexts, plans):
    body = json.dumps(
        [(asdict(p), asdict(plan)) for p, plan in zip(contexts, plans, strict=True)],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return "cuhepy-lab-per-node-cut-v1:" + hashlib.sha256(body).hexdigest()


def make_trace(query, index, count, dimension, pk, canonical, rotations, plans):
    contexts = profiles(query, index, count, dimension, pk, canonical, rotations)
    if type(plans) is not tuple or len(plans) != len(contexts):
        raise ValueError("Exact immutable group plans required")
    labels = []
    for group, (context, plan) in enumerate(zip(contexts, plans, strict=True)):
        label = planner.replay(context, plan)
        if plan.count != min(context.d, len(index) - group * context.d):
            raise ValueError("Plan does not cover the exact original snapshot")
        if not context.safe(label.peak):
            raise ValueError("Unsafe public Q/P plan envelope")
        labels.append(label)
    # Every context and full schedule is guarded before the first multiply.
    n, q, d = pk.n, int(pk.q), canonical.padded
    cuts, output = [], []
    key_digits = {}
    zero_pair = ((0,) * n,) * 2
    zero_state = ((0,) * n,) * contexts[0].ell
    for group, (context, plan) in enumerate(zip(contexts, plans, strict=True)):
        tiles = index[group * d : (group + 1) * d]

        def visit(value, offset, stride):
            if value.mode == "zero":
                return zero_pair, zero_state
            if value.level == -1:
                tile = tiles[offset]
                product = bgv.multiply(query, tile, pk, karatsuba=True)
                source = tuple(map(int, product.components[2]))
                digits = gadget.canonical_digits(source, q, 30)
                cuts.append(
                    gadget.Cut(group, -1, offset, "canonical30", source, digits)
                )
                correction = gadget.switched(digits, canonical.relin, q)
                pair = tuple(
                    tuple((int(x) + y) % q for x, y in zip(poly, corr, strict=True))
                    for poly, corr in zip(
                        product.components[:2], correction, strict=True
                    )
                )
                pair = tuple(
                    tuple(x % q for x in gadget.permute(poly, shift=1 - d))
                    for poly in pair
                )
                state = None
                if value.mode == "seed":
                    state = seed.c1_seed(
                        tuple(tuple(map(int, p)) for p in query.components),
                        tuple(tuple(map(int, p)) for p in tile.components),
                        digits,
                        tuple(tuple(map(int, column[1])) for column in canonical.relin),
                        q,
                        context.bits,
                    )
                    state = tuple(gadget.permute(row, shift=1 - d) for row in state)
                    gadget.validate_digits(
                        pair[1], state, context.bits, q, context.seed_bound
                    )
                return pair, state
            left, left_state = visit(value.left, offset, stride * 2)
            right, right_state = visit(value.right, offset + stride, stride * 2)
            shift = d >> (value.level + 1)
            exponent, key = rotations.rotations[value.level]
            moved = tuple(gadget.permute(row, shift=shift) for row in right)
            plus = tuple(
                tuple((x + y) % q for x, y in zip(a, b, strict=True))
                for a, b in zip(left, moved, strict=True)
            )
            minus = tuple(
                tuple((x - y) % q for x, y in zip(a, b, strict=True))
                for a, b in zip(left, moved, strict=True)
            )
            c0, source = (
                tuple(x % q for x in gadget.permute(row, exponent)) for row in minus
            )
            # Bounds are recomputed from the immutable public plan, not inferred
            # from the observed state/digit magnitudes or a private phase.
            a_label = planner._replay(context, value.left)
            b_label = planner._replay(context, value.right)
            source_bound = context.digit_bound
            if value.mode == "derived":
                source_bound = a_label.state + b_label.state
                digits = gadget.source_state(left_state, right_state, shift, exponent)
            else:
                digits = gadget.canonical_digits(source, q, context.bits)
            gadget.validate_digits(source, digits, context.bits, q, source_bound)
            cuts.append(
                gadget.Cut(
                    group,
                    value.level,
                    offset,
                    f"{value.mode}{context.bits}",
                    source,
                    digits,
                )
            )
            b, a = gadget.switched(digits, key, q)
            pair = (
                tuple((x + y + z) % q for x, y, z in zip(plus[0], c0, b, strict=True)),
                tuple((x + y) % q for x, y in zip(plus[1], a, strict=True)),
            )
            state = None
            if value.retain:
                if value.level not in key_digits:
                    key_digits[value.level] = gadget.public_a_digits(
                        key, q, context.bits
                    )
                a_digits = key_digits[value.level]
                if value.mode == "canonical" and value.right.count == 0:
                    state = gadget.unary_state(digits, exponent, a_digits)
                else:
                    state = gadget.next_state(
                        left_state, right_state, shift, digits, a_digits
                    )
                gadget.validate_digits(
                    pair[1],
                    state,
                    context.bits,
                    q,
                    planner._replay(context, value).state,
                )
            return pair, state

        pair, _ = visit(plan, 0, 1)
        output.append(pair)
    bounds = tuple(v.peak for v in labels)
    ciphers = [
        bgv.Ciphertext(tuple(tuple(map(mpz, p)) for p in pair), pk.key_id, bound)
        for pair, bound in zip(output, bounds, strict=True)
    ]
    packet = compact.pack(
        [compact.compact(c, pk, 16) for c in ciphers], count, dimension, pk
    )
    return gadget.Transcript(
        policy(contexts, plans),
        pk.key_id,
        count,
        dimension,
        tuple(cuts),
        tuple(output),
        bounds,
        packet,
    )


def check_trace(
    query, index, count, dimension, pk, canonical, rotations, plans, supplied
):
    """Complete strict public replay; no private diagnostic is called here."""
    try:

        def polynomial(row):
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
            or type(supplied.cuts) is not tuple
            or type(supplied.bounds) is not tuple
            or any(type(x) is not int for x in supplied.bounds)
            or type(supplied.full_output) is not tuple
        ):
            return False
        for pair in supplied.full_output:
            if (
                type(pair) is not tuple
                or len(pair) != 2
                or not all(polynomial(p) for p in pair)
            ):
                return False
        for cut in supplied.cuts:
            if (
                type(cut) is not gadget.Cut
                or type(cut.kind) is not str
                or any(type(x) is not int for x in (cut.group, cut.level, cut.node))
                or not polynomial(cut.source)
                or type(cut.digits) is not tuple
                or not all(polynomial(p) for p in cut.digits)
            ):
                return False
        return supplied == make_trace(
            query, index, count, dimension, pk, canonical, rotations, plans
        )
    except (ValueError, TypeError, AttributeError, IndexError, OverflowError):
        return False
