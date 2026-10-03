"""Q65–Q66: bounded integer gadget propagation through a unary anchor.

The gadget algebra is a known method. This small-ring public reference tests a
packing-dependent cut policy; it is not a production verifier or a novel HE
primitive. All norms come from public worst-case bounds, never observed private
errors. Existing production/native arithmetic is untouched. A complete native
admission implementation and private/parameter assurance remain separate work.
"""

from __future__ import annotations

from dataclasses import dataclass

from gmpy2 import mpz

from cuhepy.bfv.scheme import _ring_product
from experiments.bfv_search_lab import butterfly_bgv as butterfly
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace

Polynomial = tuple[int, ...]
Digits = tuple[Polynomial, ...]
POLICY = "cuhepy-lab-unary-anchor-one-propagated-stage-v1"


def integer_product(a: Polynomial, b: Polynomial) -> Polynomial:
    """Exact signed Z[X]/(X**N+1) product, deliberately small-ring only."""
    if len(a) != len(b) or not 1 <= len(a) <= 128:
        raise ValueError("Integer reference requires equal small rings")
    n, result = len(a), [0] * len(a)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            at = i + j
            result[at % n] += x * y * (-1 if at >= n else 1)
    return tuple(result)


def permute(a: Polynomial, exponent: int = 1, shift: int = 0) -> Polynomial:
    """Signed integer monomial/automorphism; never reduce a digit modulo Q."""
    n = len(a)
    if not n or type(exponent) is not int or exponent % 2 != 1:
        raise ValueError("Invalid integer automorphism")
    out = [0] * n
    for i, x in enumerate(a):
        quotient, at = divmod(i * exponent + shift, n)
        out[at] += x * (-1 if quotient % 2 else 1)
    return tuple(out)


def canonical_digits(a: Polynomial, q: int, bits: int) -> Digits:
    if type(q) is not int or q < 3 or type(bits) is not int or not 1 <= bits <= 60:
        raise ValueError("Invalid radix context")
    if not a or any(type(x) is not int or not 0 <= x < q for x in a):
        raise ValueError("Canonical coefficients required")
    ell, mask = (q.bit_length() + bits - 1) // bits, (1 << bits) - 1
    return tuple(tuple((x >> (j * bits)) & mask for x in a) for j in range(ell))


def recompose(digits: Digits, bits: int, q: int) -> Polynomial:
    if not digits or not digits[0] or any(len(d) != len(digits[0]) for d in digits):
        raise ValueError("Invalid common integer gadget shape")
    return tuple(
        sum(d[i] << (j * bits) for j, d in enumerate(digits)) % q
        for i in range(len(digits[0]))
    )


def validate_digits(
    source: Polynomial,
    digits: Digits,
    bits: int,
    q: int,
    bound: int,
    *,
    boxed: bool = False,
) -> None:
    """Require one common integer tuple, not separately chosen RNS lifts."""
    ell = (q.bit_length() + bits - 1) // bits
    if (
        type(bound) is not int
        or bound < 0
        or len(digits) != ell
        or any(len(d) != len(source) for d in digits)
        or any(
            type(x) is not int or abs(x) > bound or (boxed and x < 0)
            for d in digits
            for x in d
        )
        or recompose(digits, bits, q) != source
    ):
        raise ValueError("Invalid bounded common-integer representation")


def public_a_digits(key: trace.SwitchKey, q: int, bits: int) -> tuple[Digits, ...]:
    return tuple(
        canonical_digits(tuple(map(int, column[1])), q, bits) for column in key
    )


def unary_state(digits: Digits, exponent: int, a_digits: tuple[Digits, ...]) -> Digits:
    """G*E = old_C1 + sum_a d_a*K_A[a] after an entirely unary stage."""
    n, ell = len(digits[0]), len(digits)
    inverse = pow(exponent, -1, 2 * n)
    result = []
    for j in range(ell):
        out = list(permute(digits[j], inverse))
        for a in range(ell):
            product = integer_product(digits[a], a_digits[a][j])
            out = [x + y for x, y in zip(out, product, strict=True)]
        result.append(tuple(out))
    return tuple(result)


def source_state(
    left: Digits, right: Digits | None, shift: int, exponent: int
) -> Digits:
    result = []
    for j, a in enumerate(left):
        b = (0,) * len(a) if right is None else permute(right[j], shift=shift)
        result.append(
            permute(tuple(x - y for x, y in zip(a, b, strict=True)), exponent)
        )
    return tuple(result)


def next_state(
    left: Digits,
    right: Digits | None,
    shift: int,
    source: Digits,
    a_digits: tuple[Digits, ...],
) -> Digits:
    """Optional further unnormalized step, mainly an unsafe-noise control."""
    result = []
    for j, a in enumerate(left):
        b = (0,) * len(a) if right is None else permute(right[j], shift=shift)
        out = [x + y for x, y in zip(a, b, strict=True)]
        for k, d in enumerate(source):
            product = integer_product(d, a_digits[k][j])
            out = [x + y for x, y in zip(out, product, strict=True)]
        result.append(tuple(out))
    return tuple(result)


def switched(
    digits: Digits, key: trace.SwitchKey, q: int
) -> tuple[Polynomial, Polynomial]:
    n, out = len(digits[0]), [[0] * len(digits[0]) for _ in range(2)]
    for d, column in zip(digits, key, strict=True):
        common = tuple(mpz(x % q) for x in d)
        for k in range(2):
            product = _ring_product(common, column[k], mpz(q))
            out[k] = [(x + int(y)) % q for x, y in zip(out[k], product, strict=True)]
    assert all(len(p) == n for p in out)
    return tuple(out[0]), tuple(out[1])


def fused_correction(
    first: Digits,
    right: Digits | None,
    first_exponent: int,
    next_exponent: int,
    shift: int,
    a_digits: tuple[Digits, ...],
    key: trace.SwitchKey,
    q: int,
) -> tuple[Polynomial, Polynomial]:
    """Known public composite-key control; includes all radix cross terms.

    H[a,k] = sum_j sigma_h(A[a,j])*K_next[j,k]. This reference constructs
    H each call. A timed control must charge one shared precomputation and its
    lifetime; it may cache H with exactly the same opportunity as a candidate.
    """
    n, ell = len(first[0]), len(first)
    h = []
    for a in range(ell):
        row = []
        for k in range(2):
            out = [0] * n
            for j in range(ell):
                p = _ring_product(
                    tuple(mpz(x % q) for x in permute(a_digits[a][j], next_exponent)),
                    key[j][k],
                    mpz(q),
                )
                out = [(x + int(y)) % q for x, y in zip(out, p, strict=True)]
            row.append(tuple(out))
        h.append(tuple(row))
    inverse = pow(first_exponent, -1, 2 * n)
    out = [[0] * n for _ in range(2)]
    for a, d in enumerate(first):
        families = []
        for exponent in (next_exponent * inverse, next_exponent):
            left_poly = permute(d, exponent)
            right_poly = (
                (0,) * n
                if right is None
                else permute(right[a], exponent, next_exponent * shift)
            )
            families.append(
                tuple(
                    mpz((x - y) % q) for x, y in zip(left_poly, right_poly, strict=True)
                )
            )
        for k in range(2):
            p0 = _ring_product(families[0], key[a][k], mpz(q))
            p1 = _ring_product(families[1], tuple(map(mpz, h[a][k])), mpz(q))
            out[k] = [
                (x + int(y) + int(z)) % q
                for x, y, z in zip(out[k], p0, p1, strict=True)
            ]
    return tuple(out[0]), tuple(out[1])


def model(
    n: int,
    q: int,
    t: int,
    eta: int,
    padded: int,
    tiles: int,
    bits: int,
    query_bound: int,
    index_bound: int,
    *,
    propagated_stages: int = 1,
    terminal: int | None = None,
) -> dict:
    """Deterministic support/noise and operation/body ledger; no timing data."""
    if (
        n < 8
        or n & (n - 1)
        or not 1 <= padded <= n // 2
        or padded & (padded - 1)
        or not 1 <= tiles <= padded
        or not 0 <= propagated_stages <= 2
        or not 1 <= bits <= 60
        or min(query_bound, index_bound) < 0
    ):
        raise ValueError("Invalid propagation schedule")
    ell, base = (q.bit_length() + bits - 1) // bits, 1 << bits
    l0, factor = base - 1, 1 + ell * n * (base - 1)
    switch_scale = t * eta * n * ell
    canonical_error = switch_scale * l0
    product_bound = n * query_bound * index_bound + canonical_error
    shift, count, bounds, rows = padded // 2, tiles, None, []
    anchor = propagated_stages > 0 and shift > 1 and count <= shift
    for level in range(padded.bit_length() - 1):
        source_bounds, out_bounds = [], []
        propagate = anchor and 1 <= level <= propagated_stages
        for i in range(min(shift, count)):
            binary = i + shift < count
            if propagate:
                plus_bound = bounds[i] + (bounds[i + shift] if binary else 0)
                source_bounds.append(plus_bound)
                out_bounds.append(plus_bound * factor)
            else:
                source_bounds.append(l0)
                out_bounds.append(l0 * factor if anchor and level == 0 else 0)
        weight = padded // (1 << (level + 1))
        rows.append(
            {
                "level": level,
                "nodes": len(source_bounds),
                "binary_nodes": max(0, count - shift),
                "kind": "propagated" if propagate else "canonical",
                "common_source_bound": max(source_bounds),
                "switch_error_bound": switch_scale * max(source_bounds),
                "suffix_support_weight": weight,
            }
        )
        bounds, count, shift = out_bounds, len(out_bounds), shift // 2
    bound = padded * product_bound + sum(
        r["suffix_support_weight"] * r["switch_error_bound"] for r in rows
    )
    rotations = sum(r["nodes"] for r in rows)
    removed = sum(r["nodes"] for r in rows if r["kind"] == "propagated")
    poly_bytes = (n * q.bit_length() + 7) // 8
    result = {
        "n": n,
        "q": q,
        "t": t,
        "eta": eta,
        "padded": padded,
        "tiles": tiles,
        "digit_bits": bits,
        "digits": ell,
        "requested_propagated_stages": propagated_stages,
        "free_unary_anchor": anchor,
        "canonical_digit_bound": l0,
        "propagation_factor_bound": factor,
        "stages": rows,
        "full_phase_bound": bound,
        "Q_guard": 2 * bound < q,
        "product_cuts": tiles,
        "rotation_switches": rotations,
        "canonical_source_cuts": tiles + rotations - removed,
        "removed_source_cuts": removed,
        "full_source_and_terminal_Q_body_bytes": (tiles + rotations - removed + 2)
        * poly_bytes,
        "canonical_full_source_and_terminal_Q_body_bytes": (tiles + rotations + 2)
        * poly_bytes,
        "body_saving_bytes": removed * poly_bytes,
        "canonical_switch_ring_products": 2 * ell * (tiles + rotations),
        "direct_extra_integer_products": ell
        * ell
        * sum(r["nodes"] for r in rows[: 1 + propagated_stages - 1])
        if anchor
        else 0,
        "fused_extra_online_ring_products": 2 * ell * rows[1]["nodes"]
        if anchor and propagated_stages == 1
        else None,
        "shared_fused_H_polynomials": 2 * ell
        if anchor and propagated_stages == 1
        else 0,
        "shared_fused_H_body_bytes": 2 * ell * poly_bytes
        if anchor and propagated_stages == 1
        else 0,
        "shared_A_digit_body_bytes": ell * ell * ((n * bits + 7) // 8) if anchor else 0,
        "one_shared_H_setup_ring_products": 2 * ell * ell
        if anchor and propagated_stages == 1
        else 0,
        "modeled_not_measured": True,
        "production_parameter_assurance": False,
    }
    if terminal is not None:
        if not t < terminal < q or (terminal - q) % t:
            raise ValueError("Invalid fixed terminal context")
        reduced = (terminal * bound + q - 1) // q + ((n + 1) * t + 1) // 2
        result.update(
            terminal=terminal,
            terminal_phase_bound=reduced,
            terminal_guard=2 * reduced < terminal and result["Q_guard"],
            full_terminal_packed_body_bytes=2 * ((n * terminal.bit_length() + 7) // 8),
        )
    return result


@dataclass(frozen=True)
class Cut:
    group: int
    level: int  # -1 is product relinearization.
    node: int
    kind: str
    source: Polynomial
    digits: Digits


@dataclass(frozen=True)
class Transcript:
    policy: str
    key_id: str
    count: int
    dimension: int
    cuts: tuple[Cut, ...]
    full_output: tuple[tuple[Polynomial, Polynomial], ...]
    bounds: tuple[int, ...]
    response: bytes


def make_trace(
    query: bgv.Ciphertext,
    index: list[bgv.Ciphertext],
    count: int,
    dimension: int,
    pk: bgv.PublicKey,
    keys: trace.EvaluationKeys,
    *,
    propagate: bool = True,
    terminal_bits: int = 16,
) -> Transcript:
    """Recompute the whole registered relation with only public inputs.

    The tiny reference deliberately materializes integer states. It does not
    claim the cut savings reduce this replay's work. A native implementation
    must replace these states with charged public linear maps and separately
    audit its immutable request/snapshot/attempt/response binding.
    """
    if type(propagate) is not bool or pk.n > 128:
        raise ValueError("Small public reference only")
    butterfly.validate_keys(pk, keys)
    capacity, q = pk.n // keys.padded, int(pk.q)
    if (
        type(count) is not int
        or count < 1
        or len(index) != (count + capacity - 1) // capacity
    ):
        raise ValueError("Wrong index count")
    if (
        not 1 <= dimension <= keys.padded
        or (1 << (dimension - 1).bit_length()) != keys.padded
        or pk.t <= 2 * dimension
    ):
        raise ValueError("Wrong search dimension")
    for c in (query, *index):
        bgv._validate(c, pk)
        if len(c.components) != 2:
            raise ValueError("Two-component inputs required")
    p = compact.terminal_modulus(pk.q, pk.t, terminal_bits)
    models = [
        model(
            pk.n,
            q,
            pk.t,
            pk.eta,
            keys.padded,
            len(index[start : start + keys.padded]),
            keys.digit_bits,
            int(query.phase_bound),
            max(int(c.phase_bound) for c in index[start : start + keys.padded]),
            propagated_stages=int(propagate),
            terminal=int(p),
        )
        for start in range(0, len(index), keys.padded)
    ]
    if any(not m["Q_guard"] or not m["terminal_guard"] for m in models):
        raise ValueError("Public propagation or terminal correctness guard failed")
    output, cuts = [], []
    for group, start in enumerate(range(0, len(index), keys.padded)):
        work = []
        for node, tile in enumerate(index[start : start + keys.padded]):
            product = bgv.multiply(query, tile, pk, karatsuba=True)
            source = tuple(map(int, product.components[2]))
            digits = canonical_digits(source, q, keys.digit_bits)
            cuts.append(Cut(group, -1, node, "canonical", source, digits))
            b, a = switched(digits, keys.relin, q)
            pair = tuple(
                tuple((int(x) + y) % q for x, y in zip(poly, corr, strict=True))
                for poly, corr in zip(product.components[:2], (b, a), strict=True)
            )
            work.append(
                tuple(
                    tuple(x % q for x in permute(poly, shift=1 - keys.padded))
                    for poly in pair
                )
            )
        states, shift = None, keys.padded // 2
        for level, (exponent, key) in enumerate(keys.rotations):
            merged, new_states = [], []
            kind = models[group]["stages"][level]["kind"]
            anchor = models[group]["free_unary_anchor"] and level == 0
            a_digits = public_a_digits(key, q, keys.digit_bits) if anchor else None
            for i in range(min(shift, len(work))):
                right_at = i + shift
                has_right = right_at < len(work)
                right = (
                    tuple(permute(poly, shift=shift) for poly in work[right_at])
                    if has_right
                    else ((0,) * pk.n,) * 2
                )
                plus = tuple(
                    tuple((x + y) % q for x, y in zip(a, b, strict=True))
                    for a, b in zip(work[i], right, strict=True)
                )
                minus = tuple(
                    tuple((x - y) % q for x, y in zip(a, b, strict=True))
                    for a, b in zip(work[i], right, strict=True)
                )
                c0, source = (
                    tuple(x % q for x in permute(poly, exponent)) for poly in minus
                )
                if kind == "propagated":
                    digits = source_state(
                        states[i],
                        states[right_at] if has_right else None,
                        shift,
                        exponent,
                    )
                else:
                    digits = canonical_digits(source, q, keys.digit_bits)
                validate_digits(
                    source,
                    digits,
                    keys.digit_bits,
                    q,
                    models[group]["stages"][level]["common_source_bound"],
                    boxed=kind == "canonical",
                )
                cuts.append(Cut(group, level, i, kind, source, digits))
                b, a = switched(digits, key, q)
                pair = (
                    tuple(
                        (x + y + z) % q for x, y, z in zip(plus[0], c0, b, strict=True)
                    ),
                    tuple((x + y) % q for x, y in zip(plus[1], a, strict=True)),
                )
                merged.append(pair)
                if anchor:
                    state = unary_state(digits, exponent, a_digits)
                    if recompose(state, keys.digit_bits, q) != pair[1]:
                        raise AssertionError("Unary C1 propagation identity failed")
                    new_states.append(state)
            work, states, shift = merged, new_states or None, shift // 2
        output.append(work[0])
    bounds = tuple(m["full_phase_bound"] for m in models)
    ciphers = [
        bgv.Ciphertext(tuple(tuple(map(mpz, poly)) for poly in pair), pk.key_id, bound)
        for pair, bound in zip(output, bounds, strict=True)
    ]
    response = compact.pack(
        [compact.compact(c, pk, terminal_bits) for c in ciphers], count, dimension, pk
    )
    return Transcript(
        POLICY if propagate else "canonical-support-control-v1",
        pk.key_id,
        count,
        dimension,
        tuple(cuts),
        tuple(output),
        bounds,
        response,
    )


def check_trace(
    query: bgv.Ciphertext,
    index: list[bgv.Ciphertext],
    count: int,
    dimension: int,
    pk: bgv.PublicKey,
    keys: trace.EvaluationKeys,
    supplied: Transcript,
    *,
    propagate: bool = True,
    terminal_bits: int = 16,
) -> bool:
    """Exact public replay for local correctness; never call private arithmetic."""
    try:

        def poly(value, *, signed=False):
            return (
                type(value) is tuple
                and len(value) == pk.n
                and all(
                    type(x) is int
                    and (-int(pk.q) < x < int(pk.q) if signed else 0 <= x < pk.q)
                    for x in value
                )
            )

        groups, ell = (
            (count + pk.n - 1) // pk.n,
            (pk.q.bit_length() + keys.digit_bits - 1) // keys.digit_bits,
        )
        cuts = len(index)
        for start in range(0, len(index), keys.padded):
            nodes = len(index[start : start + keys.padded])
            shift = keys.padded // 2
            while shift:
                nodes = min(nodes, shift)
                cuts += nodes
                shift //= 2
        if (
            type(supplied) is not Transcript
            or type(supplied.response) is not bytes
            or type(supplied.policy) is not str
            or type(supplied.key_id) is not str
            or type(supplied.count) is not int
            or type(supplied.dimension) is not int
            or type(supplied.bounds) is not tuple
            or len(supplied.bounds) != groups
            or any(type(b) is not int for b in supplied.bounds)
            or type(supplied.full_output) is not tuple
            or len(supplied.full_output) != groups
            or any(
                type(pair) is not tuple
                or len(pair) != 2
                or not all(poly(p) for p in pair)
                for pair in supplied.full_output
            )
            or type(supplied.cuts) is not tuple
            or len(supplied.cuts) != cuts
        ):
            return False
        for cut in supplied.cuts:
            if (
                type(cut) is not Cut
                or type(cut.kind) is not str
                or any(type(v) is not int for v in (cut.group, cut.level, cut.node))
                or not poly(cut.source)
                or type(cut.digits) is not tuple
                or len(cut.digits) != ell
                or not all(poly(d, signed=True) for d in cut.digits)
            ):
                return False
        return supplied == make_trace(
            query,
            index,
            count,
            dimension,
            pk,
            keys,
            propagate=propagate,
            terminal_bits=terminal_bits,
        )
    except (ValueError, TypeError, IndexError, OverflowError, AttributeError):
        return False
