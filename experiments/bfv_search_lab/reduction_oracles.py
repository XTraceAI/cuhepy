"""E20: independent integer-ring identities and delayed-switch cost models.

No encrypted timing, parameter assurance or universal lower bound is implied.
The count model switches each distinct formal secret term separately, using
the existing gadget construction. It deliberately retains all structural terms.
"""

from __future__ import annotations

from dataclasses import dataclass

Source = tuple[int, int]  # sigma_exponent(s)**power; (1, 0) is the constant.
Form = dict[Source, tuple[int, ...]]


def validate_layout(n: int, padded: int, cut: int) -> None:
    if (
        type(n) is not int or n < 2 or n & (n - 1)
        or type(padded) is not int or not 1 <= padded <= n // 2
        or padded & (padded - 1) or type(cut) is not int
        or not 0 <= cut < padded.bit_length()
    ):
        raise ValueError("Expected a power-of-two ring/layout and a valid delay depth")


def ring_product(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[int, ...]:
    """Schoolbook multiplication over Z[X]/(X**N+1), independent of HE helpers."""
    if not a or len(a) != len(b):
        raise ValueError("Ring operands must have equal nonzero length")
    n, result = len(a), [0] * len(a)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            degree = i + j
            result[degree % n] += x * y * (-1 if degree >= n else 1)
    return tuple(result)


def permute(poly: tuple[int, ...], exponent: int = 1, shift: int = 0) -> tuple[int, ...]:
    n, result = len(poly), [0] * len(poly)
    if not n or exponent % 2 != 1:
        raise ValueError("Expected nonempty ring and odd automorphism exponent")
    for i, value in enumerate(poly):
        quotient, at = divmod(i * exponent + shift, n)
        result[at] += value * (-1 if quotient % 2 else 1)
    return tuple(result)


def add_forms(a: Form, b: Form, sign: int = 1) -> Form:
    n = len(next(iter(a.values())))
    zero = (0,) * n
    return {
        source: tuple(x + sign * y for x, y in zip(a.get(source, zero), b.get(source, zero), strict=True))
        for source in a.keys() | b.keys()
    }


def transform_form(form: Form, exponent: int = 1, shift: int = 0) -> Form:
    n = len(next(iter(form.values())))
    return {
        ((exponent * g) % (2 * n), power) if power else (1, 0): permute(poly, exponent, shift)
        for (g, power), poly in form.items()
    }


def evaluate_form(form: Form, secret: tuple[int, ...]) -> tuple[int, ...]:
    """Evaluate a formal basis over integers, without key switching or rounding."""
    out = [0] * len(secret)
    for (g, power), poly in form.items():
        if not power:
            value = poly
        else:
            basis = permute(secret, g)
            if power == 2:
                basis = ring_product(basis, basis)
            elif power != 1:
                raise ValueError("Only linear/quadratic secret terms are modeled")
            value = ring_product(poly, basis)
        out = [x + y for x, y in zip(out, value, strict=True)]
    return tuple(out)


def expanded_butterfly(products: list[Form], padded: int) -> Form:
    """Keep every automorphed secret term through the complete butterfly."""
    if not products:
        raise ValueError("Expected at least one tensor product")
    n = len(next(iter(products[0].values())))
    validate_layout(n, padded, 0)
    if len(products) > padded:
        raise ValueError("One response group contains at most D tensors")
    work = [transform_form(form, shift=1 - padded) for form in products]
    generator, shift = 1 + 2 * n // padded, padded // 2
    for level in range(padded.bit_length() - 1):
        merged = []
        for i in range(min(shift, len(work))):
            plus = minus = work[i]
            if i + shift < len(work):
                right = transform_form(work[i + shift], shift=shift)
                plus, minus = add_forms(work[i], right), add_forms(work[i], right, -1)
            merged.append(add_forms(plus, transform_form(minus, pow(generator, 1 << level, 2 * n))))
        work, shift = merged, shift // 2
    return work[0]


def projected_phases(phases: list[tuple[int, ...]], padded: int) -> tuple[int, ...]:
    """Direct coefficient selection; independent of the butterfly identity."""
    n, out = len(phases[0]), [0] * len(phases[0])
    for tile, phase in enumerate(phases):
        shifted = permute(phase, shift=1 - padded)
        for position in range(0, n, padded):
            out[position + tile] += padded * shifted[position]
    return tuple(out)


def required_sources(n: int, padded: int, cut: int) -> tuple[Source, ...]:
    validate_layout(n, padded, cut)
    generator = 1 + 2 * n // padded
    sources = {
        (pow(generator, j, 2 * n), power)
        for j in range(1 << cut) for power in (1, 2)
    } - {(1, 1)}
    sources.update(
        (pow(generator, 1 << level, 2 * n), 1)
        for level in range(cut, padded.bit_length() - 1)
    )
    return tuple(sorted(sources))


@dataclass(frozen=True)
class ScheduleCost:
    tensor_tiles: int
    cut_depth: int
    switch_calls: int
    distinct_keys: int
    product_bound_weight: int
    switch_error_weight: int
    max_basis_terms_per_cipher: int
    max_checkpoint_polynomials: int
    key_coefficient_bytes: int


def schedule_cost(
    n: int, padded: int, tiles: int, cut: int, q_bits: int = 120, digit_bits: int = 30
) -> ScheduleCost:
    """One response group, including tails; checkpoint storage excludes temporaries.

    The resulting phase bound is product_bound_weight * max_product_bound +
    switch_error_weight * single_switch_error. This is conservative arithmetic
    bookkeeping, not a noise distribution or an HE security estimate.
    """
    validate_layout(n, padded, cut)
    if (type(tiles) is not int or not 1 <= tiles <= padded
            or type(q_bits) is not int or q_bits < 1
            or type(digit_bits) is not int or digit_bits < 1):
        raise ValueError("Expected positive gadget widths and 1..D tiles")
    work = [(1, 0)] * tiles
    calls, terms, peak = 0, 3, 3 * tiles
    shift = padded // 2
    for level in range(padded.bit_length()):
        if level == cut:
            per_node = 2 * (1 << cut) - 1
            calls += len(work) * per_node
            work = [(a, b + per_node) for a, b in work]
            terms = 2
        peak = max(peak, terms * len(work))
        if not shift:
            break
        merged = []
        for i in range(min(shift, len(work))):
            a, b = work[i]
            c, d = work[i + shift] if i + shift < len(work) else (0, 0)
            extra = int(level >= cut)
            merged.append((2 * (a + c), 2 * (b + d) + extra))
            calls += extra
        work, shift = merged, shift // 2
        if level < cut:
            terms = 1 + 2 * (1 << (level + 1))
        peak = max(peak, terms * len(work))
    key_count = len(required_sources(n, padded, cut))
    digits = (q_bits + digit_bits - 1) // digit_bits
    return ScheduleCost(
        tiles, cut, calls, key_count, work[0][0], work[0][1],
        1 + 2 * (1 << cut), peak, key_count * digits * 2 * ((n * q_bits + 7) // 8),
    )
