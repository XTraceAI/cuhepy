"""E20: homemade BGV reference with an explicitly delayed key-basis collapse.

This toy evaluator preserves automorphed linear/quadratic secret terms through
the first `cut` butterfly levels. It then switches each source to (1,s), and
finishes the normal butterfly. Extra related-secret evaluation keys, variable-
time owner arithmetic and loose phase bounds are experimental assumptions.
No authentication or production parameter assurance is supplied.
"""

from __future__ import annotations

from dataclasses import dataclass
import secrets

from gmpy2 import mpz

from cuhepy.bfv.scheme import _automorphism, _ring_product, _small_poly
from cuhepy.types import BFVPolynomial
from experiments.bfv_search_lab import reduction_oracles as oracle
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace

Form = dict[oracle.Source, BFVPolynomial]


@dataclass(frozen=True)
class EvaluationKeys:
    key_id: str
    padded: int
    cut: int
    digit_bits: int
    sources: tuple[tuple[oracle.Source, trace.SwitchKey], ...]
    switch_error_bound: int


def evaluation_keys(
    pk: bgv.PublicKey, sk: bgv.SecretKey, padded: int, cut: int, digit_bits: int = 12
) -> EvaluationKeys:
    """Owner-only generation; no foreign HE implementation is used."""
    sources = oracle.required_sources(pk.n, padded, cut)
    if (sk.key_id != pk.key_id or len(sk.s) != pk.n
            or type(digit_bits) is not int or not 4 <= digit_bits <= 60):
        raise ValueError("Wrong key context or gadget width")
    digits = (pk.q.bit_length() + digit_bits - 1) // digit_bits
    result = []
    for exponent, power in sources:
        target = _automorphism(sk.s, exponent, pk.q)
        if power == 2:
            target = _ring_product(target, target, pk.q)
        columns = []
        for j in range(digits):
            a = tuple(mpz(secrets.randbelow(int(pk.q))) for _ in range(pk.n))
            error = _small_poly(pk.n, pk.eta, pk.q)
            product = _ring_product(a, sk.s, pk.q)
            factor = mpz(1) << (j * digit_bits)
            b = tuple((factor * v + pk.t * e - x) % pk.q
                      for v, e, x in zip(target, error, product, strict=True))
            columns.append((b, a))
        result.append(((exponent, power), tuple(columns)))
    error_bound = pk.t * pk.eta * pk.n * ((1 << digit_bits) - 1) * digits
    return EvaluationKeys(pk.key_id, padded, cut, digit_bits, tuple(result), error_bound)


def _validate_keys(pk: bgv.PublicKey, keys: EvaluationKeys) -> None:
    sources = oracle.required_sources(pk.n, keys.padded, keys.cut)
    if (keys.key_id != pk.key_id or type(keys.digit_bits) is not int
            or not 4 <= keys.digit_bits <= 60):
        raise ValueError("Wrong delayed-switch key context")
    digits = (pk.q.bit_length() + keys.digit_bits - 1) // keys.digit_bits
    error = pk.t * pk.eta * pk.n * ((1 << keys.digit_bits) - 1) * digits
    if tuple(source for source, _ in keys.sources) != sources or error != keys.switch_error_bound:
        raise ValueError("Wrong delayed-switch sources or error bound")
    for _, key in keys.sources:
        if len(key) != digits or any(
            len(pair) != 2 or any(len(p) != pk.n or any(not 0 <= c < pk.q for c in p) for p in pair)
            for pair in key
        ):
            raise ValueError("Invalid delayed-switch gadget key")


def _add(a: Form, b: Form, pk: bgv.PublicKey, sign: int = 1) -> Form:
    zero = (mpz(0),) * pk.n
    return {source: tuple((x + sign * y) % pk.q for x, y in
                         zip(a.get(source, zero), b.get(source, zero), strict=True))
            for source in a.keys() | b.keys()}


def _shift(form: Form, shift: int, pk: bgv.PublicKey) -> Form:
    result = {}
    for source, poly in form.items():
        moved = [mpz(0)] * pk.n
        for i, c in enumerate(poly):
            quotient, at = divmod(i + shift, pk.n)
            moved[at] = (-c if quotient % 2 else c) % pk.q
        result[source] = tuple(moved)
    return result


def _auto(form: Form, exponent: int, pk: bgv.PublicKey) -> Form:
    return {((g * exponent) % (2 * pk.n), power) if power else (1, 0):
            _automorphism(poly, exponent, pk.q) for (g, power), poly in form.items()}


def _collapse(
    form: Form, pk: bgv.PublicKey, key_map: dict[oracle.Source, trace.SwitchKey], bits: int
) -> tuple[Form, int]:
    zero = (mpz(0),) * pk.n
    out = {(1, 0): form.get((1, 0), zero), (1, 1): form.get((1, 1), zero)}
    count = 0
    for source, poly in sorted(form.items()):
        if source in ((1, 0), (1, 1)):
            continue
        b, a = trace._switch(poly, key_map[source], pk, bits)
        out = _add(out, {(1, 0): b, (1, 1): a}, pk)
        count += 1
    return out, count


def search(
    query: bgv.Ciphertext, index: list[bgv.Ciphertext], count: int,
    pk: bgv.PublicKey, keys: EvaluationKeys,
) -> list[bgv.Ciphertext]:
    """Public-only reference. Bounds are owner metadata, never response proofs."""
    _validate_keys(pk, keys)
    capacity = pk.n // keys.padded
    if type(count) is not int or count < 0 or len(index) != (count + capacity - 1) // capacity:
        raise ValueError("Invalid delayed-switch index shape")
    for cipher in (query, *index):
        bgv._validate(cipher, pk)
        if len(cipher.components) != 2:
            raise ValueError("Expected fresh two-component inputs")
    # Reject inadequate Q before doing any ciphertext arithmetic.
    for start in range(0, len(index), keys.padded):
        group = index[start:start + keys.padded]
        model = oracle.schedule_cost(pk.n, keys.padded, len(group), keys.cut)
        product_bound = max(pk.n * query.phase_bound * ct.phase_bound for ct in group)
        if 2 * (model.product_bound_weight * product_bound
                + model.switch_error_weight * keys.switch_error_bound) >= pk.q:
            raise ValueError("Delayed-switch correctness bound exceeds Q/2")
    output, key_map = [], dict(keys.sources)
    generator = 1 + 2 * pk.n // keys.padded
    for start in range(0, len(index), keys.padded):
        work = []
        for tile in index[start:start + keys.padded]:
            product = bgv.multiply(query, tile, pk, karatsuba=True)
            form = {(1, j): poly for j, poly in enumerate(product.components)}
            work.append((_shift(form, 1 - keys.padded, pk), product.phase_bound))
        shift = keys.padded // 2
        for level in range(keys.padded.bit_length()):
            if level == keys.cut:
                collapsed = []
                for form, bound in work:
                    reduced, switches = _collapse(form, pk, key_map, keys.digit_bits)
                    collapsed.append((reduced, bound + switches * keys.switch_error_bound))
                work = collapsed
            if not shift:
                break
            merged = []
            exponent = pow(generator, 1 << level, 2 * pk.n)
            for i in range(min(shift, len(work))):
                plus, bound = work[i]
                minus = plus
                if i + shift < len(work):
                    right, right_bound = work[i + shift]
                    right = _shift(right, shift, pk)
                    plus, minus = _add(plus, right, pk), _add(minus, right, pk, -1)
                    bound += right_bound
                rotated = _auto(minus, exponent, pk)
                switches = 0
                if level >= keys.cut:
                    rotated, switches = _collapse(rotated, pk, key_map, keys.digit_bits)
                merged.append((_add(plus, rotated, pk), 2 * bound + switches * keys.switch_error_bound))
            work, shift = merged, shift // 2
        form, bound = work[0]
        output.append(trace._bounded((form[(1, 0)], form[(1, 1)]), bound, pk))
    return output
