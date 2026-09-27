"""Joint coefficient trace/packing, using the established packing butterfly.

At stage j, h = D/2**(j+1) and sigma = sigma_g**(2**j). Since
sigma(X**h) = -X**h, A + X**h B + sigma(A - X**h B) applies one
trace step to both inputs with one automorphism. Earlier monomial shifts
are fixed by this sigma. Repeating the stages gives exactly
sum_i X**i Trace_D(f_i), where f_i is a shifted correlation product.

This adapts the automorphism packing identity in Chen, Dai, Kim and Song,
"Efficient Homomorphic Conversion Between (Ring) LWE Ciphertexts", Algorithm 2,
https://eprint.iacr.org/2020/015. It is not a claim of a new packing primitive.
The independent per-tile reference remains in trace_bgv.py.
"""

from __future__ import annotations

from cuhepy.bfv.scheme import _automorphism
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


def schedule(padded: int, bounds: list[int], switch_error: int) -> tuple[int, int]:
    """Return the final public phase bound and the exact automorphism count."""
    if (
        type(padded) is not int or padded < 1 or padded & (padded - 1)
        or not bounds or len(bounds) > padded or any(b < 0 for b in bounds)
        or switch_error < 0
    ):
        raise ValueError("Invalid butterfly bound schedule")
    work = bounds.copy()
    shift, rotations = padded // 2, 0
    while shift:
        work = [
            2 * (work[i] + (work[i + shift] if i + shift < len(work) else 0))
            + switch_error
            for i in range(min(shift, len(work)))
        ]
        rotations += len(work)
        shift //= 2
    return work[0], rotations


def validate_keys(pk: bgv.PublicKey, keys: trace.EvaluationKeys) -> None:
    trace._layout(pk.n, keys.padded)
    if keys.key_id != pk.key_id or not 4 <= keys.digit_bits <= 60:
        raise ValueError("Wrong butterfly evaluation keys")
    generator = 1 + 2 * pk.n // keys.padded
    expected = [pow(generator, 1 << j, 2 * pk.n) for j in range(keys.padded.bit_length() - 1)]
    digits = (pk.q.bit_length() + keys.digit_bits - 1) // keys.digit_bits
    error = pk.t * pk.eta * pk.n * ((1 << keys.digit_bits) - 1) * digits
    if [g for g, _ in keys.rotations] != expected or keys.switch_error_bound != error:
        raise ValueError("Invalid butterfly rotation schedule or error bound")
    for key in (keys.relin, *(key for _, key in keys.rotations)):
        if len(key) != digits or any(
            len(pair) != 2 or any(
                len(poly) != pk.n or any(not 0 <= x < pk.q for x in poly) for poly in pair
            ) for pair in key
        ):
            raise ValueError("Invalid butterfly gadget key")


def response_bounds(
    query: bgv.Ciphertext, index: list[bgv.Ciphertext], count: int,
    pk: bgv.PublicKey, keys: trace.EvaluationKeys,
) -> list[int]:
    """Check all inputs and reject unsafe bounds before starting any evaluation.

    Bounds are trusted owner-side experimental metadata, not proofs supplied by
    a server. They must never become a decryption authorization mechanism.
    """
    capacity = pk.n // keys.padded
    if type(count) is not int or count < 0 or len(index) != (count + capacity - 1) // capacity:
        raise ValueError("Invalid butterfly index shape")
    for cipher in (query, *index):
        bgv._validate(cipher, pk)
        if len(cipher.components) != 2:
            raise ValueError("Butterfly requires two-component inputs")
    bounds = []
    for start in range(0, len(index), keys.padded):
        bound, _ = schedule(keys.padded, [
            pk.n * query.phase_bound * tile.phase_bound + keys.switch_error_bound
            for tile in index[start:start + keys.padded]
        ], keys.switch_error_bound)
        if 2 * bound >= pk.q:
            raise ValueError("Butterfly correctness bound exceeds Q/2")
        bounds.append(bound)
    return bounds


def _subtract(lhs: bgv.Ciphertext, rhs: bgv.Ciphertext, pk: bgv.PublicKey) -> bgv.Ciphertext:
    return trace._bounded(tuple(
        tuple((a - b) % pk.q for a, b in zip(p, q, strict=True))
        for p, q in zip(lhs.components, rhs.components, strict=True)
    ), lhs.phase_bound + rhs.phase_bound, pk)


def _rotate(cipher: bgv.Ciphertext, exponent: int, key: trace.SwitchKey,
            pk: bgv.PublicKey, keys: trace.EvaluationKeys) -> bgv.Ciphertext:
    c0, c1 = (_automorphism(poly, exponent, pk.q) for poly in cipher.components)
    b, a = trace._switch(c1, key, pk, keys.digit_bits)
    return trace._bounded((tuple((x + y) % pk.q for x, y in zip(c0, b, strict=True)), a),
                          cipher.phase_bound + keys.switch_error_bound, pk)


def search(query: bgv.Ciphertext, index: list[bgv.Ciphertext], count: int,
           pk: bgv.PublicKey, keys: trace.EvaluationKeys) -> list[bgv.Ciphertext]:
    """Public-only Python/GMP reference for the joint packing circuit."""
    validate_keys(pk, keys)
    bounds = response_bounds(query, index, count, pk, keys)
    output = []
    for group, start in enumerate(range(0, len(index), keys.padded)):
        work = []
        for tile in index[start:start + keys.padded]:
            product = bgv.multiply(query, tile, pk, karatsuba=True)
            switched = trace._switch(product.components[2], keys.relin, pk, keys.digit_bits)
            reduced = trace._bounded(tuple(
                tuple((a + b) % pk.q for a, b in zip(p, q, strict=True))
                for p, q in zip(product.components[:2], switched, strict=True)
            ), product.phase_bound + keys.switch_error_bound, pk)
            work.append(trace._monomial(reduced, 1 - keys.padded, pk))
        shift = keys.padded // 2
        for exponent, key in keys.rotations:
            merged = []
            for i in range(min(shift, len(work))):
                plus = minus = work[i]
                if i + shift < len(work):
                    right = trace._monomial(work[i + shift], shift, pk)
                    plus, minus = trace._add(work[i], right, pk), _subtract(work[i], right, pk)
                merged.append(trace._add(plus, _rotate(minus, exponent, key, pk, keys), pk))
            work, shift = merged, shift // 2
        assert work[0].phase_bound == bounds[group]
        output.append(work[0])
    return output
