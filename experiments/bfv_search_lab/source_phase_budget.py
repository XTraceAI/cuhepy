"""E93 independent owner-BGV phase budgets; no parameter or privacy approval.

The source is seeded *owner* encryption, not public-key encryption. All bounds
are integer support bounds. A changed modulus changes keys/index and hardness
premises even when the same correctness envelope remains valid.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction

from gmpy2 import is_prime


@dataclass(frozen=True)
class Envelope:
    n: int
    t: int
    eta: int
    columns: int
    message_products: int
    message_error_products: int
    error_products: int
    centered_phase: int
    owner_fresh: int
    ordinary_public_key_fresh: int


def envelope(n, t, eta, columns):
    if (any(type(x) is not int for x in (n, t, eta, columns))
            or not 1 <= n <= 32768 or n & (n - 1)
            or not 3 <= t <= 65537 or t % 2 != 1
            or not 1 <= eta <= 64 or not 1 <= columns <= 4096):
        raise ValueError("Invalid bounded source geometry")
    message, error = t // 2, t * eta
    terms = (n * columns * message**2, 2 * n * columns * message * error,
             n * columns * error**2)
    return Envelope(n, t, eta, columns, *terms, sum(terms), message + error,
                    message + t * eta * (2 * n + 1))


def integer_product(left, right):
    """Independent schoolbook product over Z[X]/(X^N+1), not modulo Q."""
    if len(left) != len(right) or not left:
        raise ValueError("Mismatched phase vectors")
    n, result = len(left), [0] * len(left)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            result[(i + j) % n] += a * b * (1 if i + j < n else -1)
    return tuple(result)


def expanded_phase(messages_left, messages_right, errors_left, errors_right, t):
    """Trusted diagnostic separates plaintext carries from BGV noise.

    These inputs include private errors. This is not a server API, noise meter
    or publishable plaintext/noise witness for the final protocol.
    """
    arrays = (messages_left, messages_right, errors_left, errors_right)
    if (type(t) is not int or t < 3 or t % 2 != 1
            or any(type(rows) is not tuple or not rows for rows in arrays)
            or len({len(rows) for rows in arrays}) != 1
            or any(type(p) is not tuple or not p or any(type(x) is not int for x in p)
                   for rows in arrays for p in rows)
            or len({len(p) for rows in arrays for p in rows}) != 1):
        raise ValueError("Invalid diagnostic phase inputs")
    n = len(messages_left[0])
    plain, cross, noise = [0] * n, [0] * n, [0] * n
    for ml, mr, el, er in zip(*arrays, strict=True):
        for out, products in ((plain, (integer_product(ml, mr),)),
                              (cross, (integer_product(ml, er), integer_product(mr, el))),
                              (noise, (integer_product(el, er),))):
            for poly in products:
                for i, value in enumerate(poly):
                    out[i] += value
    phase = tuple(m + t * c + t**2 * e for m, c, e in zip(plain, cross, noise, strict=True))
    centered = tuple((m + t // 2) % t - t // 2 for m in plain)
    carry = tuple((m - r) // t for m, r in zip(plain, centered, strict=True))
    bgv_error = tuple(v + c + t * e for v, c, e in zip(carry, cross, noise, strict=True))
    assert phase == tuple(m + t * e for m, e in zip(centered, bgv_error, strict=True))
    return {"integer_plaintext_product": tuple(plain), "centered_plaintext": centered,
            "plaintext_carry": carry, "message_error_cross": tuple(cross),
            "error_product": tuple(noise), "BGV_error_including_plaintext_carry": bgv_error,
            "centered_phase_before_possible_Q_wrap": phase}


def ntt_prime_above(n, minimum):
    if (type(n) is not int or not 1 <= n <= 32768 or n & (n - 1)
            or type(minimum) is not int or minimum < 2):
        raise ValueError("Invalid prime-search bound")
    candidate = ((minimum - 1 + 2 * n - 1) // (2 * n)) * (2 * n) + 1
    while candidate < 1 << 64 and not is_prime(candidate):
        candidate += 2 * n
    if candidate >= 1 << 64:
        raise ValueError("No word-size NTT context in this screen")
    return candidate


def source_margin(q, t, bound, target, *, domain):
    """Numerator room for subsequent drift, before KS/rounding/PBS costs.

    q*rounded_phase-target*unit_phase is the numerator convention. Quarter
    models the signed odd-LUT ideal margin; half is nearest-message decoding.
    A generic full-domain PBS theorem is not instantiated by choosing 'half'.
    """
    if (any(type(x) is not int for x in (q, t, bound, target))
            or not 3 <= t < q < 1 << 64 or q % 2 != 1
            or bound < 0 or target < 2 or domain not in ("half", "quarter")):
        raise ValueError("Invalid source-margin context")
    divisor = 2 if domain == "half" else 4
    return Fraction(target * (q - divisor * bound), divisor * t)
