"""E37 same-field secret polynomial remainder fingerprints (Rabin family).

For a uniform hidden monic irreducible f of degree d over F_Q, a fixed
nonzero error polynomial of degree at most L-1 collides only if f divides it.
There are at most floor((L-1)/d) such factors among I_Q(d) choices. A bounded
verification-only first-false-accept transcript costs a union bound B.

The key and digests must remain hidden, inputs/setup trusted, lengths fixed,
and private leakage excluded. This is NOT a new hash primitive, complete HE
protocol, MAC exposed to an attacker, or private-side-channel assurance.
"""

from __future__ import annotations

from fractions import Fraction
import itertools
import random
import secrets

import gmpy2
from gmpy2 import mpz

Polynomial = tuple[int, ...]


def field(q: int, degree: int) -> None:
    if (type(q) is not int or not 3 <= q < 1 << 56 or not gmpy2.is_prime(q)
            or type(degree) is not int or not 1 <= degree <= 8):
        raise ValueError("Expected a bounded prime field and degree 1..8")


def trim(a: Polynomial) -> Polynomial:
    end = len(a)
    while end and not a[end - 1]:
        end -= 1
    return a[:end]


def remainder(a: Polynomial, f: Polynomial, q: int) -> Polynomial:
    """Independent ordinary schoolbook division; f may be nonmonic for gcd."""
    work, divisor = list(trim(tuple(x % q for x in a))), trim(tuple(x % q for x in f))
    if not divisor:
        raise ValueError("Zero polynomial divisor")
    inverse = pow(divisor[-1], -1, q)
    while len(work) >= len(divisor):
        scale, shift = work[-1] * inverse % q, len(work) - len(divisor)
        for j, value in enumerate(divisor):
            work[shift + j] = (work[shift + j] - scale * value) % q
        while work and not work[-1]:
            work.pop()
    return tuple(work)


def multiply(a: Polynomial, b: Polynomial, f: Polynomial, q: int) -> Polynomial:
    result = [0] * max(0, len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            result[i + j] = (result[i + j] + x * y) % q
    return remainder(tuple(result), f, q)


def power(a: Polynomial, exponent: int, f: Polynomial, q: int) -> Polynomial:
    result: Polynomial = (1,)
    while exponent:
        if exponent & 1:
            result = multiply(result, a, f, q)
        a = multiply(a, a, f, q)
        exponent >>= 1
    return result


def gcd(a: Polynomial, b: Polynomial, q: int) -> Polynomial:
    while b:
        a, b = b, remainder(a, b, q)
    if not a:
        return ()
    inverse = pow(a[-1], -1, q)
    return tuple(x * inverse % q for x in a)


def prime_divisors(n: int) -> tuple[int, ...]:
    return tuple(p for p in range(2, n + 1) if n % p == 0 and gmpy2.is_prime(p))


def irreducible(f: Polynomial, q: int) -> bool:
    degree = len(f) - 1
    field(q, degree)
    if type(f) is not tuple or f[-1] != 1 or any(type(x) is not int or not 0 <= x < q for x in f):
        raise ValueError("Expected a canonical monic bounded polynomial")
    if degree == 1:
        return True
    x = remainder((0, 1), f, q)
    frobenius = x
    checks = {degree // p for p in prime_divisors(degree)}
    for i in range(1, degree + 1):
        frobenius = power(frobenius, q, f, q)
        if i in checks:
            difference = list(frobenius) + [0] * max(0, len(x) - len(frobenius))
            for j, value in enumerate(x):
                difference[j] = (difference[j] - value) % q
            if len(gcd(f, trim(tuple(difference)), q)) > 1:
                return False
    return frobenius == x


def count(q: int, degree: int) -> int:
    """Exact I_Q(d), via the elementary finite-field/Mobius count."""
    field(q, degree)
    numerator = 0
    for divisor in range(1, degree + 1):
        if degree % divisor:
            continue
        primes = prime_divisors(divisor)
        mu = 0 if any(divisor % (p * p) == 0 for p in primes) else (-1) ** len(primes)
        numerator += mu * q ** (degree // divisor)
    assert numerator % degree == 0
    return numerator // degree


def collision(q: int, degree: int, length: int, budget: int = 1024) -> Fraction:
    field(q, degree)
    if (type(length) is not int or not 1 <= length <= 1 << 24
            or type(budget) is not int or not 1 <= budget <= 65536):
        raise ValueError("Expected a fixed bounded coefficient length and attempt budget")
    return min(Fraction(1), Fraction(budget * ((length - 1) // degree), count(q, degree)))


def choose(q: int, length: int, *, budget: int = 1024, integrity_bits: int = 128) -> int:
    if type(integrity_bits) is not int or not 32 <= integrity_bits <= 256:
        raise ValueError("Invalid conditional integrity target")
    for degree in range(1, 9):
        if collision(q, degree, length, budget) <= Fraction(1, 1 << integrity_bits):
            return degree
    raise ValueError("Conditional target exceeds bounded polynomial degree")


def sample(q: int, degree: int, *, rng: random.Random | None = None) -> Polynomial:
    """Uniform rejection sampling; injected deterministic RNG is tests only."""
    field(q, degree)
    sampler = rng if rng is not None else secrets.SystemRandom()
    for _ in range(4096):
        f = tuple(sampler.randrange(q) for _ in range(degree)) + (1,)
        if irreducible(f, q):
            return f
    raise RuntimeError("Irreducible sampling exceeded the bounded trial count")


def enumerate_keys(q: int, degree: int) -> tuple[Polynomial, ...]:
    field(q, degree)
    if q ** degree > 65536:
        raise ValueError("Key enumeration is a tiny oracle only")
    return tuple(f for lower in itertools.product(range(q), repeat=degree)
                 if irreducible(f := lower + (1,), q))


def digest(values: tuple[int | mpz, ...], f: Polynomial, q: int) -> tuple[mpz, ...]:
    """GMP Horner/LFSR reference; fixed coefficient length, ordinary formal Z."""
    if (not 1 <= len(values) <= 1 << 20 or any(not 0 <= x < q for x in values)
            or not irreducible(f, q)):
        raise ValueError("Invalid canonical remainder fingerprint input/key")
    modulus, lower = mpz(q), tuple(mpz(x) for x in f[:-1])
    state = [mpz(0)] * len(lower)
    for value in reversed(values):
        high = state[-1]
        state = [(value - high * lower[0]) % modulus] + [
            (state[j - 1] - high * lower[j]) % modulus for j in range(1, len(lower))]
    return tuple(state)


def powers(length: int, f: Polynomial, q: int) -> tuple[tuple[mpz, ...], ...]:
    """Transpose remainders of Z^i: d complete coefficient challenge rows."""
    if type(length) is not int or not 1 <= length <= 1 << 20 or not irreducible(f, q):
        raise ValueError("Invalid bounded remainder challenge length/key")
    degree, modulus = len(f) - 1, mpz(q)
    state = [mpz(1)] + [mpz(0)] * (degree - 1)
    rows: list[list[mpz]] = [[] for _ in range(degree)]
    lower = tuple(mpz(x) for x in f[:-1])
    for _ in range(length):
        for row, value in zip(rows, state, strict=True):
            row.append(value)
        high = state[-1]
        state = [-high * lower[0] % modulus] + [
            (state[j - 1] - high * lower[j]) % modulus for j in range(1, degree)]
    return tuple(tuple(row) for row in rows)
