"""E114 conditional ideal-mask codec law and outward rational tail control.

This module supplies known counting/concentration controls, not a sampler,
authenticated evaluator or parameter approval. IID codec errors require a
genuinely uniform fresh full ring mask and a unit secret. The deployed public
SHAKE seed and supported secret sampler do not establish those premises.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from math import comb, gcd


def _integers(*values):
    if any(type(value) is not int for value in values):
        raise ValueError("Expected exact integers")


def ceil_div(a: int, b: int) -> int:
    _integers(a, b)
    if b <= 0:
        raise ValueError("Expected positive divisor")
    return -(-a // b)


def _positive_rational(value):
    if type(value) is not Fraction or value <= 0:
        raise ValueError("Expected a positive exact Fraction")


@dataclass(frozen=True)
class QuantizerLaw:
    """Exact scalar law for a uniform canonical coefficient c in [0,Q).

    Values are delta/t. Each full R cycle and the final partial cycle are
    counted by interval lengths; Q itself is never enumerated.
    """

    q: int
    t: int
    drop: int

    def __post_init__(self):
        _integers(self.q, self.t, self.drop)
        if (not self.q & 1 or not 3 <= self.t < self.q or not self.t & 1
                or not 1 <= self.drop < self.q.bit_length()):
            raise ValueError("Invalid quantizer domain")
        if 2 * self.added_bound >= self.q:
            raise ValueError("Added error has no unique centered lift")

    @property
    def radix(self):
        return 1 << self.drop

    @property
    def intervals(self):
        return (self.radix - 1) // self.t

    @property
    def center_units(self):
        return self.intervals // 2

    @property
    def added_bound(self):
        return self.t * ceil_div(self.intervals, 2)

    @property
    def full_cycles(self):
        return self.q // self.radix

    @property
    def tail(self):
        return self.q % self.radix

    def mass(self, bin_index: int) -> int:
        _integers(bin_index)
        if not 0 <= bin_index <= self.intervals:
            raise ValueError("Bin outside the full radix support")
        start = bin_index * self.t
        full = max(0, min(self.t, self.radix - start))
        tail = max(0, min(self.t, self.tail - start))
        return self.full_cycles * full + tail

    def pmf(self) -> tuple[tuple[int, int], ...]:
        return tuple((self.center_units - k, self.mass(k))
                     for k in range(self.intervals + 1))

    def mean_units(self) -> Fraction:
        return Fraction(sum(value * mass for value, mass in self.pmf()), self.q)

    def second_moment_units(self) -> Fraction:
        return Fraction(sum(value * value * mass for value, mass in self.pmf()), self.q)

    def added_error(self, coefficient: int) -> int:
        _integers(coefficient)
        if not 0 <= coefficient < self.q:
            raise ValueError("Expected canonical original coefficient")
        return self.t * (self.center_units - (coefficient % self.radix) // self.t)

    def literal_map(self, coefficient: int) -> tuple[int, int]:
        """The existing public word/reconstruction formula, for small tests."""
        self.added_error(coefficient)  # Admit the original canonical coefficient.
        high, low = divmod(coefficient, self.radix)
        word = high * self.t + low % self.t
        reconstructed = (high * self.radix + low % self.t
                         + self.t * self.center_units) % self.q
        return word, reconstructed

    def _cycle_mgf_sum(self, length: int, base: Fraction) -> Fraction:
        whole, tail = divmod(length, self.t)
        if base == 1:
            return Fraction(length)
        # A finite geometric sum, including the last incomplete plaintext bin.
        geometric = ((1 - base ** (-whole)) / (1 - 1 / base)
                     if whole else Fraction(0))
        return (self.t * base ** self.center_units * geometric
                + tail * base ** (self.center_units - whole))

    def mgf(self, base: Fraction) -> Fraction:
        _positive_rational(base)
        return (self.full_cycles * self._cycle_mgf_sum(self.radix, base)
                + self._cycle_mgf_sum(self.tail, base)) / self.q


def cbd_pmf(eta: int) -> tuple[tuple[int, int], ...]:
    """CBD_eta: exact coin-string weights, denominator 4**eta."""
    _integers(eta)
    if not 1 <= eta <= 64:
        raise ValueError("Invalid CBD support")
    return tuple((value, comb(2 * eta, value + eta))
                 for value in range(-eta, eta + 1))


def cbd_mgf(eta: int, base: Fraction) -> Fraction:
    cbd_pmf(eta)
    _positive_rational(base)
    return ((1 + base) * (1 + 1 / base) / 4) ** eta


def joint_mgf(law: QuantizerLaw, eta: int, base: Fraction) -> Fraction:
    if type(law) is not QuantizerLaw:
        raise ValueError("Expected exact admitted law")
    return law.mgf(base) * cbd_mgf(eta, base)


def upward_dyadic(value: Fraction, bits: int = 32) -> Fraction:
    _positive_rational(value)
    _integers(bits)
    if not 1 <= bits <= 64:
        raise ValueError("Invalid outward precision")
    return Fraction(ceil_div(value.numerator * (1 << bits), value.denominator), 1 << bits)


def terminal_radius(q: int, p: int, t: int, n: int) -> tuple[int, int]:
    """Greatest B with ceil(P*B/Q)+ceil((N+1)t/2) <= (P-1)/2.

    This is the sufficient complete signed-ternary terminal bound, not an
    observed phase or permission to decode an unauthenticated packet.
    """
    _integers(q, p, t, n)
    if (not q & 1 or not p & 1 or not t & 1 or not q > t >= 3
            or not t < p < q or n < 1 or p % t != q % t
            or gcd(q, t) != 1 or gcd(p, t) != 1):
        raise ValueError("Invalid congruent terminal context")
    rounding = ceil_div((n + 1) * t, 2)
    available = (p - 1) // 2 - rounding
    if available < 0:
        return -1, rounding
    return min((q - 1) // 2, q * available // p), rounding


def tail_certificate(*, n: int, threshold: int, t: int, weight_bound: int,
                     plus: Fraction, minus: Fraction, base: Fraction,
                     lifetime_queries: int, output_coefficients: int) -> dict:
    """Known endpoint-convexity/Markov control, with rational log enclosures.

    The argument conditions on fixed weights |a_i|<=weight_bound. Independent
    Z_i are required; reused maintenance terms stay outside the threshold.
    Neither output nor query independence is needed by the final union bound.
    """
    _integers(n, threshold, t, weight_bound, lifetime_queries, output_coefficients)
    if min(n, t, weight_bound, lifetime_queries, output_coefficients) < 1:
        raise ValueError("Invalid tail dimensions")
    _positive_rational(plus)
    _positive_rational(minus)
    _positive_rational(base)
    if base <= 1:
        raise ValueError("Expected exponential base above one")
    plus_up, minus_up = upward_dyadic(plus), upward_dyadic(minus)
    # The maximum is >=1 by M(z)M(1/z)>=1; retaining 1 is conservative even
    # for an arbitrary caller-supplied pair and keeps log(M)<=M-1 applicable.
    upper = max(Fraction(1), plus_up, minus_up)
    j = threshold // (t * weight_bound)
    a = j * (base - 1) / base - n * (upper - 1)
    exponent = a.numerator // a.denominator
    if threshold <= 0 or a <= 0 or exponent < 1:
        per_output = Fraction(1)
    else:
        per_output = min(Fraction(1), Fraction(1, 1 << (exponent - 1)))
    union_factor = lifetime_queries * output_coefficients
    lifetime = min(Fraction(1), union_factor * per_output)
    return {"threshold": threshold, "normalized_floor_threshold": j,
            "base": base, "mgf_plus_upward": plus_up,
            "mgf_minus_upward": minus_up, "mgf_endpoint_upper": upper,
            "log_exponent_lower": a, "floor_log_exponent_lower": exponent,
            "per_output_two_sided_upper": per_output,
            "lifetime_union_factor": union_factor,
            "lifetime_upper": lifetime,
            "conditional_target_2_pow_minus_128": lifetime <= Fraction(1, 1 << 128),
            "target_scope": "ideal conditional statistical component only",
            "ordinary_control_ratio": 1}


def ideal_card(profile, deterministic_bound: dict, *, base=Fraction(16385, 16384)):
    """One disclosed owner-index card; no new profile search or setup run."""
    profile.validate()
    if type(deterministic_bound) is not dict:
        raise ValueError("Expected exact complete deterministic bound")
    if (deterministic_bound["index_mode"] != "owner"
            or deterministic_bound["relaxed_common_digits"] is not True):
        raise ValueError("Requires owner index and common bounded-digit control")
    q, p = deterministic_bound["q"], deterministic_bound["p"]
    law = QuantizerLaw(q, profile.t, deterministic_bound["query_drop"])
    radius, rounding = terminal_radius(q, p, profile.t, profile.n)
    weight = 1 + profile.t * profile.eta
    switch = (profile.t * profile.eta * profile.n
              * deterministic_bound["levels"] * ((1 << profile.digit_bits) - 1))
    if switch != deterministic_bound["switch_bound"]:
        raise ValueError("Mismatched maintenance control")
    maintenance = (2 * profile.padded - 1) * switch
    signal = profile.dimension * weight
    threshold = (radius - maintenance) // profile.padded - signal + 1
    plus, minus = (joint_mgf(law, profile.eta, sign_base)
                   for sign_base in (base, 1 / base))
    outputs = profile.n * ceil_div(profile.count, profile.n)
    certificate = tail_certificate(n=profile.n, threshold=threshold, t=profile.t,
                                   weight_bound=weight, plus=plus, minus=minus,
                                   base=base, lifetime_queries=1 << 32,
                                   output_coefficients=outputs)
    return law, plus, minus, {"safe_q_phase_radius": radius,
                             "terminal_rounding_cap": rounding,
                             "index_phase_coefficient_bound": weight,
                             "switch_bound": switch, "complete_maintenance_cap": maintenance,
                             "pretrace_signal_cap": signal,
                             "trace_factor": profile.padded,
                             "all_output_coefficients_per_query": outputs,
                             "certificate": certificate,
                             "actual_sampler_or_parameter_approved": False}
