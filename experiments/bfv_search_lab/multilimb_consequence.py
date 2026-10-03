"""E120 exact public selection/support screen; no HE or statistical backend.

The owner index is a hypothetical reenrollment premise. Broad bounded common
words and canonical-only words have different admission laws. Mathematical
envelopes and emitted HE packet counts give neither API nor security approval.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd, prod

import gmpy2

SEEDED_TAG = b"cuhepy-lab-bgv-seeded-query-v1"
ROUNDED_TAG = b"cuhepy-lab-bgv-query-rounded-v1"
COMPACT_TAG = "cuhepy-lab-bgv-compact-v1"
SELECTOR_CAP = 4096


def _integers(*values):
    if any(type(x) is not int for x in values):
        raise ValueError("Expected exact integers")


def _prime64(value):
    """Same public unsigned64 diagnostic as the pinned E113 control."""
    if type(value) is not int or not 2 <= value < 1 << 64:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if value % p == 0:
            return value == p
    d, shifts = value-1, 0
    while not d & 1:
        d >>= 1
        shifts += 1
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        base %= value
        if base == 0:
            continue
        x = pow(base, d, value)
        if x in (1, value-1):
            continue
        for _ in range(shifts-1):
            x = x*x % value
            if x == value-1:
                break
        else:
            return False
    return True


@dataclass(frozen=True)
class Graph:
    n: int
    dimension: int
    count: int
    t: int
    eta: int
    digit_bits: int

    def validate(self):
        _integers(self.n, self.dimension, self.count, self.t, self.eta, self.digit_bits)
        if (not 8 <= self.n <= 32768 or self.n & (self.n-1)
                or not 1 <= self.dimension <= self.n//2
                or not 1 <= self.count <= 64*self.n
                or not 2*self.dimension < self.t < 1 << 30 or not self.t & 1
                or not 1 <= self.eta <= 64 or not 4 <= self.digit_bits <= 60):
            raise ValueError("Invalid bounded coefficient-search graph")
        return self

    @property
    def padded(self):
        self.validate()
        return 1 << (self.dimension-1).bit_length()


@dataclass(frozen=True)
class Context:
    graph: Graph
    q: int
    p: int

    def validate(self):
        if type(self.graph) is not Graph:
            raise ValueError("Expected the public graph")
        self.graph.validate()
        _integers(self.q, self.p)
        if (not 16 <= self.q.bit_length() <= 240 or not self.q & 1
                or not 16 <= self.p.bit_length() <= 60 or not _prime64(self.p)
                or not self.graph.t < self.p < self.q
                or (self.p-self.q) % self.graph.t
                or gcd(self.q*self.p, self.graph.t) != 1 or gcd(self.q, self.p) != 1):
            raise ValueError("Invalid odd congruent terminal/codec context")
        return self


def reproduce_rns_primes(n, requested_bits, *, cap=SELECTOR_CAP):
    """Literal source candidate order; no key, sampler or NTT constructor."""
    _integers(n, requested_bits, cap)
    if (not 8 <= n <= 32768 or n & (n-1)
            or not 60 <= requested_bits <= 240 or requested_bits % 60
            or not 1 <= cap <= SELECTOR_CAP):
        raise ValueError("Invalid bounded source RNS selector")
    candidate, primes, checks = (1 << 60)-2*n+1, [], []
    for _ in range(requested_bits//60):
        for tried in range(1, cap+1):
            # The source's default probable-prime decision is reproduced first.
            if gmpy2.is_prime(candidate):
                break
            candidate -= 2*n
        else:
            raise RuntimeError("RNS selector candidate cap exhausted")
        if candidate <= 1 << 59 or not _prime64(candidate) or candidate % (2*n) != 1:
            raise ValueError("Selected source prime failed public validation")
        primes.append(candidate)
        checks.append(tried)
        candidate -= 2*n
    if len(set(primes)) != len(primes):
        raise ValueError("Source limbs are not distinct")
    return tuple(primes), tuple(checks)


def reproduce_terminal_modulus(q, t, bits, *, cap=SELECTOR_CAP):
    """Literal compact selector, retaining its32-round probable-prime call."""
    _integers(q, t, bits, cap)
    if (not 16 <= q.bit_length() <= 240 or not q & 1
            or not 16 <= bits <= 60 or bits >= q.bit_length()
            or not 3 <= t < 1 << (bits-2) or not t & 1 or q % t == 0
            or not 1 <= cap <= SELECTOR_CAP):
        raise ValueError("Invalid bounded terminal selector")
    candidate = (1 << bits)-1
    candidate -= (candidate-q) % t
    if not candidate & 1:
        candidate -= t
    for tried in range(1, cap+1):
        if candidate < 1 << (bits-1):
            raise RuntimeError("Source terminal interval exhausted")
        if gmpy2.is_prime(candidate, 32):
            if not _prime64(candidate) or gcd(candidate, q) != 1:
                raise ValueError("Selected terminal failed public validation")
            return candidate, tried
        candidate -= 2*t
    raise RuntimeError("Terminal selector candidate cap exhausted")


def _context(ctx):
    if type(ctx) is not Context:
        raise ValueError("Expected an exact public context")
    return ctx.validate()


def ceil_div(a, b):
    _integers(a, b)
    if a < 0 or b <= 0:
        raise ValueError("Expected nonnegative numerator/positive denominator")
    return -(-a//b)


def uint_size(value):
    _integers(value)
    if not 0 <= value < 1 << 64:
        raise ValueError("Outside source MsgPack unsigned domain")
    return 1 if value < 128 else 2 if value < 256 else 3 if value < 65536 else 5 if value < 1 << 32 else 9


def array_size(length):
    _integers(length)
    if not 0 <= length < 1 << 32:
        raise ValueError("Outside source MsgPack array domain")
    return 1 if length < 16 else 3 if length < 65536 else 5


def binary_size(length):
    _integers(length)
    if not 0 <= length < 1 << 32:
        raise ValueError("Outside source MsgPack binary domain")
    return length+(2 if length < 256 else 3 if length < 65536 else 5)


def string_size(value):
    if type(value) is not str:
        raise ValueError("Expected source UTF8 string")
    length = len(value.encode("utf8"))
    if length >= 1 << 32:
        raise ValueError("Outside source MsgPack string domain")
    return length+(1 if length < 32 else 2 if length < 256 else 3 if length < 65536 else 5)


def coefficient_encoding(ctx, drop):
    _context(ctx)
    _integers(drop)
    if not 0 <= drop < ctx.q.bit_length():
        raise ValueError("Invalid public drop")
    if drop == 0:
        maximum, bits, center, units = ctx.q-1, ctx.q.bit_length(), 0, 0
    else:
        radix = 1 << drop
        intervals = (radix-1)//ctx.graph.t
        high, tail = divmod(ctx.q-1, radix)
        maximum = high*ctx.graph.t+min(ctx.graph.t-1, tail)
        bits, center = maximum.bit_length(), ctx.graph.t*(intervals//2)
        units = (intervals+1)//2
    return {"drop": drop, "max_word": maximum, "coefficient_bits": bits,
            "center": center, "added_error_units": units,
            "added_bound": ctx.graph.t*units,
            "body_bytes": ceil_div(ctx.graph.n*bits, 8)}


def query_schema(ctx, drop):
    encoding = coefficient_encoding(ctx, drop)
    if drop == 0:
        header = array_size(4)+binary_size(len(SEEDED_TAG))+2*binary_size(32)
    else:
        header = array_size(5)+binary_size(len(ROUNDED_TAG))+2*binary_size(32)+uint_size(drop)
    packet = header+binary_size(encoding["body_bytes"])
    return {**encoding, "field_count": 4 if drop == 0 else 5,
            "header_without_body_bytes": header,
            "body_framing_bytes": binary_size(encoding["body_bytes"])-encoding["body_bytes"],
            "query_packet_bytes": packet}


def response_schema(ctx):
    _context(ctx)
    g, pbits = ctx.graph, ctx.p.bit_length()
    groups, pfield = ceil_div(g.count, g.n), ceil_div(pbits, 8)
    poly = ceil_div(g.n*pbits, 8)
    header = (array_size(7)+string_size(COMPACT_TAG)+uint_size(g.n)+uint_size(g.t)
              +binary_size(pfield)+binary_size(32)+uint_size(g.count)+uint_size(g.dimension))
    packet = array_size(2)+header+array_size(groups)+groups*(array_size(2)+2*binary_size(poly))
    return {"terminal_bits": pbits, "terminal_field_bytes": pfield,
            "response_ciphertexts": groups, "response_poly_bytes": poly,
            "response_coefficient_body_bytes": groups*2*poly,
            "header_bytes": header, "response_packet_bytes": packet,
            "all_output_coefficients": groups*g.n,
            "transport_receipts_proofs_enrollment_unknown": True}


def maximum_digit_sum(q, bits):
    """Known first-differing-digit extremum, with one attaining canonical word."""
    _integers(q, bits)
    if not 3 <= q < 1 << 240 or not 4 <= bits <= 60:
        raise ValueError("Invalid bounded canonical digit domain")
    radix = 1 << bits
    digits = [(q-1 >> j) & (radix-1) for j in range(0, q.bit_length(), bits)]
    best, witness = sum(digits), q-1
    for j, digit in enumerate(digits):
        if digit:
            high = (q-1) >> ((j+1)*bits)
            word = (high << ((j+1)*bits))+(digit-1)*(radix**j)+radix**j-1
            score = sum(digits[j+1:])+digit-1+j*(radix-1)
            if score > best:
                best, witness = score, word
    return best, witness


def switch_envelope(ctx, law):
    _context(ctx)
    if type(law) is not str or law not in ("broad", "canonical"):
        raise ValueError("Unknown common-word admission law")
    g = ctx.graph
    levels = ceil_div(ctx.q.bit_length(), g.digit_bits)
    relaxed = levels*((1 << g.digit_bits)-1)
    canonical, witness = maximum_digit_sum(ctx.q, g.digit_bits)
    cap = relaxed if law == "broad" else canonical
    return {"law": law, "planes": levels, "digit_sum_cap": cap,
            "canonical_cap": canonical, "canonical_attaining_word": witness,
            "broad_cap": relaxed, "switch_bound": g.t*g.eta*g.n*cap,
            "word_geQ_allowed": law == "broad"}


def terminal_safe(ctx):
    _context(ctx)
    rounding = ceil_div((ctx.graph.n+1)*ctx.graph.t, 2)
    terminal_capacity = (ctx.p-1)//2-rounding
    if terminal_capacity < 0:
        raise ValueError("Terminal rounding alone consumes the margin")
    safe = min((ctx.q-1)//2, ctx.q*terminal_capacity//ctx.p)
    return {"rounding_bound": rounding, "terminal_capacity": terminal_capacity,
            "safe_q_phase_radius": safe}


def complete_bound(ctx, drop, law):
    enc = coefficient_encoding(ctx, drop)
    switch = switch_envelope(ctx, law)
    g, d = ctx.graph, ctx.graph.padded
    weight = 1+g.t*g.eta
    product = weight*(g.dimension+g.n*g.t*(g.eta+enc["added_error_units"]))
    maintenance = (2*d-1)*switch["switch_bound"]
    final = d*product+maintenance
    rounding = terminal_safe(ctx)["rounding_bound"]
    terminal = ceil_div(ctx.p*final, ctx.q)+rounding
    query_meta = g.t//2+g.t*g.eta+enc["added_bound"]
    public_fresh = g.t//2+g.t*g.eta*(2*g.n+1)
    owner_meta = g.t//2+g.t*g.eta
    source_switch = g.t*g.eta*g.n*switch["broad_cap"]
    support_meta = d*g.n*query_meta*owner_meta+(2*d-1)*source_switch
    capacity = g.n//d
    tiles = ceil_div(g.count, capacity)
    native_meta = []
    for start in range(0, tiles, d):
        work = [g.n*query_meta*owner_meta+source_switch]*min(d, tiles-start)
        shift = d//2
        while shift:
            work = [2*(work[i]+(work[i+shift] if i+shift < len(work) else 0))+source_switch
                    for i in range(min(shift, len(work)))]
            shift //= 2
        native_meta.append(work[0])
    return {"drop": drop, "law": law, "product_bound": product,
            "maintenance_bound": maintenance, "final_bound": final,
            "terminal_bound": terminal, "raw_admitted": 2*final < ctx.q,
            "terminal_admitted": 2*terminal < ctx.p,
            "envelope_admitted": 2*final < ctx.q and 2*terminal < ctx.p,
            "rounded_query_metadata_bound": query_meta,
            "rounded_query_guard_admitted": ctx.q.bit_length() >= 32 and 2*query_meta < ctx.q,
            "general_keygen_guard_admitted": 2*g.n*public_fresh**2 < ctx.q,
            "general_keygen_guard_twice_product": 2*g.n*public_fresh**2,
            "owner_packet_generic_phase_metadata": owner_meta,
            "optin_E15_support_metadata_final_bound": support_meta,
            "optin_E15_support_metadata_raw_admitted": 2*support_meta < ctx.q,
            "optin_E15_support_metadata_terminal_admitted":
                2*(ceil_div(ctx.p*support_meta, ctx.q)+rounding) < ctx.p,
            "default_native_owner_metadata_final_bounds": tuple(native_meta),
            "default_native_owner_metadata_raw_admitted": all(2*b < ctx.q for b in native_meta),
            "default_native_owner_metadata_terminal_admitted":
                all(2*(ceil_div(ctx.p*b, ctx.q)+rounding) < ctx.p for b in native_meta),
            "metadata_index_is_prospective_owner_not_captured_public_index": True,
            "hypothetical_owner_metadata_only": True}


def deterministic_baseline(ctx, law):
    zero = complete_bound(ctx, 0, law)
    safe = terminal_safe(ctx)["safe_q_phase_radius"]
    if not zero["envelope_admitted"]:
        return {"law": law, "drop": None, "unrounded": zero,
                "stop": "unrounded_registered_envelope_rejects"}
    g, d = ctx.graph, ctx.graph.padded
    scale = d*g.n*g.t*(1+g.t*g.eta)
    allowance = (safe-zero["final_bound"])//scale
    inverse = g.t*(2*allowance+1)
    drop = min(ctx.q.bit_length()-1, inverse.bit_length()-1)
    selected = complete_bound(ctx, drop, law)
    successor = complete_bound(ctx, drop+1, law) if drop+1 < ctx.q.bit_length() else None
    if not selected["envelope_admitted"] or (successor and successor["envelope_admitted"]):
        raise ArithmeticError("Integer inversion boundary failed original strict guards")
    return {"law": law, "drop": drop, "unrounded": zero,
            "unit_allowance": allowance, "power_limit": inverse,
            "selected": selected, "immediate_successor": successor,
            "maximal_only_within_registered_envelope": True}


def select_candidate(ctx, canonical_baseline):
    """One monotone schema boundary; no suffix, norm or noise-tail calculation."""
    _context(ctx)
    if ctx.q.bit_length() > 128:
        raise ValueError("Drop integer header monotonicity is only fixed-fixint here")
    if (type(canonical_baseline) is not dict or canonical_baseline.get("law") != "canonical"
            or type(canonical_baseline.get("drop")) is not int):
        raise ValueError("An admitted canonical registered baseline is required")
    drop = canonical_baseline["drop"]
    if not 0 <= drop < ctx.q.bit_length():
        raise ValueError("Invalid canonical baseline drop")
    # Recheck owner-local inputs, rather than trusting a wire-supplied baseline.
    if deterministic_baseline(ctx, "canonical") != canonical_baseline:
        raise ValueError("Canonical baseline differs from owner-derived boundary")
    response = response_schema(ctx)
    baseline = query_schema(ctx, drop)
    exchange = baseline["query_packet_bytes"]+response["response_packet_bytes"]
    probes = {}

    def probe(value):
        if value not in probes:
            query = query_schema(ctx, value)
            actual = query["query_packet_bytes"]+response["response_packet_bytes"]
            probes[value] = {"drop": value, "exchange_bytes": actual,
                             "meets5percent": 20*actual <= 19*exchange, "query": query}
        return probes[value]["meets5percent"]

    lower, upper = drop, ctx.q.bit_length()-1
    selected = None
    if lower < upper and probe(upper):
        while upper-lower > 1:
            middle = (lower+upper)//2
            if probe(middle):
                upper = middle
            else:
                lower = middle
        selected = probes[upper]
    budget = (ctx.q.bit_length()-1).bit_length()+2
    if len(probes) > budget:
        raise ArithmeticError("Format probe budget exceeded")
    previous = probes.get(lower) if selected else None
    if selected and lower == drop:
        previous = {"drop": drop, "exchange_bytes": exchange, "meets5percent": False,
                    "query": baseline}
    return {"baseline_drop": drop, "baseline_query": baseline,
            "baseline_exchange_bytes": exchange, "response": response,
            "candidate": selected, "immediate_predecessor": previous,
            "format_probes": [probes[b] for b in sorted(probes)],
            "format_probe_count": len(probes), "format_probe_budget": budget,
            "comparison": "20*candidate_exchange <= 19*canonical_baseline_exchange",
            "canonical_control_vs_broad_candidate_contracts_differ": True,
            "stop": None if selected else "no_allowed_single_format_candidate"}


def norm_prefix(n, source_order_primes):
    """Nonzero ternary bound, with independent limb caps and unchanged order."""
    _integers(n)
    if (not 8 <= n <= 32768 or n & (n-1) or type(source_order_primes) is not tuple
            or not 1 <= len(source_order_primes) <= 4
            or any(type(p) is not int or not _prime64(p) or p % (2*n) != 1
                   for p in source_order_primes)
            or len(set(source_order_primes)) != len(source_order_primes)):
        raise ValueError("Expected distinct split source-order prime limbs")
    bound, caps = n**(n//2), []
    for p in source_order_primes:
        lower, upper = 0, n
        while lower < upper:
            middle = (lower+upper+1)//2
            if p**middle <= bound:
                lower = middle
            else:
                upper = middle-1
        caps.append(lower)
    k = max(caps)
    return {"n": n, "source_order_primes": source_order_primes,
            "limb_nullity_caps": tuple(caps), "common_nullity_cap": k,
            "prefix_length": n-k, "norm_bound_bits": bound.bit_length(),
            "q_product": prod(source_order_primes), "zero_excluded": True,
            "fixed_consecutive_prefix_only": True,
            "weighted_divisor_not_Q_power": True}


def suffix_screen(ctx, candidate_drop, certificate):
    _context(ctx)
    if (type(certificate) is not dict or certificate.get("n") != ctx.graph.n
            or certificate.get("q_product") != ctx.q
            or type(certificate.get("source_order_primes")) is not tuple
            or norm_prefix(ctx.graph.n, certificate["source_order_primes"]) != certificate):
        raise ValueError("Norm certificate does not match the public owner context")
    enc = coefficient_encoding(ctx, candidate_drop)
    g, d = ctx.graph, ctx.graph.padded
    switch = switch_envelope(ctx, "broad")["switch_bound"]
    maintenance = (2*d-1)*switch
    safe = terminal_safe(ctx)["safe_q_phase_radius"]
    h = (safe-maintenance)//d-g.dimension*(1+g.t*g.eta)+1
    suffix = certificate["common_nullity_cap"]*g.t*(1+g.t*g.eta)*(g.eta+enc["added_error_units"])
    retained = h-suffix
    return {"candidate_drop": candidate_drop, "main_law": "broad",
            "max_abs_E_plus_delta_units": g.eta+enc["added_error_units"],
            "first_unsafe_integer_random_threshold": h,
            "paid_correlated_suffix": suffix, "retained_threshold": retained,
            "suffix_consumes_margin": retained <= 0,
            "necessary_feasibility_only": True, "probability_calculated": False,
            "stop": "suffix_consumes_registered_margin" if retained <= 0
                    else "necessary_suffix_pass_return_for_separate_registration"}
