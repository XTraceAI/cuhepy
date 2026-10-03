"""E102 exact restricted noise controls; not a sampler or release protocol.

Fix reused keys/index/history before averaging still-fresh CBD atoms. Canonical
switch digits can depend on those atoms; a uniform L1 setup event bounds that
maintenance without assuming independent digits/errors. These are standard
conditioning, norm and Chernoff controls, not a new HE security theorem.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from fractions import Fraction
from functools import lru_cache
from math import comb, isqrt


BASES = (Fraction(5, 4), Fraction(3, 2), Fraction(2))


def _integer(value, low, high, description):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(description)


def polynomial(value):
    if (type(value) is not tuple or not 1 <= len(value) <= 32768
            or len(value) & (len(value)-1) or any(type(x) is not int for x in value)):
        raise ValueError("Bounded integer power-of-two polynomial required")
    return value


def add(left, right):
    polynomial(left)
    polynomial(right)
    if len(left) != len(right):
        raise ValueError("Equal ring dimensions required")
    return tuple(a+b for a, b in zip(left, right, strict=True))


def multiply(left, right):
    """Integer negacyclic reference; no Q reduction or NTT rounding."""
    polynomial(left)
    polynomial(right)
    n = len(left)
    if len(right) != n:
        raise ValueError("Equal ring dimensions required")
    out = [0]*n
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            out[(i+j) % n] += a*b*(1 if i+j < n else -1)
    return tuple(out)


def coefficient_weights(fixed, coefficient, scale=1):
    polynomial(fixed)
    _integer(coefficient, 0, len(fixed)-1, "Ring coefficient required")
    if type(scale) is not int:
        raise ValueError("Integer scale required")
    n = len(fixed)
    # Fixed[k-j mod N] multiplies fresh E[j], with one negacyclic sign.
    return tuple(scale*fixed[(coefficient-j) % n]*(1 if j <= coefficient else -1)
                 for j in range(n))


def digits(poly, q, radix):
    polynomial(poly)
    _integer(q, 3, (1 << 241)-1, "Bounded Q required")
    _integer(radix, 2, 1 << 60, "Bounded radix required")
    if any(not 0 <= x < q for x in poly):
        raise ValueError("Canonical Q residues required before decomposition")
    levels, power = 0, 1
    while power < q:
        levels += 1
        power *= radix
    return tuple(tuple(x//radix**j % radix for x in poly) for j in range(levels))


def switch_residual(canonical, errors, q, radix, t):
    columns = digits(canonical, q, radix)
    _integer(t, 3, (1 << 30)-1, "Plaintext modulus required")
    if (type(errors) is not tuple or len(errors) != len(columns)
            or any(len(polynomial(e)) != len(canonical) for e in errors)):
        raise ValueError("One fixed full-ring error polynomial per gadget row required")
    out = (0,)*len(canonical)
    for column, error in zip(columns, errors, strict=True):
        out = add(out, tuple(t*x for x in multiply(column, error)))
    return out


def uniform_switch_cap(errors, radix, t):
    """All canonical/adaptive digits; no fresh-error MGF claim."""
    _integer(radix, 2, 1 << 60, "Bounded radix required")
    _integer(t, 3, (1 << 30)-1, "Plaintext modulus required")
    if type(errors) is not tuple or not errors:
        raise ValueError("Fixed error polynomials required")
    n = len(polynomial(errors[0]))
    if any(len(polynomial(e)) != n for e in errors):
        raise ValueError("Equal error polynomial dimensions required")
    return t*(radix-1)*sum(abs(x) for error in errors for x in error)


def cbd_counts(eta):
    _integer(eta, 1, 64, "CBD eta required")
    return {e: comb(2*eta, eta+e) for e in range(-eta, eta+1)}


@dataclass(frozen=True)
class Law:
    """Exact integer multiplicities, not an approximate probability array."""

    counts: tuple[tuple[int, int], ...]
    denominator: int

    def __post_init__(self):
        if (type(self.counts) is not tuple or not self.counts
                or any(type(x) is not tuple or len(x) != 2 or type(x[0]) is not int
                       or type(x[1]) is not int or x[1] <= 0 for x in self.counts)
                or tuple(sorted(self.counts)) != self.counts
                or len({x for x, _ in self.counts}) != len(self.counts)
                or type(self.denominator) is not int or self.denominator <= 0
                or sum(m for _, m in self.counts) != self.denominator):
            raise ValueError("Canonical exact finite law required")


def affine_cbd(terms, eta=1):
    """Aggregate aliases BEFORE convolution; names identify actual fresh atoms."""
    if (type(terms) is not tuple or len(terms) > 256
            or any(type(row) is not tuple or len(row) != 2 or type(row[0]) is not str
                   or not row[0] or type(row[1]) is not int for row in terms)):
        raise ValueError("Declared bounded integer atom weights required")
    masses = cbd_counts(eta)
    weights = Counter()
    for atom, weight in terms:
        weights[atom] += weight
    counts, denominator = {0: 1}, 1
    for weight in weights.values():
        if not weight:
            continue
        new = Counter()
        for x, mass in counts.items():
            for e, multiplicity in masses.items():
                new[x+weight*e] += mass*multiplicity
        if len(new) > 100000:
            raise ValueError("Exact law exceeds registered diagnostic support budget")
        counts, denominator = new, denominator*4**eta
    return Law(tuple(sorted(counts.items())), denominator)


def absolute_cbd_sum(eta, atoms):
    _integer(atoms, 0, 128, "Exact absolute-CBD diagnostic atom budget exceeded")
    masses = cbd_counts(eta)
    absolute = Counter()
    for e, mass in masses.items():
        absolute[abs(e)] += mass
    law = {0: 1}
    for _ in range(atoms):
        out = Counter()
        for x, mass in law.items():
            for e, multiplicity in absolute.items():
                out[x+e] += mass*multiplicity
        law = out
    return Law(tuple(sorted(law.items())), 4**(eta*atoms))


def tail(law, threshold, *, two_sided=True):
    _integer(threshold, 0, 1 << 256, "Nonnegative exact tail threshold required")
    if type(law) is not Law or type(two_sided) is not bool:
        raise ValueError("Declared exact tail law required")
    return Fraction(sum(m for x, m in law.counts if
                        (abs(x) if two_sided else x) >= threshold), law.denominator)


def power_mgf(law, base):
    """E[base**X], an exact MGF at log(base); no floating logarithm used."""
    if type(law) is not Law or type(base) is not Fraction or not 1 < base <= 2:
        raise ValueError("Exact rational base in (1,2] required")
    return sum((Fraction(m, law.denominator)*base**x for x, m in law.counts), Fraction(0))


def chernoff(law, threshold, *, two_sided=True, bases=BASES):
    _integer(threshold, 1, 1 << 256, "Positive Chernoff threshold required")
    if type(law) is not Law or type(two_sided) is not bool:
        raise ValueError("Declared exact law required")
    if type(bases) is not tuple or not bases:
        raise ValueError("Finite declared rational grid required")
    if threshold > max(abs(x) if two_sided else x for x, _ in law.counts):
        return Fraction(0)
    reflected = Law(tuple(sorted((-x, mass) for x, mass in law.counts)), law.denominator)
    return min(Fraction(1), *(power_mgf(law, r)/r**threshold
                              + (power_mgf(reflected, r)/r**threshold if two_sided else 0)
                              for r in bases))


@lru_cache(maxsize=256)
def l1_setup_cap(eta, atoms, failure, *, bases=BASES):
    """Uniform good-setup cap for independent honest CBD setup errors.

    No conditioning on published key bodies or adaptively selected setup rows.
    This analytical event does not implement or justify rejection sampling.
    """
    _integer(atoms, 1, 32768, "Bounded setup atom count required")
    if type(failure) is not Fraction or not 0 < failure < 1:
        raise ValueError("Exact failure budget in (0,1) required")
    single = absolute_cbd_sum(eta, 1)
    maximum, best = eta*atoms, eta*atoms
    for base in bases:
        moment = power_mgf(single, base)**atoms
        low, high = 0, maximum
        while low < high:
            middle = (low+high)//2
            # Failure is ||E||1 > middle, so Markov threshold is middle+1.
            if moment <= failure*base**(middle+1):
                high = middle
            else:
                low = middle+1
        best = min(best, low)
    # At the full support, probability is exactly zero even if Markov is loose.
    bound = Fraction(0) if best == maximum else min(
        Fraction(1), *(power_mgf(single, r)**atoms/r**(best+1) for r in bases))
    assert bound <= failure
    return best, bound


def concentration_radius(twice_proxy, kappa, events):
    """Known conservative integer CBD/Hoeffding radius for strict exceedance."""
    _integer(twice_proxy, 0, 1 << 256, "Bounded nonnegative twice-variance proxy required")
    _integer(kappa, 1, 256, "Correctness exponent required")
    _integer(events, 1, 1 << 64, "Whole generated-query coefficient family required")
    logarithm = (2*events-1).bit_length()
    square = twice_proxy*(kappa+logarithm)
    root = isqrt(square)
    return root+(root*root != square)


def lifetime_failure(setup_failure, per_query, generated):
    """Known conditional tower/union bound; query failures need not be IID."""
    _integer(generated, 1, 1 << 64, "Count all generated queries, including abandoned ones")
    if any(type(x) is not Fraction or not 0 <= x <= 1 for x in (setup_failure, per_query)):
        raise ValueError("Exact failure probabilities required")
    return min(Fraction(1), setup_failure+generated*per_query)


def model_card(n, eta, levels, trace_factor, lifetime, kappa, query_mode):
    """Complete paid toy geometry, not actual modulus/key/response measurements."""
    _integer(n, 2, 128, "Registered model ring dimension required")
    if n & (n-1):
        raise ValueError("Power-of-two ring dimension required")
    _integer(levels, 2, 4, "Registered gadget levels required")
    _integer(trace_factor, 2, 4, "Registered trace factor required")
    if trace_factor & (trace_factor-1) or query_mode not in ("seeded-owner", "public-key"):
        raise ValueError("Registered trace/query mode required")
    _integer(lifetime, 1, 64, "Registered lifetime required")
    _integer(kappa, 1, 32, "Registered correctness exponent required")
    t, radix, message = 5, 16, 2
    families = 1+(trace_factor.bit_length()-1)  # Relin plus every trace rotation.
    setup_budget = Fraction(1, 2**kappa)
    cap, family_failure = l1_setup_cap(eta, n*levels, setup_budget/families)
    setup_failure = families*family_failure
    fixed_index = message+t*eta  # Owner-seeded enrollment support.
    fixed_query = message if query_mode == "seeded-owner" else message+2*t*n*eta
    fresh_query_support = message+t*eta if query_mode == "seeded-owner" else fixed_query+t*eta
    source_support = n*fixed_index*fresh_query_support
    mean = n*fixed_index*fixed_query
    events = lifetime*n*trace_factor  # All tiles/all coefficients, before postselection.
    radius = concentration_radius(eta*n*(t*fixed_index)**2, kappa, events)
    source_conditional = min(source_support, mean+radius)
    old_switch = t*(radix-1)*n*levels*eta
    l1_switch = t*(radix-1)*cap
    tiles = trace_factor  # Pay a full response group.

    def completed(source, maintenance):
        return tiles*(trace_factor*(source+maintenance)+(trace_factor-1)*maintenance)

    deterministic = completed(source_support, old_switch)
    e94_with_maintenance = completed(source_conditional, old_switch)
    candidate = completed(source_conditional, l1_switch)
    # Independent baseline formula gets every same optimization and premise.
    known = tiles*trace_factor*source_conditional+tiles*(2*trace_factor-1)*l1_switch
    assert candidate == known and candidate <= e94_with_maintenance <= deterministic
    # Q must support every radix digit level AND no centered wrap. The fixed
    # four-bit radix/level count often prevents translating a noise win to Q.
    requested_bits = (2*candidate+1).bit_length()
    capacity_bits = 4*levels
    return {"N": n, "eta": eta, "levels": levels, "trace_factor": trace_factor,
            "tiles_per_reply": tiles, "lifetime": lifetime, "kappa": kappa,
            "query_mode": query_mode, "full_key_support": n, "setup_key_families": families,
            "setup_error_atoms_per_family": n*levels, "uniform_L1_cap": cap,
            "support_L1_cap": n*levels*eta, "setup_failure_upper": str(setup_failure),
            "query_lifetime_failure_upper": str(Fraction(1, 2**kappa)),
            "combined_correctness_failure_upper": str(setup_failure+Fraction(1, 2**kappa)),
            "original_phase_support": source_support, "conditional_original_phase": source_conditional,
            "complete_all_support_phase": deterministic,
            "complete_E94_with_support_maintenance_phase": e94_with_maintenance,
            "complete_uniform_setup_phase": candidate, "strongest_known_adapter_phase": known,
            "known_adapter_identical": True, "correctness_only_required_Q_bits": requested_bits,
            "fixed_radix_level_capacity_bits": capacity_bits,
            "fixed_level_geometry_can_cover_required_Q": requested_bits <= capacity_bits,
            "key_raw_bytes_at_fixed_radix_level_capacity": 2*n*levels*families*((capacity_bits+7)//8),
            "terminal_two_component_raw_bytes_at_32_bits": 2*n*4,
            "query_raw_coefficient_bytes_at_fixed_capacity": n*((capacity_bits+7)//8)*(1 if query_mode == "seeded-owner" else 2),
            "seeded_query_additional_seed_bytes": 32 if query_mode == "seeded-owner" else 0,
            "wire_envelopes_PBS_proof_binding_update_costs": "uninstantiated; no complete resource claim",
            "originality_resource_gate_passed": False, "parameters_approved": False}
