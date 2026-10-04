"""Q76.5 independent static certificate for the selected homemade BGV graph.

This module imports no optimizer, HE arithmetic, native adapter or noise oracle.
It reconstructs the reference schedule and support bounds from trusted public
metadata. A certificate describes a plan; it proves neither ciphertext equality
nor honest private origin, native refinement, attestation or release authority.
Those are separate, explicit obligations of the selected runtime/protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from math import gcd

import gmpy2

MODES = (
    "full_common_Q_relation",
    "protected_original_request_only_replay",
    "exact_three_aggregate_protected_prefix_suffix",
)
CERTIFICATE_DOMAIN = b"cuhepy/q76-plan-certificate/v1\0"
MAX_CERTIFICATE_BYTES = 1 << 21
MAX_NESTING = 16
MAX_ARRAY_ITEMS = 1024
COMMON_WIDTH = 15
RADIX_BITS = 30
DIGITS = 4
UINT64_MAX = (1 << 64) - 1

# Frozen public inputs, not a fresh parameter selection or security approval.
# Both small pairs are from Q74 public-fixtures.json.gz; the large pair is from
# the completed Q76.3b source-cohort1 report. Ordered bases are part of context.
RETAINED_PROFILES = (
    (
        16,
        3,
        11,
        1,
        1329227995784911300417119789528939649,
        33554267,
        (1152921504606845473, 1152921504606844513),
    ),
    (
        32,
        5,
        19,
        1,
        1329227995784909824677593892767984513,
        33554291,
        (1152921504606844417, 1152921504606844289),
    ),
    (
        16384,
        512,
        1031,
        21,
        1329227995784613643754746428306227201,
        33548413,
        (1152921504606748673, 1152921504606683137),
    ),
)


def _fixed(value, name):
    if type(value) is not bytes or len(value) != 32:
        raise ValueError(f"Invalid immutable {name}")


@dataclass(frozen=True)
class Geometry:
    n: int
    dimension: int
    t: int
    eta: int
    q: int
    p: int
    primes: tuple[int, int]

    def __post_init__(self):
        self._validate()

    def _validate(self):
        values = (self.n, self.dimension, self.t, self.eta, self.q, self.p)
        if (
            any(type(x) is not int for x in values)
            or type(self.primes) is not tuple
            or len(self.primes) != 2
            or any(type(x) is not int for x in self.primes)
            or (*values, self.primes) not in RETAINED_PROFILES
        ):
            raise ValueError("Only the three frozen owner-canonical profiles are eligible")
        padded = 1 << (self.dimension - 1).bit_length()
        if (
            self.n & (self.n - 1)
            or self.n < 2 * padded
            or not 2 * padded < self.t
            or self.t % 2 != 1
            or gcd(padded, self.t) != 1
            or self.q.bit_length() != 120
            or self.primes[0] * self.primes[1] != self.q
            or gcd(*self.primes) != 1
            or any(
                not 1 << 59 <= x < 1 << 60 or (x - 1) % (2 * self.n) or not gmpy2.is_prime(x, 50)
                for x in self.primes
            )
            or not 1 << 15 <= self.p < self.q
            or self.p % 2 != 1
            or not gmpy2.is_prime(self.p, 50)
            or self.p % self.t != self.q % self.t
        ):
            raise ValueError("Invalid actual prime, predivision or terminal basis")

    @property
    def padded(self):
        return 1 << (self.dimension - 1).bit_length()

    @property
    def levels(self):
        return self.padded.bit_length() - 1


def geometry(number):
    """Select a frozen profile by trusted local choice, never a peer field."""
    if type(number) is not int or not 0 <= number < len(RETAINED_PROFILES):
        raise ValueError("Invalid retained profile selection")
    return Geometry(*RETAINED_PROFILES[number])


@dataclass(frozen=True)
class TrustedPlan:
    geometry: Geometry
    count: int
    key_id: bytes
    ordered_ids_digest: bytes
    snapshot_id: bytes
    policy_digest: bytes
    code_digest: bytes
    mode: str

    def __post_init__(self):
        self._validate()

    def _validate(self):
        if type(self.geometry) is not Geometry:
            raise ValueError("Trusted selected geometry required")
        self.geometry._validate()
        if type(self.count) is not int or not 1 <= self.count <= 2 * self.geometry.n:
            raise ValueError("Invalid complete record coverage")
        if type(self.mode) is not str or self.mode not in MODES:
            raise ValueError("Unimplemented or peer-selected placement")
        for name in ("key_id", "ordered_ids_digest", "snapshot_id", "policy_digest", "code_digest"):
            _fixed(getattr(self, name), name)

    @property
    def groups(self):
        return (self.count + self.geometry.n - 1) // self.geometry.n


def _ceil(numerator, denominator):
    return (numerator + denominator - 1) // denominator


def support_bounds(profile):
    """Conservative deterministic supports; no Profile.envelope or sampled noise."""
    if type(profile) is not Geometry:
        raise ValueError("Selected geometry required")
    profile._validate()
    fresh = profile.t // 2 + profile.t * profile.eta
    switch = profile.t * profile.eta * profile.n * DIGITS * ((1 << RADIX_BITS) - 1)
    expansion = [fresh]
    for _ in range(profile.levels):
        expansion.append(2 * expansion[-1] + switch)
    product = profile.n * profile.dimension * fresh * expansion[-1]
    output = product + switch
    terminal = _ceil(profile.p * output, profile.q) + _ceil((profile.n + 1) * profile.t, 2)
    if (
        any(2 * x >= profile.q for x in expansion)
        or 2 * output >= profile.q
        or 2 * terminal >= profile.p
    ):
        raise ValueError("Complete public phase/terminal guard fails")
    return fresh, switch, tuple(expansion), product, output, terminal


def counted_resources(plan):
    """Canonical components, not native allocator capacities or exact stage peaks."""
    if type(plan) is not TrustedPlan:
        raise ValueError("Trusted plan required")
    plan._validate()
    p, groups = plan.geometry, plan.groups
    common = p.n * COMMON_WIDTH
    public_rows = 8 * (p.levels + 1) + 3 * p.dimension * groups
    full = (p.padded - 1 + 3 * groups) * common
    aggregates = 3 * groups * common
    return {
        "common_polynomial_bytes": common,
        "evaluation_key_common_bytes": (p.levels + 1) * DIGITS * 2 * common,
        "index_common_bytes": 2 * p.dimension * groups * common,
        "original_query_common_bytes": 2 * common,
        "source_polynomials": p.padded - 1 + groups,
        "full_witness_body_bytes": full,
        "aggregate_claim_body_bytes": aggregates,
        "mode_internal_claim_body_bytes": full
        if plan.mode == MODES[0]
        else aggregates
        if plan.mode == MODES[2]
        else 0,
        "client_coefficient_body_bytes": 2 * groups * _ceil(p.n * p.p.bit_length(), 8),
        "public_RNS_rows": public_rows,
        "resident_RNS_row_component_bytes": public_rows * p.n * 2 * 8,
        "resident_map_shift_component_bytes": p.levels * p.n * (8 + 16),
        "setup_forward_prime_NTTs": 2 * (8 * (p.levels + 1) + 2 * p.dimension * groups + p.levels),
        "complete_ordered_ID_bytes": 8 * plan.count,
        "cache_vector_bytes": plan.count * _ceil(p.dimension, 8),
        "cache_body_with_ID_bytes": plan.count * (8 + _ceil(p.dimension, 8)),
        "cache_complete_acquisition_bytes": plan.count * (8 + _ceil(p.dimension, 8)) + 51 + 288,
        "counts_scope": "canonical components only; bytes are not time or exact resident copies",
        "paid_lifetimes": [
            "owner private context and provisioning",
            "signed enrollment and seeded input parsing",
            "key/index RNS preparation and invalidation",
            "maps/NTT plans/graph storage",
            "producer and admission scratch",
            "terminal codec and complete framing copies",
            "request and authorized release",
            "cache acquisition/update/prefetch contention",
        ],
        "unclosed_components": [
            "native allocator capacities and simultaneous stage peaks",
            "Python/crypto objects and parser/framing live copies",
            "NTT plan/graph container overhead",
            "deployed transport/attestation/private release",
        ],
        "RSS_policy": "process high-water RSS is not an exact native stage peak",
    }


def reference_statement(plan):
    """Reconstruct every static obligation from the fixed reference, not a peer graph."""
    if type(plan) is not TrustedPlan:
        raise ValueError("Trusted plan required")
    plan._validate()
    p, groups = plan.geometry, plan.groups
    fresh, switch, phases, product, output, terminal = support_bounds(p)
    expansion = []
    for level in range(p.levels):
        width = 1 << level
        expansion.append(
            {
                "level": level,
                "automorphism": 1 + p.n // width,
                "minus_monomial_exponent": -width,
                "branches": [[k, width - 1 + k, k, width + k] for k in range(width)],
            }
        )
    protected_work = (
        ["complete canonical-digit both-prime relation", "complete terminal equality"]
        if plan.mode == MODES[0]
        else [
            "genuine expansion",
            "all three tensor products",
            "canonical relinearization",
            "complete terminal codec",
        ]
    )
    if plan.mode == MODES[2]:
        protected_work += [
            "all three claim transforms and comparisons",
            "six forward-prime NTTs per group",
        ]
    return {
        "version": 1,
        "context": {
            "N": p.n,
            "dimension": p.dimension,
            "padded": p.padded,
            "t": p.t,
            "eta": p.eta,
            "Q": p.q,
            "P": p.p,
            "ordered_primes": list(p.primes),
            "count": plan.count,
            "groups": groups,
            **{
                name: getattr(plan, name).hex()
                for name in (
                    "key_id",
                    "ordered_ids_digest",
                    "snapshot_id",
                    "policy_digest",
                    "code_digest",
                )
            },
            "mode": plan.mode,
        },
        "origin": {
            "status": "honest owner premise, not proved by authentication",
            "index_origin": "owner",
            "policy": "canonical30",
            "query_encoding": "D^-1 times signed binary coefficients",
            "index_encoding": "group-major feature polynomials of signed binary rows",
            "unused_feature_and_record_plaintext": "zero",
            "secret_absolute_support": 1,
            "independent_error_absolute_support": p.eta,
            "sampler": "OS-backed centered binomial",
            "seed_basis": "fresh independent 32-byte domain-separated rejection-sampled seeds",
            "evaluation_key_targets": "s squared and the exact listed automorphisms",
        },
        "representation": {
            "lift": "unique canonical whole-Q integer",
            "minimum": 0,
            "exclusive_maximum": p.q,
            "word_bytes": COMMON_WIDTH,
            "radix_bits": RADIX_BITS,
            "digits": DIGITS,
            "digit_minimum": 0,
            "digit_exclusive_maximum": 1 << RADIX_BITS,
            "digit_lowering": "shared before both actual primes",
            "actual_prime_count": 2,
            "NTT": "complete invertible negacyclic vectors",
            "frequencies_per_prime": p.n,
            "expanded_query": "derived only from the original query",
            "CRT": "coprime complete actual basis",
        },
        "key_schedule": {
            "columns": DIGITS,
            "ciphertext_components": 2,
            "relinearization_keys": 1,
            "rotation_exponents": [1 + p.n // (1 << level) for level in range(p.levels)],
        },
        "expansion": {
            "original_query_pairs": 1,
            "levels": expansion,
            "final_feature_positions": list(range(p.padded)),
            "signed_branches": ["C plus rotated C", "X^-width times C minus rotated C"],
        },
        "contraction": {
            "terms": ["A=q0*i0", "C=q1*i1", "B=(q0+q1)*(i0+i1)-A-C"],
            "feature_group_coverage": [
                [group, feature, group * p.dimension + feature]
                for group in range(groups)
                for feature in range(p.dimension)
            ],
            "occupied_records": [min(p.n, plan.count - group * p.n) for group in range(groups)],
            "unused_record_plaintext_positions": groups * p.n - plan.count,
            "unused_feature_positions": p.padded - p.dimension,
            "C2_sources": [p.padded - 1 + group for group in range(groups)],
            "relinearizations": groups,
            "final_Q_polynomials": 2 * groups,
        },
        "phase": {
            "fresh": fresh,
            "switch": switch,
            "each_expansion_level": list(phases),
            "contracted": product,
            "output": output,
            "terminal": terminal,
            "full_guard": "twice every expansion/output support strictly below Q",
            "terminal_guard": "twice terminal support strictly below P",
        },
        "terminal": {
            "codec": "r=x mod t; k=floor((2*(P*x-Q*r)+Q*t)/(2*Q*t)); (k*t+r) mod P",
            "input_interval": "canonical [0,Q)",
            "components_per_group": 2,
            "coefficients_per_component": p.n,
            "coefficient_bits": p.p.bit_length(),
            "physical_padding": "zero",
            "unused_record_ciphertext": "may be nonzero; decrypted message must be zero",
            "frame": "complete canonical header and every component/coefficient/group",
            "score": "centered d-2*Hamming with complete parity and range checks",
            "tie_key": ["distance", "original row ordinal"],
            "IDs": "complete ordered labels",
        },
        "placement": {
            "mode": plan.mode,
            "protected_work": protected_work,
            "random_challenge": "none",
            "replay_source_witness": "none",
            "aggregate_arithmetic_savings": "none claimed",
            "code_selection": "trusted local selection, never producer-selected",
        },
        "authority": {
            "certificate": "public static plan, not a release capability",
            "owner_currentness": "separately trusted current owner pin",
            "response_predicate": "actual mode-specific complete runtime equality required",
            "binding": "original request plus snapshot/epoch/policy/nonce/frame/ordered IDs",
            "attempt": "trusted nonrollback consumption and at-most-once release required",
            "native_refinement": "explicit remaining premise, not proved by code digest",
            "attestation": "actual implementation and review remain Q78",
            "HE_secret_custody": "owner/client only",
            "CPU_signer": "CPU secret when deployed",
        },
        "resources": counted_resources(plan),
    }


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def make_certificate(plan):
    """Public declaration producer; the receiver must still check independently."""
    packet = _canonical(reference_statement(plan))
    if len(packet) > MAX_CERTIFICATE_BYTES:
        raise ValueError("Certificate exceeds the registered cap")
    return packet


def certificate_digest(packet):
    if type(packet) is not bytes or not 1 <= len(packet) <= MAX_CERTIFICATE_BYTES:
        raise ValueError("Wrong immutable bounded certificate")
    return hashlib.sha256(CERTIFICATE_DOMAIN + packet).digest()


def _pairs(pairs):
    if len(pairs) > 128:
        raise ValueError("Too many certificate fields")
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate certificate field")
        result[key] = value
    return result


def _integer(token):
    if len(token.lstrip("-")) > 64:
        raise ValueError("Overlong integer")
    return int(token)


def _forbidden(_token):
    raise ValueError("Noninteger numeric certificate token")


def _bounded_tree(value):
    if type(value) is dict:
        if len(value) > 128 or any(
            type(k) is not str or len(k) > 64 or not k.isascii() for k in value
        ):
            raise ValueError("Invalid field names")
        for child in value.values():
            _bounded_tree(child)
    elif type(value) is list:
        if len(value) > MAX_ARRAY_ITEMS:
            raise ValueError("Array exceeds fixed schedule cap")
        for child in value:
            _bounded_tree(child)
    elif type(value) is str:
        if not value.isascii() or len(value) > 256:
            raise ValueError("Invalid certificate string")
    elif type(value) is not int:
        raise ValueError("Certificate leaves must be exact integers or ASCII strings")


def _parse(packet):
    certificate_digest(packet)  # Check immutable bytes and cap before decoding.
    try:
        source = packet.decode("ascii")
        # Bound nesting before json's recursive parser. Brackets in quoted
        # strings have no structural meaning, including escaped quotes.
        depth, quoted, escaped = 0, False, False
        for char in source:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > MAX_NESTING:
                    raise ValueError("Certificate nesting exceeds cap")
            elif char in "]}":
                depth -= 1
                if depth < 0:
                    raise ValueError("Unbalanced certificate")
        value = json.loads(
            source,
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_forbidden,
            parse_constant=_forbidden,
        )
        _bounded_tree(value)
        if _canonical(value) != packet:
            raise ValueError("Noncanonical certificate bytes")
        return value
    except (UnicodeError, json.JSONDecodeError, TypeError, OverflowError, RecursionError) as error:
        raise ValueError("Malformed bounded certificate") from error


@dataclass(frozen=True)
class ValidatedPlan:
    """Public immutable metadata only; constructing it conveys no authority."""

    plan: TrustedPlan
    certificate: bytes
    digest: bytes
    terminal_support: int


def check_certificate(packet, trusted_plan, *, expected_digest=None):
    """Validate the full reference even when an old supplied digest matches."""
    value = _parse(packet)
    expected = reference_statement(trusted_plan)
    if value != expected:
        raise ValueError("Certificate violates the independently reconstructed reference")
    digest = certificate_digest(packet)
    if expected_digest is not None:
        _fixed(expected_digest, "certificate digest")
        if digest != expected_digest:
            raise ValueError("Wrong current certificate digest")
    return ValidatedPlan(trusted_plan, packet, digest, expected["phase"]["terminal"])
