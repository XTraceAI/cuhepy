"""E93 bounded integer fresh-epoch precision controls, not a release protocol.

Trusted prerequisites: source family fixed before fresh independent IID target
ternary and switching-mask/centered-binomial coins; original score authenticity;
valid source bounds and correct owner key generation. Hashes do not prove these
facts. This verifier repeats all public switching work. The callback is opaque,
not an authorization to decrypt. Post-PBS/key-body-derived masks are excluded.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from fractions import Fraction
import hashlib
import json
from math import gcd, isqrt

from experiments.bfv_search_lab import partial_packed_switch as switch


TERNARY_CBD = "independent-uniform-ternary-and-centered-binomial"


def ceil_sqrt(value):
    if type(value) is not int or value < 0:
        raise ValueError("Expected a nonnegative integer square")
    root = isqrt(value)
    return root + (root * root < value)


def tail_threshold(twice_proxy, kappa, events):
    """Known MGF + union bound; exact integer and conservative ln(2)<=1."""
    if (type(twice_proxy) is not int or not 0 <= twice_proxy < 1 << 256
            or type(kappa) is not int or not 1 <= kappa <= 256
            or type(events) is not int or not 1 <= events < 1 << 64):
        raise ValueError("Invalid whole-family tail context")
    ceiling_log_two_events = (2 * events - 1).bit_length()
    return ceil_sqrt(twice_proxy * (kappa + ceiling_log_two_events))


def row_weights(poly, coefficient, prefix):
    """Signed convolution coefficients of the SAME reused secret/error vector."""
    n = len(poly)
    if (type(coefficient) is not int or not 0 <= coefficient < n
            or type(prefix) is not int or not 1 <= prefix <= n):
        raise ValueError("Invalid coefficient or supported prefix")
    return tuple(poly[(coefficient - i) % n] * (1 if i <= coefficient else -1)
                 for i in range(prefix))


def aggregate_weights(terms):
    """Sum weights per coin ID before squaring; duplicated errors are not fresh."""
    result = Counter()
    for coin, coefficient in terms:
        result[coin] += coefficient
    return tuple(sorted((coin, value) for coin, value in result.items() if value))


@dataclass(frozen=True)
class View:
    source: int
    sign: int
    target: int
    coefficients: tuple[int, ...]
    domain: str


@dataclass(frozen=True)
class Family:
    # Components are already converted by the approved public BGV unit.
    q: int
    t: int
    source_prefix: int
    source_phase_bound: int
    source_key_id: str
    original_query_root: str
    original_index_root: str
    epoch_id: str
    kappa: int
    sources: tuple[tuple[tuple[int, ...], ...], ...]
    views: tuple[View, ...]


@dataclass(frozen=True)
class OwnerApprovedEpoch:
    # This object is trusted owner input. Its strings are binding labels, NOT
    # evidence that sampling/provenance/order was honest or attested.
    family_anchor: str
    target_key_id: str
    error_eta: int
    law: str
    keys: switch.Keys


def validate_family(family):
    if (type(family) is not Family or type(family.q) is not int
            or not 3 <= family.q < 1 << 64 or family.q % 2 != 1
            or type(family.t) is not int or not 3 <= family.t < family.q
            or family.t % 2 != 1 or gcd(family.t, family.q) != 1
            or type(family.source_phase_bound) is not int
            or family.source_phase_bound < 0 or 2 * family.source_phase_bound >= family.q
            or type(family.kappa) is not int or not 1 <= family.kappa <= 256
            or type(family.sources) is not tuple or not 1 <= len(family.sources) <= 32):
        raise ValueError("Invalid bounded original family")
    n = len(family.sources[0][0]) if (type(family.sources[0]) is tuple and family.sources[0]
                                   and type(family.sources[0][0]) is tuple) else 0
    if (not 2 <= n <= 16 or n & (n - 1) or type(family.source_prefix) is not int
            or not 1 <= family.source_prefix <= n
            or any(type(parts) is not tuple or len(parts) != 3
                   or any(type(poly) is not tuple or len(poly) != n
                          or any(type(x) is not int or not 0 <= x < family.q for x in poly)
                          for poly in parts) for parts in family.sources)):
        raise ValueError("Missing or noncanonical original components/prefix")
    for label in (family.source_key_id, family.original_query_root, family.original_index_root, family.epoch_id):
        if type(label) is not str or not 1 <= len(label) <= 64:
            raise ValueError("Missing original source binding")
    if type(family.views) is not tuple or not 1 <= len(family.views) <= 64:
        raise ValueError("Missing prescribed views")
    for view in family.views:
        if (type(view) is not View or type(view.source) is not int
                or not 0 <= view.source < len(family.sources)
                or type(view.sign) is not int or view.sign not in (-1, 1)
                or type(view.target) is not int or not 4 <= view.target <= 1 << 64
                or view.target & (view.target - 1)
                or type(view.domain) is not str or view.domain not in ("nearest", "odd_lut")
                or type(view.coefficients) is not tuple or not view.coefficients
                or any(type(i) is not int or not 0 <= i < n for i in view.coefficients)
                or len(set(view.coefficients)) != len(view.coefficients)):
            raise ValueError("Unapproved sign, stage, domain or coefficient view")
    return n, sum(len(view.coefficients) for view in family.views)


def family_anchor(family):
    validate_family(family)
    body = json.dumps(asdict(family), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(b"E93-precommitted-source-family-v1\0" + body).hexdigest()


def approve_view(family, epoch, view):
    # switch.validate checks every key row and both source/target support sizes.
    n, _ = validate_family(family)
    if (type(epoch) is not OwnerApprovedEpoch or epoch.family_anchor != family_anchor(family)
            or type(epoch.target_key_id) is not str or not 1 <= len(epoch.target_key_id) <= 64
            or type(epoch.error_eta) is not int or not 1 <= epoch.error_eta <= 64
            or epoch.law != TERNARY_CBD or type(epoch.keys) is not switch.Keys
            or epoch.keys.q != family.q):
        raise ValueError("Wrong trusted owner epoch, law or context")
    components = tuple(tuple(view.sign * x % family.q for x in poly)
                       for poly in family.sources[view.source])
    approved = switch.Approved(components, epoch.keys, family.source_prefix, view.target,
                               epoch.error_eta, 1 << 200, False, "E93-approved-BGV-unit",
                               family.source_key_id, epoch.target_key_id, family.epoch_id)
    assert switch.validate(approved)[0] == n
    return approved


def budget(family, view):
    if view.domain == "nearest":
        return Fraction(view.target * (family.q - 2 * family.source_phase_bound), 2 * family.t)
    # Finite signed odd-domain LUT, including the half-position center rounding
    # allowance. This is stricter than the ideal 1/(4t) source-only ledger.
    degree = view.target // 2
    allowed_error = (degree // family.t - 1) // 2
    return family.q * Fraction(2 * allowed_error - 1, 2) - Fraction(
        view.target * family.source_phase_bound, family.t)


@dataclass(frozen=True)
class Event:
    coefficient: int
    twice_proxy: int
    statistical_bound: int
    deterministic_bound: int
    body_bound: int
    source_residual_bound: int
    total_bound: int
    sufficient: bool


@dataclass(frozen=True)
class ViewCertificate:
    output: tuple[tuple[int, ...], ...]
    rounded: tuple[tuple[int, ...], ...]
    events: tuple[Event, ...]


@dataclass(frozen=True)
class Certificate:
    family_anchor: str
    epoch_anchor: str
    whole_family_events: int
    views: tuple[ViewCertificate, ...]


def epoch_anchor(epoch):
    body = json.dumps(asdict(epoch), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(b"E93-owner-approved-key-context-v1\0" + body).hexdigest()


def build(family, epoch):
    _, count = validate_family(family)
    certificates = []
    for view in family.views:
        approved = approve_view(family, epoch, view)
        output, residual, _ = switch.switch(approved)
        all_digits, _ = switch.decomposition(approved)
        retained = (*all_digits[0], *all_digits[1][epoch.keys.skipped_c2_levels:])
        error_squares = sum(x * x for poly in retained for x in poly)
        error_l1 = sum(abs(x) for poly in retained for x in poly)
        raw = tuple(tuple(switch.round_integer(x, family.q, view.target) for x in poly)
                    for poly in output)
        drift = tuple(tuple(family.q * r - view.target * x for r, x in zip(poly, source, strict=True))
                      for poly, source in zip(raw, output, strict=True))
        # Source residual is dependent on original S. No fresh-secret argument
        # is used for it. This deterministic all-S box is deliberately explicit.
        residual_bound = switch.quadratic_box(residual, family.source_prefix)
        events = []
        for coefficient in view.coefficients:
            weights = row_weights(drift[1], coefficient, epoch.keys.target_prefix)
            twice_proxy = 2 * sum(x * x for x in weights) + epoch.error_eta * view.target**2 * error_squares
            statistical = tail_threshold(twice_proxy, family.kappa, count)
            deterministic = sum(map(abs, weights)) + view.target * epoch.error_eta * error_l1
            body = abs(drift[0][coefficient])
            assert body <= family.q // 2
            total = body + min(statistical, deterministic) + view.target * residual_bound
            events.append(Event(coefficient, twice_proxy, statistical, deterministic, body,
                                residual_bound, total, total < budget(family, view)))
        certificates.append(ViewCertificate(output, tuple(tuple(x % view.target for x in poly) for poly in raw),
                                            tuple(events)))
    return Certificate(family_anchor(family), epoch_anchor(epoch), count, tuple(certificates))


def verify_and_release(family, epoch, certificate, selected, callback):
    """Complete public recomputation only; not upstream proof/key-law assurance."""
    n, _ = validate_family(family)
    if (type(certificate) is not Certificate or type(certificate.whole_family_events) is not int
            or type(certificate.family_anchor) is not str or type(certificate.epoch_anchor) is not str
            or type(certificate.views) is not tuple or len(certificate.views) != len(family.views)):
        raise ValueError("Malformed whole-family certificate")
    for view, cert in zip(family.views, certificate.views, strict=True):
        if (type(cert) is not ViewCertificate or type(cert.events) is not tuple
                or len(cert.events) != len(view.coefficients)):
            raise ValueError("Missing view or coefficient event")
        for arrays in (cert.output, cert.rounded):
            if (type(arrays) is not tuple or len(arrays) != 2
                    or any(type(poly) is not tuple or len(poly) != n
                           or any(type(x) is not int or not 0 <= x < 1 << 64 for x in poly)
                           for poly in arrays)):
                raise ValueError("Noncanonical public switched output")
        for event in cert.events:
            if (type(event) is not Event or type(event.sufficient) is not bool
                    or any(type(x) is not int or not 0 <= x < 1 << 256 for x in
                           (event.coefficient, event.twice_proxy, event.statistical_bound,
                            event.deterministic_bound, event.body_bound, event.source_residual_bound,
                            event.total_bound))):
                raise ValueError("Noncanonical exact coefficient budget")
    if certificate != build(family, epoch):
        raise ValueError("Wrong original family, epoch, switch or full precision bound")
    if (type(selected) is not tuple or not selected
            or any(type(i) is not int or not 0 <= i < len(family.views) for i in selected)
            or len(set(selected)) != len(selected)):
        raise ValueError("Unapproved or duplicated selected views")
    if any(not e.sufficient for i in selected for e in certificate.views[i].events):
        raise ValueError("Selected finite-domain source/noise budget is insufficient")
    return callback(tuple(certificate.views[i] for i in selected))


def exact_distribution(weights, *, law="ternary", eta=1):
    """Exact rational-tail numerator counts, no Gaussian/Monte Carlo estimate."""
    if (type(weights) is not tuple or any(type(x) is not int for x in weights)
            or law not in ("ternary", "centered_binomial")
            or type(eta) is not int or not 1 <= eta <= 64):
        raise ValueError("Invalid finite distribution context")
    atoms, denominator = ((-1, 1), (0, 1), (1, 1)), 3
    if law == "centered_binomial":
        # eta differences of two Bernoulli(1/2) bits.
        base = Counter({0: 1})
        for _ in range(eta):
            new = Counter()
            for old, count in base.items():
                for value, multiplicity in ((-1, 1), (0, 2), (1, 1)):
                    new[old + value] += count * multiplicity
            base = new
        atoms, denominator = tuple(base.items()), 4**eta
    result = Counter({0: 1})
    for weight in weights:
        new = Counter()
        for old, count in result.items():
            for value, multiplicity in atoms:
                new[old + weight * value] += count * multiplicity
        result = new
    return result, denominator**len(weights)
