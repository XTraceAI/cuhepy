"""E92 bounded mixed-key/approximate switching control, not production HE.

GMP ring arithmetic is homemade E91 code. No secret/key-error witness is in
the certificate. Owner-approved honest key rows and original source binding
remain external premises; the opaque callback is not decryption permission.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json

from experiments.bfv_search_lab.batched_score_bridge import centered, context, digits
from experiments.bfv_search_lab.quadratic_drift import (
    Moment, linear_bound, moments, quadratic_box, ring_product,
)


def _poly(poly, n, q):
    if (type(poly) is not tuple or len(poly) != n
            or any(type(x) is not int or not 0 <= x < q for x in poly)):
        raise ValueError("Canonical bounded public polynomial required")


@dataclass(frozen=True)
class Keys:
    q: int
    radix: int
    target_prefix: int
    skipped_c2_levels: int
    # All C1 levels, followed by C2 levels starting at skipped_c2_levels.
    # Each row is (mask polynomial, plus-sign body polynomial).
    values: tuple[tuple[tuple[tuple[int, ...], tuple[int, ...]], ...], ...]


@dataclass(frozen=True)
class Approved:
    # Originals must already have the known BGV modular-unit conversion.
    components: tuple[tuple[int, ...], ...]
    keys: Keys
    source_prefix: int
    target: int
    key_error_coefficient_bound: int
    drift_budget_numerator: int
    require_zero_residual_mask: bool
    context_id: str
    source_key_id: str
    target_key_id: str
    epoch: str


def validate(approved):
    if type(approved) is not Approved or type(approved.keys) is not Keys:
        raise ValueError("Owner-approved exact public input and key rows required")
    keys = approved.keys
    levels = context(keys.q, keys.radix)
    if (type(approved.components) is not tuple or len(approved.components) != 3
            or type(approved.components[0]) is not tuple):
        raise ValueError("Direct source components under (1,S,S-squared) required")
    n = len(approved.components[0])
    if (not 2 <= n <= 16 or n & (n - 1)
            or type(approved.source_prefix) is not int or not 1 <= approved.source_prefix <= n
            or type(keys.target_prefix) is not int or not 1 <= keys.target_prefix <= n
            or type(keys.skipped_c2_levels) is not int or not 0 <= keys.skipped_c2_levels <= levels
            or type(approved.target) is not int or not 2 <= approved.target <= 1 << 64
            or approved.target & (approved.target - 1)
            or type(approved.key_error_coefficient_bound) is not int
            or not 0 <= approved.key_error_coefficient_bound <= 65536
            or type(approved.drift_budget_numerator) is not int
            or not 0 <= approved.drift_budget_numerator < 1 << 256
            or type(approved.require_zero_residual_mask) is not bool
            or any(type(x) is not str or not 1 <= len(x) <= 64 for x in
                   (approved.context_id, approved.source_key_id, approved.target_key_id, approved.epoch))
            or approved.source_key_id == approved.target_key_id):
        raise ValueError("Invalid source/target support, precision, keys or budget")
    for poly in approved.components:
        _poly(poly, n, keys.q)
    if type(keys.values) is not tuple or len(keys.values) != 2:
        raise ValueError("Both original S and derived S-squared key families required")
    for family, count in zip(keys.values, (levels, levels - keys.skipped_c2_levels), strict=True):
        if type(family) is not tuple or len(family) != count:
            raise ValueError("Missing or extra retained key level")
        for pair in family:
            if type(pair) is not tuple or len(pair) != 2:
                raise ValueError("Each approved row needs a mask and body")
            for poly in pair:
                _poly(poly, n, keys.q)
    return n, levels


def anchor(approved):
    validate(approved)
    body = json.dumps(asdict(approved), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(b"E92-mixed-source-target-subrelation-v1\0" + body).hexdigest()


def decomposition(approved):
    n, levels = validate(approved)
    q, radix = approved.keys.q, approved.keys.radix
    all_digits = tuple(tuple(digits(x, q, radix) for x in poly) for poly in approved.components[1:])
    polynomials = tuple(tuple(tuple(row[level] for row in family) for level in range(levels))
                        for family in all_digits)
    skip = approved.keys.skipped_c2_levels
    residual = tuple(sum(polynomials[1][level][i] * radix ** level for level in range(skip))
                     for i in range(n))
    return polynomials, residual


def switch(approved):
    """Same output as ordinary approximate switching; residual is a public trace."""
    n, _ = validate(approved)
    keys, output = approved.keys, [list(approved.components[0]), [0] * n]
    all_digits, residual = decomposition(approved)
    retained = (all_digits[0], all_digits[1][keys.skipped_c2_levels:])
    key_error_bound = 0
    for digit_family, key_family in zip(retained, keys.values, strict=True):
        for digit, (mask, body) in zip(digit_family, key_family, strict=True):
            key_error_bound += approved.key_error_coefficient_bound * sum(map(abs, digit))
            for index, poly in enumerate((body, mask)):
                product = ring_product(digit, poly)
                output[index] = [(x + y) % keys.q for x, y in zip(output[index], product, strict=True)]
    return tuple(tuple(poly) for poly in output), residual, key_error_bound


def round_integer(value, q, target):
    # Upward ties; odd q and dyadic target have no coefficient half tie.
    return (2 * target * value + q) // (2 * q)


@dataclass(frozen=True)
class Certificate:
    anchor: str
    output: tuple[tuple[int, ...], ...]
    residual: tuple[int, ...]
    rounded: tuple[tuple[int, ...], ...]
    drift: tuple[tuple[int, ...], ...]
    moments: tuple[Moment, ...]
    body_bound: int
    linear_bound: int
    residual_box_bound: int
    residual_moment_bound: int
    key_error_bound: int
    total_bound: int
    residual_mask_zero: bool


def build(approved):
    output, residual, error = switch(approved)
    q, target = approved.keys.q, approved.target
    raw = tuple(tuple(round_integer(x, q, target) for x in poly) for poly in output)
    drift = tuple(tuple(q * r - target * x for r, x in zip(poly, src, strict=True))
                  for poly, src in zip(raw, output, strict=True))
    traces = moments(residual)
    body, linear = max(map(abs, drift[0])), linear_bound(drift[1], approved.keys.target_prefix)
    box = quadratic_box(residual, approved.source_prefix)
    spectral = approved.source_prefix * min(m.root_upper for m in traces)
    total = body + linear + target * (min(box, spectral) + error)
    zero = all(round_integer(x, q, target) == 0 for x in residual)
    return Certificate(anchor(approved), output, residual,
                       tuple(tuple(x % target for x in poly) for poly in raw), drift, traces,
                       body, linear, box, spectral, error, total, zero)


def verify_and_release(approved, certificate, callback):
    """Paid full public recomputation; upstream/private release assurance is open."""
    n, _ = validate(approved)
    if (type(certificate) is not Certificate or type(certificate.anchor) is not str
            or certificate.anchor != anchor(approved)
            or type(certificate.residual_mask_zero) is not bool):
        raise ValueError("Wrong approved context or zero-mask framing")
    for arrays in (certificate.output, certificate.rounded, certificate.drift):
        if (type(arrays) is not tuple or len(arrays) != 2
                or any(type(poly) is not tuple or len(poly) != n
                       or any(type(x) is not int or abs(x) >= 1 << 128 for x in poly) for poly in arrays)):
            raise ValueError("Missing, extra or noncanonical output/drift")
    if (type(certificate.residual) is not tuple or len(certificate.residual) != n
            or any(type(x) is not int or abs(x) >= 1 << 64 for x in certificate.residual)
            or type(certificate.moments) is not tuple or len(certificate.moments) != 4):
        raise ValueError("Invalid public residual or moment framing")
    for moment, power in zip(certificate.moments, (1, 2, 4, 8), strict=True):
        if (type(moment) is not Moment or type(moment.power) is not int or moment.power != power
                or type(moment.polynomial) is not tuple or len(moment.polynomial) != n
                or any(type(x) is not int or abs(x) >= 1 << 2048 for x in moment.polynomial)
                or type(moment.trace) is not int or not 0 <= moment.trace < 1 << 2048
                or type(moment.root_upper) is not int or not 0 <= moment.root_upper < 1 << 256):
            raise ValueError("Noncanonical exact residual moment")
    if any(type(x) is not int or not 0 <= x < 1 << 256 for x in
           (certificate.body_bound, certificate.linear_bound, certificate.residual_box_bound,
            certificate.residual_moment_bound, certificate.key_error_bound, certificate.total_bound)):
        raise ValueError("Invalid public numerator bound")
    if certificate != build(approved):
        raise ValueError("False partial switch, residual, rounding, moment or bound")
    if approved.require_zero_residual_mask and not certificate.residual_mask_zero:
        raise ValueError("Proposed mixed route requires a zero rounded residual mask")
    if certificate.total_bound > approved.drift_budget_numerator:
        raise ValueError("Complete public drift bound exceeds approved budget")
    return callback(certificate)


def residual_bound(value, q, radix, skip):
    """Scalar exact carry control used by tests and deterministic count cards."""
    values = digits(value, q, radix)
    if type(skip) is not int or not 0 <= skip <= len(values):
        raise ValueError("Invalid omitted low-level count")
    low = sum(digit * radix ** i for i, digit in enumerate(values[:skip]))
    assert abs(low) <= (radix ** skip - 1) // 2
    assert low + sum(digit * radix ** i for i, digit in enumerate(values[skip:], start=skip)) == centered(value, q)
    return low
