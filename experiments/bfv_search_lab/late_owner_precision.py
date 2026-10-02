"""E95 fixed-key late-entropy arithmetic control; NOT a release protocol.

Originals and approved reused keys precede each honest true-uniform owner zero.
No target-secret posterior distribution is assumed. Full public recomputation
does not attest original scores, sampling/order, PBS or private implementation.
Private generation is a small reference, not constant-time production crypto.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import secrets
import threading

from experiments.bfv_search_lab import committed_precision_epoch as epoch
from experiments.bfv_search_lab import partial_packed_switch as switch


LAW = "late-owner-true-uniform-mask-independent-CBD-error"


def digest(domain, value):
    return hashlib.sha256(domain + json.dumps(asdict(value), sort_keys=True,
                                             separators=(",", ":")).encode()).hexdigest()


def rounding_error(value, q, target):
    """Odd-Q/dyadic-B integer residue; exactly centered and without half ties."""
    if (any(type(x) is not int for x in (value, q, target))
            or not 3 <= q < 1 << 64 or q % 2 != 1 or not 0 <= value < q
            or not 2 <= target <= 1 << 64 or target & (target - 1)):
        raise ValueError("Expected a canonical odd-Q/dyadic rounding context")
    return q * switch.round_integer(value, q, target) - target * value


def precision(q, target, prefix, eta, kappa, events):
    rounding_error(0, q, target)
    if (type(prefix) is not int or not 1 <= prefix <= 32768
            or type(eta) is not int or not 1 <= eta <= 64):
        raise ValueError("Invalid fixed-target support or fresh zero error")
    half = q // 2
    proxy = 2 * half**2 * prefix + eta * target**2
    return proxy, epoch.tail_threshold(proxy, kappa, events), half * prefix + target * eta


@dataclass(frozen=True)
class OwnerKeys:
    target_key_id: str
    key_error_bound: int
    zero_error_eta: int
    keys: switch.Keys


@dataclass(frozen=True)
class OwnerZero:
    # Trusted owner input, not a server-supplied sampling or generation proof.
    family_anchor: str
    keys_anchor: str
    zero_id: str
    law: str
    body: tuple[int, ...]
    mask: tuple[int, ...]


def keys_anchor(policy):
    if type(policy) is not OwnerKeys:
        raise ValueError("Owner-approved reused keys required")
    return digest(b"E95-reused-keys-v1\0", policy)


def approve(family, policy, view):
    epoch.validate_family(family)
    if (type(policy) is not OwnerKeys or type(policy.keys) is not switch.Keys
            or type(policy.target_key_id) is not str
            or not 1 <= len(policy.target_key_id) <= 64
            or type(policy.key_error_bound) is not int or not 0 <= policy.key_error_bound <= 64
            or type(policy.zero_error_eta) is not int or not 1 <= policy.zero_error_eta <= 64
            or policy.keys.q != family.q):
        raise ValueError("Wrong approved key support/error context")
    parts = tuple(tuple(view.sign * x % family.q for x in poly)
                  for poly in family.sources[view.source])
    approved = switch.Approved(parts, policy.keys, family.source_prefix, view.target,
                               policy.key_error_bound, 1 << 200, False, "E95-approved-BGV-unit",
                               family.source_key_id, policy.target_key_id, family.epoch_id)
    switch.validate(approved)
    return approved


def validate_zero(family, policy, zero):
    n, count = epoch.validate_family(family)
    approve(family, policy, family.views[0])
    if (type(zero) is not OwnerZero or type(zero.family_anchor) is not str
            or zero.family_anchor != epoch.family_anchor(family)
            or type(zero.keys_anchor) is not str or zero.keys_anchor != keys_anchor(policy)
            or type(zero.zero_id) is not str or len(zero.zero_id) != 32
            or any(c not in "0123456789abcdef" for c in zero.zero_id)
            or type(zero.law) is not str or zero.law != LAW):
        raise ValueError("Wrong owner zero binding, ID or trusted law")
    for poly in (zero.body, zero.mask):
        switch._poly(poly, n, family.q)
    return n, count


class OwnerLedger:
    """Volatile owner reservation/consume guard, not durable provenance.

    Reserve BEFORE private sampling. Abandoned/rejected generated zeros burn
    their slot. One accepted callback per zero; no reset/rollback/fork promise.
    The approved key context is fixed across the whole ledger lifetime.
    """

    def __init__(self, policy, maximum):
        if type(maximum) is not int or not 1 <= maximum <= 1 << 32:
            raise ValueError("Invalid generated-zero lifetime")
        self.key_root, self.maximum = keys_anchor(policy), maximum
        self._issued, self._lock = {}, threading.Lock()

    def reserve(self, family, policy, zero_id):
        epoch.validate_family(family)
        approve(family, policy, family.views[0])
        if (type(zero_id) is not bytes or len(zero_id) != 16
                or keys_anchor(policy) != self.key_root):
            raise ValueError("Wrong canonical zero ID or reused keys")
        binding = epoch.family_anchor(family)
        with self._lock:
            if zero_id.hex() in self._issued:
                raise RuntimeError("Zero already reserved; replay is not fresh")
            if len(self._issued) >= self.maximum:
                raise RuntimeError("Generated-zero lifetime exhausted")
            self._issued[zero_id.hex()] = (binding, False)

    def consume(self, zero):
        with self._lock:
            value = self._issued.get(zero.zero_id)
            if zero.keys_anchor != self.key_root or value != (zero.family_anchor, False):
                raise RuntimeError("Unreserved, wrong-family or already consumed zero")
            self._issued[zero.zero_id] = (zero.family_anchor, True)


def generate_owner_zero(family, policy, ledger, zero_id, target_secret):
    """Owner-only small GMP/reference generation; never publish the error.

    Approved support is a public cap, not an IID secret-law claim. secrets
    rejection-samples each independent uniform coefficient from ideal OS coins.
    No SHAKE seed, public zero pool, quality rejection or server coins are used.
    """
    n, _ = epoch.validate_family(family)
    approve(family, policy, family.views[0])
    if (type(target_secret) is not tuple or len(target_secret) != n
            or any(type(x) is not int or abs(x) > 1 for x in target_secret)
            or any(target_secret[policy.keys.target_prefix:]) or type(ledger) is not OwnerLedger):
        raise ValueError("Invalid private target support or owner ledger")
    ledger.reserve(family, policy, zero_id)
    mask = tuple(secrets.randbelow(family.q) for _ in range(n))
    eta = policy.zero_error_eta
    error = tuple(secrets.randbits(eta).bit_count() - secrets.randbits(eta).bit_count()
                  for _ in range(n))
    product = switch.ring_product(mask, target_secret)
    body = tuple((e - v) % family.q for e, v in zip(error, product, strict=True))
    return OwnerZero(epoch.family_anchor(family), keys_anchor(policy), zero_id.hex(), LAW, body, mask)


@dataclass(frozen=True)
class Event:
    coefficient: int
    twice_proxy: int
    statistical_bound: int
    deterministic_bound: int
    body_bound: int
    old_key_error_bound: int
    source_residual_bound: int
    total_bound: int
    sufficient: bool


@dataclass(frozen=True)
class ViewCertificate:
    switched: tuple[tuple[int, ...], ...]
    added: tuple[tuple[int, ...], ...]
    rounded: tuple[tuple[int, ...], ...]
    events: tuple[Event, ...]


@dataclass(frozen=True)
class Certificate:
    family_anchor: str
    keys_anchor: str
    zero_anchor: str
    whole_family_events: int
    views: tuple[ViewCertificate, ...]


def zero_anchor(zero):
    return digest(b"E95-owner-zero-v1\0", zero)


def build(family, policy, zero):
    _, count = validate_zero(family, policy, zero)
    result = []
    for view in family.views:
        approved = approve(family, policy, view)
        output, residual, key_error = switch.switch(approved)
        added = tuple(tuple((x + y) % family.q for x, y in zip(poly, fresh, strict=True))
                      for poly, fresh in zip(output, (zero.body, zero.mask), strict=True))
        raw = tuple(tuple(switch.round_integer(x, family.q, view.target) for x in poly)
                    for poly in added)
        drift = tuple(tuple(rounding_error(x, family.q, view.target) for x in poly) for poly in added)
        residual_bound = switch.quadratic_box(residual, family.source_prefix)
        proxy, statistical, _ = precision(family.q, view.target, policy.keys.target_prefix,
                                         policy.zero_error_eta, family.kappa, count)
        events = []
        for coefficient in view.coefficients:
            # This actual public support cap is also valid for every fixed T.
            weights = epoch.row_weights(drift[1], coefficient, policy.keys.target_prefix)
            deterministic = sum(map(abs, weights)) + view.target * policy.zero_error_eta
            body = abs(drift[0][coefficient])
            total = body + min(statistical, deterministic) + view.target * (key_error + residual_bound)
            events.append(Event(coefficient, proxy, statistical, deterministic, body,
                                key_error, residual_bound, total, total < epoch.budget(family, view)))
        result.append(ViewCertificate(output, added, tuple(tuple(x % view.target for x in poly) for poly in raw),
                                      tuple(events)))
    return Certificate(epoch.family_anchor(family), keys_anchor(policy), zero_anchor(zero), count, tuple(result))


def verify_and_consume(family, policy, zero, certificate, selected, ledger, callback):
    """Full public work then one opaque callback; no decryption authorization."""
    n, _ = validate_zero(family, policy, zero)
    if (type(certificate) is not Certificate or type(certificate.whole_family_events) is not int
            or any(type(x) is not str for x in
                   (certificate.family_anchor, certificate.keys_anchor, certificate.zero_anchor))
            or type(certificate.views) is not tuple or len(certificate.views) != len(family.views)):
        raise ValueError("Malformed whole original-plus-zero relation")
    for view, cert in zip(family.views, certificate.views, strict=True):
        if (type(cert) is not ViewCertificate or type(cert.events) is not tuple
                or len(cert.events) != len(view.coefficients)):
            raise ValueError("Missing prescribed view/precision event")
        for arrays, modulus in ((cert.switched, family.q), (cert.added, family.q), (cert.rounded, view.target)):
            if type(arrays) is not tuple or len(arrays) != 2:
                raise ValueError("Wrong output component count")
            for poly in arrays:
                switch._poly(poly, n, modulus)
        for event in cert.events:
            if (type(event) is not Event or type(event.sufficient) is not bool
                    or any(type(x) is not int or not 0 <= x < 1 << 256 for x in
                           (event.coefficient, event.twice_proxy, event.statistical_bound,
                            event.deterministic_bound, event.body_bound, event.old_key_error_bound,
                            event.source_residual_bound, event.total_bound))):
                raise ValueError("Noncanonical exact precision witness")
    if certificate != build(family, policy, zero):
        raise ValueError("Wrong originals, reused keys, owner zero, arithmetic or budget")
    if (type(selected) is not tuple or not selected or len(set(selected)) != len(selected)
            or any(type(i) is not int or not 0 <= i < len(family.views) for i in selected)
            or not all(event.sufficient for i in selected for event in certificate.views[i].events)):
        raise ValueError("Unapproved or insufficient selected views")
    if type(ledger) is not OwnerLedger:
        raise ValueError("Owner reservation context required")
    ledger.consume(zero)  # Burn before the callback, including callback failure.
    return callback(tuple(certificate.views[i] for i in selected))
