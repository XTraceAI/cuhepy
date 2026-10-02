"""E97 homemade fixed-input stochastic rounding control, not a release protocol.

Trusted originals/reused keys precede fresh independent owner coins. No secret
posterior, uniform ciphertext or fresh old-key error law is assumed. Full public
recomputation is a diagnostic subrelation; it does not attest scores, honest
coin sampling/order, PBS, durable state or private implementation security.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import secrets
import threading

from experiments.bfv_search_lab import committed_precision_epoch as epoch
from experiments.bfv_search_lab import partial_packed_switch as switch


LAW = "owner-independent-uniform-body-and-mask-rounding-coins"


def digest(domain, value):
    return hashlib.sha256(domain + json.dumps(asdict(value), sort_keys=True,
                                             separators=(",", ":")).encode()).hexdigest()


def round_integer(value, q, target, coin):
    """Exact unbiased Bernoulli rounding; supports odd/even Q and noncoprime B."""
    if (any(type(x) is not int for x in (value, q, target, coin))
            or not 2 <= q < 1 << 64 or not 2 <= target <= 1 << 64
            or not 0 <= value < q or not 0 <= coin < q):
        raise ValueError("Canonical integer rounding input and independent coin required")
    quotient, remainder = divmod(target * value, q)
    return quotient + (coin < remainder)


def uniform_precision(q, prefix, kappa, events):
    if (type(q) is not int or not 2 <= q < 1 << 64
            or type(prefix) is not int or not 1 <= prefix <= 32768):
        raise ValueError("Invalid rounding modulus or fixed-target support")
    twice_proxy = (q*q*(prefix+1)+1)//2
    return twice_proxy, epoch.tail_threshold(twice_proxy, kappa, events)


@dataclass(frozen=True)
class OwnerKeys:
    target_key_id: str
    key_error_bound: int
    keys: switch.Keys


def keys_anchor(policy):
    if type(policy) is not OwnerKeys:
        raise ValueError("Owner-approved reused keys required")
    return digest(b"E97-reused-keys-v1\0", policy)


def approve(family, policy, view):
    epoch.validate_family(family)
    if (type(policy) is not OwnerKeys or type(policy.keys) is not switch.Keys
            or type(policy.target_key_id) is not str or not 1 <= len(policy.target_key_id) <= 64
            or type(policy.key_error_bound) is not int or not 0 <= policy.key_error_bound <= 64
            or policy.keys.q != family.q):
        raise ValueError("Wrong approved reused key/error context")
    parts = tuple(tuple(view.sign*x % family.q for x in poly)
                  for poly in family.sources[view.source])
    approved = switch.Approved(parts, policy.keys, family.source_prefix, view.target,
                               policy.key_error_bound, 1 << 200, False, "E97-approved-BGV-unit",
                               family.source_key_id, policy.target_key_id, family.epoch_id)
    switch.validate(approved)
    return approved


@dataclass(frozen=True)
class OwnerCoins:
    # Trusted public owner packet, not a server sampling/order proof.
    family_anchor: str
    keys_anchor: str
    coin_id: str
    law: str
    body: tuple[int, ...]
    mask: tuple[int, ...]


def validate_coins(family, policy, coins):
    n, count = epoch.validate_family(family)
    approve(family, policy, family.views[0])
    if (type(coins) is not OwnerCoins or type(coins.family_anchor) is not str
            or coins.family_anchor != epoch.family_anchor(family)
            or type(coins.keys_anchor) is not str or coins.keys_anchor != keys_anchor(policy)
            or type(coins.coin_id) is not str or len(coins.coin_id) != 32
            or any(c not in "0123456789abcdef" for c in coins.coin_id)
            or type(coins.law) is not str or coins.law != LAW):
        raise ValueError("Wrong original/owner coin binding or trusted law")
    for poly in (coins.body, coins.mask):
        switch._poly(poly, n, family.q)
    return n, count


class OwnerLedger:
    """Volatile reserve-before-generation and consume-before-callback control.

    Abandoned generations burn slots; no reset, durable rollback/fork or trusted
    clock claim. The reused key context is fixed for this ledger lifetime.
    """

    def __init__(self, policy, maximum):
        if type(maximum) is not int or not 1 <= maximum <= 1 << 32:
            raise ValueError("Invalid generated-coin lifetime")
        self.key_root, self.maximum = keys_anchor(policy), maximum
        self._issued, self._lock = {}, threading.Lock()

    def reserve(self, family, policy, coin_id):
        epoch.validate_family(family)
        approve(family, policy, family.views[0])
        if (type(coin_id) is not bytes or len(coin_id) != 16
                or keys_anchor(policy) != self.key_root):
            raise ValueError("Wrong coin ID or fixed reused keys")
        binding = epoch.family_anchor(family)
        with self._lock:
            if coin_id.hex() in self._issued:
                raise RuntimeError("Coin packet already reserved")
            if len(self._issued) >= self.maximum:
                raise RuntimeError("Generated-coin lifetime exhausted")
            self._issued[coin_id.hex()] = (binding, None, False)

    def bind(self, family, policy, coins):
        """Bind the exact trusted packet once, after reservation/sampling."""
        validate_coins(family, policy, coins)
        with self._lock:
            if (coins.keys_anchor != self.key_root
                    or self._issued.get(coins.coin_id) != (coins.family_anchor, None, False)):
                raise RuntimeError("Wrong or already bound coin reservation")
            self._issued[coins.coin_id] = (coins.family_anchor, coins_anchor(coins), False)

    def consume(self, coins):
        with self._lock:
            if (coins.keys_anchor != self.key_root
                    or self._issued.get(coins.coin_id) != (coins.family_anchor, coins_anchor(coins), False)):
                raise RuntimeError("Wrong-family, unreserved or consumed coin packet")
            self._issued[coins.coin_id] = (coins.family_anchor, coins_anchor(coins), True)


def generate_owner_coins(family, policy, ledger, coin_id):
    """No owner secret/product: independent OS rejection sampling in ideal model."""
    n, _ = epoch.validate_family(family)
    approve(family, policy, family.views[0])
    if type(ledger) is not OwnerLedger:
        raise ValueError("Owner reservation context required")
    ledger.reserve(family, policy, coin_id)
    body = tuple(secrets.randbelow(family.q) for _ in range(n))
    mask = tuple(secrets.randbelow(family.q) for _ in range(n))
    coins = OwnerCoins(epoch.family_anchor(family), keys_anchor(policy), coin_id.hex(), LAW, body, mask)
    ledger.bind(family, policy, coins)
    return coins


def signed_coins(coins, sign, q):
    # Complement each independent coordinate for exact negation coupling.
    return tuple(tuple(u if sign == 1 else q-1-u for u in poly)
                 for poly in (coins.body, coins.mask))


@dataclass(frozen=True)
class Event:
    coefficient: int
    active_terms: int
    variance: int
    maximum_error: int
    twice_proxy: int
    uniform_bound: int
    active_hoeffding_bound: int
    bernstein_bound: int
    statistical_bound: int
    deterministic_bound: int
    old_key_error_bound: int
    source_residual_bound: int
    total_bound: int
    sufficient: bool


@dataclass(frozen=True)
class ViewCertificate:
    switched: tuple[tuple[int, ...], ...]
    rounded: tuple[tuple[int, ...], ...]
    events: tuple[Event, ...]


@dataclass(frozen=True)
class Certificate:
    family_anchor: str
    keys_anchor: str
    coins_anchor: str
    whole_family_events: int
    views: tuple[ViewCertificate, ...]


def coins_anchor(coins):
    return digest(b"E97-owner-rounding-coins-v1\0", coins)


def build(family, policy, coins):
    n, count = validate_coins(family, policy, coins)
    result = []
    for view in family.views:
        approved = approve(family, policy, view)
        output, residual, old_error = switch.switch(approved)
        used = signed_coins(coins, view.sign, family.q)
        raw = tuple(tuple(round_integer(x, family.q, view.target, u)
                          for x, u in zip(poly, us, strict=True))
                    for poly, us in zip(output, used, strict=True))
        drift = tuple(tuple(family.q*r-view.target*x for r, x in zip(rs, xs, strict=True))
                      for rs, xs in zip(raw, output, strict=True))
        remainders = tuple(tuple(view.target*x % family.q for x in poly) for poly in output)
        residual_bound = switch.quadratic_box(residual, family.source_prefix)
        prefix = policy.keys.target_prefix
        uniform = uniform_precision(family.q, prefix, family.kappa, count)[1]
        confidence = family.kappa + (2*count-1).bit_length()
        events = []
        for coefficient in view.coefficients:
            # Remainders/thresholds depend ONLY on the fixed original switch.
            terms = (remainders[0][coefficient],
                     *(remainders[1][(coefficient-i) % n] for i in range(prefix)))
            active = sum(bool(r) for r in terms)
            variance = sum(r*(family.q-r) for r in terms)
            maximum = max(max(r, family.q-r) if r else 0 for r in terms)
            proxy = (family.q**2*active+1)//2
            hoeffding = epoch.tail_threshold(proxy, family.kappa, count)
            bernstein = epoch.ceil_sqrt(2*variance*confidence) + (2*maximum*confidence+2)//3
            statistical = min(hoeffding, bernstein)
            weights = epoch.row_weights(drift[1], coefficient, prefix)
            deterministic = abs(drift[0][coefficient]) + sum(map(abs, weights))
            total = min(statistical, deterministic) + view.target*(old_error+residual_bound)
            events.append(Event(coefficient, active, variance, maximum, proxy, uniform, hoeffding,
                                bernstein, statistical, deterministic, old_error, residual_bound,
                                total, total < epoch.budget(family, view)))
        result.append(ViewCertificate(output, tuple(tuple(x % view.target for x in poly) for poly in raw),
                                      tuple(events)))
    return Certificate(epoch.family_anchor(family), keys_anchor(policy), coins_anchor(coins), count, tuple(result))


def verify_and_consume(family, policy, coins, certificate, selected, ledger, callback):
    """Complete public subrelation then one opaque callback, no decrypt gate."""
    n, _ = validate_coins(family, policy, coins)
    if (type(certificate) is not Certificate or type(certificate.whole_family_events) is not int
            or any(type(x) is not str for x in
                   (certificate.family_anchor, certificate.keys_anchor, certificate.coins_anchor))
            or type(certificate.views) is not tuple or len(certificate.views) != len(family.views)):
        raise ValueError("Malformed whole original/coin rounding relation")
    for view, cert in zip(family.views, certificate.views, strict=True):
        if (type(cert) is not ViewCertificate or type(cert.events) is not tuple
                or len(cert.events) != len(view.coefficients)):
            raise ValueError("Missing prescribed view/precision event")
        for arrays, modulus in ((cert.switched, family.q), (cert.rounded, view.target)):
            if type(arrays) is not tuple or len(arrays) != 2:
                raise ValueError("Wrong public component count")
            for poly in arrays:
                switch._poly(poly, n, modulus)
        for event in cert.events:
            if (type(event) is not Event or type(event.sufficient) is not bool
                    or any(type(getattr(event, field)) is not int
                           or not 0 <= getattr(event, field) < 1 << 256
                           for field in event.__dataclass_fields__ if field != "sufficient")):
                raise ValueError("Noncanonical exact precision witness")
    if certificate != build(family, policy, coins):
        raise ValueError("Wrong originals, reused keys, coins, arithmetic or budget")
    if (type(selected) is not tuple or not selected
            or any(type(i) is not int or not 0 <= i < len(family.views) for i in selected)
            or len(set(selected)) != len(selected)
            or not all(event.sufficient for i in selected for event in certificate.views[i].events)):
        raise ValueError("Unapproved or insufficient selected views")
    if type(ledger) is not OwnerLedger:
        raise ValueError("Owner reservation context required")
    ledger.consume(coins)
    return callback(tuple(certificate.views[i] for i in selected))
