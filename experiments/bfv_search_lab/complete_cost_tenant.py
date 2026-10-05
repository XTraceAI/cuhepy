"""Honest owner provisioning for the registered complete-cost cohort.

Keys are generated only by an explicit owner action, after the caller proves
clean-manager/telemetry readiness. Every crypto resource is consumed first in
the global fsynced ledger. Public recovery blobs and failed feature prefixes
are retained; private HE, signing and cache keys are never serialized here.

This is a research runner, not secure cross-device key provisioning, durable
currentness, attestation, private constant-time assurance or parameter approval.
The full study must validate its committed execution addendum before creating
this holder. Public integration tests replace all fresh crypto with stubs.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import secrets
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from experiments.bfv_search_lab import authenticated_cache as cache
from experiments.bfv_search_lab import complete_cost_cohort as cohort
from experiments.bfv_search_lab import complete_cost_coordinator as coordinator
from experiments.bfv_search_lab import complete_cost_owner as owner
from experiments.bfv_search_lab import complete_cost_trace as trace
from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab import seeded_bgv as seeded
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_bgv as shared
from experiments.bfv_search_lab import shared_query_certificate as cert
from experiments.bfv_search_lab import shared_query_client_context as context
from experiments.bfv_search_lab.shared_query_bounds import Profile

DOMAIN = b"cuhepy/Q77/honest-tenant/v1\0"


def _token(anchor, slot, label):
    """Opaque public namespace tokens; never a plaintext or secret-key hash."""
    return hashlib.sha256(DOMAIN + anchor + bytes([slot]) + label.encode()).digest()


def _public_polynomials(keys):
    switches = (keys.relin, *(switch for _, switch in keys.rotations))
    return tuple(tuple(map(int, poly)) for switch in switches for pair in switch for poly in pair)


@dataclass(frozen=True)
class OwnerView:
    """Retained public revision. All three HE modes refer to these same rows."""

    rows: tuple[int, ...]
    ids: tuple[int, ...]
    records: tuple[cohort.EnrollmentRecord, ...]
    descriptor: context.Delivery
    cache_delivery: cache.Delivery | cache.PatchDelivery

    def record(self, mode):
        if mode not in cert.MODES:
            raise ValueError("Fixed implemented mode required")
        return self.records[cert.MODES.index(mode)]


class TenantProvisioner(owner._Owned):
    """Two owner key slots and independent index/update attempts, without resume."""

    def __init__(self, root, ledger, *, geometry, guard, ready, byte_limit=8 << 30):
        if (
            type(ledger) is not cohort.ResourceLedger
            or type(geometry) is not cert.Geometry
            or not callable(guard)
            or not callable(ready)
        ):
            raise ValueError("Fixed global ledger, geometry and readiness/guard callbacks required")
        geometry._validate()
        self._initialize()
        self.root = Path(root).resolve()
        self.root.mkdir()
        self.archive = cohort.PublicArchive(self.root / "public", byte_limit=byte_limit)
        self.ledger, self.geometry, self.guard, self.ready = ledger, geometry, guard, ready
        self._slots, self._failed = set(), False
        self.tenants = []

    def create(self, slot, *, policy_builder):
        self._process()
        self._open()
        if self._failed or type(slot) is not int or slot not in (0, 1) or slot in self._slots:
            raise RuntimeError("Failed or consumed tenant slot")
        if not callable(policy_builder):
            raise ValueError("Trusted public policy builder required")
        self.guard()
        if self.ready() is not True:
            raise RuntimeError("Clean manager and active telemetry must precede owner keys")
        self._slots.add(slot)
        log = trace.EventLog(f"tenant-{slot}")
        try:
            with log.event("owner-signing-key"):
                self.ledger.take("owner_signing_keys", 1, label=f"tenant-{slot}-owner-key")
                signing = Ed25519PrivateKey.generate()
            anchor = signing.public_key().public_bytes_raw()
            with log.event("owner-cache-key"):
                self.ledger.take("cache_AES_keys", 1, label=f"tenant-{slot}-cache-key")
                cache_key = secrets.token_bytes(32)
            with log.event("owner-HE-key"):
                self.ledger.take("HE_keys", 1, label=f"tenant-{slot}-HE-key")
                g = self.geometry
                pk, sk = bgv.key_gen(g.n, g.t, 120, g.eta, rns_modulus=True)
                owner.public_fingerprint(pk, g)
            self.guard()
            with log.event("owner-evaluation-keys"):
                keys = shared.evaluation_keys(pk, sk, g.dimension)
            with log.event("retain-public-keys"):
                body = native.pack_common(_public_polynomials(keys), g.n, g.q)
                key_blob = self.archive.put(body, kind="evaluation-keys")
                public_body = native.pack_common(
                    (tuple(map(int, pk.a)), tuple(map(int, pk.b))), g.n, g.q
                )
                public_blob = self.archive.put(public_body, kind="public-key")
            policies, code_digest = policy_builder(anchor)
            if (
                type(policies) is not tuple
                or len(policies) != 3
                or any(type(x) is not bytes or len(x) != 32 for x in (*policies, code_digest))
            ):
                raise ValueError("All three pinned public mode policies/code required")
            tenant = HonestTenant(
                self,
                slot,
                signing,
                cache_key,
                pk,
                sk,
                key_blob,
                public_blob,
                policies,
                code_digest,
                log,
            )
            self.tenants.append(tenant)
            coordinator.write_once(self.root / f"tenant-{slot}.json", tenant.inventory())
            return tenant
        except BaseException:
            self._failed = True
            coordinator.write_once(
                self.root / f"tenant-{slot}-failed.json",
                {
                    "slot": slot,
                    "status": "failed-consumed",
                    "events": log.inventory(),
                    "private_keys_serialized": False,
                },
            )
            raise

    def inventory(self):
        self._process()
        return {
            "failed": self._failed,
            "consumed_slots": sorted(self._slots),
            "archive": self.archive.inventory(),
            "private_keys_serialized": False,
        }

    def close(self):
        self._process()
        if not self._closed:
            for tenant in self.tenants:
                tenant.close()
            self._closed = True


class HonestTenant(owner._Owned):
    """Owner-only retained secrets. Independent session holders use these keys."""

    def __init__(
        self,
        provisioner,
        slot,
        signing,
        cache_key,
        pk,
        sk,
        keys,
        public,
        policies,
        code_digest,
        log,
    ):
        self._initialize()
        self.provisioner, self.slot, self.log = provisioner, slot, log
        self._signing, self._cache_key, self._pk, self._sk = signing, cache_key, pk, sk
        self.keys, self.public, self.policies, self.code_digest = (
            keys,
            public,
            policies,
            code_digest,
        )
        self.anchor = signing.public_key().public_bytes_raw()
        self.namespace = _token(self.anchor, slot, "namespace")
        self.cache_key_id = _token(self.anchor, slot, "cache-key-identity")
        self._attempts, self._failed, self._initial = set(), False, {}
        self.groups = []

    def __repr__(self):
        return "HonestTenant(<owner private context>)"

    def _begin(self, label):
        self._process()
        self._open()
        trace._label(label)
        if self._failed or label in self._attempts:
            raise RuntimeError("Failed or consumed tenant operation")
        self._attempts.add(label)
        self.provisioner.guard()

    def _group(self, rows, label):
        """Append each real packet before the next attempt; keep failed prefixes."""
        p, g = self.provisioner, self.provisioner.geometry
        stage = p.root / f"tenant-{self.slot}-{label}.partial-group"
        packets, metrics = [], {"encrypt_wall_ns": 0, "encrypt_cpu_ns": 0, "features": 0}
        with self.log.event(label):
            with stage.open("xb") as stream:
                stream.write(cohort._array_header(g.dimension))
                stream.flush()
                os.fsync(stream.fileno())
                for feature in range(g.dimension):
                    p.guard()
                    p.ledger.take(
                        "feature_encryptions", 1, label=f"t{self.slot}-{label}-f{feature}"
                    )
                    message = [1 - 2 * ((word >> feature) & 1) for word in rows]
                    message.extend([0] * (g.n - len(rows)))
                    start, cpu = time.perf_counter_ns(), time.thread_time_ns()
                    packet = seeded.encrypt(message, self._pk, self._sk)
                    metrics["encrypt_wall_ns"] += time.perf_counter_ns() - start
                    metrics["encrypt_cpu_ns"] += time.thread_time_ns() - cpu
                    # Archive group validation also bounds the canonical bin header.
                    if type(packet) is not bytes or not 1 <= len(packet) <= g.n * 15 + 256:
                        raise ValueError("Complete bounded freshly encrypted packet required")
                    stream.write(cohort._bin_header(len(packet)) + packet)
                    stream.flush()
                    os.fsync(stream.fileno())
                    packets.append(packet)
                    metrics["features"] += 1
            p.guard()
            reference = p.archive.put_group(tuple(packets), n=g.n, dimension=g.dimension)
            digest, size = hashlib.sha256(), 0
            with stage.open("rb") as stream:
                for chunk in iter(lambda: stream.read(cohort.BLOCK), b""):
                    digest.update(chunk)
                    size += len(chunk)
            if digest.hexdigest() != reference.sha256 or size != reference.bytes:
                raise RuntimeError("Feature prefix differs from retained recovery group")
            # stream() checks the complete archived digest, even without a second
            # whole-file owner copy. Only then may successful staging be retired.
            for _chunk in p.archive.stream(reference):
                pass
            metrics.update(reference=reference.__dict__, retired_prefix=str(stage))
            coordinator.write_once(stage.with_suffix(".json"), metrics)
            stage.unlink()
            self.groups.append(metrics)
            return reference

    def _cache_snapshot(self, rows, ids, label):
        g = self.provisioner.geometry
        with self.log.event(label):
            delivery = cache.seal_snapshot(
                rows,
                ids,
                g.dimension,
                self._cache_key,
                self._signing,
                namespace=self.namespace,
                key_id=self.cache_key_id,
                snapshot_id=_token(self.anchor, self.slot, label),
                epoch=1,
            )
            self._retain_cache(delivery)
            return delivery

    def _retain_cache(self, delivery):
        archive = self.provisioner.archive
        archive.put(delivery.packet, kind="cache")
        archive.put(delivery.descriptor, kind="descriptor")

    def _view(self, rows, ids, groups, delivery, epoch, label):
        g, archive = self.provisioner.geometry, self.provisioner.archive
        metadata = native.PublicMetadata(
            Profile(g.n, g.dimension, g.q, g.p, g.t, g.eta, "owner", "canonical30"),
            g.primes,
            self._pk.key_id,
            ids,
        )
        records, bindings, certificates = [], [], []
        with self.log.event(label):
            for mode, policy in zip(cert.MODES, self.policies, strict=True):
                record = cohort.sign_record(
                    archive,
                    metadata,
                    self.keys,
                    groups,
                    epoch=epoch,
                    policy_digest=policy,
                    signing_owner=self._signing,
                )
                plan = cert.TrustedPlan(
                    g,
                    len(ids),
                    bytes.fromhex(metadata.key_id),
                    hashlib.sha256(b"".join(x.to_bytes(8, "little") for x in ids)).digest(),
                    bytes.fromhex(record.snapshot_id),
                    policy,
                    self.code_digest,
                    mode,
                )
                packet = cert.make_certificate(plan)
                records.append(record)
                certificates.append(packet)
                bindings.append(
                    context.ModeBinding(
                        mode,
                        epoch,
                        bytes.fromhex(record.snapshot_id),
                        policy,
                        self.code_digest,
                        cert.certificate_digest(packet),
                    )
                )
            c = delivery.context
            descriptor = context.seal_descriptor(
                ids,
                self._signing,
                namespace=self.namespace,
                revision=_token(self.anchor, self.slot, label),
                epoch=c.epoch,
                geometry=g,
                key_id=bytes.fromhex(self._pk.key_id),
                cache=context.CacheBinding(c.key_id, c.snapshot_id, c.epoch, c.ordered_ids_digest),
                modes=tuple(bindings),
                certificates=tuple(certificates),
            )
            archive.put(descriptor.packet, kind="descriptor")
            return OwnerView(rows, ids, tuple(records), descriptor, delivery)

    def initial(self, rows, ids):
        label = f"initial-{len(rows)}"
        self._begin(label)
        try:
            self._validate_rows(rows, ids)
            g = self.provisioner.geometry
            groups = tuple(
                self._group(rows[start : start + g.n], f"{label}-g{start // g.n}")
                for start in range(0, len(rows), g.n)
            )
            delivery = self._cache_snapshot(rows, ids, label + "-cache")
            view = self._view(rows, ids, groups, delivery, 1, label + "-views")
            self._initial[len(rows)] = view
            return view
        except BaseException:
            self._failed = True
            raise

    def _validate_rows(self, rows, ids):
        g = self.provisioner.geometry
        if (
            type(rows) is not tuple
            or type(ids) is not tuple
            or not 1 <= len(rows) <= 2 * g.n
            or len(ids) != len(rows)
            or len(set(ids)) != len(ids)
            or any(type(x) is not int or not 0 <= x < 1 << 64 for x in ids)
        ):
            raise ValueError("Complete immutable rows and unique UInt64 IDs required")
        for word in rows:
            trace._word(word, g.dimension)

    def update(self, previous, words, *, label, encrypted):
        """Each lifetime starts from its initial view; only remote updates use HE."""
        self._begin(label)
        if (
            type(previous) is not OwnerView
            or previous is not self._initial.get(len(previous.rows))
            or type(words) is not tuple
            or len(words) != 8
            or type(encrypted) is not bool
        ):
            self._failed = True
            raise ValueError("Fixed initial owner view and eight-word update law required")
        try:
            for word in words:
                trace._word(word, self.provisioner.geometry.dimension)
            rows = tuple(words[i % 2] ^ 1 if i < 32 else row for i, row in enumerate(previous.rows))
            with self.log.event(label + "-cache"):
                delivery = cache.seal_update(
                    tuple((i, rows[i]) for i in range(min(32, len(rows)))),
                    self._cache_key,
                    self._signing,
                    previous.cache_delivery.context,
                    snapshot_id=_token(self.anchor, self.slot, label + "-cache"),
                )
                self._retain_cache(delivery)
            if not encrypted:
                return delivery, rows  # No stale HE view is claimed as current.
            groups = previous.records[0].groups
            changed = self._group(rows[: self.provisioner.geometry.n], label + "-group")
            return self._view(
                rows, previous.ids, (changed, *groups[1:]), delivery, 2, label + "-views"
            )
        except BaseException:
            self._failed = True
            raise

    def custody(self):
        self._process()
        self._open()
        return owner.OwnerKeyCustody(self._pk, self._sk, self.provisioner.geometry)

    def cache_client(self, native_cache, current):
        self._process()
        self._open()
        return cache.CacheClient(native_cache, self._cache_key, self.anchor, current)

    def signing_owner(self):
        self._process()
        self._open()
        return self._signing  # Trusted local runner only; never a worker config.

    def inventory(self):
        self._process()
        return {
            "slot": self.slot,
            "anchor": self.anchor.hex(),
            "namespace": self.namespace.hex(),
            "public_key": self.public.__dict__,
            "evaluation_keys": self.keys.__dict__,
            "groups": self.groups,
            "failed": self._failed,
            "events": self.log.inventory(),
            "private_keys_serialized": False,
            "secure_zeroization_claim": False,
        }

    def close(self):
        self._process()
        if not self._closed:
            self._closed = True
            self._pk = self._sk = self._signing = self._cache_key = None
