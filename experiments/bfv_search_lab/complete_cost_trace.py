"""Q77 owner event paths through the shared relay and authenticated adapters.

These are actual owner operations, not a latency model or a sum of samples.
Each trace owns its receipt, cache and request state. Background acquisition
uses the same endpoint as remote search; its CPU thread is explicitly pinned.
All current pins are supplied by the trusted owner channel. A peer packet
cannot select executable code, a decoder, a key or the next logical epoch.

This local measurement adapter is not attestation or secure provisioning.
Owner encryption and Python key handling remain variable time. The bounded
public gate replaces encryption, private decoding and native cache arithmetic
with labelled public stubs; actual HE correctness belongs to the frozen cohort.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import os
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from experiments.bfv_search_lab import authenticated_cache as cache
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_owner as owner
from experiments.bfv_search_lab import complete_cost_relay as relay
from experiments.bfv_search_lab import seeded_bgv as seeded
from experiments.bfv_search_lab import shared_query_bgv as shared
from experiments.bfv_search_lab import shared_query_certificate as cert
from experiments.bfv_search_lab import shared_query_client_context as context

MAX_EVENTS = 4096
MAX_QUERIES = 720


def _label(value):
    if (
        type(value) is not str
        or not 1 <= len(value) <= 96
        or any(
            c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
            for c in value
        )
    ):
        raise ValueError("Bounded trusted local event label required")


def _word(value, dimension):
    if type(value) is not int or not 0 <= value < 1 << dimension:
        raise ValueError("Complete owner query word required")


def _cache_context(metadata):
    binding = metadata.cache
    return cache.Context(
        metadata.pin.namespace,
        binding.key_id,
        binding.snapshot_id,
        binding.epoch,
        len(metadata.ids),
        metadata.geometry.dimension,
        binding.ordered_ids_digest,
    )


class EventLog(owner._Owned):
    """Bounded process-local actual event intervals, CPU and dependency edges.

    Parent intervals may overlap children. A dependency must already have finished
    successfully; it is not inferred by adding stage times. Failed events retain
    their interval and coarse exception class without serializing diagnostics or
    private payloads. This public log is not durable cryptographic authority.
    """

    def __init__(self, label):
        _label(label)
        self._initialize()
        self.label = label
        self._events = []

    @contextmanager
    def event(self, label, *, parent=None, dependencies=(), arrival_ns=None):
        self._process()
        _label(label)
        start, cpu = time.perf_counter_ns(), time.thread_time_ns()
        if arrival_ns is not None and (type(arrival_ns) is not int or not 0 <= arrival_ns <= start):
            raise ValueError("Actual or elapsed scheduled arrival required")
        if type(dependencies) is not tuple:
            raise ValueError("Fixed event dependency tuple required")
        with self._lock:
            self._open()
            if len(self._events) >= MAX_EVENTS:
                raise RuntimeError("Registered event ceiling exhausted")
            for dep in dependencies:
                if (
                    type(dep) is not int
                    or not 0 <= dep < len(self._events)
                    or self._events[dep]["status"] != "complete"
                ):
                    raise ValueError("Dependency has not completed successfully")
            if parent is not None and (
                type(parent) is not int
                or not 0 <= parent < len(self._events)
                or self._events[parent]["status"] != "running"
            ):
                raise ValueError("Actual running parent event required")
            item = {
                "id": len(self._events),
                "label": label,
                "parent": parent,
                "dependencies": dependencies,
                "start_ns": start,
                "arrival_ns": arrival_ns,
                "end_ns": None,
                "thread_cpu_ns": None,
                "status": "running",
                "thread_id": threading.get_native_id(),
                "process": self._pid,
                "error_class": None,
            }
            self._events.append(item)
        status, error_class = "complete", None
        try:
            yield item["id"]
        except BaseException as error:
            status, error_class = "failed", type(error).__name__
            raise
        finally:
            end, used = time.perf_counter_ns(), time.thread_time_ns() - cpu
            with self._lock:
                item["end_ns"], item["thread_cpu_ns"] = end, used
                item["status"], item["error_class"] = status, error_class

    def inventory(self):
        self._process()
        with self._lock:
            return {
                "label": self.label,
                "process": self._pid,
                "events": [dict(e) for e in self._events],
                "qualification": (
                    "Actual overlapping intervals; never sum parent and child durations as latency"
                ),
            }


class OwnerQuerySource(owner._Owned):
    """Fixed owner encryption/signing path with a consumed local attempt budget.

    The coordinator must assign a distinct frozen domain to each source lifetime.
    The domain/counter supplies public request nonces, not encryption entropy.
    Fresh encryption uses the existing independent OS-backed sampler. The budget
    is consumed before encryption, including a failed call; no pool or retry exists.
    """

    def __init__(
        self,
        keys,
        signing_owner,
        *,
        domain,
        encryption_limit,
        attempt_observer=None,
        packet_observer=None,
    ):
        if (
            type(keys) is not owner.OwnerKeyCustody
            or not isinstance(signing_owner, Ed25519PrivateKey)
            or type(domain) is not bytes
            or len(domain) != 32
            or type(encryption_limit) is not int
            or not 1 <= encryption_limit <= MAX_QUERIES
            or attempt_observer is not None
            and not callable(attempt_observer)
            or packet_observer is not None
            and not callable(packet_observer)
        ):
            raise ValueError("Fixed owner custody, signing key, domain and query budget required")
        keys._process()
        with keys._lock:
            keys._open()
        self._initialize()
        self._keys, self._signing = keys, signing_owner
        self.owner_anchor = signing_owner.public_key().public_bytes_raw()
        self.domain, self.encryption_limit, self._issued = domain, encryption_limit, 0
        # Trusted owner callbacks, never supplied by a response. Persist the
        # global attempt before entropy/arithmetic and retain the actual public
        # signed original before it can be sent or used to begin a receipt.
        self._attempt_observer = attempt_observer
        self._packet_observer = packet_observer

    def __repr__(self):
        return "OwnerQuerySource(<private owner context>)"

    def prepare(self, metadata, mode, word):
        self._process()
        if type(metadata) is not context.ClientMetadata:
            raise ValueError("Current verified owner metadata required")
        selected = metadata.mode(mode)
        _word(word, metadata.geometry.dimension)
        self._keys._process()
        with self._lock, self._keys._lock:
            self._open()
            self._keys._bind_locked(metadata)
            if self._issued >= self.encryption_limit:
                raise RuntimeError("Registered owner query budget exhausted")
            index = self._issued
            self._issued += 1
            if self._attempt_observer is not None:
                self._attempt_observer(index)
            nonce = hashlib.sha256(
                b"cuhepy/Q77/owner-query/v1\0" + self.domain + index.to_bytes(8, "little")
            ).digest()
            bits = tuple((word >> i) & 1 for i in range(metadata.geometry.dimension))
            plaintext = shared.encode_query(bits, metadata.geometry.n, metadata.geometry.t)
            packet = seeded.encrypt(plaintext, self._keys._pk, self._keys._secret)
            original = auth.sign_request(
                selected.snapshot_id,
                selected.epoch,
                selected.policy_digest,
                nonce,
                packet,
                self._signing,
            )
            if self._packet_observer is not None:
                self._packet_observer(original, index)
            return original

    def inventory(self):
        self._process()
        with self._lock:
            return {
                "issued": self._issued,
                "limit": self.encryption_limit,
                "domain": self.domain.hex(),
                "process": self._pid,
                "closed": self._closed,
                "global_attempt_observer": self._attempt_observer is not None,
                "actual_packet_observer": self._packet_observer is not None,
            }

    def close(self):
        self._process()
        with self._lock:
            self._closed, self._signing = True, None
            self._attempt_observer = self._packet_observer = None
            # Caller owns key/signing references; this does not erase them.


class AcquisitionJob(owner._Owned):
    """Owned background acquisition and a bounded join, never an automatic retry."""

    def __init__(self, trace, deadline_ns, cpu):
        # A newly created thread may inherit the owner's single-CPU mask.
        # Validate the requested CPU by actually applying it in that thread;
        # the parent's current mask is not the process's allowed cpuset.
        if type(trace) is not OwnerTrace or type(cpu) is not int or not 0 <= cpu < 4096:
            raise ValueError("Owner trace and permitted background CPU required")
        self._initialize()
        self._trace, self._deadline, self._cpu = trace, deadline_ns, cpu
        self._affinity = None
        self._error, self._complete = None, threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="Q77-owner-acquisition", daemon=False
        )

    def _run(self):
        try:
            os.sched_setaffinity(0, {self._cpu})
            self._affinity = sorted(os.sched_getaffinity(0))
            if self._affinity != [self._cpu]:
                raise RuntimeError("Background thread differs from frozen CPU")
            self._trace.acquire(deadline_ns=self._deadline)
        except BaseException as error:
            self._error = error
            self._trace._fail()
        finally:
            self._complete.set()

    def join(self, *, deadline_ns):
        self._process()
        try:
            remaining = relay._remaining(deadline_ns)
        except relay.transport.TransportError:
            self._trace._fail()
            self._trace.endpoint.close()
            raise TimeoutError("Owned background join deadline exhausted") from None
        self._thread.join(remaining / 1e9)
        if self._thread.is_alive():
            self._trace._fail()
            self._trace.endpoint.close()
            raise TimeoutError("Owned background acquisition did not finish before deadline")
        if self._error is not None:
            raise RuntimeError("Owned background acquisition failed") from self._error

    def inventory(self):
        self._process()
        return {
            "cpu": self._cpu,
            "observed_affinity": self._affinity,
            "complete": self._complete.is_set(),
            "alive": self._thread.is_alive(),
            "failed": self._error is not None,
        }


class OwnerTrace(owner._Owned):
    """One independently owned policy trajectory through actual owner APIs.

    Inputs are fixed typed local handles. Cache-only traces need no HE custody.
    The caller owns their explicit close order and provisioning costs. A failed
    operation disables this trajectory; another request cannot silently retry it
    or turn failed prefetch into a new remote fallback. Closing a receipt client
    does not close shared tenant keys. Explicit stop_remote permits cache-only use
    after a successful prefetch, with that lifetime visible in the inventory.
    """

    def __init__(
        self,
        descriptor,
        endpoint,
        log,
        *,
        mode=None,
        client=None,
        query_source=None,
        cache_client=None,
    ):
        if (
            type(descriptor) is not context.DescriptorClient
            or type(endpoint) is not relay.OwnerEndpoint
            or type(log) is not EventLog
        ):
            raise ValueError("Fixed process-owned descriptor, endpoint and event log required")
        if mode is None:
            if client is not None or query_source is not None:
                raise ValueError("Cache-only trajectory cannot carry a remote private capability")
        elif (
            mode not in cert.MODES
            or type(client) is not owner.OwnerClient
            or type(query_source) is not OwnerQuerySource
            or client._descriptor is not descriptor
            or client._keys is not query_source._keys
            or query_source.owner_anchor != descriptor._anchor
        ):
            raise ValueError("One fixed current owner remote path required")
        if cache_client is not None and type(cache_client) is not cache.CacheClient:
            raise ValueError("Fixed authenticated cache handle required")
        if mode is None and cache_client is None:
            raise ValueError("At least one actual owner search path required")
        descriptor._process()
        with descriptor._lock:
            metadata = descriptor.metadata()
            if cache_client is not None and cache_client.current_context != _cache_context(
                metadata
            ):
                raise ValueError("Cache differs from descriptor's complete current binding")
        endpoint._process()
        log._process()
        self._initialize()
        self.descriptor, self.endpoint, self.log = descriptor, endpoint, log
        self.mode, self.client, self.query_source, self.cache = (
            mode,
            client,
            query_source,
            cache_client,
        )
        self._failed, self._remote_enabled = False, mode is not None
        self._queries, self._results, self._job = set(), [], None
        self._acquisition_started = False
        self._races = []

    def _ready(self):
        self._open()
        if self._failed:
            raise RuntimeError("Failed owner trajectory cannot be retried")

    def _fail(self):
        self._process()
        with self._lock:
            self._failed = True
            if self.client is not None:
                self.client.close()

    def _deadline(self, deadline_ns):
        if type(deadline_ns) is not int:
            raise ValueError("Absolute owner operation deadline required")
        remaining = deadline_ns - time.perf_counter_ns()
        if remaining <= 0:
            raise relay.transport.TransportError("Owner operation deadline exhausted")
        if remaining > self.endpoint.timeout_ns:
            raise ValueError("Bounded absolute owner operation deadline required")

    def cache_ready(self):
        self._process()
        with self.descriptor._lock, self._lock:
            self._ready()
            if self.cache is None:
                return False
            metadata = self.descriptor.metadata()
            return (
                self.cache.current_context == _cache_context(metadata)
                and self.cache.inventory()["active"]
            )

    def query(self, word, *, label, policy, arrival_ns, deadline_ns):
        self._process()
        _label(label)
        if type(policy) is not str or policy not in ("remote", "cache", "prefetch"):
            raise ValueError("Trusted fixed owner policy required")
        self._deadline(deadline_ns)
        with self.descriptor._lock, self._lock:
            self._ready()
            metadata = self.descriptor.metadata()
            _word(word, metadata.geometry.dimension)
            if label in self._queries or len(self._queries) >= MAX_QUERIES:
                raise ValueError("Consumed or excess owner query label")
            use_cache = policy == "cache" or policy == "prefetch" and self.cache_ready()
            if use_cache and self.cache is None or not use_cache and not self._remote_enabled:
                raise RuntimeError("Selected owner search path is unavailable")
            self._queries.add(label)
        try:
            with self.log.event(label, arrival_ns=arrival_ns) as parent:
                if use_cache:
                    with self.log.event("cache-scan", parent=parent), self.descriptor._lock:
                        if self.descriptor.metadata() != metadata:
                            raise ValueError("Current owner descriptor changed before cache scan")
                        self._deadline(deadline_ns)
                        answer = self.cache.query(word)
                        if answer.context != _cache_context(metadata):
                            raise ValueError("Cache answer differs from current descriptor")
                        result = owner.SearchResult(
                            answer.scores,
                            tuple(
                                owner.Match(i, metadata.ids[i], answer.scores[i])
                                for i in answer.top3_positions
                            ),
                        )
                else:
                    with (
                        self.log.event("owner-query-encryption-signature", parent=parent),
                        self.descriptor._lock,
                    ):
                        if self.descriptor.metadata() != metadata:
                            raise ValueError(
                                "Current owner descriptor changed before query preparation"
                            )
                        original = self.query_source.prepare(metadata, self.mode, word)
                        pending = self.client.begin(self.mode, original)
                    self._deadline(deadline_ns)
                    with self.log.event("remote-shared-link", parent=parent):
                        response = self.endpoint.rpc(
                            auth._pack([b"search", auth._pack([b"run", original])]),
                            deadline_ns=deadline_ns,
                        )
                    self._deadline(deadline_ns)
                    with self.log.event("authenticated-private-finish", parent=parent):
                        result = pending.finish(response)
                self._deadline(deadline_ns)
                if type(result) is not owner.SearchResult or len(result.distances) != len(
                    metadata.ids
                ):
                    raise ValueError("Complete owner search result required")
                digest = hashlib.sha256(
                    b"".join(x.to_bytes(2, "little") for x in result.distances)
                ).hexdigest()
                with self._lock:
                    self._ready()
                    self._results.append(
                        {
                            "label": label,
                            "path": "cache" if use_cache else "remote",
                            "epoch": metadata.pin.epoch,
                            "revision": metadata.pin.revision.hex(),
                            "count": len(result.distances),
                            "distances_sha256": digest,
                            "nearest": [asdict(m) for m in result.nearest],
                        }
                    )
                return result
        except BaseException:
            self._fail()
            raise

    def race_query(self, word, *, label, arrival_ns, deadline_ns, remote_cpu):
        """Return the first actual valid answer while keeping losing work paid.

        Cache publication may win after the remote query has started. The
        remote thread remains owned until join_races; its RPC, verification,
        private finish and any failure are retained. This is not cancellation
        or a promise that a failed acquisition can silently become remote-only.
        """
        self._process()
        _label(label)
        self._deadline(deadline_ns)
        if type(remote_cpu) is not int or not 0 <= remote_cpu < (os.cpu_count() or 1):
            raise ValueError("Explicit owner remote-thread CPU required")
        with self._lock:
            self._ready()
            if self._job is None or label in self._queries:
                raise ValueError("One active acquisition and fresh race label required")
            if len(self._races) >= 8:
                raise RuntimeError("Eight-query racing trajectory cap exhausted")
        if self.cache_ready():
            return self.query(
                word, label=label, policy="cache", arrival_ns=arrival_ns, deadline_ns=deadline_ns
            )
        done = threading.Event()
        item = {
            "label": label,
            "winner": None,
            "error_class": None,
            "start_ns": time.perf_counter_ns(),
            "end_ns": None,
        }
        answer = []

        def remote():
            try:
                os.sched_setaffinity(0, {remote_cpu})
                answer.append(
                    self.query(
                        word,
                        label=label + "-remote",
                        policy="remote",
                        arrival_ns=arrival_ns,
                        deadline_ns=deadline_ns,
                    )
                )
            except BaseException as error:
                item["error_class"] = type(error).__name__
                self._fail()
            finally:
                item["remote_end_ns"] = time.perf_counter_ns()
                done.set()

        thread = threading.Thread(target=remote, name="Q77-owner-remote-race", daemon=False)
        with self._lock:
            self._queries.add(label)
            self._races.append((thread, item))
        try:
            with self.log.event(label, arrival_ns=arrival_ns):
                thread.start()
                while True:
                    self._deadline(deadline_ns)
                    self._ready()  # Includes acquisition/loser failure.
                    if done.is_set():
                        if not answer:
                            raise RuntimeError("Remote race failed")
                        result, item["winner"] = answer[0], "remote"
                        break
                    if self.cache_ready():
                        cached = self.query(
                            word,
                            label=label + "-cache",
                            policy="cache",
                            arrival_ns=arrival_ns,
                            deadline_ns=deadline_ns,
                        )
                        # If both complete during the cache scan, use the one
                        # that actually finished first, not the polling order.
                        cache_end = time.perf_counter_ns()
                        if done.is_set() and answer and item["remote_end_ns"] <= cache_end:
                            result, item["winner"] = answer[0], "remote"
                        else:
                            result, item["winner"] = cached, "cache"
                        break
                    done.wait(min(0.01, max(0, (deadline_ns - time.perf_counter_ns()) / 1e9)))
                self._ready()
                item["end_ns"] = time.perf_counter_ns()
                return result
        except BaseException:
            self._fail()
            raise

    def join_races(self, *, deadline_ns):
        """Settle every owned loser before remote shutdown or an owner update."""
        self._process()
        for thread, item in self._races:
            remaining = deadline_ns - time.perf_counter_ns()
            if remaining <= 0:
                raise RuntimeError("Owned race cleanup deadline exhausted")
            if thread.ident is not None:
                thread.join(remaining / 1e9)
            if thread.is_alive():
                raise RuntimeError("Owned remote race did not finish")
            if item["error_class"] is not None:
                raise RuntimeError("Paid losing remote work failed")

    def acquire(self, *, deadline_ns):
        self._process()
        self._deadline(deadline_ns)
        with self.descriptor._lock, self._lock:
            self._ready()
            if self.cache is None or self._acquisition_started:
                raise RuntimeError("One declared absent-cache acquisition required")
            if self.cache.inventory()["active"]:
                raise ValueError("Cache already acquired; cannot claim cold acquisition")
            self._acquisition_started = True
            metadata = self.descriptor.metadata()
        try:
            with self.log.event("cache-acquisition") as parent:
                with self.log.event("snapshot-shared-link", parent=parent):
                    packet = self.endpoint.rpc(auth._pack([b"snapshot"]), deadline_ns=deadline_ns)
                with (
                    self.log.event("cache-authenticate-publish", parent=parent),
                    self.descriptor._lock,
                ):
                    self._deadline(deadline_ns)
                    if self.descriptor.metadata() != metadata:
                        raise ValueError("Owner current pin changed during cache acquisition")
                    fields = auth._unpack(packet, limit=self.endpoint.cap, array_cap=2)
                    if (
                        type(fields) is not list
                        or len(fields) != 2
                        or any(type(x) is not bytes for x in fields)
                    ):
                        raise ValueError("Complete bounded cache delivery required")
                    self.cache.acquire(*fields)
                self._deadline(deadline_ns)
        except BaseException:
            self._fail()
            raise

    def start_acquisition(self, *, deadline_ns, cpu):
        self._process()
        self._deadline(deadline_ns)
        with self._lock:
            self._ready()
            if self._job is not None or self._acquisition_started:
                raise RuntimeError("Background acquisition already consumed")
            job = AcquisitionJob(self, deadline_ns, cpu)
            self._job = job
            job._thread.start()
            return job

    def advance(self, trusted_pin, descriptor_packet, *, cache_context=None, deadline_ns):
        """Honest owner update, not a received-packet choice of the current pin.

        Validate the new complete descriptor before either pin changes. Hold the
        descriptor lock across publication/invalidation so old in-flight receipts and
        cache deliveries cannot publish under the new pin. A partial failure poisons
        the trace rather than rolling the current authority back.
        """
        self._process()
        self._deadline(deadline_ns)
        try:
            with self.log.event("owner-current-update"), self.descriptor._lock, self._lock:
                self._ready()
                old = self.descriptor.metadata()
                new = context.verify_descriptor(
                    descriptor_packet, self.descriptor._anchor, trusted_pin
                )
                if (
                    new.key_id != old.key_id
                    or new.geometry != old.geometry
                    or new.ids != old.ids
                    or trusted_pin.namespace != old.pin.namespace
                    or trusted_pin.epoch != old.pin.epoch + 1
                    or trusted_pin.revision == old.pin.revision
                ):
                    raise ValueError("One fixed-key/geometry/ID owner revision advance required")
                if self.cache is not None and (
                    type(cache_context) is not cache.Context or cache_context != _cache_context(new)
                ):
                    raise ValueError("Complete owner cache update binding required")
                if self.cache is None and cache_context is not None:
                    raise ValueError("Cache authority supplied to remote-only trace")
                self.descriptor.advance_current(trusted_pin)
                self.descriptor.acquire(descriptor_packet)
                if self.cache is not None:
                    self.cache.pin_current(cache_context)
                self._deadline(deadline_ns)
        except BaseException:
            self._fail()
            raise

    def patch(self, *, deadline_ns):
        self._process()
        self._deadline(deadline_ns)
        with self.descriptor._lock, self._lock:
            self._ready()
            if self.cache is None or self.cache.inventory()["active"]:
                raise ValueError("Invalidated retained cache required for compact patch")
            metadata = self.descriptor.metadata()
        try:
            with self.log.event("cache-update") as parent:
                with self.log.event("patch-shared-link", parent=parent):
                    packet = self.endpoint.rpc(auth._pack([b"patch"]), deadline_ns=deadline_ns)
                with (
                    self.log.event("cache-authenticate-patch", parent=parent),
                    self.descriptor._lock,
                ):
                    self._deadline(deadline_ns)
                    if self.descriptor.metadata() != metadata:
                        raise ValueError("Current owner pin changed during cache patch")
                    fields = auth._unpack(packet, limit=self.endpoint.cap, array_cap=2)
                    if (
                        type(fields) is not list
                        or len(fields) != 2
                        or any(type(x) is not bytes for x in fields)
                    ):
                        raise ValueError("Complete bounded cache patch required")
                    self.cache.apply_update(*fields)
                self._deadline(deadline_ns)
        except BaseException:
            self._fail()
            raise

    def stop_remote(self):
        self._process()
        with self._lock:
            self._ready()
            if self.client is not None:
                self.client.close()
            self._remote_enabled = False

    def inventory(self):
        self._process()
        with self._lock:
            return {
                "process": self._pid,
                "mode": self.mode,
                "failed": self._failed,
                "closed": self._closed,
                "remote_enabled": self._remote_enabled,
                "consumed_query_labels": sorted(self._queries),
                "results": [
                    dict(r, nearest=[dict(m) for m in r["nearest"]]) for r in self._results
                ],
                "background": None if self._job is None else self._job.inventory(),
                "races": [
                    dict(item, remote_thread_alive=thread.is_alive())
                    for thread, item in self._races
                ],
                "query_budget": None
                if self.query_source is None
                else self.query_source.inventory(),
                "endpoint": self.endpoint.inventory(),
                "trace": self.log.inventory(),
            }

    def close(self):
        self._process()
        with self._lock:
            self._closed = True
            job = self._job
            if self.client is not None:
                self.client.close()
        self.endpoint.close()
        if job is not None:
            job._thread.join(self.endpoint.timeout_ns / 1e9)
            if job._thread.is_alive():
                raise RuntimeError("Owned background thread did not stop")
        for thread, _item in self._races:
            if thread.ident is not None:
                thread.join(self.endpoint.timeout_ns / 1e9)
            if thread.is_alive():
                raise RuntimeError("Owned remote race thread did not stop")
        # Caller explicitly closes cache, query source, descriptor and tenant
        # keys after their registered lifetimes; shared keys are never copied
        # into a public child. Python cannot forcibly preempt a native call.
