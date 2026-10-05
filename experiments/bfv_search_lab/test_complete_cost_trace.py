"""Bounded owner event/control gate, with labelled public arithmetic stubs.

No valid HE key, actual HE encryption/decryption or native search is used.
Owner/verifier signing material and the AES material are existing public
UNIT-ONLY fixtures. Cache authentication is exercised, with deterministic
public fixture nonces; this is not a deployment key or nonce recipe.
"""

from dataclasses import replace
import copy
import hashlib
import json
import os
import pickle
import threading
import time
from types import SimpleNamespace

import gmpy2
import pytest

from experiments.bfv_search_lab import authenticated_cache as cache
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_network as network
from experiments.bfv_search_lab import complete_cost_owner as owner
from experiments.bfv_search_lab import complete_cost_protocol as receipt
from experiments.bfv_search_lab import complete_cost_relay as relay
from experiments.bfv_search_lab import complete_cost_trace as trace
from experiments.bfv_search_lab import complete_cost_transport as transport
from experiments.bfv_search_lab import shared_query_certificate as cert
from experiments.bfv_search_lab import shared_query_client_context as context
from experiments.bfv_search_lab import test_complete_cost_owner as custody_public
from experiments.bfv_search_lab import test_complete_cost_protocol as public
from experiments.bfv_search_lab import test_complete_cost_relay as relay_public

owners = public.owners
TIMEOUT = 2_000_000_000


def deadline():
    return time.perf_counter_ns() + TIMEOUT - 1_000_000


def reference(rows, dimension, word):
    return tuple(sum(((x >> i) & 1) != ((word >> i) & 1) for i in range(dimension)) for x in rows)


@pytest.fixture
def make_trace(monkeypatch, owners):
    made, nonce_number = [], [0]

    def fixture_nonce(size):
        assert size == 12
        nonce_number[0] += 1
        return nonce_number[0].to_bytes(12, "little")

    monkeypatch.setattr(cache.secrets, "token_bytes", fixture_nonce)

    def make(*, mode=cert.MODES[0], with_cache=True, limit=10):
        p, pk, sk = custody_public.material(0)
        keys = owner.OwnerKeyCustody(pk, sk, p)
        descriptor, metadata, delivery = custody_public.descriptor(
            owners[0], p, bytes.fromhex(pk.key_id), 5
        )
        endpoint = relay.OwnerEndpoint(
            1,
            upload_budget=network.DirectionBudget(transport.Link(10_000_000, 0)),
            cap=relay_public.CAP,
            timeout_ns=TIMEOUT,
        )
        signing = owners[0]
        anchors = tuple((m, owners[1].public_key().public_bytes_raw()) for m in cert.MODES)
        client = None if mode is None else owner.OwnerClient(descriptor, anchors, keys)
        source = (
            None
            if mode is None
            else trace.OwnerQuerySource(
                keys,
                signing,
                domain=public.token("trace-source" + str(len(made))),
                encryption_limit=limit,
            )
        )
        symmetric = hashlib.sha256(b"Q76.4c public unit AES fixture").digest()
        f = SimpleNamespace(
            keys=keys,
            descriptor=descriptor,
            metadata=metadata,
            delivery=delivery,
            endpoint=endpoint,
            client=client,
            source=source,
            rows=(0, 0, 1, 3, 7),
            word=0,
            encrypted=[],
            private_entries=0,
            decoder_creations=0,
            native_scans=0,
            rpc_calls=[],
            nonce_failure=False,
            reply_fault=None,
            snapshot_entered=threading.Event(),
            snapshot_release=threading.Event(),
            block_snapshot=False,
            snapshot_failure=False,
            search_entered=threading.Event(),
            search_release=threading.Event(),
            block_search=False,
            cache=None,
            key=symmetric,
            mode=mode,
            log=trace.EventLog("owner-policy"),
        )

        class PublicDecoderStub:
            def __init__(self, *_args, **_kwargs):
                f.decoder_creations += 1
                self.modulus = gmpy2.mpz(p.p)

            def decode_packed(self, _pairs):
                f.private_entries += 1
                distances = reference(f.rows, p.dimension, f.word)
                values = [(p.dimension - 2 * x) % p.t for x in distances]
                return [values + [0] * (p.n - len(values))]

            def close(self):
                pass

        def stub_encrypt(plaintext, selected_pk, selected_sk):
            assert selected_pk == pk and selected_sk == sk
            f.encrypted.append(tuple(plaintext))
            if f.nonce_failure:
                raise RuntimeError("unit encryption diagnostic must remain local")
            padded = 1 << (p.dimension - 1).bit_length()
            signs = tuple(x * padded % p.t for x in plaintext[: p.dimension])
            assert all(x in (1, p.t - 1) for x in signs) and not any(plaintext[p.dimension :])
            f.word = sum((x == p.t - 1) << i for i, x in enumerate(signs))
            return b"public query grammar fixture"

        def stub_scan(_native, raw, count, dimension, query):
            f.native_scans += 1
            width, word = (dimension + 7) // 8, int.from_bytes(query, "little")
            values = tuple(
                (int.from_bytes(raw[at : at + width], "little") ^ word).bit_count()
                for at in range(0, len(raw), width)
            )
            assert len(values) == count
            return values, tuple(sorted(range(count), key=lambda i: (values[i], i))[:3])

        monkeypatch.setattr(owner.private, "PrivateDecoder", PublicDecoderStub)
        monkeypatch.setattr(trace.seeded, "encrypt", stub_encrypt)
        monkeypatch.setattr(cache.NativePopcount, "scan", stub_scan)
        if with_cache:
            # Allocate grammar-only native holder without constructing/loading
            # a library. Its scan is the explicitly labelled public stub above.
            native = object.__new__(cache.NativePopcount)
            native._initialize_owner()
            f.cache = cache.CacheClient(
                native,
                symmetric,
                signing.public_key().public_bytes_raw(),
                trace._cache_context(metadata),
            )
            c = f.cache.current_context
            f.snapshot = cache.seal_snapshot(
                f.rows,
                metadata.ids,
                p.dimension,
                symmetric,
                signing,
                namespace=c.namespace,
                key_id=c.key_id,
                snapshot_id=c.snapshot_id,
                epoch=c.epoch,
            )

        def response(packet, *, deadline_ns):
            assert 0 < deadline_ns - time.perf_counter_ns() <= TIMEOUT
            fields = auth._unpack(packet, limit=f.endpoint.cap, array_cap=3)
            f.rpc_calls.append(fields[0])
            if fields[0] == b"snapshot":
                f.snapshot_entered.set()
                if f.block_snapshot:
                    assert f.snapshot_release.wait(1)
                if f.snapshot_failure:
                    raise RuntimeError("unit acquisition failure")
                return auth._pack([f.snapshot.packet, f.snapshot.descriptor])
            if fields[0] == b"patch":
                return auth._pack([f.patch.packet, f.patch.descriptor])
            assert fields[0] == b"search"
            nested = auth._unpack(fields[1], limit=f.endpoint.cap, array_cap=2)
            assert nested[0] == b"run" and len(nested) == 2
            current = f.descriptor.metadata()
            binding = receipt.original_binding(
                nested[1], signing.public_key().public_bytes_raw(), current, mode
            )
            packet = receipt._signed_packet(
                owners[1], current, mode, binding, public.frame(current)
            )
            f.search_entered.set()
            if f.block_search:
                assert f.search_release.wait(1)
            if f.reply_fault == "signature":
                packet = packet[:-1] + bytes([packet[-1] ^ 1])
            if f.reply_fault == "binding":
                packet = receipt._signed_packet(
                    owners[1],
                    current,
                    mode,
                    replace(binding, nonce=public.token("foreign")),
                    public.frame(current),
                )
            return packet

        f.response = response
        monkeypatch.setattr(endpoint, "rpc", response)
        f.trace = trace.OwnerTrace(
            descriptor,
            endpoint,
            f.log,
            mode=mode,
            client=client,
            query_source=source,
            cache_client=f.cache,
        )

        def query(word=0, label="query0", policy="remote", deadline_ns=None, arrival_ns=None):
            return f.trace.query(
                word,
                label=label,
                policy=policy,
                arrival_ns=time.perf_counter_ns() if arrival_ns is None else arrival_ns,
                deadline_ns=deadline() if deadline_ns is None else deadline_ns,
            )

        def update():
            old = f.descriptor.metadata()
            modes, packets = [], []
            for m in cert.MODES:
                prior = old.mode(m)
                plan = cert.TrustedPlan(
                    p,
                    len(old.ids),
                    old.key_id,
                    old.ordered_ids_digest,
                    public.token(m + "updated"),
                    prior.policy_digest,
                    prior.code_digest,
                    m,
                )
                packet = cert.make_certificate(plan)
                packets.append(packet)
                modes.append(
                    context.ModeBinding(
                        m,
                        2,
                        plan.snapshot_id,
                        plan.policy_digest,
                        plan.code_digest,
                        cert.certificate_digest(packet),
                    )
                )
            current_cache = replace(old.cache, snapshot_id=public.token("cache-updated"), epoch=2)
            updated = context.seal_descriptor(
                old.ids,
                signing,
                namespace=old.pin.namespace,
                revision=public.token("updated-revision"),
                epoch=2,
                geometry=p,
                key_id=old.key_id,
                cache=current_cache,
                modes=tuple(modes),
                certificates=tuple(packets),
            )
            new = context.verify_descriptor(
                updated.packet, signing.public_key().public_bytes_raw(), updated.pin
            )
            changed = (
                replace(f.snapshot.context, snapshot_id=current_cache.snapshot_id, epoch=2)
                if f.cache
                else None
            )
            if f.cache:
                f.patch = cache.seal_update(
                    ((0, 7),),
                    symmetric,
                    signing,
                    f.snapshot.context,
                    snapshot_id=current_cache.snapshot_id,
                )
            return updated, new, changed

        f.query, f.update = query, update
        made.append(f)
        return f

    yield make
    for f in made:
        f.snapshot_release.set()
        f.search_release.set()
        f.trace.close()
        if f.cache:
            f.cache.close()
        if f.source:
            f.source.close()
        f.keys.close()
        f.descriptor.close()


@pytest.mark.parametrize("mode", cert.MODES)
def test_all_three_remote_paths_end_at_consumed_complete_owner_result(make_trace, mode):
    f = make_trace(mode=mode)
    result = f.query(1)
    assert result.distances == reference(f.rows, 3, 1)
    assert f.private_entries == f.decoder_creations == len(f.encrypted) == 1
    assert f.source.inventory()["issued"] == 1
    events = f.log.inventory()["events"]
    assert [e["label"] for e in events] == [
        "query0",
        "owner-query-encryption-signature",
        "remote-shared-link",
        "authenticated-private-finish",
    ]
    assert all(e["status"] == "complete" and e["end_ns"] >= e["start_ns"] for e in events)
    assert all(e["parent"] == 0 for e in events[1:])
    assert events[0]["start_ns"] >= events[0]["arrival_ns"]


def test_allowed_cache_only_path_needs_no_HE_client_or_encryption(make_trace):
    f = make_trace(mode=None)
    f.trace.acquire(deadline_ns=deadline())
    result = f.query(0, policy="cache")
    assert result.distances == (0, 0, 1, 2, 3)
    assert tuple(m.ordinal for m in result.nearest) == (0, 1, 2)
    assert tuple(m.identifier for m in result.nearest) == f.metadata.ids[:3]
    assert f.client is f.source is None and f.private_entries == len(f.encrypted) == 0
    assert f.rpc_calls == [b"snapshot"] and f.native_scans == 1


def test_actual_owner_update_invalidates_cache_then_compact_patch_restores_it(make_trace):
    f = make_trace()
    f.trace.acquire(deadline_ns=deadline())
    updated, new, c = f.update()
    f.trace.advance(updated.pin, updated.packet, cache_context=c, deadline_ns=deadline())
    assert not f.trace.cache_ready() and f.descriptor.metadata() == new
    with pytest.raises(ValueError):
        f.cache.query(0)
    f.trace.patch(deadline_ns=deadline())
    f.rows = (7,) + f.rows[1:]
    assert f.query(policy="cache").distances == reference(f.rows, 3, 0)
    assert f.query(label="query1").distances == reference(f.rows, 3, 0)
    assert [r["epoch"] for r in f.trace.inventory()["results"]] == [2, 2]


def test_prefetch_overlaps_real_owner_work_and_switches_only_after_publication(make_trace):
    f = make_trace()
    f.block_snapshot = True
    job = f.trace.start_acquisition(deadline_ns=deadline(), cpu=min(os.sched_getaffinity(0)))
    assert f.snapshot_entered.wait(1)
    f.query(policy="prefetch")
    assert not f.trace.cache_ready()
    f.snapshot_release.set()
    job.join(deadline_ns=deadline())
    f.query(label="query1", policy="prefetch")
    assert [r["path"] for r in f.trace.inventory()["results"]] == ["remote", "cache"]
    assert len(f.encrypted) == f.private_entries == 1
    e = f.log.inventory()["events"]
    acquisition = next(x for x in e if x["label"] == "cache-acquisition")
    first = next(x for x in e if x["label"] == "query0")
    assert acquisition["start_ns"] < first["start_ns"] < first["end_ns"] < acquisition["end_ns"]
    assert job.inventory()["complete"] and not job.inventory()["alive"]


def test_trace_complete_remote_and_cache_paths_use_real_shared_TCP_relay(
    make_trace, monkeypatch, tmp_path
):
    f = make_trace()

    def backend_run(backend):
        while not backend.done.is_set():
            try:
                sock, _ = backend.listener.accept()
            except TimeoutError:
                continue
            stream = transport.BoundedStream(
                sock, cap=relay_public.CAP, link=relay.LOCAL_DISPATCH, timeout_ns=TIMEOUT
            )
            try:
                original = stream.receive(kind="public-unit-request")
                packet = f.response(auth._pack([b"search", original]), deadline_ns=deadline())
                stream.send(packet, kind="public-unit-signed-grammar")
            finally:
                stream.close()

    monkeypatch.setattr(relay_public.Echo, "run", backend_run)
    h = relay_public.Harness(tmp_path)
    try:
        for field, value in (("packet", f.snapshot.packet), ("descriptor", f.snapshot.descriptor)):
            h.cfg["snapshot"][field] = relay_public.public_file(
                tmp_path, "signed-cache-" + field, value
            )
        h.config.write_text(json.dumps(h.cfg))
        f.trace.endpoint = h.endpoint
        f.endpoint = h.endpoint
        f.trace.acquire(deadline_ns=deadline())
        assert f.query().distances == f.query(label="query1", policy="cache").distances
        assert len(h.endpoint.inventory()["transfers"]) == 4
        # Each small message reserves its eight-byte header and body.
        assert len(h.budget.history()) == len(h.role.download_budget.history()) == 4
        transfers = h.endpoint.inventory()["transfers"]
        assert sum(r.wire_bytes for r in h.budget.history()) == sum(
            r["wire_bytes"] for r in transfers if r["direction"] == "send"
        )
        assert sum(r.wire_bytes for r in h.role.download_budget.history()) == sum(
            r["wire_bytes"] for r in transfers if r["direction"] == "receive"
        )
        assert f.private_entries == 1
    finally:
        h.close()


@pytest.mark.parametrize("fault", ["signature", "binding"])
def test_invalid_result_disables_trajectory_before_public_private_stub(make_trace, fault):
    f = make_trace()
    f.reply_fault = fault
    with pytest.raises(ValueError):
        f.query()
    assert f.private_entries == f.decoder_creations == 0
    f.reply_fault = None
    with pytest.raises(RuntimeError):
        f.query(label="retry")
    assert len(f.encrypted) == 1 and f.trace.inventory()["failed"]


def test_encryption_attempt_is_consumed_even_when_owner_preparation_fails(make_trace):
    f = make_trace()
    f.nonce_failure = True
    with pytest.raises(RuntimeError):
        f.query()
    assert f.source.inventory()["issued"] == 1 and f.rpc_calls == []
    assert f.private_entries == 0 and f.trace.inventory()["failed"]


def test_frozen_query_budget_refuses_second_encryption_before_work(make_trace):
    f = make_trace(limit=1)
    f.query()
    with pytest.raises(RuntimeError):
        f.query(label="query1")
    assert f.source.inventory()["issued"] == len(f.encrypted) == f.private_entries == 1


def test_consumed_owner_query_label_cannot_request_more_work(make_trace):
    f = make_trace()
    f.query()
    with pytest.raises(ValueError):
        f.query()
    assert len(f.encrypted) == f.private_entries == 1


@pytest.mark.parametrize("offset", [-1, 3_000_000_000])
def test_invalid_absolute_deadline_precedes_encryption_or_transfer(make_trace, offset):
    f = make_trace()
    if offset > 0:
        # Exercise the legal endpoint maximum, where a capped remaining-time
        # helper must not hide an overlong caller deadline.
        f.endpoint.timeout_ns = 3_600_000_000_000
        offset += f.endpoint.timeout_ns
    with pytest.raises((ValueError, transport.TransportError)):
        f.query(deadline_ns=time.perf_counter_ns() + offset)
    assert not f.encrypted and not f.rpc_calls and not f.log.inventory()["events"]


def test_future_arrival_cannot_be_recorded_as_an_actual_query(make_trace):
    f = make_trace()
    with pytest.raises(ValueError):
        f.query(arrival_ns=time.perf_counter_ns() + 1_000_000_000)
    assert not f.encrypted and f.trace.inventory()["failed"]


@pytest.mark.parametrize("target", ["log", "source", "trace"])
def test_process_ownership_is_checked_before_inherited_held_lock(make_trace, target):
    f = make_trace()
    handle = getattr(f, target)
    pid = handle._pid
    with handle._lock:
        handle._pid = pid + 1
        try:
            with pytest.raises(RuntimeError):
                handle.inventory()
        finally:
            handle._pid = pid


@pytest.mark.parametrize("target", ["log", "source", "trace"])
def test_owner_trace_handles_cannot_copy_or_serialize_private_authority(make_trace, target):
    handle = getattr(make_trace(), target)
    with pytest.raises(TypeError):
        copy.copy(handle)
    with pytest.raises(TypeError):
        pickle.dumps(handle)


def test_event_intervals_dependency_order_and_local_failure_scope():
    log = trace.EventLog("public-events")
    with log.event("setup") as first, log.event("child", parent=first):
        pass
    with log.event("after", dependencies=(first,)):
        pass
    with pytest.raises(ValueError), log.event("failed"):
        raise ValueError("private diagnostic must not appear in event inventory")
    events = log.inventory()["events"]
    assert (
        events[0]["start_ns"] <= events[1]["start_ns"] <= events[1]["end_ns"] <= events[0]["end_ns"]
    )
    assert events[2]["start_ns"] >= events[0]["end_ns"] and events[3]["status"] == "failed"
    assert events[3]["error_class"] == "ValueError" and "diagnostic" not in json.dumps(events)


def test_unfinished_failed_or_missing_dependencies_cannot_authorize_next_event():
    log = trace.EventLog("public-events")
    with (
        log.event("running") as running,
        pytest.raises(ValueError),
        log.event("early", dependencies=(running,)),
    ):
        pass
    with pytest.raises(ValueError), log.event("bad") as failed:
        raise ValueError("local failure")
    for dependencies in ((failed,), (999,), (True,)):
        with pytest.raises(ValueError), log.event("blocked", dependencies=dependencies):
            pass
    with pytest.raises(ValueError), log.event("orphan", parent=running):
        pass
    assert len(log.inventory()["events"]) == 2


def test_failed_background_acquisition_cannot_silently_fall_back_to_remote(make_trace):
    f = make_trace()
    f.snapshot_failure = True
    job = f.trace.start_acquisition(deadline_ns=deadline(), cpu=min(os.sched_getaffinity(0)))
    with pytest.raises(RuntimeError):
        job.join(deadline_ns=deadline())
    with pytest.raises(RuntimeError):
        f.query(policy="prefetch")
    assert f.trace.inventory()["failed"] and not f.encrypted


def test_late_acquisition_after_owner_update_cannot_publish_old_cache(make_trace):
    f = make_trace()
    f.block_snapshot = True
    job = f.trace.start_acquisition(deadline_ns=deadline(), cpu=min(os.sched_getaffinity(0)))
    assert f.snapshot_entered.wait(1)
    updated, _, c = f.update()
    f.trace.advance(updated.pin, updated.packet, cache_context=c, deadline_ns=deadline())
    f.snapshot_release.set()
    with pytest.raises(RuntimeError):
        job.join(deadline_ns=deadline())
    assert not f.cache.inventory()["active"] and f.trace.inventory()["failed"]


def test_inflight_old_receipt_after_update_cannot_reach_private_finish(make_trace):
    f = make_trace()
    f.block_search = True
    errors = []

    def run_query():
        try:
            f.query()
        except Exception as error:
            errors.append(error)

    worker = threading.Thread(target=run_query)
    worker.start()
    try:
        assert f.search_entered.wait(1)
        updated, _, c = f.update()
        f.trace.advance(updated.pin, updated.packet, cache_context=c, deadline_ns=deadline())
    finally:
        f.search_release.set()
        worker.join(2)
    assert not worker.is_alive() and len(errors) == 1
    assert f.private_entries == f.decoder_creations == 0 and f.trace.inventory()["failed"]


def test_wrong_cache_binding_cannot_advance_either_owner_authority(make_trace):
    f = make_trace()
    old = f.descriptor.metadata()
    updated, _, c = f.update()
    with pytest.raises(ValueError):
        f.trace.advance(
            updated.pin,
            updated.packet,
            cache_context=replace(c, snapshot_id=public.token("foreign")),
            deadline_ns=deadline(),
        )
    assert f.descriptor.metadata() == old and f.cache.current_context == trace._cache_context(old)


def test_prefetch_can_explicitly_close_remote_lifetime_and_keep_current_cache(make_trace):
    f = make_trace()
    f.trace.acquire(deadline_ns=deadline())
    f.trace.stop_remote()
    assert f.query(policy="prefetch").distances == reference(f.rows, 3, 0)
    with pytest.raises(RuntimeError):
        f.query(label="unavailable", policy="remote")
    assert f.keys._secret is not None and not f.keys._closed and not f.encrypted


@pytest.mark.parametrize("word", [True, -1, 8])
def test_invalid_owner_query_word_cannot_consume_encryption_or_events(make_trace, word):
    f = make_trace()
    with pytest.raises(ValueError):
        f.query(word)
    assert not f.encrypted and not f.rpc_calls and not f.log.inventory()["events"]


def test_full_acquisition_is_consumed_once_and_independent_cache_starts_absent(make_trace):
    a = make_trace(mode=None)
    a.trace.acquire(deadline_ns=deadline())
    b = make_trace(mode=None)
    assert a.trace.cache_ready() and not b.trace.cache_ready()
    with pytest.raises(RuntimeError):
        a.trace.acquire(deadline_ns=deadline())
    assert a.rpc_calls == [b"snapshot"] and b.rpc_calls == []


def test_malformed_cache_body_is_not_published_and_disables_trajectory(make_trace):
    f = make_trace()
    f.snapshot = replace(
        f.snapshot, packet=f.snapshot.packet[:-1] + bytes([f.snapshot.packet[-1] ^ 1])
    )
    with pytest.raises(ValueError):
        f.trace.acquire(deadline_ns=deadline())
    assert not f.cache.inventory()["active"] and f.trace.inventory()["failed"]


def test_background_CPU_can_differ_from_narrowed_owner_thread(make_trace):
    f = make_trace(mode=None)
    allowed = sorted(os.sched_getaffinity(0))
    assert len(allowed) >= 2, "Frozen public host has at least two permitted CPUs"
    errors = []

    def pinned_owner():
        try:
            os.sched_setaffinity(0, {allowed[0]})
            job = f.trace.start_acquisition(deadline_ns=deadline(), cpu=allowed[1])
            job.join(deadline_ns=deadline())
            assert job.inventory()["observed_affinity"] == [allowed[1]]
            assert os.sched_getaffinity(0) == {allowed[0]}
        except Exception as error:
            errors.append(error)

    worker = threading.Thread(target=pinned_owner)
    worker.start()
    worker.join(3)
    assert not worker.is_alive() and not errors
    assert os.sched_getaffinity(0) == set(allowed) and f.trace.cache_ready()


def test_inventory_does_not_expose_mutable_references_to_recorded_results(make_trace):
    f = make_trace()
    f.query()
    external = f.trace.inventory()
    external["results"][0]["nearest"][0]["distance"] = 100
    external["results"][0]["path"] = "changed"
    current = f.trace.inventory()["results"][0]
    assert current["nearest"][0]["distance"] == 0 and current["path"] == "remote"


def test_expired_background_join_closes_endpoint_and_disables_fallback(make_trace):
    f = make_trace()
    f.block_snapshot = True
    job = f.trace.start_acquisition(deadline_ns=deadline(), cpu=min(os.sched_getaffinity(0)))
    assert f.snapshot_entered.wait(1)
    try:
        with pytest.raises(TimeoutError):
            job.join(deadline_ns=time.perf_counter_ns() - 1)
        assert f.endpoint._closed and f.trace.inventory()["failed"]
        with pytest.raises(RuntimeError):
            f.query(policy="prefetch")
    finally:
        f.snapshot_release.set()
        job._thread.join(2)
    assert not job.inventory()["alive"]
