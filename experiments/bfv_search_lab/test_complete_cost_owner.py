"""Q77/R1 public custody/control/score units, with no real private arithmetic.

The pk/ternary material below is public grammar data, not a valid HE key pair.
The private backend is always a public plaintext stub. Signed packets use the
two existing public UNIT-ONLY signing contexts and do not assert native
admission. Real HE correctness and worker isolation require the later cohort.
"""

import copy
from dataclasses import replace
import hashlib
import os
import pickle
import signal
import threading
from types import SimpleNamespace

import gmpy2
import pytest

from experiments.bfv_search_lab import complete_cost_owner as owner
from experiments.bfv_search_lab import complete_cost_protocol as receipt
from experiments.bfv_search_lab import lifecycle_shared_query as life
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_certificate as cert
from experiments.bfv_search_lab import shared_query_client_context as context
from experiments.bfv_search_lab import test_complete_cost_protocol as public

owners = public.owners


def material(profile):
    p = cert.geometry(profile)
    a = tuple(gmpy2.mpz((i * 7) % p.q) for i in range(p.n))
    b = tuple(gmpy2.mpz(p.q - 1 - i) for i in range(p.n))
    # Independent byte-by-byte reference to the existing Q120 public hash law.
    digest = hashlib.sha256(f"cuhepy-shallow-bgv-v1:{p.n}:{p.t}:{p.q}:{p.eta}".encode())
    for polynomial in (a, b):
        digest.update(b"".join(int(value).to_bytes(15, "little") for value in polynomial))
    key_id = digest.hexdigest()
    pk = bgv.PublicKey(p.n, p.t, gmpy2.mpz(p.q), p.eta, a, b, key_id)
    sk = bgv.SecretKey(tuple(gmpy2.mpz((0, 1, p.q - 1)[i % 3]) for i in range(p.n)), key_id)
    return p, pk, sk


def descriptor(signing_owner, geometry, key_id, count):
    ids = tuple((1 << 64) - 1 - i for i in range(count))
    raw = b"".join(x.to_bytes(8, "little") for x in ids)
    plans = tuple(
        cert.TrustedPlan(
            geometry,
            count,
            key_id,
            hashlib.sha256(raw).digest(),
            public.token(mode + "snapshot"),
            public.token(mode + "policy"),
            public.token(mode + "code"),
            mode,
        )
        for mode in cert.MODES
    )
    packets = tuple(cert.make_certificate(plan) for plan in plans)
    modes = tuple(
        context.ModeBinding(
            plan.mode,
            1,
            plan.snapshot_id,
            plan.policy_digest,
            plan.code_digest,
            cert.certificate_digest(packet),
        )
        for plan, packet in zip(plans, packets, strict=True)
    )
    cache = context.CacheBinding(
        public.token("cachekey"), public.token("cache"), 1, context.cache_ids_digest(raw, count)
    )
    delivery = context.seal_descriptor(
        ids,
        signing_owner,
        namespace=public.token("namespace"),
        revision=public.token("revision"),
        epoch=1,
        geometry=geometry,
        key_id=key_id,
        cache=cache,
        modes=modes,
        certificates=packets,
    )
    handle = context.DescriptorClient(signing_owner.public_key().public_bytes_raw(), delivery.pin)
    metadata = handle.acquire(delivery.packet)
    return handle, metadata, delivery


@pytest.fixture
def factory(monkeypatch, owners):
    made = []

    def make(*, profile=0, count=None, mode=cert.MODES[0]):
        p, pk, sk = material(profile)
        count = p.n + 1 if count is None else count
        keys = owner.OwnerKeyCustody(pk, sk, p)
        handle, metadata, delivery = descriptor(owners[0], p, bytes.fromhex(pk.key_id), count)
        anchors = tuple(
            (choice, owners[1].public_key().public_bytes_raw()) for choice in cert.MODES
        )
        client = owner.OwnerClient(handle, anchors, keys)
        distances = tuple((i // 2) % (p.dimension + 1) for i in range(count))
        values = [(p.dimension - 2 * distance) % p.t for distance in distances]
        values.extend([0] * (((count + p.n - 1) // p.n) * p.n - count))
        polynomials = [values[i : i + p.n] for i in range(0, len(values), p.n)]
        f = SimpleNamespace(
            geometry=p,
            pk=pk,
            sk=sk,
            keys=keys,
            handle=handle,
            metadata=metadata,
            delivery=delivery,
            anchors=anchors,
            client=client,
            mode=mode,
            distances=distances,
            polynomials=polynomials,
            creations=0,
            decodes=0,
            closes=0,
            failure=None,
            close_failure=False,
            blocking=False,
            entered=threading.Event(),
            release=threading.Event(),
            pairs=[],
            instances=[],
            clients=[client],
        )

        class PublicDecoderStub:
            def __init__(self, selected_pk, selected_sk, *, bits):
                f.creations += 1
                assert selected_pk == pk and selected_sk == sk and bits == p.p.bit_length()
                if f.failure == "initialize":
                    raise RuntimeError("unit private diagnostic")
                self.modulus = gmpy2.mpz(p.p + (f.failure == "modulus"))
                f.instances.append(self)

            def decode_packed(self, pairs):
                f.decodes += 1
                f.pairs.append(pairs)
                assert type(pairs) is tuple and all(type(pair) is tuple for pair in pairs)
                if f.blocking:
                    f.entered.set()
                    assert f.release.wait(5)
                if f.failure == "decode":
                    raise RuntimeError("unit private diagnostic")
                return copy.deepcopy(f.polynomials)

            def close(self):
                f.closes += 1
                if f.close_failure:
                    raise RuntimeError("unit private cleanup diagnostic")

        monkeypatch.setattr(owner.private, "PrivateDecoder", PublicDecoderStub)

        def attempt(*, nonce="nonce", choice=mode, selected_client=client):
            original = public.original(owners[0], metadata, choice, nonce=nonce)
            pending = selected_client.begin(choice, original)
            packet = receipt._signed_packet(
                owners[1], metadata, choice, pending.binding, public.frame(metadata)
            )
            return pending, packet

        f.attempt = attempt
        made.append(f)
        return f

    yield make
    for f in made:
        f.release.set()
        for client in f.clients:
            client.close()
        f.keys.close()
        f.handle.close()


@pytest.mark.parametrize("profile", [0, 1])
@pytest.mark.parametrize("coverage", ["one", "two", "three", "full", "partial", "double"])
def test_complete_distances_tails_and_original_ordinal_ties(factory, profile, coverage):
    n = cert.geometry(profile).n
    count = {"one": 1, "two": 2, "three": 3, "full": n, "partial": n + 1, "double": 2 * n}[coverage]
    f = factory(profile=profile, count=count)
    assert f.creations == f.decodes == 0
    pending, packet = f.attempt()
    answer = pending.finish(packet)
    assert answer.distances == f.distances
    order = sorted(range(count), key=lambda i: (f.distances[i], i))[:3]
    assert answer.nearest == tuple(owner.Match(i, f.metadata.ids[i], f.distances[i]) for i in order)
    assert f.creations == f.decodes == 1
    assert f.pairs[0] == tuple(
        tuple(pair)
        for pair in receipt._unpack(public.frame(f.metadata), receipt.frame_limit(f.metadata))[1]
    )
    with pytest.raises(life.ConsumedRequestError):
        pending.finish(packet)
    assert f.decodes == 1


@pytest.mark.parametrize("mode", cert.MODES)
def test_each_fixed_receipt_mode_reaches_only_the_owner_stub(factory, mode):
    f = factory(mode=mode)
    pending, packet = f.attempt()
    assert pending.finish(packet).distances == f.distances


@pytest.mark.parametrize(
    "fault",
    [
        "type",
        "degree",
        "plaintext",
        "modulus",
        "eta",
        "short_a",
        "list_b",
        "bool_coefficient",
        "large_coefficient",
        "key_id",
    ],
)
def test_public_key_shape_profile_and_fingerprint_before_private_initialization(factory, fault):
    f = factory()
    changes = {
        "degree": {"n": True},
        "plaintext": {"t": f.pk.t + 2},
        "modulus": {"q": f.pk.q + 1},
        "eta": {"eta": f.pk.eta + 1},
        "short_a": {"a": f.pk.a[:-1]},
        "list_b": {"b": list(f.pk.b)},
        "bool_coefficient": {"a": (True, *f.pk.a[1:])},
        "large_coefficient": {"b": (f.pk.q, *f.pk.b[1:])},
        "key_id": {"key_id": "0" * 64},
    }
    pk = object() if fault == "type" else replace(f.pk, **changes[fault])
    with pytest.raises(ValueError):
        owner.OwnerKeyCustody(pk, f.sk, f.geometry)
    assert f.creations == 0


@pytest.mark.parametrize("fault", ["type", "id", "short", "list", "bool", "nonternary", "negative"])
def test_secret_import_metadata_rejected_without_native_work(factory, fault):
    f = factory()
    changes = {
        "id": {"key_id": "0" * 64},
        "short": {"s": f.sk.s[:-1]},
        "list": {"s": list(f.sk.s)},
        "bool": {"s": (True, *f.sk.s[1:])},
        "nonternary": {"s": (2, *f.sk.s[1:])},
        "negative": {"s": (-1, *f.sk.s[1:])},
    }
    sk = object() if fault == "type" else replace(f.sk, **changes[fault])
    with pytest.raises(ValueError):
        owner.OwnerKeyCustody(f.pk, sk, f.geometry)
    assert f.creations == 0


@pytest.mark.parametrize(
    "fault", ["foreign_key", "foreign_geometry", "closed_key", "descriptor_type", "key_type"]
)
def test_client_requires_its_complete_trusted_local_key_context(factory, owners, fault):
    f = factory()
    handle, keys = f.handle, f.keys
    if fault == "foreign_key":
        handle, _, _ = descriptor(
            owners[0], f.geometry, public.token("foreign"), len(f.metadata.ids)
        )
    elif fault == "foreign_geometry":
        p, pk, sk = material(1)
        keys = owner.OwnerKeyCustody(pk, sk, p)
    elif fault == "closed_key":
        keys.close()
    elif fault == "descriptor_type":
        handle = object()
    else:
        keys = object()
    with pytest.raises((ValueError, RuntimeError)):
        owner.OwnerClient(handle, f.anchors, keys)
    if fault == "foreign_key":
        handle.close()
    if fault == "foreign_geometry":
        keys.close()
    assert f.creations == 0


@pytest.mark.parametrize(
    "fault",
    ["truncated", "signature", "foreign_request", "wrong_mode", "malformed_frame", "stale_pin"],
)
def test_public_rejection_cannot_initialize_or_decode_and_consumes_attempt(factory, owners, fault):
    f = factory()
    pending, packet = f.attempt()
    if fault == "truncated":
        packet = packet[:-1]
    elif fault == "signature":
        outer = receipt._unpack(packet, 4096)
        packet = receipt._pack([outer[0], outer[1], bytes(64)])
    elif fault == "foreign_request":
        packet = receipt._signed_packet(
            owners[1],
            f.metadata,
            f.mode,
            replace(pending.binding, nonce=public.token("other")),
            public.frame(f.metadata),
        )
    elif fault == "wrong_mode":
        choice = cert.MODES[1]
        original = public.original(owners[0], f.metadata, choice, nonce="other")
        binding = receipt.original_binding(
            original, owners[0].public_key().public_bytes_raw(), f.metadata, choice
        )
        packet = receipt._signed_packet(
            owners[1], f.metadata, choice, binding, public.frame(f.metadata)
        )
    elif fault == "malformed_frame":
        packet = receipt._pack(
            [
                receipt.ENVELOPE_TAG,
                receipt._payload(f.metadata, f.mode, pending.binding, b"invalid frame"),
                b"",
            ]
        )
        outer = receipt._unpack(packet, 4096)
        packet = receipt._pack([outer[0], outer[1], owners[1].sign(receipt.SIGN_DOMAIN + outer[1])])
    else:
        f.handle.advance_current(
            replace(
                f.delivery.pin,
                epoch=2,
                revision=public.token("new revision"),
                payload_digest=public.token("new"),
            )
        )
    with pytest.raises((ValueError, life.StaleSnapshotError)):
        pending.finish(packet)
    assert f.creations == f.decodes == 0
    with pytest.raises(life.ConsumedRequestError):
        pending.finish(packet)
    assert not f.keys._closed


@pytest.mark.parametrize(
    "fault",
    [
        "groups",
        "outer_tuple",
        "row_length",
        "row_tuple",
        "negative",
        "modulus",
        "bool",
        "float",
        "out_of_range",
        "parity",
        "tail",
        "last_tail_bool",
    ],
)
def test_every_decoded_lane_validated_and_failed_context_disabled(factory, fault):
    f = factory()
    p = f.geometry
    if fault == "groups":
        f.polynomials.pop()
    elif fault == "outer_tuple":
        f.polynomials = tuple(f.polynomials)
    elif fault == "row_length":
        f.polynomials[-1].pop()
    elif fault == "row_tuple":
        f.polynomials[-1] = tuple(f.polynomials[-1])
    elif fault in ("tail", "last_tail_bool"):
        f.polynomials[-1][-1] = 1 if fault == "tail" else False
    else:
        values = {
            "negative": -1,
            "modulus": p.t,
            "bool": True,
            "float": 0.0,
            "out_of_range": p.dimension + 2,
            "parity": p.dimension - 1,
        }
        f.polynomials[0][0] = values[fault]
    pending, packet = f.attempt()
    with pytest.raises(receipt.PrivateFinishFailed, match="attempt stays consumed"):
        pending.finish(packet)
    assert f.creations == f.decodes == f.closes == 1
    assert f.keys._closed and f.keys._secret is None and f.keys._decoder is None
    with pytest.raises(life.ConsumedRequestError):
        pending.finish(packet)
    with pytest.raises(RuntimeError, match="Closed"):
        f.attempt(nonce="new")
    assert f.decodes == 1


@pytest.mark.parametrize("failure", ["initialize", "modulus", "decode"])
def test_backend_failure_coarse_consumed_and_no_new_private_retry(factory, failure):
    f = factory()
    f.failure, f.close_failure = failure, True
    pending, packet = f.attempt()
    with pytest.raises(receipt.PrivateFinishFailed) as error:
        pending.finish(packet)
    assert "diagnostic" not in str(error.value)
    assert f.keys._closed and f.keys._secret is None
    with pytest.raises(RuntimeError, match="Closed"):
        f.attempt(nonce="new")
    assert f.creations == 1 and f.decodes == (failure == "decode")


def test_lazy_backend_reused_and_per_client_close_keeps_owner_keys(factory):
    f = factory()
    for i in range(3):
        pending, packet = f.attempt(nonce="nonce" + str(i))
        assert pending.finish(packet).distances == f.distances
    assert f.creations == 1 and f.decodes == 3
    f.client.close()
    f.client.close()
    assert not f.keys._closed and f.closes == 0
    f.keys.close()
    f.keys.close()
    assert f.closes == 1 and f.keys._secret is None and f.keys._decoder is None


def test_close_before_receipt_claim_never_creates_private_backend(factory):
    f = factory()
    pending, packet = f.attempt()
    f.keys.close()
    with pytest.raises(receipt.PrivateFinishFailed):
        pending.finish(packet)
    assert f.creations == f.decodes == 0
    with pytest.raises(life.ConsumedRequestError):
        pending.finish(packet)


@pytest.mark.parametrize("kind", ["keys", "client", "attempt"])
@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_custody_client_and_attempt_cannot_copy_or_serialize(factory, kind, operation):
    f = factory()
    pending, _ = f.attempt()
    selected = {"keys": f.keys, "client": f.client, "attempt": pending}[kind]
    with pytest.raises(TypeError):
        operation(selected)
    assert f.creations == 0


@pytest.mark.parametrize("kind", ["keys", "client", "attempt"])
def test_inherited_use_rejected_before_a_parent_thread_mutex(factory, owners, kind):
    f = factory()
    pending, packet = f.attempt()
    lock = f.keys._lock if kind == "keys" else f.client._lock
    held, release = threading.Event(), threading.Event()

    def holding():
        with lock:
            held.set()
            assert release.wait(5)

    thread = threading.Thread(target=holding)
    thread.start()
    assert held.wait(3)
    try:
        pid = os.fork()
        if pid == 0:
            signal.alarm(3)
            try:
                if kind == "keys":
                    f.keys.close()
                elif kind == "client":
                    f.client.begin(f.mode, public.original(owners[0], f.metadata, f.mode))
                else:
                    pending.finish(packet)
            except RuntimeError:
                os._exit(0)
            except BaseException:
                os._exit(2)
            os._exit(3)
        _, status = os.waitpid(pid, 0)
        assert status == 0
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive() and f.creations == 0


def test_two_finishes_claim_once_under_concurrency(factory):
    f = factory()
    pending, packet = f.attempt()
    results, errors = [], []
    start = threading.Barrier(3)

    def finish():
        start.wait()
        try:
            results.append(pending.finish(packet))
        except Exception as error:
            errors.append(type(error))

    threads = [threading.Thread(target=finish) for _ in range(2)]
    for thread in threads:
        thread.start()
    start.wait()
    for thread in threads:
        thread.join(3)
    assert all(not thread.is_alive() for thread in threads)
    assert len(results) == 1 and results[0].distances == f.distances
    assert errors == [life.ConsumedRequestError] and f.creations == f.decodes == 1


def test_key_close_linearizes_after_an_active_decode(factory):
    f = factory()
    f.blocking = True
    pending, packet = f.attempt()
    results, errors = [], []

    def finish():
        try:
            results.append(pending.finish(packet))
        except Exception as error:
            errors.append(type(error))

    closing = threading.Event()
    finish_thread = threading.Thread(target=finish)
    finish_thread.start()
    assert f.entered.wait(3)

    def close():
        closing.set()
        f.keys.close()

    close_thread = threading.Thread(target=close)
    close_thread.start()
    assert closing.wait(3)
    f.release.set()
    finish_thread.join(3)
    close_thread.join(3)
    assert not finish_thread.is_alive() and not close_thread.is_alive()
    assert not errors and results[0].distances == f.distances
    assert f.keys._closed and f.closes == 1


@pytest.mark.parametrize("fault", ["client", "attempt", "metadata", "unreserved"])
def test_owner_attempt_requires_actual_reserved_context(factory, fault):
    f = factory()
    pending, _ = f.attempt()
    client, raw, metadata = f.client, pending._attempt, f.metadata
    if fault == "client":
        client = object()
    elif fault == "attempt":
        raw = object()
    elif fault == "metadata":
        metadata = replace(metadata, key_id=public.token("foreign"))
    else:
        raw = receipt._Attempt(
            f.client._receiver,
            metadata,
            f.mode,
            replace(pending.binding, nonce=public.token("unused")),
        )
    with pytest.raises(ValueError):
        owner.OwnerAttempt(client, raw, metadata)
    assert f.creations == 0
