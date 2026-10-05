"""Q77 public receipt faults and local ownership; no HE key or private HE work.

The all-zero compact rows and placeholder seeded-query bytes are grammar
fixtures, not valid owner-origin HE examples. Journal fixtures explicitly start
from a trusted reserved record; they do not claim native admission was run.
"""

import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import pickle
import select
import signal
import socket
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import gmpy2
import msgpack
import pytest

from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import complete_cost_protocol as result
from experiments.bfv_search_lab import lifecycle_shared_query as life
from experiments.bfv_search_lab import shared_query_certificate as cert
from experiments.bfv_search_lab import shared_query_client_context as context


def token(label):
    return hashlib.sha256(label.encode()).digest()


@pytest.fixture(scope="session")
def owners():
    # Exactly two public, deterministic UNIT-ONLY Ed25519 contexts.
    return tuple(
        Ed25519PrivateKey.from_private_bytes(token(label))
        for label in (
            "Q77 public unit owner",
            "Q77 public unit verifier",
        )
    )


def descriptor(owner, *, profile=0, count=5, epoch=1):
    p = cert.geometry(profile)
    ids = tuple((1 << 64) - 1 - i for i in range(count))
    raw = b"".join(x.to_bytes(8, "little") for x in ids)
    digest = hashlib.sha256(raw).digest()
    plans = tuple(
        cert.TrustedPlan(
            p,
            count,
            token("key"),
            digest,
            token(mode + str(epoch)),
            token(mode + "policy"),
            token(mode + "code"),
            mode,
        )
        for mode in cert.MODES
    )
    packets = tuple(cert.make_certificate(plan) for plan in plans)
    modes = tuple(
        context.ModeBinding(
            plan.mode,
            epoch,
            plan.snapshot_id,
            plan.policy_digest,
            plan.code_digest,
            cert.certificate_digest(packet),
        )
        for plan, packet in zip(plans, packets, strict=True)
    )
    cache = context.CacheBinding(
        token("cachekey"), token("cache" + str(epoch)), epoch, context.cache_ids_digest(raw, count)
    )
    delivery = context.seal_descriptor(
        ids,
        owner,
        namespace=token("namespace"),
        revision=token("revision" + str(epoch)),
        epoch=epoch,
        geometry=p,
        key_id=token("key"),
        cache=cache,
        modes=modes,
        certificates=packets,
    )
    handle = context.DescriptorClient(owner.public_key().public_bytes_raw(), delivery.pin)
    metadata = handle.acquire(delivery.packet)
    return handle, metadata, delivery


def frame(metadata):
    p = metadata.geometry
    header = [
        "cuhepy-lab-bgv-compact-v1",
        p.n,
        p.t,
        p.p.to_bytes((p.p.bit_length() + 7) // 8, "little"),
        metadata.key_id,
        len(metadata.ids),
        p.dimension,
    ]
    groups = (len(metadata.ids) + p.n - 1) // p.n
    width = (p.n * p.p.bit_length() + 7) // 8
    return auth._pack([header, [[bytes(width), bytes(width)] for _ in range(groups)]])


def original(owner, metadata, mode, *, nonce="nonce"):
    selected = metadata.mode(mode)
    return auth.sign_request(
        selected.snapshot_id,
        selected.epoch,
        selected.policy_digest,
        token(nonce),
        b"public query grammar fixture",
        owner,
    )


def client_fixture(owners, **kwargs):
    handle, metadata, delivery = descriptor(owners[0], **kwargs)
    anchors = tuple((mode, owners[1].public_key().public_bytes_raw()) for mode in cert.MODES)
    return result.ResultClient(handle, anchors), metadata, delivery


def trusted_authorization(tmp_path, owner, metadata, binding, admitted_frame):
    """Only tests the journal-claim bridge, not a public native predicate."""
    journal = life.LocalJournal(
        tmp_path / "journal.sqlite",
        owner.public_key().public_bytes_raw(),
        binding.policy_digest,
        token("scope"),
    )
    with journal._transaction() as connection:
        connection.execute(
            "INSERT INTO snapshot VALUES(1,?,?,?)",
            (binding.snapshot_id, binding.epoch.to_bytes(8, "little"), binding.ids_digest),
        )
        connection.execute(
            "INSERT INTO attempts(nonce,binding,snapshot,epoch,state) VALUES(?,?,?,?,?)",
            (
                binding.nonce,
                life._binding_bytes(binding),
                binding.snapshot_id,
                binding.epoch.to_bytes(8, "little"),
                "reserved",
            ),
        )
    authorization = journal._authorize(
        life.Reservation(journal.journal_id, binding), token("reply"), admitted_frame
    )
    assert authorization is not None
    return journal, authorization


@pytest.mark.parametrize("mode", cert.MODES)
def test_complete_result_requires_durable_claim_and_only_one_private_finish(owners, tmp_path, mode):
    client, metadata, _ = client_fixture(owners)
    attempt = client.begin(mode, original(owners[0], metadata, mode))
    expected = frame(metadata)
    journal, authorization = trusted_authorization(
        tmp_path, owners[0], metadata, attempt.binding, expected
    )
    signer = result.LocalResultSigner(journal, owners[1], client._descriptor)
    packet = signer.issue(authorization, mode)
    status = journal.status(attempt.binding.nonce)
    assert (
        status["state"] == "delivered" and status["authorized_once"] == status["callback_once"] == 1
    )
    calls = []
    assert (
        attempt.finish(packet, lambda data: calls.append(data) or "owner-only-value")
        == "owner-only-value"
    )
    assert calls == [expected]
    with pytest.raises(life.ConsumedRequestError):
        attempt.finish(packet, lambda _: calls.append(b"second"))
    with pytest.raises(life.ConsumedRequestError):
        signer.issue(authorization, mode)
    assert len(calls) == 1
    signer.close()
    journal.close()


RECEIPT_FAULTS = tuple(
    [(i,) for i in range(8)] + [(6, i) for i in range(6)] + [(7, i) for i in range(6)]
)


@pytest.mark.parametrize("path", RECEIPT_FAULTS, ids=lambda path: ".".join(map(str, path)))
def test_signed_foreign_receipt_metadata_cannot_reach_private_callback(owners, path):
    client, metadata, _ = client_fixture(owners)
    mode = cert.MODES[0]
    attempt = client.begin(mode, original(owners[0], metadata, mode))
    fields = msgpack.unpackb(
        result._payload(metadata, mode, attempt.binding, frame(metadata)), raw=False
    )
    target = fields
    for part in path[:-1]:
        target = target[part]
    old = target[path[-1]]
    target[path[-1]] = old + 1 if type(old) is int else (b"foreign" if type(old) is bytes else [])
    payload = auth._pack(fields)
    packet = auth._pack(
        [result.ENVELOPE_TAG, payload, owners[1].sign(result.SIGN_DOMAIN + payload)]
    )
    calls = []
    with pytest.raises(ValueError):
        attempt.finish(packet, lambda _: calls.append(True))
    assert calls == []
    with pytest.raises(life.ConsumedRequestError):
        attempt.finish(
            result._signed_packet(owners[1], metadata, mode, attempt.binding, frame(metadata)),
            lambda _: calls.append(True),
        )
    assert calls == []


@pytest.mark.parametrize(
    "part",
    [
        "tag",
        "payload",
        "signature",
        "extra",
        "truncated",
        "foreign-key",
        "oversize",
        "noncanonical",
    ],
)
def test_result_envelope_faults_never_call_private_code(owners, part):
    client, metadata, _ = client_fixture(owners)
    mode = cert.MODES[0]
    attempt = client.begin(mode, original(owners[0], metadata, mode))
    packet = result._signed_packet(owners[1], metadata, mode, attempt.binding, frame(metadata))
    fields = msgpack.unpackb(packet, raw=False)
    if part == "tag":
        fields[0] = b"other"
    if part == "payload":
        fields[1] = fields[1][:-1] + bytes([fields[1][-1] ^ 1])
    if part == "signature":
        fields[2] = fields[2][:-1] + bytes([fields[2][-1] ^ 1])
    if part == "extra":
        fields.append(b"extra")
    if part == "foreign-key":
        fields[2] = owners[0].sign(result.SIGN_DOMAIN + fields[1])
    packet = auth._pack(fields)
    if part == "truncated":
        packet = packet[:-1]
    if part == "oversize":
        packet = bytes(result.frame_limit(metadata) + 2049)
    if part == "noncanonical":
        packet = b"\xdc\x00\x03" + packet[1:]
    calls = []
    with pytest.raises(ValueError):
        attempt.finish(packet, lambda _: calls.append(True))
    assert not calls


FRAME_FAULTS = tuple(
    [("header", i) for i in range(7)]
    + [
        (x, 0)
        for x in (
            "extra-top",
            "missing-group",
            "extra-group",
            "missing-component",
            "extra-component",
            "short-row",
            "long-row",
            "noncanonical-coefficient",
            "wrong-row-type",
            "map",
            "trailing",
            "bool-header",
            "noncanonical-encoding",
        )
    ]
)


@pytest.mark.parametrize("fault", FRAME_FAULTS, ids=lambda value: str(value))
def test_even_signed_frame_grammar_faults_reject_before_private_finish(owners, fault):
    client, metadata, _ = client_fixture(owners)
    mode = cert.MODES[0]
    attempt = client.begin(mode, original(owners[0], metadata, mode))
    fields = msgpack.unpackb(frame(metadata), raw=False)
    kind, at = fault
    if kind == "header":
        fields[0][at] = b"bad"
    if kind == "extra-top":
        fields.append([])
    if kind == "missing-group":
        fields[1] = []
    if kind == "extra-group":
        fields[1].append(fields[1][0])
    if kind == "missing-component":
        fields[1][0].pop()
    if kind == "extra-component":
        fields[1][0].append(fields[1][0][0])
    if kind == "short-row":
        fields[1][0][0] = fields[1][0][0][:-1]
    if kind == "long-row":
        fields[1][0][0] += b"\0"
    if kind == "noncanonical-coefficient":
        width = len(fields[1][0][0])
        fields[1][0][0] = int(metadata.geometry.p).to_bytes(width, "little")
    if kind == "wrong-row-type":
        fields[1][0][0] = "zero"
    if kind == "map":
        fields[1] = {}
    if kind == "bool-header":
        fields[0][5] = True
    bad = auth._pack(fields)
    if kind == "trailing":
        bad += b"\0"
    if kind == "noncanonical-encoding":
        bad = b"\xdc\x00\x02" + bad[1:]
    payload = result._payload(metadata, mode, attempt.binding, bad)
    packet = auth._pack(
        [result.ENVELOPE_TAG, payload, owners[1].sign(result.SIGN_DOMAIN + payload)]
    )
    calls = []
    with pytest.raises(ValueError):
        attempt.finish(packet, lambda _: calls.append(True))
    assert not calls


@pytest.mark.parametrize(
    "profile,count", [(0, 5), (0, 17), (1, 32), (2, 8224), (2, 16384), (2, 32768)]
)
def test_public_full_coordinate_coverage_and_nonzero_ciphertext_tails(owners, profile, count):
    _, metadata, _ = descriptor(owners[0], profile=profile, count=count)
    fields = msgpack.unpackb(frame(metadata), raw=False)
    p = metadata.geometry
    coefficients = [0] * p.n
    coefficients[-1] = p.p - 1
    fields[1][-1][1] = gmpy2.pack(coefficients, p.p.bit_length()).to_bytes(
        len(fields[1][-1][1]), "little"
    )
    valid = auth._pack(fields)
    assert (
        result.validate_frame(valid, metadata) == valid
    )  # Ciphertext tails are not required zero.


@pytest.mark.parametrize("field", [0, 1, 2, 3, 4])
def test_signed_foreign_original_does_not_reserve_a_private_attempt(owners, field):
    client, metadata, _ = client_fixture(owners)
    mode = cert.MODES[0]
    good = original(owners[0], metadata, mode)
    fields = msgpack.unpackb(msgpack.unpackb(good, raw=False)[1], raw=False)
    fields[field] = True if field == 1 else (b"wrong" if field != 4 else b"")
    bad = auth._sign(auth.QUERY_TAG, auth._pack(fields), owners[0])
    with pytest.raises(ValueError):
        client.begin(mode, bad)
    assert not client._attempts
    assert client.begin(mode, good).binding.nonce == token("nonce")


def test_stale_descriptor_rejects_old_result_before_private_callback(owners):
    client, metadata, _ = client_fixture(owners)
    mode = cert.MODES[0]
    attempt = client.begin(mode, original(owners[0], metadata, mode))
    packet = result._signed_packet(owners[1], metadata, mode, attempt.binding, frame(metadata))
    _, _, next_delivery = descriptor(owners[0], epoch=2)
    client._descriptor.advance_current(next_delivery.pin)
    client._descriptor.acquire(next_delivery.packet)
    calls = []
    with pytest.raises(life.StaleSnapshotError):
        attempt.finish(packet, lambda _: calls.append(True))
    assert not calls


def test_private_failure_is_coarse_and_consumed_without_retry(owners):
    client, metadata, _ = client_fixture(owners)
    mode = cert.MODES[0]
    attempt = client.begin(mode, original(owners[0], metadata, mode))
    packet = result._signed_packet(owners[1], metadata, mode, attempt.binding, frame(metadata))
    calls = []

    def private(_):
        calls.append(True)
        raise ValueError("unit-only private diagnostic must not appear")

    with pytest.raises(result.PrivateFinishFailed) as caught:
        attempt.finish(packet, private)
    assert "diagnostic" not in str(caught.value) and caught.value.__suppress_context__
    with pytest.raises(life.ConsumedRequestError):
        attempt.finish(packet, private)
    assert len(calls) == 1


def test_duplicate_original_mode_substitution_and_request_cap(owners, monkeypatch):
    client, metadata, _ = client_fixture(owners)
    mode = cert.MODES[0]
    original_packet = original(owners[0], metadata, mode)
    client.begin(mode, original_packet)
    with pytest.raises(life.ConsumedRequestError):
        client.begin(mode, original_packet)
    with pytest.raises(ValueError):
        client.begin(cert.MODES[1], original_packet)
    monkeypatch.setattr(result, "MAX_ATTEMPTS", 1)
    with pytest.raises(RuntimeError):
        client.begin(mode, original(owners[0], metadata, mode, nonce="other"))


@pytest.mark.parametrize(
    "tamper", ["frame", "reply-hash", "journal", "nonce", "policy", "snapshot", "epoch", "ids"]
)
def test_issuer_cannot_sign_a_counterfeit_authorization(owners, tmp_path, tamper):
    client, metadata, _ = client_fixture(owners)
    mode = cert.MODES[0]
    attempt = client.begin(mode, original(owners[0], metadata, mode))
    good_frame = frame(metadata)
    journal, authorization = trusted_authorization(
        tmp_path, owners[0], metadata, attempt.binding, good_frame
    )
    signer = result.LocalResultSigner(journal, owners[1], client._descriptor)
    if tamper == "frame":
        bad = replace(authorization, frame=good_frame[:-1])
    elif tamper == "reply-hash":
        bad = replace(authorization, reply_hash=token("wrong"))
    elif tamper == "journal":
        bad = replace(authorization, journal_id=token("wrong"))
    else:
        field = {
            "nonce": "nonce",
            "policy": "policy_digest",
            "snapshot": "snapshot_id",
            "epoch": "epoch",
            "ids": "ids_digest",
        }[tamper]
        value = authorization.binding.epoch + 1 if field == "epoch" else token("wrong")
        bad = replace(authorization, binding=replace(authorization.binding, **{field: value}))
    with pytest.raises((ValueError, life.LifecycleError)):
        signer.issue(bad, mode)
    assert journal.status(attempt.binding.nonce)["callback_once"] == 0
    journal.close()


def test_concurrent_owner_delivery_invokes_private_code_once(owners):
    client, metadata, _ = client_fixture(owners)
    mode = cert.MODES[0]
    attempt = client.begin(mode, original(owners[0], metadata, mode))
    packet = result._signed_packet(owners[1], metadata, mode, attempt.binding, frame(metadata))
    barrier, calls, outputs = threading.Barrier(3), [], []

    def worker():
        barrier.wait()
        try:
            outputs.append(attempt.finish(packet, lambda _: calls.append(True) or "value"))
        except life.ConsumedRequestError:
            outputs.append("consumed")

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(2)
    assert not any(thread.is_alive() for thread in threads)
    assert sorted(outputs) == ["consumed", "value"] and calls == [True]


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_client_and_attempt_ownership_cannot_be_copied(owners, operation):
    client, metadata, _ = client_fixture(owners)
    attempt = client.begin(cert.MODES[0], original(owners[0], metadata, cert.MODES[0]))
    for handle in (client, attempt):
        with pytest.raises(TypeError):
            operation(handle)


def test_closed_or_forked_handle_rejects_before_inherited_locks(owners):
    client, metadata, _ = client_fixture(owners)
    mode = cert.MODES[0]
    original_packet = original(owners[0], metadata, mode)
    client._lock.acquire()
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            client.begin(mode, original_packet)
            os.write(write_fd, b"bad")
        except RuntimeError:
            os.write(write_fd, b"rejected")
        finally:
            os._exit(0)
    os.close(write_fd)
    try:
        ready, _, _ = select.select([read_fd], [], [], 3)
        if not ready:
            os.kill(child, signal.SIGKILL)
        assert ready and os.read(read_fd, 32) == b"rejected"
    finally:
        client._lock.release()
        os.close(read_fd)
        os.waitpid(child, 0)
    client.close()
    with pytest.raises(RuntimeError):
        client.begin(mode, original_packet)


@pytest.mark.parametrize(
    "anchors", [None, [], (), (("bad", bytes(32)),), tuple((mode, b"short") for mode in cert.MODES)]
)
def test_received_or_incomplete_anchor_choices_are_not_supported(owners, anchors):
    handle, _, _ = descriptor(owners[0])
    with pytest.raises(ValueError):
        result.ResultClient(handle, anchors)


@pytest.mark.parametrize("path", [(3,), (6, 1), (7, 1)])
def test_signed_bool_integer_alias_is_not_the_exact_owner_payload(owners, path):
    client, metadata, _ = client_fixture(owners)
    mode = cert.MODES[0]
    attempt = client.begin(mode, original(owners[0], metadata, mode))
    fields = msgpack.unpackb(
        result._payload(metadata, mode, attempt.binding, frame(metadata)), raw=False
    )
    target = fields
    for at in path[:-1]:
        target = target[at]
    assert target[path[-1]] == 1
    target[path[-1]] = True
    payload = auth._pack(fields)
    packet = auth._pack(
        [result.ENVELOPE_TAG, payload, owners[1].sign(result.SIGN_DOMAIN + payload)]
    )
    calls = []
    with pytest.raises(ValueError):
        attempt.finish(packet, lambda _: calls.append(True))
    assert not calls


def test_signer_completion_failure_cannot_return_or_reissue_a_claimed_result(
    owners, tmp_path, monkeypatch
):
    client, metadata, _ = client_fixture(owners)
    mode = cert.MODES[0]
    attempt = client.begin(mode, original(owners[0], metadata, mode))
    journal, authorization = trusted_authorization(
        tmp_path, owners[0], metadata, attempt.binding, frame(metadata)
    )
    signer = result.LocalResultSigner(journal, owners[1], client._descriptor)

    def fail_record(*_):
        raise RuntimeError("unit-only completion recording failure")

    monkeypatch.setattr(journal, "_finish", fail_record)
    with pytest.raises(life.LifecycleError):
        signer.issue(authorization, mode)
    assert journal.status(attempt.binding.nonce)["state"] == "dispatch_started"
    with pytest.raises(life.ConsumedRequestError):
        signer.issue(authorization, mode)
    journal.close()


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_signer_ownership_cannot_be_copied(owners, tmp_path, operation):
    client, metadata, _ = client_fixture(owners)
    binding = result.original_binding(
        original(owners[0], metadata, cert.MODES[0]),
        client._descriptor._anchor,
        metadata,
        cert.MODES[0],
    )
    journal, _ = trusted_authorization(tmp_path, owners[0], metadata, binding, frame(metadata))
    signer = result.LocalResultSigner(journal, owners[1], client._descriptor)
    with pytest.raises(TypeError):
        operation(signer)
    signer.close()
    with pytest.raises(RuntimeError):
        _ = signer.public_key
    journal.close()


def test_owner_pin_advance_waits_for_already_claimed_private_finish(owners):
    client, metadata, _ = client_fixture(owners)
    mode = cert.MODES[0]
    attempt = client.begin(mode, original(owners[0], metadata, mode))
    packet = result._signed_packet(owners[1], metadata, mode, attempt.binding, frame(metadata))
    _, _, future = descriptor(owners[0], epoch=2)
    entered, release, advanced = threading.Event(), threading.Event(), threading.Event()
    outputs, errors = [], []

    def private(_):
        entered.set()
        assert release.wait(2)
        return "owner-only"

    def finish():
        try:
            outputs.append(attempt.finish(packet, private))
        except BaseException as error:
            errors.append(error)

    def advance():
        try:
            client._descriptor.advance_current(future.pin)
            advanced.set()
        except BaseException as error:
            errors.append(error)

    delivery_thread = threading.Thread(target=finish)
    delivery_thread.start()
    assert entered.wait(1)
    advance_thread = threading.Thread(target=advance)
    advance_thread.start()
    assert not advanced.wait(0.02)
    release.set()
    delivery_thread.join(2)
    advance_thread.join(2)
    assert not errors and outputs == ["owner-only"] and advanced.is_set()


def test_signer_rejects_a_foreign_owner_journal(owners, tmp_path):
    client, metadata, _ = client_fixture(owners)
    selected = metadata.mode(cert.MODES[0])
    journal = life.LocalJournal(
        tmp_path / "wrong-owner.sqlite",
        owners[1].public_key().public_bytes_raw(),
        selected.policy_digest,
        token("scope"),
    )
    with pytest.raises(ValueError):
        result.LocalResultSigner(journal, owners[1], client._descriptor)
    journal.close()


def test_signer_rejects_a_closed_journal_before_use(owners, tmp_path):
    client, metadata, _ = client_fixture(owners)
    selected = metadata.mode(cert.MODES[0])
    journal = life.LocalJournal(
        tmp_path / "closed.sqlite",
        owners[0].public_key().public_bytes_raw(),
        selected.policy_digest,
        token("scope"),
    )
    journal.close()
    with pytest.raises(life.LifecycleError):
        result.LocalResultSigner(journal, owners[1], client._descriptor)


def retained_role_material(owners, directory, *, profile=0, mode=None):
    """Only retained public ciphertexts and the same two unit signing contexts."""
    from benchmarks import complete_cost_shared_query_lab as roles
    from benchmarks import native_shared_query_lab as lab
    from experiments.bfv_search_lab import native_shared_query as native
    from experiments.bfv_search_lab.test_authenticated_shared_query import owner_inputs

    work = Path("/home/pete/yavor-projects/xtrace-work")
    fixture_dir = work / "research-data/shared-query-admission-20261004/q74"
    report, entries = lab.public_cases(fixture_dir)
    case_id = "c0-q0-m17-owner-canonical30" if profile == 0 else "c1-q0-m33-owner-canonical30"
    entry = next(row for row in entries if row["id"] == case_id)
    public = lab.public_fixtures(fixture_dir, report)
    _, tape, metadata, keys, packets, seeded_query = owner_inputs(fixture_dir, entry, public)
    baseline = json.loads(
        (work / "research-data/q77-complete-cost-20261004/registration-baseline.json").read_text()
    )
    names = (
        "libshared_query_native.so",
        "libshared_query_replay.so",
        "libshared_query_aggregate.so",
    )
    libraries = tuple(
        {key: found[key] for key in ("file", "bytes", "sha256")}
        for name in names
        for found in baseline["isolated_libraries"]
        if Path(found["file"]).name == name
    )
    assert len(libraries) == 3
    factories = tuple(
        factory(owners[0].public_key().public_bytes_raw(), native.NativeLibrary(library["file"]))
        for factory, library in zip(roles.FACTORIES, libraries, strict=True)
    )
    enrollments = tuple(
        auth.sign_enrollment(metadata, keys, packets, 1, factory.policy_digest, owners[0])
        for factory in factories
    )
    snapshots = tuple(
        hashlib.sha256(
            auth.ENROLL_TAG
            + owners[0].public_key().public_bytes_raw()
            + auth._unpack(packet, limit=native.PACKET_CAP, array_cap=3)[1]
        ).digest()
        for packet in enrollments
    )
    raw_ids = b"".join(value.to_bytes(8, "little") for value in metadata.ids)
    digest = hashlib.sha256(raw_ids).digest()
    plans = tuple(
        cert.TrustedPlan(
            cert.geometry(profile),
            len(metadata.ids),
            bytes.fromhex(metadata.key_id),
            digest,
            snapshot,
            factory.policy_digest,
            bytes.fromhex(library["sha256"]),
            choice,
        )
        for choice, snapshot, factory, library in zip(
            cert.MODES, snapshots, factories, libraries, strict=True
        )
    )
    certificates = tuple(cert.make_certificate(plan) for plan in plans)
    modes = tuple(
        context.ModeBinding(
            plan.mode,
            1,
            plan.snapshot_id,
            plan.policy_digest,
            plan.code_digest,
            cert.certificate_digest(packet),
        )
        for plan, packet in zip(plans, certificates, strict=True)
    )
    delivery = context.seal_descriptor(
        metadata.ids,
        owners[0],
        namespace=token("role-scope"),
        revision=token("role-revision"),
        epoch=1,
        geometry=cert.geometry(profile),
        key_id=bytes.fromhex(metadata.key_id),
        cache=context.CacheBinding(
            token("role-cache-key"),
            token("role-cache-snapshot"),
            1,
            context.cache_ids_digest(raw_ids, len(metadata.ids)),
        ),
        modes=modes,
        certificates=certificates,
    )
    descriptor_path = directory / "descriptor.bin"
    descriptor_path.write_bytes(delivery.packet)
    handle = context.DescriptorClient(owners[0].public_key().public_bytes_raw(), delivery.pin)
    public_metadata = handle.acquire(delivery.packet)
    chosen = mode if mode is not None else cert.MODES[0]
    at = cert.MODES.index(chosen)
    enrollment_path = directory / "enrollment.bin"
    enrollment_path.write_bytes(enrollments[at])

    def file_pin(path):
        data = path.read_bytes()
        return {"file": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def config(role, *, port=0):
        value = {
            "role": role,
            "mode": chosen,
            "library": libraries[at],
            "owner_anchor": owners[0].public_key().public_bytes_raw().hex(),
            "journal": str(directory / (role + ".sqlite")),
            "protected_port": port,
            "current_pin": {
                "namespace": delivery.pin.namespace.hex(),
                "revision": delivery.pin.revision.hex(),
                "epoch": delivery.pin.epoch,
                "payload_digest": delivery.pin.payload_digest.hex(),
            },
            "descriptor": file_pin(descriptor_path),
            "enrollment": file_pin(enrollment_path),
        }
        path = directory / (role + ".json")
        path.write_text(json.dumps(value, indent=2) + "\n")
        return path

    signed_original = auth.sign_request(
        snapshots[at],
        1,
        factories[at].policy_digest,
        token("retained-role-query"),
        seeded_query,
        owners[0],
    )
    freeze = Path(os.environ["CUHEPY_Q77_PUBLIC_GATE_FREEZE"])
    return roles, config, freeze, handle, public_metadata, signed_original, tape.response


@pytest.mark.parametrize("profile,mode", [(p, m) for p in (0, 1) for m in cert.MODES])
def test_actual_native_frontend_protected_receipt_and_owner_path_match_retained_frame(
    owners, tmp_path, profile, mode
):
    from experiments.bfv_search_lab import complete_cost_transport as wire

    roles, config, freeze, handle, metadata, original_packet, expected = retained_role_material(
        owners, tmp_path, profile=profile, mode=mode
    )
    protected = roles.LocalRole(config("protected"), freeze, signer=owners[1])
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    fast = wire.Link(1_000_000_000, 0)
    frontend = roles.LocalRole(
        config("frontend", port=listener.getsockname()[1]), freeze, internal_link=fast
    )
    if mode == cert.MODES[1]:
        assert (
            frontend.enrollment is None
            and frontend.inventory()["native_preparation_exists"] is False
        )
    client = result.ResultClient(
        handle, tuple((choice, protected._signer.public_key) for choice in cert.MODES)
    )
    attempt = client.begin(mode, original_packet)
    errors = []

    def protected_server():
        sock = None
        stream = None
        try:
            listener.settimeout(2)
            sock, _ = listener.accept()
            stream = wire.BoundedStream(sock, cap=1 << 31, link=fast, timeout_ns=2_000_000_000)
            reply = protected.execute(stream.receive(kind="test-role-input"))
            stream.send(reply, kind="test-role-result")
        except BaseException as error:
            errors.append(error)
        finally:
            if stream is not None:
                stream.close()
            elif sock is not None:
                sock.close()

    thread = threading.Thread(target=protected_server, daemon=True)
    thread.start()
    try:
        receipt = frontend.execute(auth._pack([b"run", original_packet]))
        calls = []
        assert attempt.finish(receipt, lambda frame: calls.append(frame) or frame) == expected
        assert calls == [expected]
        status = protected.journal.status(attempt.binding.nonce)
        assert (
            status["state"] == "delivered"
            and status["authorized_once"] == status["callback_once"] == 1
        )
        assert protected.inventory()["HE_private_key_present_or_private_HE_work"] is False
        assert protected.inventory()["journal"] == {
            "attempts": 1,
            "authorizations": 1,
            "callback_claims": 1,
        }
        assert len(frontend.transfers) == 2
    finally:
        listener.close()
        thread.join(3)
        frontend.close()
        protected.close()
        client.close()
        handle.close()
    assert not errors and not thread.is_alive()


@pytest.mark.parametrize("field", ["mode", "owner_anchor", "protected_port", "library"])
def test_role_refresh_cannot_change_fixed_code_root_or_mode(owners, tmp_path, field):
    roles, config, freeze, _, _, _, _ = retained_role_material(owners, tmp_path)
    path = config("protected")
    role = roles.LocalRole(path, freeze, signer=owners[1])
    value = json.loads(path.read_text())
    value[field] = "different" if field != "protected_port" else 1234
    path.write_text(json.dumps(value))
    try:
        with pytest.raises(ValueError):
            role.execute(auth._pack([b"refresh"]))
        assert role.journal.summary()["callback_claims"] == 0
    finally:
        role.close()


@pytest.mark.parametrize("mode", [cert.MODES[0], cert.MODES[2]])
def test_actual_bad_native_result_never_emits_a_signed_receipt(owners, tmp_path, mode):
    roles, config, freeze, _, _, original_packet, _ = retained_role_material(
        owners, tmp_path, mode=mode
    )
    role = roles.LocalRole(config("protected"), freeze, signer=owners[1])
    try:
        with role.enrollment.request(original_packet) as request:
            packet = request.produce_packet()
        fields = auth._unpack(packet, limit=1 << 31, array_cap=9)
        body = fields[7]
        fields[7] = body[:-1] + bytes([body[-1] ^ 1])
        with pytest.raises(ValueError):
            role.execute(auth._pack([b"run", original_packet, auth._pack(fields)]))
        assert role.journal.summary() == {"attempts": 1, "authorizations": 0, "callback_claims": 0}
        with pytest.raises(life.ConsumedRequestError):
            role.execute(auth._pack([b"run", original_packet, packet]))
    finally:
        role.close()


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_worker_role_ownership_cannot_be_copied(owners, tmp_path, operation):
    roles, config, freeze, _, _, _, _ = retained_role_material(owners, tmp_path)
    role = roles.LocalRole(config("protected"), freeze, signer=owners[1])
    try:
        with pytest.raises(TypeError):
            operation(role)
    finally:
        role.close()
    with pytest.raises(RuntimeError):
        role.execute(auth._pack([b"descriptor"]))
