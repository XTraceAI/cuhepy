"""Local lifecycle adversaries using retained HE data and public test hooks."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import copy
import hashlib
import multiprocessing
import os
from pathlib import Path
import pickle
import select
import sqlite3
import threading

import msgpack
import pytest

from benchmarks import native_shared_query_lab as lab
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import lifecycle_shared_query as life
from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab import seeded_bgv as seeded
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_bgv as shared
from experiments.bfv_search_lab import test_authenticated_shared_query as auth_tests
from experiments.bfv_search_lab.test_native_shared_query import CASE_IDS


@pytest.fixture(scope="module")
def material():
    # Two supporting standard signature keys; all HE material is retained.
    return auth_tests.material.__wrapped__()


def signed_query(material, enrollment, query, nonce):
    return auth.sign_request(
        enrollment.snapshot_id,
        enrollment.epoch,
        enrollment._factory.policy_digest,
        nonce,
        query,
        material[4],
    )


def reply(enrollment, packet, ctx, tape):
    with enrollment.request(packet) as request:
        return request.reply(lab.body(ctx, tape), tape.response)


@pytest.fixture
def case(material, tmp_path):
    library, _directory, _entries, _fixtures, owner, _foreign, factory, data = material
    ctx, tape, metadata, keys, index, query = data
    enrollment_packet = auth.sign_enrollment(metadata, keys, index, 1, factory.policy_digest, owner)
    scope = hashlib.sha256(b"q76-lifecycle-unit-scope").digest()
    public = auth_tests.public_key(owner)
    with (
        factory.enroll(enrollment_packet) as enrollment,
        life.LocalJournal(
            tmp_path / "state.sqlite", public, factory.policy_digest, scope
        ) as journal,
    ):
        journal.install(enrollment)
        packet = signed_query(material, enrollment, query, bytes([7]) * 32)
        yield {
            "library": library,
            "factory": factory,
            "owner": owner,
            "public": public,
            "scope": scope,
            "ctx": ctx,
            "tape": tape,
            "data": data,
            "enrollment": enrollment,
            "enrollment_packet": enrollment_packet,
            "journal": journal,
            "authorizer": life.LocalAuthorizer(journal),
            "guard": life.LocalReleaseGuard(journal),
            "packet": packet,
            "reply": reply(enrollment, packet, ctx, tape),
        }


def admit(case):
    return case["authorizer"].admit(case["enrollment"], case["packet"], case["reply"])


def replacement(case, epoch=2, metadata=None):
    _ctx, _tape, original_metadata, keys, index, _query = case["data"]
    packet = auth.sign_enrollment(
        original_metadata if metadata is None else metadata,
        keys,
        index,
        epoch,
        case["factory"].policy_digest,
        case["owner"],
    )
    return case["factory"].enroll(packet)


def reopen(case):
    return life.LocalJournal(
        case["journal"].path, case["public"], case["factory"].policy_digest, case["scope"]
    )


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_every_retained_frame_authorizes_then_dispatches_once(material, tmp_path, case_id):
    library, directory, entries, fixtures, owner, _foreign, factory, _data = material
    ctx, tape, metadata, keys, index, query = auth_tests.owner_inputs(
        directory, entries[case_id], fixtures
    )
    packet = auth.sign_enrollment(metadata, keys, index, 1, factory.policy_digest, owner)
    with (
        factory.enroll(packet) as enrollment,
        life.LocalJournal(
            tmp_path / "flow.sqlite",
            auth_tests.public_key(owner),
            factory.policy_digest,
            hashlib.sha256(case_id.encode()).digest(),
        ) as journal,
    ):
        journal.install(enrollment)
        original = signed_query(material, enrollment, query, bytes([1]) * 32)
        proof = reply(enrollment, original, ctx, tape)
        token = life.LocalAuthorizer(journal).admit(enrollment, original, proof)
        assert token.frame == tape.response
        received = []
        assert life.LocalReleaseGuard(journal).deliver(token, received.append) is None
        assert received == [tape.response]
        assert journal.summary() == {"attempts": 1, "authorizations": 1, "callback_claims": 1}
        assert journal.status(token.binding.nonce)["state"] == "delivered"
        with pytest.raises(life.ConsumedRequestError):
            life.LocalAuthorizer(journal).admit(enrollment, original, proof)
        with pytest.raises(life.ConsumedRequestError):
            life.LocalReleaseGuard(journal).deliver(token, received.append)


@pytest.mark.parametrize("fault", ["body", "frame", "snapshot", "epoch_bool", "trailing"])
def test_bad_complete_reply_is_consumed_without_authorization(case, fault):
    fields = msgpack.unpackb(case["reply"], raw=False)
    if fault in ("body", "frame"):
        at = 7 if fault == "body" else 8
        fields[at] = fields[at][:-1] + bytes([fields[at][-1] ^ 1])
    elif fault == "snapshot":
        fields[1] = bytes(32)
    elif fault == "epoch_bool":
        fields[2] = True
    packet = case["reply"] + b"\x00" if fault == "trailing" else auth._pack(fields)
    assert case["authorizer"].admit(case["enrollment"], case["packet"], packet) is None
    assert case["journal"].summary() == {"attempts": 1, "authorizations": 0, "callback_claims": 0}
    with pytest.raises(life.ConsumedRequestError):
        admit(case)


@pytest.mark.parametrize("fault", ["signature", "foreign_owner", "trailing"])
def test_unauthenticated_request_cannot_consume_nonce_or_prepare(
    case, material, monkeypatch, fault
):
    tag, payload, signature = msgpack.unpackb(case["packet"], raw=False)
    if fault == "signature":
        bad = auth._pack([tag, payload, bytes(64)])
    elif fault == "foreign_owner":
        bad = auth._sign(tag, payload, material[5])
    else:
        bad = case["packet"] + b"\x00"

    def forbidden(*_args, **_kwargs):
        pytest.fail("Unauthenticated request cannot prepare native query/seed")

    with monkeypatch.context() as patch:
        patch.setattr(seeded, "expand", forbidden)
        patch.setattr(case["enrollment"]._context, "query", forbidden)
        with pytest.raises(ValueError):
            case["authorizer"].admit(case["enrollment"], bad, case["reply"])
    assert case["journal"].summary()["attempts"] == 0
    assert admit(case) is not None


@pytest.mark.parametrize("fault", ["truncated", "last_q", "noncanonical"])
def test_signed_bad_seed_consumes_before_native_work(case, monkeypatch, fault):
    tag, payload, _signature = msgpack.unpackb(case["packet"], raw=False)
    fields = msgpack.unpackb(payload, raw=False)
    if fault == "truncated":
        fields[4] = fields[4][:-1]
    elif fault == "noncanonical":
        fields[4] = b"\xdc\x00\x04" + fields[4][1:]
    else:
        seed_fields = msgpack.unpackb(fields[4], raw=False)
        seed_fields[3] = seed_fields[3][:-15] + case["ctx"].profile.q.to_bytes(15, "little")
        fields[4] = auth._pack(seed_fields)
    bad = auth._sign(tag, auth._pack(fields), case["owner"])

    def forbidden(*_args, **_kwargs):
        pytest.fail("Malformed seed cannot enter native query")

    monkeypatch.setattr(case["enrollment"]._context, "query", forbidden)
    with pytest.raises(ValueError):
        case["authorizer"].admit(case["enrollment"], bad, case["reply"])
    status = case["journal"].status(bytes([7]) * 32)
    assert status["state"] == "rejected" and status["authorized_once"] == 0
    with pytest.raises(life.ConsumedRequestError):
        admit(case)


def test_nonce_cannot_be_resigned_for_a_different_query(case, material):
    assert admit(case) is not None
    directory, entries, fixtures = material[1:4]
    alternate = auth_tests.owner_inputs(directory, entries[CASE_IDS[-5]], fixtures)[5]
    other = signed_query(material, case["enrollment"], alternate, bytes([7]) * 32)
    assert other != case["packet"]
    with pytest.raises(life.ConsumedRequestError):
        case["authorizer"].admit(case["enrollment"], other, case["reply"])


def test_nonce_cannot_be_reused_in_new_snapshot(case, material):
    token = admit(case)
    with replacement(case) as newer:
        case["journal"].install(newer)
        other = signed_query(material, newer, case["data"][5], token.binding.nonce)
        with pytest.raises(life.ConsumedRequestError):
            case["authorizer"].admit(newer, other, case["reply"])


def test_snapshot_idempotence_does_not_allow_equal_epoch_equivocation(case):
    case["journal"].install(case["enrollment"])
    metadata = replace(case["data"][2], ids=tuple(reversed(case["data"][2].ids)))
    with (
        replacement(case, epoch=1, metadata=metadata) as other,
        pytest.raises(life.StaleSnapshotError),
    ):
        case["journal"].install(other)
    assert admit(case) is not None


def test_snapshot_epoch_cannot_regress_and_stale_signed_nonce_is_consumed(case):
    with replacement(case) as newer:
        case["journal"].install(newer)
        with pytest.raises(life.StaleSnapshotError):
            case["journal"].install(case["enrollment"])
        with pytest.raises(life.StaleSnapshotError):
            admit(case)
        status = case["journal"].status(bytes([7]) * 32)
        assert status["state"] == "rejected" and status["reason"] == "stale_at_reservation"
        assert status["authorized_once"] == status["callback_once"] == 0


def test_snapshot_rechecked_between_full_admission_and_authorization(case, monkeypatch):
    original = auth.PublicRequest.checked_frame
    with replacement(case) as newer:

        def retire(request, packet):
            frame = original(request, packet)
            assert frame is not None
            case["journal"].install(newer)
            return frame

        monkeypatch.setattr(auth.PublicRequest, "checked_frame", retire)
        assert admit(case) is None
    status = case["journal"].status(bytes([7]) * 32)
    assert status["reason"] == "stale_at_authorization" and status["authorized_once"] == 0


def test_snapshot_rechecked_before_callback_claim(case):
    token = admit(case)
    with replacement(case) as newer:
        case["journal"].install(newer)
        calls = []
        with pytest.raises(life.StaleSnapshotError):
            case["guard"].deliver(token, calls.append)
        assert not calls
    status = case["journal"].status(token.binding.nonce)
    assert status["authorized_once"] == 1 and status["callback_once"] == 0
    assert status["reason"] == "stale_at_dispatch"


def test_snapshot_update_after_committed_dispatch_is_ordered_later(case):
    token = admit(case)
    entered, finish = threading.Event(), threading.Event()
    received = []

    def hook(frame):
        assert case["journal"].status(token.binding.nonce)["state"] == "dispatch_started"
        entered.set()
        assert finish.wait(5)
        received.append(frame)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(case["guard"].deliver, token, hook)
        assert entered.wait(5)
        try:
            with replacement(case) as newer:
                case["journal"].install(newer)  # No DB lock held across hook.
        finally:
            finish.set()
        assert future.result(timeout=5) is None
    assert received == [case["tape"].response]
    assert case["journal"].status(token.binding.nonce)["state"] == "delivered"


def test_callback_output_is_discarded_and_errors_are_generic(case, material):
    token = admit(case)
    assert case["guard"].deliver(token, lambda _frame: b"private-hook-value") is None
    packet = signed_query(material, case["enrollment"], case["data"][5], bytes([8]) * 32)
    proof = reply(case["enrollment"], packet, case["ctx"], case["tape"])
    failed = case["authorizer"].admit(case["enrollment"], packet, proof)

    def hook(_frame):
        raise ValueError("private diagnostic must not be the public result")

    with pytest.raises(life.CallbackFailed) as error:
        case["guard"].deliver(failed, hook)
    assert "private diagnostic" not in str(error.value)
    assert error.value.__context__ is None
    assert case["journal"].status(failed.binding.nonce)["state"] == "callback_failed"
    with pytest.raises(life.ConsumedRequestError):
        case["guard"].deliver(failed, lambda _frame: None)


@pytest.mark.parametrize("hook", [None, lambda _frame: (_ for _ in ()).throw(KeyboardInterrupt())])
def test_invalid_or_interrupted_callback_is_never_retried(case, hook):
    token = admit(case)
    with pytest.raises((life.CallbackFailed, KeyboardInterrupt)):
        case["guard"].deliver(token, hook)
    assert case["journal"].status(token.binding.nonce)["callback_once"] == 1
    with reopen(case) as other, pytest.raises(life.ConsumedRequestError):
        life.LocalReleaseGuard(other).deliver(token, lambda _frame: None)


@pytest.mark.parametrize(
    "field",
    [
        "journal",
        "reply_hash",
        "frame",
        "snapshot_id",
        "epoch",
        "policy_digest",
        "request_digest",
        "nonce",
        "ids_digest",
    ],
)
def test_forged_local_token_cannot_bypass_record_or_full_frame(case, field):
    token = admit(case)
    if field == "journal":
        bad = replace(token, journal_id=bytes(32))
    elif field == "frame":
        bad = replace(token, frame=token.frame[:-1] + bytes([token.frame[-1] ^ 1]))
    elif field == "reply_hash":
        bad = replace(token, reply_hash=bytes(32))
    else:
        bad = replace(
            token,
            binding=replace(token.binding, **{field: True if field == "epoch" else bytes(32)}),
        )
    calls = []
    with pytest.raises((ValueError, life.LifecycleError)):
        case["guard"].deliver(bad, calls.append)
    assert not calls and case["journal"].status(token.binding.nonce)["callback_once"] == 0
    case["guard"].deliver(token, calls.append)
    assert calls == [token.frame]


def test_restart_preserves_authorization_and_failed_consumption(case):
    token = admit(case)
    case["journal"].close()
    with reopen(case) as journal:
        guard = life.LocalReleaseGuard(journal)
        guard.deliver(token, lambda _frame: None)
        assert journal.status(token.binding.nonce)["state"] == "delivered"
    with reopen(case) as journal:
        with pytest.raises(life.ConsumedRequestError):
            life.LocalReleaseGuard(journal).deliver(token, lambda _frame: None)
        with pytest.raises(life.ConsumedRequestError):
            life.LocalAuthorizer(journal).admit(case["enrollment"], case["packet"], case["reply"])


@pytest.mark.parametrize("field", ["owner", "policy", "scope"])
def test_journal_namespace_cannot_be_reopened_with_different_authority(case, field):
    values = dict(owner=case["public"], policy=case["factory"].policy_digest, scope=case["scope"])
    values[field] = bytes(32)
    with pytest.raises(life.LifecycleError):
        life.LocalJournal(case["journal"].path, values["owner"], values["policy"], values["scope"])
    assert admit(case) is not None


def test_journal_code_binding_and_schema_fail_closed(case, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(life, "_hash", lambda _value: bytes(32))
        with pytest.raises(life.LifecycleError):
            reopen(case)
    with sqlite3.connect(case["journal"].path) as connection:
        connection.execute("CREATE TABLE unexpected(value BLOB)")
    with pytest.raises(life.LifecycleError):
        admit(case)


def test_missing_or_invalid_database_never_dispatches(case):
    token = admit(case)
    case["journal"].path.unlink()
    calls = []
    with pytest.raises(life.LifecycleError):
        case["guard"].deliver(token, calls.append)
    assert not calls
    case["journal"].path.write_bytes(b"not-a-sqlite-database")
    with pytest.raises((life.LifecycleError, sqlite3.Error)):
        case["guard"].deliver(token, calls.append)
    assert not calls


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_journal_ownership_is_not_copied_or_serialized(case, operation):
    with pytest.raises(TypeError):
        operation(case["journal"])


def test_closed_or_foreign_owned_enrollment_rejects_before_seed_work(case, monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Closed controller cannot prepare native query/seed")

    monkeypatch.setattr(seeded, "expand", forbidden)
    case["journal"].close()
    with pytest.raises(life.LifecycleError):
        admit(case)


def test_closed_enrollment_rejects_without_consumption_or_seed_work(case, monkeypatch):
    case["enrollment"].close()

    def forbidden(*_args, **_kwargs):
        pytest.fail("Closed enrollment cannot expand seeded inputs")

    monkeypatch.setattr(seeded, "expand", forbidden)
    with pytest.raises(RuntimeError):
        admit(case)
    assert case["journal"].summary()["attempts"] == 0


def test_foreign_owner_enrollment_rejected_before_journal_or_seed(case, material, monkeypatch):
    foreign = material[5]
    factory = auth.OwnerFactory(auth_tests.public_key(foreign), case["library"])
    _ctx, _tape, metadata, keys, index, query = case["data"]
    signed = auth.sign_enrollment(metadata, keys, index, 1, factory.policy_digest, foreign)
    with factory.enroll(signed) as enrollment:
        request = auth.sign_request(
            enrollment.snapshot_id, 1, factory.policy_digest, bytes([7]) * 32, query, foreign
        )

        def forbidden(*_args, **_kwargs):
            pytest.fail("Foreign owner cannot access this journal or prepare inputs")

        with monkeypatch.context() as patch:
            patch.setattr(case["journal"], "_connect", forbidden)
            patch.setattr(seeded, "expand", forbidden)
            with pytest.raises(ValueError):
                case["journal"].install(enrollment)
            with pytest.raises(ValueError):
                case["authorizer"].admit(enrollment, request, case["reply"])
    assert case["journal"].summary()["attempts"] == 0


def test_failed_reservation_storage_cannot_start_admission(case, monkeypatch):
    def unavailable():
        raise life.LifecycleError("Test storage unavailable")

    def forbidden(*_args, **_kwargs):
        pytest.fail("A failed durable reservation cannot start query work")

    with monkeypatch.context() as patch:
        patch.setattr(case["journal"], "_connect", unavailable)
        patch.setattr(seeded, "expand", forbidden)
        patch.setattr(case["enrollment"]._context, "query", forbidden)
        with pytest.raises(life.LifecycleError):
            admit(case)
    assert case["journal"].summary()["attempts"] == 0


@pytest.mark.parametrize("callback_fails", [False, True])
def test_completion_storage_failure_cannot_retry_or_expose_hook_error(
    case, monkeypatch, callback_fails
):
    token = admit(case)
    calls = []

    def hook(frame):
        calls.append(frame)
        if callback_fails:
            raise ValueError("private-hook-diagnostic")

    def unavailable(*_args):
        raise life.LifecycleError("Test completion storage unavailable")

    monkeypatch.setattr(case["journal"], "_finish", unavailable)
    with pytest.raises(life.LifecycleError) as error:
        case["guard"].deliver(token, hook)
    assert str(error.value) == "Callback claim consumed; completion unavailable"
    assert error.value.__suppress_context__
    assert calls == [token.frame]
    assert case["journal"].status(token.binding.nonce)["state"] == "dispatch_started"
    with pytest.raises(life.ConsumedRequestError):
        case["guard"].deliver(token, hook)
    assert len(calls) == 1


@pytest.mark.parametrize("pragma", ["application_id", "user_version"])
def test_nonempty_foreign_metadata_is_not_reinitialized_as_new_journal(case, tmp_path, pragma):
    path = tmp_path / "foreign-empty.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute(f"PRAGMA {pragma}=99")
    with pytest.raises(life.LifecycleError):
        life.LocalJournal(path, case["public"], case["factory"].policy_digest, case["scope"])
    with sqlite3.connect(path) as connection:
        assert connection.execute(f"PRAGMA {pragma}").fetchone()[0] == 99
        assert not connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table'"
        ).fetchall()


def test_uint64_maximum_epoch_and_ids_are_not_sqlite_signed_integers(case, material):
    epoch = (1 << 64) - 1
    metadata = replace(
        case["data"][2], ids=tuple(epoch - i for i in range(len(case["data"][2].ids)))
    )
    with replacement(case, epoch, metadata) as newer:
        case["journal"].install(newer)
        packet = signed_query(material, newer, case["data"][5], bytes([9]) * 32)
        proof = reply(newer, packet, case["ctx"], case["tape"])
        token = case["authorizer"].admit(newer, packet, proof)
        assert token.binding.epoch == epoch
        assert case["journal"].status(token.binding.nonce)["epoch"] == epoch
        case["guard"].deliver(token, lambda _frame: None)


def test_public_authorizer_never_replays_decrypts_or_uses_a_hook(case, monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Public admission cannot use producer/private/hook oracle")

    for module, names in [
        (bgv, ("key_gen", "encrypt", "decrypt")),
        (seeded, ("encrypt",)),
        (shared, ("produce", "expected_frame")),
    ]:
        for name in names:
            monkeypatch.setattr(module, name, forbidden)
    monkeypatch.setattr(native.NativeQuery, "produce", forbidden)
    monkeypatch.setattr(life.LocalReleaseGuard, "deliver", forbidden)
    assert admit(case) is not None


def test_thread_races_authorize_and_dispatch_at_most_once(case):
    start = threading.Barrier(4)

    def attempt():
        start.wait(timeout=5)
        try:
            return admit(case)
        except life.ConsumedRequestError:
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        tokens = list(pool.map(lambda _i: attempt(), range(4)))
    accepted = [token for token in tokens if token is not None]
    assert len(accepted) == 1
    start = threading.Barrier(4)
    received = []

    def dispatch():
        start.wait(timeout=5)
        try:
            case["guard"].deliver(accepted[0], received.append)
            return True
        except life.ConsumedRequestError:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _i: dispatch(), range(4)))
    assert sum(results) == 1 and received == [accepted[0].frame]


def _child_config(case):
    return dict(
        library=str(case["library"].path),
        database=str(case["journal"].path),
        owner=case["public"],
        scope=case["scope"],
        enrollment=case["enrollment_packet"],
        request=case["packet"],
        reply=case["reply"],
    )


def _process_worker(config, action, barrier=None, queue=None, token=None, marker=None):
    library = native.NativeLibrary(config["library"])
    factory = auth.OwnerFactory(config["owner"], library)
    with (
        factory.enroll(config["enrollment"]) as enrollment,
        life.LocalJournal(
            config["database"], config["owner"], factory.policy_digest, config["scope"]
        ) as journal,
    ):
        if barrier is not None:
            barrier.wait(timeout=10)
        if action == "reserve_crash":
            journal.reserve(enrollment, config["request"])
            os._exit(57)
        if action == "dispatch_crash":

            def crash(_frame):
                Path(marker).write_bytes(b"callback-entered")
                os._exit(58)

            life.LocalReleaseGuard(journal).deliver(token, crash)
        try:
            if action == "admit":
                token = life.LocalAuthorizer(journal).admit(
                    enrollment, config["request"], config["reply"]
                )
                assert token is not None
            elif action == "dispatch":
                life.LocalReleaseGuard(journal).deliver(token, lambda _frame: None)
            else:
                raise AssertionError("Unknown child action")
            queue.put("accepted")
        except life.ConsumedRequestError:
            queue.put("consumed")


@pytest.mark.parametrize("action", ["admit", "dispatch"])
def test_spawned_process_race_shares_durable_consumption(case, action):
    context = multiprocessing.get_context("spawn")
    queue, barrier = context.Queue(), context.Barrier(2)
    token = admit(case) if action == "dispatch" else None
    children = [
        context.Process(
            target=_process_worker, args=(_child_config(case), action, barrier, queue, token)
        )
        for _ in range(2)
    ]
    try:
        for child in children:
            child.start()
        for child in children:
            child.join(15)
            assert not child.is_alive() and child.exitcode == 0
        assert sorted(queue.get(timeout=2) for _ in children) == ["accepted", "consumed"]
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
                child.join(5)
        queue.close()
        queue.join_thread()
    summary = case["journal"].summary()
    assert summary["attempts"] == summary["authorizations"] == 1
    assert summary["callback_claims"] == (1 if action == "dispatch" else 0)


@pytest.mark.parametrize("action,exitcode", [("reserve_crash", 57), ("dispatch_crash", 58)])
def test_actual_process_exit_preserves_consumption_after_commit(case, tmp_path, action, exitcode):
    context = multiprocessing.get_context("spawn")
    token = admit(case) if action == "dispatch_crash" else None
    marker = tmp_path / "hook-entered"
    child = context.Process(
        target=_process_worker, args=(_child_config(case), action, None, None, token, str(marker))
    )
    try:
        child.start()
        child.join(15)
        assert not child.is_alive() and child.exitcode == exitcode
    finally:
        if child.is_alive():
            child.terminate()
            child.join(5)
    with reopen(case) as journal:
        row = journal.status(bytes([7]) * 32)
        if action == "reserve_crash":
            assert (
                row["state"] == "reserved" and row["authorized_once"] == row["callback_once"] == 0
            )
            with pytest.raises(life.ConsumedRequestError):
                life.LocalAuthorizer(journal).admit(
                    case["enrollment"], case["packet"], case["reply"]
                )
        else:
            assert marker.read_bytes() == b"callback-entered"
            assert row["state"] == "dispatch_started" and row["callback_once"] == 1
            with pytest.raises(life.ConsumedRequestError):
                life.LocalReleaseGuard(journal).deliver(token, lambda _frame: None)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork required")
def test_inherited_journal_rejects_before_parent_thread_database_lock(case):
    locked, release = threading.Event(), threading.Event()

    def holder():
        with case["journal"]._transaction():
            locked.set()
            assert release.wait(5)

    worker = threading.Thread(target=holder)
    worker.start()
    assert locked.wait(5)
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            case["journal"].reserve(case["enrollment"], case["packet"])
        except life.LifecycleError as error:
            assert "inherited" in str(error)
            case["journal"].close()
            os.write(write_fd, b"inherited-rejected")
            os._exit(0)
        os._exit(1)
    os.close(write_fd)
    try:
        ready, _, _ = select.select([read_fd], [], [], 2)
        assert ready and os.read(read_fd, 64) == b"inherited-rejected"
    finally:
        os.close(read_fd)
        release.set()
        worker.join(5)
        _pid, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert admit(case) is not None
