"""Matched public replay gates. Retained HE data; no private HE operations."""

from concurrent.futures import ThreadPoolExecutor
import copy
import ctypes
import hashlib
import os
from pathlib import Path
import pickle
import select
import signal
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import msgpack
import pytest

from benchmarks import native_shared_query_lab as lab
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import lifecycle_shared_query as life
from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab import replay_shared_query as replay
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_bgv as shared
from experiments.bfv_search_lab import shared_query_gmp as gmp
from experiments.bfv_search_lab import test_authenticated_shared_query as fixtures
from experiments.bfv_search_lab.test_native_shared_query import CASE_IDS


@pytest.fixture(scope="module")
def material():
    library_path, fixture_path = (
        os.getenv("CUHEPY_SHARED_QUERY_LIBRARY"),
        os.getenv("CUHEPY_SHARED_QUERY_FIXTURES"),
    )
    if not library_path or not fixture_path:
        pytest.skip("Explicit isolated replay library and retained fixtures required")
    library, directory = native.NativeLibrary(library_path), Path(fixture_path)
    report, entries = lab.public_cases(directory)
    public = lab.public_fixtures(directory, report)
    owner = Ed25519PrivateKey.generate()  # One standard signature context, no HE key.
    factory = replay.ReplayFactory(fixtures.public_key(owner), library)
    data = fixtures.owner_inputs(
        directory, next(x for x in entries if x["id"] == CASE_IDS[-1]), public
    )
    return library, directory, {x["id"]: x for x in entries}, public, owner, factory, data


def request_packet(enrollment, owner, seeded_query, nonce):
    return auth.sign_request(
        enrollment.snapshot_id,
        enrollment.epoch,
        enrollment._factory.policy_digest,
        nonce,
        seeded_query,
        owner,
    )


@pytest.fixture
def case(material):
    library, _directory, _entries, _public, owner, factory, data = material
    ctx, tape, metadata, keys, index, query = data
    signed = auth.sign_enrollment(metadata, keys, index, 1, factory.policy_digest, owner)
    with factory.enroll(signed) as enrollment:
        original = request_packet(enrollment, owner, query, bytes([7]) * 32)
        with enrollment.request(original) as request:
            yield ctx, tape, enrollment, request, original, owner, query, library


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_all_retained_frames_without_source_witness(material, case_id):
    _library, directory, entries, public, owner, factory, _data = material
    _ctx, tape, metadata, keys, index, query = fixtures.owner_inputs(
        directory, entries[case_id], public
    )
    signed = auth.sign_enrollment(metadata, keys, index, 1, factory.policy_digest, owner)
    with factory.enroll(signed) as enrollment:
        packet = request_packet(enrollment, owner, query, hashlib.sha256(case_id.encode()).digest())
        with enrollment.request(packet) as request:
            expected = request.reply(tape.response)
            assert request.produce_packet() == expected
            assert request.checked_frame(expected) == tape.response
            assert len(expected) < len(tape.response) + 512


@pytest.mark.parametrize(
    "fault",
    [
        "short",
        "trailing",
        "mutable",
        "noncanonical",
        "mode",
        "extra",
        "epoch_bool",
        "snapshot",
        "policy",
        "request",
        "nonce",
        "ids",
        "frame_type",
        "frame_cap",
    ],
)
def test_wrong_packet_or_binding_never_starts_replay(case, monkeypatch, fault):
    _ctx, tape, _enrollment, request, _original, _owner, _query, _library = case
    packet = request.reply(tape.response)
    fields = msgpack.unpackb(packet, raw=False)
    if fault == "short":
        packet = packet[:-1]
    elif fault == "trailing":
        packet += b"\x00"
    elif fault == "mutable":
        packet = bytearray(packet)
    elif fault == "noncanonical":
        packet = b"\xdc\x00\x08" + packet[1:]
    else:
        if fault == "mode":
            fields[0] = auth.REPLY_TAG
        elif fault == "extra":
            fields.append(b"forged-witness")
        elif fault == "epoch_bool":
            fields[2] = True
        elif fault in ("snapshot", "policy", "request", "nonce", "ids"):
            fields[{"snapshot": 1, "policy": 3, "request": 4, "nonce": 5, "ids": 6}[fault]] = bytes(
                32
            )
        elif fault == "frame_type":
            fields[7] = 17
        else:
            fields[7] = bytes(
                2 * request._query.metadata.groups * request._query.metadata.terminal_row_size + 257
            )
        packet = auth._pack(fields)

    def forbidden(*_args):
        pytest.fail("Invalid public context/grammar cannot start replay")

    monkeypatch.setattr(request._arithmetic, "frame", forbidden)
    assert request.checked_frame(packet) is None


@pytest.mark.parametrize(
    "fault",
    [
        "key",
        "count",
        "dimension",
        "P",
        "first_component",
        "last_component",
        "last_tail",
        "group_missing",
    ],
)
def test_complete_frame_equality_including_both_components_and_tail(case, fault):
    _ctx, tape, _enrollment, request, _original, _owner, _query, _library = case
    header, rows = msgpack.unpackb(tape.response, raw=False)
    if fault in ("key", "count", "dimension", "P"):
        slot = {"key": 4, "count": 5, "dimension": 6, "P": 3}[fault]
        header[slot] = (
            bytes(32) if slot == 4 else (bytes(len(header[3])) if slot == 3 else header[slot] - 1)
        )
    elif fault == "group_missing":
        rows.pop()
    else:
        group, part, position = (0, 0, 0) if fault == "first_component" else (-1, 1, 0)
        if fault == "last_tail":
            position = len(rows[group][part]) - 1
        row = bytearray(rows[group][part])
        row[position] ^= 1
        rows[group][part] = bytes(row)
    assert request.checked_frame(request.reply(auth._pack([header, rows]))) is None


def test_no_legacy_witness_private_or_reference_fallback(case, monkeypatch):
    _ctx, tape, _enrollment, request, _original, _owner, _query, library = case

    def forbidden(*_args, **_kwargs):
        pytest.fail("Replay cannot call a witness/private/reference fallback")

    for module, names in (
        (bgv, ("key_gen", "encrypt", "decrypt")),
        (shared, ("produce", "expected_frame")),
        (gmp.GMPPublicContext, ("produce",)),
        (native.NativeQuery, ("produce", "check", "expected_response")),
        (library._lib, ("cuhepy_shared_produce", "cuhepy_shared_check", "cuhepy_shared_terminal")),
    ):
        for name in names:
            monkeypatch.setattr(module, name, forbidden)
    assert request.produce_packet() == request.reply(tape.response)
    assert request.checked_frame(request.reply(tape.response)) == tape.response


def test_C_ABI_checks_coverage_and_nulls_before_writes(case):
    _ctx, _tape, _enrollment, request, _original, _owner, _query, library = case
    length = 2 * request._query.metadata.groups * request._query.metadata.terminal_row_size
    sentinel = ctypes.create_string_buffer(b"\xa5" * length, length)
    run = library._lib.cuhepy_shared_replay
    for wrong in (0, length - 1, length + 1):
        assert run(request._query._handle, sentinel, wrong) == -1
        assert sentinel.raw == b"\xa5" * length
    assert run(None, sentinel, length) == -1
    assert sentinel.raw == b"\xa5" * length
    assert run(request._query._handle, None, length) == -1


def test_factory_policy_and_required_symbols_fail_closed(material, monkeypatch):
    library, _directory, _entries, _public, owner, factory, _data = material
    assert (
        factory.policy_digest
        != auth.OwnerFactory(fixtures.public_key(owner), library).policy_digest
    )
    monkeypatch.setattr(library._lib, "cuhepy_shared_replay_abi", lambda: 0)
    with pytest.raises(ValueError, match="ABI"):
        replay.ReplayFactory(fixtures.public_key(owner), library)


def test_old_library_cannot_silently_replay(material):
    path = os.getenv("CUHEPY_SHARED_QUERY_ORIGINAL_LIBRARY")
    if not path:
        pytest.skip("Explicit preserved original library required")
    with pytest.raises(ValueError, match="symbols"):
        replay.ReplayFactory(fixtures.public_key(material[4]), native.NativeLibrary(path))


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_owned_requests_and_enrollments_cannot_be_copied(case, operation):
    for obj in (case[2], case[3]):
        with pytest.raises(TypeError):
            operation(obj)


def test_query_outlives_closed_context_and_serializes_threads(case):
    _ctx, tape, enrollment, request, _original, _owner, _query, _library = case
    enrollment.close()
    packet = request.reply(tape.response)
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(lambda _: request.checked_frame(packet) == tape.response, range(8)))
    request.close()
    with pytest.raises(RuntimeError):
        request.checked_frame(packet)


def test_fork_rejects_before_inherited_mutex(case):
    request = case[3]
    packet = request.reply(case[1].response)
    ready, release = threading.Event(), threading.Event()

    def hold():
        with request._query._lock:
            ready.set()
            release.wait()

    thread = threading.Thread(target=hold)
    thread.start()
    assert ready.wait(5)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            request.checked_frame(packet)
        except RuntimeError:
            request.close()
            os.write(write_fd, b"rejected")
            os._exit(0)
        os._exit(1)
    os.close(write_fd)
    try:
        readable, _, _ = select.select([read_fd], [], [], 5)
        if not readable:
            os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
        assert readable and status == 0 and os.read(read_fd, 64) == b"rejected"
    finally:
        os.close(read_fd)
        release.set()
        thread.join(5)


def journal(path, enrollment):
    return life.LocalJournal(
        path, enrollment._factory._owner_id, enrollment._factory.policy_digest, bytes([4]) * 32
    )


def test_protected_execution_recomputes_once_then_claims_once(case, tmp_path, monkeypatch):
    _ctx, tape, enrollment, request, original, _owner, _query, _library = case
    with journal(tmp_path / "state.db", enrollment) as state:
        state.install(enrollment)
        calls, run = [], request._arithmetic._run

        def count(*args):
            calls.append(1)
            return run(*args)

        monkeypatch.setattr(request._arithmetic, "_run", count)
        packet, authorization = replay.PreparedReplayAuthorizer(state).execute(enrollment, original)
        assert packet == request.reply(tape.response) and len(calls) == 1
        outputs = []
        assert life.LocalReleaseGuard(state).deliver(authorization, outputs.append) is None
        assert outputs == [tape.response]
        with pytest.raises(life.ConsumedRequestError):
            life.LocalReleaseGuard(state).deliver(authorization, outputs.append)
        with pytest.raises(life.ConsumedRequestError):
            replay.PreparedReplayAuthorizer(state).execute(enrollment, original)
        assert len(calls) == 1 and state.summary() == {
            "attempts": 1,
            "authorizations": 1,
            "callback_claims": 1,
        }


def test_proposed_frame_rejection_consumes_attempt_without_callback(case, tmp_path):
    _ctx, tape, enrollment, request, original, _owner, _query, _library = case
    bad = bytearray(tape.response)
    bad[-1] ^= 1
    with journal(tmp_path / "state.db", enrollment) as state:
        state.install(enrollment)
        assert (
            life.LocalAuthorizer(state).admit(enrollment, original, request.reply(bytes(bad)))
            is None
        )
        with pytest.raises(life.ConsumedRequestError):
            life.LocalAuthorizer(state).admit(enrollment, original, request.reply(tape.response))
        assert state.summary() == {"attempts": 1, "authorizations": 0, "callback_claims": 0}


def test_execution_failure_consumes_attempt_across_restart(case, tmp_path, monkeypatch):
    _ctx, _tape, enrollment, request, original, _owner, _query, _library = case
    path = tmp_path / "state.db"
    with journal(path, enrollment) as state:
        state.install(enrollment)

        def fail(*_args):
            raise ValueError("Public native failure")

        monkeypatch.setattr(request._arithmetic, "frame", fail)
        with pytest.raises(ValueError):
            replay.PreparedReplayAuthorizer(state).execute(enrollment, original)
        assert state.summary() == {"attempts": 1, "authorizations": 0, "callback_claims": 0}
    with journal(path, enrollment) as restarted, pytest.raises(life.ConsumedRequestError):
        replay.PreparedReplayAuthorizer(restarted).execute(enrollment, original)


def test_stale_snapshot_and_wrong_mode_do_not_release(material, case, tmp_path):
    _ctx, _tape, enrollment, _request, original, owner, _query, library = case
    factory, data = material[5:]
    _, _, metadata, keys, index, query = data
    with journal(tmp_path / "state.db", enrollment) as state:
        state.install(enrollment)
        _packet, authorization = replay.PreparedReplayAuthorizer(state).execute(
            enrollment, original
        )
        signed = auth.sign_enrollment(metadata, keys, index, 2, factory.policy_digest, owner)
        with factory.enroll(signed) as newer:
            state.install(newer)
            with pytest.raises(life.StaleSnapshotError):
                life.LocalReleaseGuard(state).deliver(
                    authorization, lambda _frame: pytest.fail("Stale hook")
                )
        regular = auth.OwnerFactory(fixtures.public_key(owner), library)
        with regular.enroll(
            auth.sign_enrollment(metadata, keys, index, 3, regular.policy_digest, owner)
        ) as foreign:
            wrong = request_packet(foreign, owner, query, bytes([9]) * 32)
            with pytest.raises(ValueError):
                replay.PreparedReplayAuthorizer(state).execute(foreign, wrong)
        assert state.summary()["callback_claims"] == 0
