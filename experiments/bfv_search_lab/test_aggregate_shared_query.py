"""Retained exact aggregate/public lifecycle gates; no HE private operations."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import copy
import ctypes
import hashlib
import os
from pathlib import Path
import pickle
import select
import signal
import threading

import msgpack
import pytest

from benchmarks import native_shared_query_lab as lab
from experiments.bfv_search_lab import aggregate_reference as reference
from experiments.bfv_search_lab import aggregate_shared_query as aggregate
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import lifecycle_shared_query as life
from experiments.bfv_search_lab import native_boundary_oracle as schoolbook
from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_bgv as shared
from experiments.bfv_search_lab import shared_query_gmp as gmp
from experiments.bfv_search_lab import test_authenticated_shared_query as auth_tests
from experiments.bfv_search_lab import test_replay_shared_query as replay_tests
from experiments.bfv_search_lab.test_native_shared_query import CASE_IDS


@pytest.fixture(scope="module")
def material():
    data = list(replay_tests.material.__wrapped__())
    data[5] = aggregate.AggregateFactory(auth_tests.public_key(data[4]), data[0])
    return tuple(data)


@pytest.fixture
def case(material):
    yield from replay_tests.case.__wrapped__(material)


def changed(body, coordinate, delta, q):
    offset = coordinate * native.COMMON_WIDTH
    value = (int.from_bytes(body[offset : offset + 15], "little") + delta) % q
    return body[:offset] + value.to_bytes(15, "little") + body[offset + 15 :]


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_every_small_aggregate_frame_and_coordinate_fault(material, case_id):
    library, directory, entries, public, owner, factory, _data = material
    ctx, tape, metadata, keys, index, query = auth_tests.owner_inputs(
        directory, entries[case_id], public
    )
    expected = reference.small_aggregates(ctx)
    assert expected == reference.from_saved_transcript(metadata, keys, lab.body(ctx, tape))
    signed = auth.sign_enrollment(metadata, keys, index, 1, factory.policy_digest, owner)
    with factory.enroll(signed) as enrollment:
        original = replay_tests.request_packet(
            enrollment, owner, query, hashlib.sha256(case_id.encode()).digest()
        )
        with enrollment.request(original) as request:
            packet = request.reply(expected, tape.response)
            assert request.produce_packet() == packet
            assert request.checked_frame(packet) == tape.response
            coordinates, faults = 3 * metadata.groups * ctx.profile.n, 0
            for coordinate in range(coordinates):
                for delta in (1, *metadata.primes):
                    other = changed(expected, coordinate, delta, ctx.profile.q)
                    assert request._arithmetic.checked_frame(request._query, other) is None
                    faults += 1
            assert faults == 3 * coordinates


@pytest.mark.parametrize("fault", ["short", "extra", "mutable", "memoryview", "first_q", "last_q"])
def test_complete_common_Q_grammar(case, fault):
    ctx, _tape, _enrollment, request, _original, _owner, _query, _library = case
    body = reference.small_aggregates(ctx)
    if fault == "short":
        body = body[:-1]
    elif fault == "extra":
        body += b"\x00"
    elif fault == "mutable":
        body = bytearray(body)
    elif fault == "memoryview":
        body = memoryview(body)
    else:
        at = 0 if fault == "first_q" else len(body) - 15
        body = body[:at] + ctx.profile.q.to_bytes(15, "little") + body[at + 15 :]
    assert request._arithmetic.checked_frame(request._query, body) is None


def test_component_cancellation_at_one_visible_point_is_insufficient(case):
    ctx, tape, _enrollment, request, _original, _owner, _query, _library = case
    body = reference.small_aggregates(ctx)
    other = changed(changed(body, 0, 1, ctx.profile.q), ctx.profile.n, -1, ctx.profile.q)
    for i in range(ctx.profile.n):
        offsets = [(part * ctx.profile.n + i) * 15 for part in range(3)]
        before = sum(int.from_bytes(body[at : at + 15], "little") for at in offsets) % ctx.profile.q
        after = sum(int.from_bytes(other[at : at + 15], "little") for at in offsets) % ctx.profile.q
        assert before == after  # A=1 would accept this entire erroneous vector.
    assert request.checked_frame(request.reply(other, tape.response)) is None


def test_each_physical_NTT_coordinate_cannot_hide_a_single_prime_fault(case):
    ctx, _tape, enrollment, request, _original, _owner, _query, _library = case
    body, n, q = reference.small_aggregates(ctx), ctx.profile.n, ctx.profile.q
    faults = 0
    # Every odd root is visited, so this does not assume the native transform's
    # root choice, bit reversal or frequency ordering. The error is zero at all
    # but one root in one actual prime, and zero everywhere in the other prime.
    for prime, other in (enrollment.metadata.primes, enrollment.metadata.primes[::-1]):
        candidate, psi = 2, 0
        while not psi:
            root = pow(candidate, (prime - 1) // (2 * n), prime)
            if pow(root, n, prime) == prime - 1:
                psi = root
            candidate += 1
        for frequency in range(n):
            scale = pow(n, -1, prime)
            delta = tuple(
                other
                * (
                    (scale * pow(psi, -(2 * frequency + 1) * i, prime) * pow(other, -1, prime))
                    % prime
                )
                for i in range(n)
            )
            assert all(value % other == 0 for value in delta)
            for point in range(n):
                residual = (
                    sum(
                        value * pow(psi, (2 * point + 1) * i, prime)
                        for i, value in enumerate(delta)
                    )
                    % prime
                )
                assert residual == int(point == frequency)
            for group in range(enrollment.metadata.groups):
                for part in range(3):
                    changed_body = bytearray(body)
                    for i, value in enumerate(delta):
                        at = ((3 * group + part) * n + i) * 15
                        coefficient = (int.from_bytes(body[at : at + 15], "little") + value) % q
                        changed_body[at : at + 15] = coefficient.to_bytes(15, "little")
                    assert (
                        request._arithmetic.checked_frame(request._query, bytes(changed_body))
                        is None
                    )
                    faults += 1
    assert faults == 2 * n * enrollment.metadata.groups * 3 == 384


@pytest.mark.parametrize(
    "fault",
    [
        "mode",
        "epoch_bool",
        "snapshot",
        "policy",
        "request",
        "nonce",
        "ids",
        "extra",
        "trailing",
        "noncanonical",
    ],
)
def test_reply_binding_cannot_select_weaker_control_or_start_native_work(case, monkeypatch, fault):
    ctx, tape, _enrollment, request, _original, _owner, _query, _library = case
    packet = request.reply(reference.small_aggregates(ctx), tape.response)
    fields = msgpack.unpackb(packet, raw=False)
    if fault == "trailing":
        packet += b"\x00"
    elif fault == "noncanonical":
        packet = b"\xdc\x00\x09" + packet[1:]
    else:
        if fault == "mode":
            fields[0] = auth.REPLY_TAG
        elif fault == "epoch_bool":
            fields[2] = True
        elif fault == "extra":
            fields.append(b"weaker-hidden-point-mode")
        else:
            fields[{"snapshot": 1, "policy": 3, "request": 4, "nonce": 5, "ids": 6}[fault]] = bytes(
                32
            )
        packet = auth._pack(fields)

    def forbidden(*_args):
        pytest.fail("Invalid binding cannot reach the protected native prefix")

    monkeypatch.setattr(request._arithmetic, "checked_frame", forbidden)
    assert request.checked_frame(packet) is None


@pytest.mark.parametrize(
    "fault", ["key", "count", "dimension", "modulus", "last_tail", "missing_group"]
)
def test_full_terminal_frame_not_only_distances(case, fault):
    ctx, tape, _enrollment, request, _original, _owner, _query, _library = case
    header, rows = msgpack.unpackb(tape.response, raw=False)
    if fault in ("key", "count", "dimension", "modulus"):
        slot = {"key": 4, "count": 5, "dimension": 6, "modulus": 3}[fault]
        header[slot] = (
            bytes(32) if slot == 4 else (bytes(len(header[3])) if slot == 3 else header[slot] - 1)
        )
    elif fault == "missing_group":
        rows.pop()
    else:
        last = rows[-1][-1]
        rows[-1][-1] = last[:-1] + bytes([last[-1] ^ 1])
    assert (
        request.checked_frame(
            request.reply(reference.small_aggregates(ctx), auth._pack([header, rows]))
        )
        is None
    )


def test_C_ABI_bounds_and_late_rejection_do_not_write_terminal_bytes(case):
    ctx, _tape, _enrollment, request, _original, _owner, _query, library = case
    body = reference.small_aggregates(ctx)
    size = 2 * request._query.metadata.groups * request._query.metadata.terminal_row_size
    output = ctypes.create_string_buffer(b"\xa5" * size, size)
    claim = ctypes.create_string_buffer(b"\x5a" * len(body), len(body))
    finish, produce = (
        library._lib.cuhepy_shared_aggregate_finish,
        library._lib.cuhepy_shared_aggregate_produce,
    )
    for invalid in (0, len(body) - 1, len(body) + 1):
        assert finish(request._query._handle, native._pointer(body), invalid, output, size) == -1
        assert produce(request._query._handle, claim, invalid, output, size) == -1
        assert output.raw == b"\xa5" * size and claim.raw == b"\x5a" * len(body)
    for invalid in (0, size - 1, size + 1):
        assert (
            finish(request._query._handle, native._pointer(body), len(body), output, invalid) == -1
        )
        assert produce(request._query._handle, claim, len(body), output, invalid) == -1
        assert output.raw == b"\xa5" * size and claim.raw == b"\x5a" * len(body)
    for function in (finish, produce):
        assert function(None, claim, len(body), output, size) == -1
        assert function(request._query._handle, None, len(body), output, size) == -1
        assert function(request._query._handle, claim, len(body), None, size) == -1
    for other, status in (
        (body[:-15] + ctx.profile.q.to_bytes(15, "little"), -1),
        (changed(body, len(body) // 15 - 1, ctx.profile.q // 2, ctx.profile.q), 0),
    ):
        assert (
            finish(request._query._handle, native._pointer(other), len(other), output, size)
            == status
        )
        assert output.raw == b"\xa5" * size


def test_public_check_never_calls_private_reference_or_producer_oracles(case, monkeypatch):
    ctx, tape, _enrollment, request, _original, _owner, _query, library = case
    body = reference.small_aggregates(ctx)
    packet = request.reply(body, tape.response)

    def forbidden(*_args, **_kwargs):
        pytest.fail("Aggregate admission cannot call a private/reference/producer oracle")

    for module, names in (
        (bgv, ("key_gen", "encrypt", "decrypt")),
        (shared, ("produce", "expected_frame")),
        (gmp.GMPPublicContext, ("produce",)),
        (reference, ("small_aggregates", "from_saved_transcript")),
        (request._arithmetic, ("produce",)),
        (
            library._lib,
            ("cuhepy_shared_produce", "cuhepy_shared_replay", "cuhepy_shared_aggregate_produce"),
        ),
    ):
        for name in names:
            monkeypatch.setattr(module, name, forbidden)
    assert request.checked_frame(packet) == tape.response


def test_original_ABI_libraries_cannot_supply_a_hidden_fallback(material, monkeypatch):
    library, _dir, _entries, _public, owner, factory, _data = material
    assert (
        factory.policy_digest
        != auth.OwnerFactory(auth_tests.public_key(owner), library).policy_digest
    )
    monkeypatch.setattr(library._lib, "cuhepy_shared_aggregate_abi", lambda: 0)
    with pytest.raises(ValueError, match="ABI"):
        aggregate.AggregateFactory(auth_tests.public_key(owner), library)
    path = os.getenv("CUHEPY_SHARED_QUERY_ORIGINAL_LIBRARY")
    if path:
        with pytest.raises(ValueError, match="symbols"):
            aggregate.AggregateFactory(auth_tests.public_key(owner), native.NativeLibrary(path))


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_owned_control_handles_cannot_be_copied(case, operation):
    for obj in (case[2], case[3]):
        with pytest.raises(TypeError):
            operation(obj)


def test_closed_context_queries_survive_and_threads_serialize(case):
    ctx, tape, enrollment, request, _original, _owner, _query, _library = case
    packet = request.reply(reference.small_aggregates(ctx), tape.response)
    enrollment.close()
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(lambda _: request.checked_frame(packet) == tape.response, range(8)))
    request.close()
    with pytest.raises(RuntimeError):
        request.checked_frame(packet)


def test_fork_rejects_before_inherited_native_mutex(case):
    ctx, tape, _enrollment, request, _original, _owner, _query, _library = case
    packet = request.reply(reference.small_aggregates(ctx), tape.response)
    ready, release = threading.Event(), threading.Event()

    def hold():
        with request._query._lock:
            ready.set()
            release.wait()

    thread = threading.Thread(target=hold)
    thread.start()
    assert ready.wait(5)
    rd, wr = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(rd)
        try:
            request.checked_frame(packet)
        except RuntimeError:
            request.close()
            os.write(wr, b"rejected")
            os._exit(0)
        os._exit(1)
    os.close(wr)
    try:
        readable, _, _ = select.select([rd], [], [], 5)
        if not readable:
            os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
        assert readable and status == 0 and os.read(rd, 64) == b"rejected"
    finally:
        os.close(rd)
        release.set()
        thread.join(5)


def test_bad_claim_consumed_good_claim_releases_once_and_persists(case, tmp_path):
    ctx, tape, enrollment, request, original, owner, seeded_query, _library = case
    body = reference.small_aggregates(ctx)
    path = tmp_path / "journal.db"
    with replay_tests.journal(path, enrollment) as journal:
        journal.install(enrollment)
        authorizer = life.LocalAuthorizer(journal)
        assert (
            authorizer.admit(
                enrollment,
                original,
                request.reply(changed(body, 0, 1, ctx.profile.q), tape.response),
            )
            is None
        )
        with pytest.raises(life.ConsumedRequestError):
            authorizer.admit(enrollment, original, request.reply(body, tape.response))
        good = replay_tests.request_packet(enrollment, owner, seeded_query, bytes([8]) * 32)
        with enrollment.request(good) as other:
            packet = other.reply(body, tape.response)
        authorization = authorizer.admit(enrollment, good, packet)
        delivered = []
        life.LocalReleaseGuard(journal).deliver(authorization, delivered.append)
        assert delivered == [tape.response]
        with pytest.raises(life.ConsumedRequestError):
            life.LocalReleaseGuard(journal).deliver(authorization, delivered.append)
        assert journal.summary() == {"attempts": 2, "authorizations": 1, "callback_claims": 1}
    with (
        replay_tests.journal(path, enrollment) as journal,
        pytest.raises(life.ConsumedRequestError),
    ):
        life.LocalAuthorizer(journal).admit(enrollment, good, packet)


def test_authorization_stales_before_callback_and_foreign_mode_rejected(material, case, tmp_path):
    ctx, tape, enrollment, request, original, owner, _query, library = case
    with replay_tests.journal(tmp_path / "state.db", enrollment) as journal:
        journal.install(enrollment)
        authorization = life.LocalAuthorizer(journal).admit(
            enrollment, original, request.reply(reference.small_aggregates(ctx), tape.response)
        )
        factory, data = material[5:]
        _, _, metadata, keys, index, _seeded = data
        with factory.enroll(
            auth.sign_enrollment(metadata, keys, index, 2, factory.policy_digest, owner)
        ) as newer:
            journal.install(newer)
            with pytest.raises(life.StaleSnapshotError):
                life.LocalReleaseGuard(journal).deliver(
                    authorization, lambda _frame: pytest.fail("Stale hook")
                )
        foreign = auth.OwnerFactory(auth_tests.public_key(owner), library)
        with (
            foreign.enroll(
                auth.sign_enrollment(metadata, keys, index, 3, foreign.policy_digest, owner)
            ) as other,
            pytest.raises(ValueError),
        ):
            journal.install(other)
        assert journal.summary()["callback_claims"] == 0


def test_schoolbook_guard_and_GMP_buffer_bounds_precede_arithmetic(case, monkeypatch):
    ctx, tape, enrollment, _request, _original, _owner, _query, _library = case

    def forbidden(*_args):
        pytest.fail("Invalid reference bounds before multiplication")

    monkeypatch.setattr(schoolbook, "multiply", forbidden)
    with pytest.raises(ValueError, match="N<=64"):
        reference.small_aggregates(replace(ctx, profile=replace(ctx.profile, n=128)))
    with pytest.raises(ValueError):
        reference.from_saved_transcript(enrollment.metadata, b"", lab.body(ctx, tape))
