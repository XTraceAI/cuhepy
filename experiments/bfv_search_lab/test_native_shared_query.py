"""Retained public fixtures and adversarial native arithmetic/ownership boundaries.

Explicit isolated library/fixture paths are required. Tests generate no HE key,
encrypt no new query/index and do no private work. No service release is implied.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import copy
import ctypes
import os
from pathlib import Path
import pickle
import select
import signal
import threading

import msgpack
import pytest

from benchmarks import native_shared_query_lab as lab
from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_bgv as shared

CASE_IDS = tuple(
    f"c{c}-q{query}-m{count}-owner-canonical30"
    for c, n in enumerate((16, 32))
    for query in range(2)
    for count in (n - 1, n, n + 1, 2 * n - 1)
)


@pytest.fixture(scope="module")
def retained():
    path = os.getenv("CUHEPY_SHARED_QUERY_FIXTURES")
    if not path:
        pytest.skip("Explicit retained fixture directory required")
    directory = Path(path)
    report, entries = lab.public_cases(directory)
    fixtures = lab.public_fixtures(directory, report)
    return directory, {x["id"]: x for x in entries}, fixtures


@pytest.fixture(scope="module")
def library():
    path = os.getenv("CUHEPY_SHARED_QUERY_LIBRARY")
    if not path:
        pytest.skip("Explicit isolated native library required")
    return native.NativeLibrary(path)


def load(retained, case_id):
    directory, entries, fixtures = retained
    return lab.load_case(directory, entries[case_id], fixtures)[:4]


@pytest.fixture
def case(retained, library):
    ctx, tape, _pk, primes = load(retained, CASE_IDS[-1])
    with (
        library.from_reference(ctx, primes) as enrollment,
        enrollment.query(native.pack_common(ctx.query, ctx.profile.n, ctx.profile.q)) as query,
    ):
        yield ctx, tape, enrollment, query, primes


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_every_retained_body_and_frame(case_id, retained, library):
    ctx, tape, _pk, primes = load(retained, case_id)
    expected = lab.body(ctx, tape)
    with (
        library.from_reference(ctx, primes) as enrollment,
        enrollment.query(native.pack_common(ctx.query, ctx.profile.n, ctx.profile.q)) as query,
    ):
        assert query.produce() == expected
        assert query.residuals(expected) == lab.limb_residuals(ctx, tape, primes)
        assert query.verifies(expected, tape.response)


@pytest.mark.parametrize("fault", ["short", "extra", "mutable", "memoryview", "first_q", "last_q"])
def test_complete_body_grammar_fails_closed(case, fault):
    ctx, tape, _enrollment, query, _primes = case
    body = lab.body(ctx, tape)
    if fault == "short":
        body = body[:-1]
    elif fault == "extra":
        body += b"\x00"
    elif fault == "mutable":
        body = bytearray(body)
    elif fault == "memoryview":
        body = memoryview(body)
    else:
        at = 0 if fault == "first_q" else len(body) - native.COMMON_WIDTH
        body = (
            body[:at]
            + ctx.profile.q.to_bytes(native.COMMON_WIDTH, "little")
            + body[at + native.COMMON_WIDTH :]
        )
    assert not query.check(body)
    assert not query.verifies(body, tape.response)


@pytest.mark.parametrize("fault", ["short", "extra", "mutable", "last_q"])
def test_original_query_coverage_precedes_native_work(case, fault):
    ctx, _tape, enrollment, _query, _primes = case
    body = native.pack_common(ctx.query, ctx.profile.n, ctx.profile.q)
    if fault == "short":
        body = body[:-1]
    elif fault == "extra":
        body += b"\x00"
    elif fault == "mutable":
        body = bytearray(body)
    else:
        body = body[: -native.COMMON_WIDTH] + ctx.profile.q.to_bytes(native.COMMON_WIDTH, "little")
    with pytest.raises(ValueError):
        enrollment.query(body)


@pytest.mark.parametrize("family", ["keys", "index"])
@pytest.mark.parametrize("fault", ["short", "extra", "mutable", "last_q"])
def test_all_enrollment_buffer_coordinates_and_lengths(case, library, family, fault):
    ctx, _tape, enrollment, _query, _primes = case
    p = ctx.profile
    keys = (ctx.relin, *(key for _, key in ctx.rotations))
    key_body = native.pack_common(
        tuple(row for key in keys for column in key for row in column), p.n, p.q
    )
    index_body = native.pack_common(tuple(row for pair in ctx.index for row in pair), p.n, p.q)
    body = key_body if family == "keys" else index_body
    if fault == "short":
        body = body[:-1]
    elif fault == "extra":
        body += b"\x00"
    elif fault == "mutable":
        body = bytearray(body)
    else:
        body = body[: -native.COMMON_WIDTH] + p.q.to_bytes(native.COMMON_WIDTH, "little")
    if family == "keys":
        key_body = body
    else:
        index_body = body
    with pytest.raises(ValueError):
        library.enroll(enrollment.metadata, key_body, index_body)


@pytest.mark.parametrize("fault", ["policy", "origin", "primes", "key_id", "ids", "count"])
def test_public_profile_scope_is_not_peer_supplied(case, fault):
    _ctx, _tape, enrollment, _query, primes = case
    metadata = enrollment.metadata
    if fault == "policy":
        fields = {"profile": replace(metadata.profile, policy="derived_last30")}
    elif fault == "origin":
        fields = {"profile": replace(metadata.profile, index_mode="public_key")}
    elif fault == "primes":
        fields = {"primes": (primes[0], primes[0])}
    elif fault == "key_id":
        fields = {"key_id": "g" * 64}
    elif fault == "ids":
        fields = {"ids": (1, 1)}
    else:
        fields = {"ids": tuple(range(2 * metadata.profile.n + 1))}
    with pytest.raises(ValueError):
        replace(metadata, **fields)


@pytest.mark.parametrize(
    "fault",
    ["short", "trailing", "key", "count", "dimension", "modulus", "last_tail", "group_missing"],
)
def test_complete_response_frame_not_just_scores(case, fault):
    _ctx, tape, _enrollment, query, _primes = case
    response = tape.response
    header, rows = msgpack.unpackb(response, raw=False)
    if fault == "short":
        response = response[:-1]
    elif fault == "trailing":
        response += b"\x00"
    else:
        if fault == "key":
            header[4] = bytes(32)
        elif fault == "count":
            header[5] -= 1
        elif fault == "dimension":
            header[6] -= 1
        elif fault == "modulus":
            header[3] = bytes(len(header[3]))
        elif fault == "last_tail":
            rows[-1][-1] = rows[-1][-1][:-1] + bytes([rows[-1][-1][-1] ^ 1])
        else:
            rows = rows[:-1]
        response = msgpack.packb([header, rows], use_bin_type=True)
    assert not query.verifies(lab.body(_ctx, tape), response)


def test_one_prime_preserving_output_fault_matches_whole_schoolbook(case):
    ctx, tape, _enrollment, query, primes = case
    changed = lab.changed_coordinate(ctx, tape, len(tape.sources) + 2 * ctx.groups - 1, primes[0])
    body = lab.body(ctx, changed)
    residuals = query.residuals(body)
    assert residuals == lab.limb_residuals(ctx, changed, primes)
    assert all(not any(pair[0]) for pair in residuals)
    assert any(any(pair[1]) for pair in residuals)
    assert not query.verifies(body, changed.response)


def test_scalar_zero_polynomial_is_rejected(case):
    ctx, tape, _enrollment, query, (p0, p1) = case
    n, q = ctx.profile.n, ctx.profile.q
    candidate, psi = 2, 0
    while not psi:
        value = pow(candidate, (p0 - 1) // (2 * n), p0)
        if pow(value, n, p0) == p0 - 1:
            psi = value
        candidate += 1
    delta = ((-p1 * psi) % q, p1, *((0,) * (n - 2)))
    assert sum(x * pow(psi, i, p0) for i, x in enumerate(delta)) % p0 == 0
    assert all(x % p1 == 0 for x in delta)
    pair = tape.full_output[-1]
    changed = tuple((x + y) % q for x, y in zip(pair[0], delta, strict=True))
    outputs = (*tape.full_output[:-1], (changed, pair[1]))
    other = replace(tape, full_output=outputs, response=shared.expected_frame(ctx, outputs))
    assert not query.verifies(lab.body(ctx, other), other.response)


def test_residual_C_ABI_requires_exact_output_length(case, library):
    ctx, tape, enrollment, query, _primes = case
    words = 2 * enrollment.stats.residual_polynomials * ctx.profile.n
    sentinel = (ctypes.c_uint64 * words)(*([123] * words))
    body = lab.body(ctx, tape)
    fn = library._lib.cuhepy_shared_residuals
    for invalid in (0, words - 1, words + 1):
        assert fn(query._handle, native._pointer(body), len(body), sentinel, invalid) == -1
        assert tuple(sentinel) == (123,) * words


def test_verification_cannot_call_producer_private_or_reference_oracles(case, library, monkeypatch):
    ctx, tape, _enrollment, query, _primes = case
    body = lab.body(ctx, tape)

    def forbidden(*_args, **_kwargs):
        pytest.fail("Public checking cannot use replay/producer/private arithmetic")

    for module, names in [
        (bgv, ("key_gen", "encrypt", "decrypt")),
        (shared, ("produce", "expected_frame")),
    ]:
        for name in names:
            monkeypatch.setattr(module, name, forbidden)
    monkeypatch.setattr(library._lib, "cuhepy_shared_produce", forbidden)
    assert query.verifies(body, tape.response)


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_handle_ownership_cannot_be_copied_or_serialized(case, operation):
    _ctx, _tape, enrollment, query, _primes = case
    for obj in (enrollment, query):
        with pytest.raises(TypeError):
            operation(obj)


def test_query_retains_context_and_closed_handles_fail(case):
    ctx, tape, enrollment, query, _primes = case
    body = lab.body(ctx, tape)
    enrollment.close()
    assert query.verifies(body, tape.response)
    with pytest.raises(RuntimeError):
        enrollment.query(native.pack_common(ctx.query, ctx.profile.n, ctx.profile.q))
    query.close()
    query.close()
    with pytest.raises(RuntimeError):
        query.check(body)


def test_parallel_queries_share_only_immutable_native_preparation(case):
    ctx, tape, enrollment, _query, _primes = case
    body = lab.body(ctx, tape)
    raw = native.pack_common(ctx.query, ctx.profile.n, ctx.profile.q)

    def run(_):
        with enrollment.query(raw) as query:
            return all(query.verifies(body, tape.response) for _ in range(8))

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(run, range(4)))


def test_fork_rejects_before_inherited_mutex(case):
    ctx, tape, _enrollment, query, _primes = case
    body = lab.body(ctx, tape)
    ready, release = threading.Event(), threading.Event()

    def hold():
        with query._lock:
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
            query.check(body)
        except RuntimeError:
            query.close()  # Also must not acquire the inherited locked mutex.
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
    assert query.verifies(body, tape.response)
