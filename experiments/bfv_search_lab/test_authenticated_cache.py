"""Q76.4c boundary regressions: no HE keys, decryptions or timing panels."""

import copy
import ctypes as ct
from dataclasses import replace
import hashlib
import os
import pickle
import select
import signal
import struct
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
import pytest

from experiments.bfv_search_lab import authenticated_cache as cache


@pytest.fixture(scope="session")
def keys():
    # Public UNIT-ONLY fixtures, reused across normal/UBSan invocations. These
    # are not a production key recipe; the retained cohort generates fresh keys.
    key = hashlib.sha256(b"Q76.4c public unit AES fixture").digest()
    return (
        key,
        hashlib.sha256(key + b"wrong-key-control").digest(),
        Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"Q76.4c public unit owner").digest()),
        Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(b"Q76.4c public unit foreign owner").digest()
        ),
    )


@pytest.fixture
def native():
    path = os.environ.get("CUHEPY_CACHE_LIBRARY")
    assert path, "Required isolated cache library must be built and pinned; do not skip this gate"
    library = cache.NativePopcount(path)
    yield library
    library.close()


def token(label):
    return hashlib.sha256(label.encode()).digest()


def snapshot(keys, rows=(0, 0, 0, 0, 1), ids=(99, 7, 42, 11, 1), dimension=3, **options):
    values = dict(
        namespace=token("namespace"),
        key_id=token("key-label"),
        snapshot_id=token("snapshot-one"),
        epoch=1,
    )
    values.update(options)
    return cache.seal_snapshot(rows, ids, dimension, keys[0], keys[2], **values)


def client(native, keys, delivery):
    return cache.CacheClient(
        native, keys[0], keys[2].public_key().public_bytes_raw(), delivery.context
    )


def authenticate_bad_body(keys, context, body, kind=cache.SNAPSHOT, previous=None):
    # Deliberately bypass the honest owner encoder to test authenticated grammar.
    contexts = (context,) if previous is None else (previous, context)
    packet = cache._seal_body(body, keys[0], kind, contexts)
    return packet, cache._sign(packet, keys[2], kind, contexts)


def raw_snapshot(rows, ids, dimension):
    width = (dimension + 7) // 8
    return b"".join(x.to_bytes(8, "little") for x in ids) + b"".join(
        x.to_bytes(width, "little") for x in rows
    )


def reference(rows, ids, dimension, query):
    # Literal bits are independent of the native word-popcount implementation.
    scores = tuple(
        sum(((row >> j) & 1) != ((query >> j) & 1) for j in range(dimension)) for row in rows
    )
    positions = tuple(sorted(range(len(rows)), key=lambda i: (scores[i], i))[:3])
    return scores, positions, tuple((scores[i], ids[i]) for i in positions)


@pytest.mark.parametrize("dimension", [1, 3, 7, 8, 9, 63, 64, 65, 511, 512])
def test_complete_scores_and_ordinal_tie_membership(native, keys, dimension):
    rows, ids = (0, 0, 0, 0, (1 << dimension) - 1), (99, 7, 42, 11, 1)
    delivery = snapshot(keys, rows, ids, dimension)
    owner = client(native, keys, delivery)
    owner.acquire(delivery.packet, delivery.descriptor)
    got = owner.query(0)
    assert (got.scores, got.top3_positions, got.top3) == reference(rows, ids, dimension, 0)
    assert got.top3_positions == (0, 1, 2) and got.top3 == ((0, 99), (0, 7), (0, 42))
    assert owner.inventory()["retained_canonical_body_bytes"] == len(rows) * (
        8 + (dimension + 7) // 8
    )


@pytest.mark.parametrize("count", [1, 2, 3, 4, 32])
def test_short_and_reversed_ID_contexts(native, keys, count):
    rows, ids = tuple([0] * count), tuple(cache.UINT64_MAX - i for i in range(count))
    delivery = snapshot(keys, rows, ids)
    owner = client(native, keys, delivery)
    with pytest.raises(ValueError):
        owner.query(0)
    owner.acquire(delivery.packet, delivery.descriptor)
    got = owner.query(0)
    assert (got.scores, got.top3_positions, got.top3) == reference(rows, ids, 3, 0)


@pytest.mark.parametrize(
    "field,value",
    [
        ("epoch", True),
        ("epoch", 0),
        ("epoch", 1 << 64),
        ("count", 0),
        ("count", 32769),
        ("dimension", 0),
        ("dimension", 513),
        ("namespace", bytearray(32)),
        ("key_id", b"short"),
        ("snapshot_id", "x" * 32),
        ("ordered_ids_digest", b"bad"),
    ],
)
def test_owner_context_bounds(keys, field, value):
    with pytest.raises(ValueError):
        replace(snapshot(keys).context, **{field: value})


@pytest.mark.parametrize(
    "rows,ids",
    [
        ((True,), (1,)),
        ((8,), (1,)),
        ((-1,), (1,)),
        ((0, 0), (1, 1)),
        ((0,), (True,)),
        ((0,), (-1,)),
        ((0,), (1 << 64,)),
        ((0,), ()),
        ((), ()),
    ],
)
def test_owner_rejects_invalid_rows_and_IDs(keys, rows, ids):
    with pytest.raises(ValueError):
        snapshot(keys, rows, ids)


class DecryptSpy:
    def __init__(self, aead):
        self.aead, self.calls = aead, 0

    def decrypt(self, *args):
        self.calls += 1
        return self.aead.decrypt(*args)


@pytest.mark.parametrize(
    "fault", ["signature", "anchor", "ciphertext", "context", "extra", "short", "kind"]
)
def test_public_rejection_precedes_AEAD_and_preserves_cache(native, keys, fault):
    delivery = snapshot(keys)
    owner = client(native, keys, delivery)
    owner.acquire(delivery.packet, delivery.descriptor)
    before = owner.query(0)
    packet, descriptor = delivery.packet, delivery.descriptor
    if fault == "signature":
        descriptor = descriptor[:-1] + bytes([descriptor[-1] ^ 1])
    elif fault == "anchor":
        descriptor = cache._sign(packet, keys[3], cache.SNAPSHOT, (delivery.context,))
    elif fault == "ciphertext":
        packet = packet[:-1] + bytes([packet[-1] ^ 1])
    elif fault == "context":
        descriptor = cache._sign(
            packet,
            keys[2],
            cache.SNAPSHOT,
            (replace(delivery.context, snapshot_id=token("foreign")),),
        )
    elif fault == "extra":
        packet += b"extra"
    elif fault == "short":
        descriptor = descriptor[:-1]
    else:
        body = bytearray(descriptor[:-64])
        body[len(cache.DESCRIPTOR_MAGIC)] = cache.UPDATE
        descriptor = bytes(body) + keys[2].sign(bytes(body))
    spy = DecryptSpy(owner._aead)
    owner._aead = spy
    with pytest.raises(ValueError):
        owner.acquire(packet, descriptor)
    assert spy.calls == 0 and owner.query(0) == before


@pytest.mark.parametrize(
    "fault", ["wrong_key", "valid_signature_bad_tag", "valid_signature_wrong_AAD"]
)
def test_AEAD_authentication_precedes_parse_publication(native, keys, fault):
    delivery = snapshot(keys)
    owner = client(native, keys, delivery)
    if fault == "wrong_key":
        owner._aead = AESGCMSIV(keys[1])
        packet, descriptor = delivery.packet, delivery.descriptor
    elif fault == "valid_signature_bad_tag":
        packet = delivery.packet[:-1] + bytes([delivery.packet[-1] ^ 1])
        descriptor = cache._sign(packet, keys[2], cache.SNAPSHOT, (delivery.context,))
    else:
        packet = cache._seal_body(
            raw_snapshot((0, 0, 0, 0, 1), (99, 7, 42, 11, 1), 3),
            keys[0],
            cache.SNAPSHOT,
            (replace(delivery.context, namespace=token("wrong-AAD")),),
        )
        descriptor = cache._sign(packet, keys[2], cache.SNAPSHOT, (delivery.context,))
    with pytest.raises(ValueError):
        owner.acquire(packet, descriptor)
    assert not owner.inventory()["active"] and owner._rows == owner._ids == b""


@pytest.mark.parametrize("fault", ["last_row_padding", "duplicate_IDs", "ID_binding"])
def test_authenticated_snapshot_grammar_rejects_without_publication(native, keys, fault):
    delivery = snapshot(keys)
    context = delivery.context
    rows, ids = [0, 0, 0, 0, 1], [99, 7, 42, 11, 1]
    if fault == "last_row_padding":
        rows[-1] = 0x81
    elif fault == "duplicate_IDs":
        ids[-1] = ids[0]
        raw_ids = b"".join(x.to_bytes(8, "little") for x in ids)
        context = replace(context, ordered_ids_digest=cache._id_digest(raw_ids, len(ids)))
    else:
        ids[-1] = 123
    owner = cache.CacheClient(native, keys[0], keys[2].public_key().public_bytes_raw(), context)
    packet, descriptor = authenticate_bad_body(keys, context, raw_snapshot(rows, ids, 3))
    with pytest.raises(ValueError):
        owner.acquire(packet, descriptor)
    assert owner._cached is None and owner._rows == owner._ids == b""


def test_update_preserves_IDs_and_ordinal_ties_and_replay_rejects(native, keys):
    delivery = snapshot(keys)
    owner = client(native, keys, delivery)
    owner.acquire(delivery.packet, delivery.descriptor)
    patch = cache.seal_update(
        ((0, 1), (4, 0)), keys[0], keys[2], delivery.context, snapshot_id=token("two")
    )
    with pytest.raises(ValueError):  # The signed patch cannot promote itself.
        owner.apply_update(patch.packet, patch.descriptor)
    owner.pin_current(patch.context)
    assert not owner.inventory()["active"]
    with pytest.raises(ValueError):
        owner.query(0)
    owner.apply_update(patch.packet, patch.descriptor)
    got = owner.query(0)
    assert (got.scores, got.top3_positions, got.top3) == reference(
        (1, 0, 0, 0, 0), (99, 7, 42, 11, 1), 3, 0
    )
    assert got.top3_positions == (1, 2, 3)
    before = owner._rows
    with pytest.raises(ValueError):
        owner.apply_update(patch.packet, patch.descriptor)
    assert owner._rows == before
    with pytest.raises(ValueError):
        owner.acquire(delivery.packet, delivery.descriptor)


@pytest.mark.parametrize(
    "changes",
    [(), ((1, 0), (0, 0)), ((0, 0), (0, 1)), ((5, 0),), ((True, 0),), ((1, 8),), ((1, -1),)],
)
def test_owner_patch_bounds(keys, changes):
    with pytest.raises(ValueError):
        cache.seal_update(
            changes, keys[0], keys[2], snapshot(keys).context, snapshot_id=token("two")
        )


@pytest.mark.parametrize(
    "fault", ["late_padding", "late_ordinal", "duplicate", "unsorted", "count", "extra"]
)
def test_authenticated_late_patch_fault_does_not_partly_mutate(native, keys, fault):
    delivery = snapshot(keys)
    owner = client(native, keys, delivery)
    owner.acquire(delivery.packet, delivery.descriptor)
    patch = cache.seal_update(
        ((0, 1), (4, 0)), keys[0], keys[2], delivery.context, snapshot_id=token("two")
    )
    owner.pin_current(patch.context)
    body = bytearray(struct.pack("<H", 2) + struct.pack("<IBIB", 0, 1, 4, 0))
    if fault == "late_padding":
        body[-1] = 0x80
    elif fault == "late_ordinal":
        body[7:11] = struct.pack("<I", 5)
    elif fault == "duplicate":
        body[7:11] = struct.pack("<I", 0)
    elif fault == "unsorted":
        body[2:6] = struct.pack("<I", 4)
        body[7:11] = struct.pack("<I", 0)
    elif fault == "count":
        body[:2] = struct.pack("<H", 33)
    else:
        body += b"x"
    packet, descriptor = authenticate_bad_body(
        keys, patch.context, bytes(body), cache.UPDATE, delivery.context
    )
    before = owner._rows
    with pytest.raises(ValueError):
        owner.apply_update(packet, descriptor)
    assert owner._rows == before and owner._cached == delivery.context
    with pytest.raises(ValueError):
        owner.query(0)


def test_gap_requires_full_acquisition_and_shape_change_cannot_patch(native, keys):
    delivery = snapshot(keys)
    owner = client(native, keys, delivery)
    owner.acquire(delivery.packet, delivery.descriptor)
    two = replace(delivery.context, snapshot_id=token("two"), epoch=2)
    three = replace(two, snapshot_id=token("three"), epoch=3)
    owner.pin_current(two)
    owner.pin_current(three)
    with pytest.raises(ValueError):
        owner.apply_update(b"", b"")
    replacement = snapshot(keys, (1, 0), (123, 456), epoch=4, snapshot_id=token("four"))
    owner.pin_current(replacement.context)
    with pytest.raises(ValueError):
        owner.apply_update(b"", b"")
    owner.acquire(replacement.packet, replacement.descriptor)
    assert owner.query(0).top3 == ((0, 456), (1, 123))


@pytest.mark.parametrize(
    "field,value",
    [
        ("epoch", 1),
        ("epoch", 3),
        ("namespace", token("foreign")),
        ("key_id", token("different-key")),
        ("snapshot_id", token("snapshot-one")),
    ],
)
def test_invalid_current_pin_preserves_active_state(native, keys, field, value):
    delivery = snapshot(keys)
    owner = client(native, keys, delivery)
    owner.acquire(delivery.packet, delivery.descriptor)
    proposal = replace(delivery.context, epoch=2, snapshot_id=token("two"))
    with pytest.raises(ValueError):
        owner.pin_current(replace(proposal, **{field: value}))
    assert owner.current_context == delivery.context and owner.inventory()["active"]


def test_UInt64_epoch_end_is_not_wrapped(keys):
    context = snapshot(keys, epoch=cache.UINT64_MAX).context
    with pytest.raises(ValueError):
        cache.seal_update(((0, 1),), keys[0], keys[2], context, snapshot_id=token("two"))


def test_late_prefetch_cannot_republish_old_snapshot(native, keys):
    delivery = snapshot(keys)
    owner = client(native, keys, delivery)
    network_finished, acquired = threading.Event(), []

    def late_download():
        assert network_finished.wait(5)
        try:
            owner.acquire(delivery.packet, delivery.descriptor)
        except ValueError:
            acquired.append("rejected")

    worker = threading.Thread(target=late_download)
    worker.start()
    owner.pin_current(replace(delivery.context, epoch=2, snapshot_id=token("two")))
    network_finished.set()
    worker.join(5)
    assert not worker.is_alive() and acquired == ["rejected"]
    assert owner._cached is None and not owner.inventory()["active"]


def test_query_and_current_pin_linearize_without_mixed_rows(native, keys):
    delivery = snapshot(keys)
    owner = client(native, keys, delivery)
    owner.acquire(delivery.packet, delivery.descriptor)
    entered, release, pinned = threading.Event(), threading.Event(), threading.Event()
    original = native.scan
    results = []

    def paused_scan(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)

    native.scan = paused_scan
    reader = threading.Thread(target=lambda: results.append(owner.query(0)))
    reader.start()
    assert entered.wait(5)
    current = replace(delivery.context, epoch=2, snapshot_id=token("two"))

    def pin():
        owner.pin_current(current)
        pinned.set()

    writer = threading.Thread(target=pin)
    writer.start()
    release.set()
    reader.join(5)
    writer.join(5)
    assert not reader.is_alive() and not writer.is_alive() and pinned.is_set()
    assert results[0].context == delivery.context and results[0].top3_positions == (0, 1, 2)
    with pytest.raises(ValueError):
        owner.query(0)


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_ownership_and_close(native, keys, operation):
    owner = client(native, keys, snapshot(keys))
    with pytest.raises(TypeError):
        operation(owner)
    with pytest.raises(TypeError):
        operation(native)
    owner.close()
    owner.close()
    assert owner._key is None and owner._rows == b""
    with pytest.raises(RuntimeError):
        owner.query(0)
    native.close()
    native.close()
    with pytest.raises(RuntimeError):
        native.scan(b"\0", 1, 3, b"\0")


@pytest.mark.parametrize("which", ["client", "native"])
def test_fork_rejects_before_inherited_held_lock(native, keys, which):
    owner = client(native, keys, snapshot(keys))
    target = owner if which == "client" else native
    held, release = threading.Event(), threading.Event()

    def hold():
        with target._lock:
            held.set()
            assert release.wait(5)

    thread = threading.Thread(target=hold)
    thread.start()
    assert held.wait(5)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            if which == "client":
                owner.query(0)
            else:
                native.scan(b"\0", 1, 3, b"\0")
        except RuntimeError:
            os.write(write_fd, b"rejected")
        finally:
            os._exit(0)
    os.close(write_fd)
    try:
        ready = select.select([read_fd], [], [], 3)[0]
        if not ready:
            os.kill(pid, signal.SIGKILL)
        assert ready and os.read(read_fd, 64) == b"rejected"
    finally:
        os.close(read_fd)
        release.set()
        thread.join(5)
        os.waitpid(pid, 0)


def direct(native, **options):
    rows = (ct.c_ubyte * 4)(0, 1, 2, 3)
    query = (ct.c_ubyte * 1)(0)
    scores = (ct.c_uint16 * 4)(999, 999, 999, 999)
    top = (ct.c_uint32 * 3)(999, 999, 999)
    values = dict(
        rows=rows,
        row_bytes=4,
        count=4,
        dimension=3,
        query=query,
        query_bytes=1,
        scores=scores,
        score_count=4,
        positions=top,
        position_count=3,
    )
    values.update(options)
    status = native._call(*values.values())
    return status, tuple(scores), tuple(top)


@pytest.mark.parametrize(
    "fault",
    [
        "count",
        "dimension",
        "row_bytes",
        "query_bytes",
        "score_count",
        "position_count",
        "rows",
        "query",
        "scores",
        "positions",
    ],
)
def test_direct_C_ABI_bounds_do_not_write_sentinels(native, fault):
    value = None if fault in ("rows", "query", "scores", "positions") else 0
    status, scores, top = direct(native, **{fault: value})
    assert status == -1 and scores == (999,) * 4 and top == (999,) * 3


@pytest.mark.parametrize(
    "fault",
    [
        "late_padding",
        "query_padding",
        "input_alias",
        "output_alias",
        "score_misalignment",
        "position_misalignment",
    ],
)
def test_direct_C_ABI_padding_alignment_and_overlap(native, fault):
    rows = (ct.c_ubyte * 32)(*([0] * 32))
    query = (ct.c_ubyte * 1)(0)
    scores = (ct.c_uint16 * 4)(999, 999, 999, 999)
    top = (ct.c_uint32 * 3)(999, 999, 999)
    arguments = [rows, 4, 4, 3, query, 1, scores, 4, top, 3]
    if fault == "late_padding":
        rows[3] = 0x80
    elif fault == "query_padding":
        query[0] = 0x80
    elif fault == "input_alias":
        arguments[6] = ct.cast(rows, ct.POINTER(ct.c_uint16))
    elif fault == "output_alias":
        arguments[8] = ct.cast(scores, ct.POINTER(ct.c_uint32))
    elif fault == "score_misalignment":
        arguments[6] = ct.cast(ct.byref(rows, 1), ct.POINTER(ct.c_uint16))
    else:
        arguments[8] = ct.cast(ct.byref(rows, 1), ct.POINTER(ct.c_uint32))
    before = bytes(rows), bytes(query), bytes(scores), bytes(top)
    assert native._call(*arguments) == -1
    assert before == (bytes(rows), bytes(query), bytes(scores), bytes(top))


def test_maximum_native_geometry_and_all_distances(native):
    rows = b"\xff" * (32768 * 64)
    query = b"\0" * 64
    scores, positions = native.scan(rows, 32768, 512, query)
    assert scores == (512,) * 32768 and positions == (0, 1, 2)
