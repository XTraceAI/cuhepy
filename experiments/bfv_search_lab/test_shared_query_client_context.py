"""Q76.5 signed false metadata, currentness and process-ownership controls."""

import copy
from dataclasses import replace
import hashlib
import os
import pickle
import select
import signal
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import msgpack
import pytest

from experiments.bfv_search_lab import shared_query_certificate as cert
from experiments.bfv_search_lab import shared_query_client_context as client


def token(label):
    return hashlib.sha256(label.encode("ascii")).digest()


@pytest.fixture(scope="session")
def owners():
    # Two distinct PUBLIC UNIT-ONLY signing contexts, never production keys.
    return tuple(
        Ed25519PrivateKey.from_private_bytes(token(x))
        for x in ("Q76.5 public unit owner", "Q76.5 public unit foreign owner")
    )


def delivery(owner, *, epoch=1, revision="revision-one", ids=None):
    p = cert.geometry(0)
    ids = ids if ids is not None else (99, 7, 42, 11, 1, *range(100, 112))
    raw = b"".join(x.to_bytes(8, "little") for x in ids)
    he_digest = hashlib.sha256(raw).digest()
    plans = tuple(
        cert.TrustedPlan(
            p,
            len(ids),
            token("HE-key"),
            he_digest,
            token(mode + " snapshot"),
            token(mode + " policy"),
            token(mode + " code"),
            mode,
        )
        for mode in cert.MODES
    )
    packets = tuple(cert.make_certificate(plan) for plan in plans)
    modes = tuple(
        client.ModeBinding(
            plan.mode,
            7,
            plan.snapshot_id,
            plan.policy_digest,
            plan.code_digest,
            cert.certificate_digest(packet),
        )
        for plan, packet in zip(plans, packets, strict=True)
    )
    cache = client.CacheBinding(
        token("cache-key"),
        token(revision + " cache"),
        epoch,
        client.cache_ids_digest(raw, len(ids)),
    )
    return client.seal_descriptor(
        ids,
        owner,
        namespace=token("namespace"),
        revision=token(revision),
        epoch=epoch,
        geometry=p,
        key_id=token("HE-key"),
        cache=cache,
        modes=modes,
        certificates=packets,
    )


def rewritten(original, owner, mutate):
    # Deliberate bypass of the honest owner encoder: signature validity alone
    # must not accept bad public metadata. The false pin retains the original
    # namespace/revision/epoch so public parsing/certificate checks are exercised.
    fields = msgpack.unpackb(msgpack.unpackb(original.packet, raw=False)[1], raw=False)
    mutate(fields)
    payload = msgpack.packb(fields, use_bin_type=True)
    packet = msgpack.packb(
        [client.ENVELOPE_TAG, payload, owner.sign(client.SIGN_DOMAIN + payload)], use_bin_type=True
    )
    pin = replace(original.pin, payload_digest=hashlib.sha256(client.PIN_DOMAIN + payload).digest())
    return client.Delivery(pin, packet)


def test_compact_context_preserves_ordinal_ID_order_without_HE_enrollment(owners):
    saved = delivery(owners[0])
    handle = client.DescriptorClient(owners[0].public_key().public_bytes_raw(), saved.pin)
    metadata = handle.acquire(saved.packet)
    assert metadata.ids[:5] == (99, 7, 42, 11, 1)
    assert (
        len(metadata.packed_ids) == 17 * 8 and tuple(x.mode for x in metadata.modes) == cert.MODES
    )
    assert metadata.cache.epoch == 1 and metadata.modes[0].epoch == 7
    assert all(metadata.mode(mode).mode == mode for mode in cert.MODES)
    assert not hasattr(metadata, "certificates") and not hasattr(handle, "decrypt")
    assert not hasattr(handle, "authorize") and handle.metadata() is metadata


CLIENT_FAULT_PATHS = tuple(
    [(i,) for i in (0, 1, 2, 3, 5, 6, 7, 8, 11, 12)]
    + [(4, i) for i in range(6)]
    + [(4, 6, i) for i in range(2)]
    + [(9, i) for i in range(4)]
    + [(10, mode, field) for mode in range(3) for field in range(6)]
)


@pytest.mark.parametrize("path", CLIENT_FAULT_PATHS, ids=lambda p: ".".join(map(str, p)))
def test_signed_and_pinned_false_field_never_publishes_metadata(owners, path):
    good = delivery(owners[0])

    def mutate(fields):
        node = fields
        for part in path[:-1]:
            node = node[part]
        value = node[path[-1]]
        if path[0] == 9 and path[-1] in (0, 1):
            # These opaque cache labels are honest-owner provisioning inputs.
            # Their private relationship to HE data is not publicly derivable.
            node[path[-1]] = value[1:]
        elif path[0] == 10 and path[-1] == 1:
            # A different valid HE epoch is an honest-owner declaration, not
            # derivable from the compact snapshot digest. Check its exact type.
            node[path[-1]] = True
        else:
            node[path[-1]] = value + 1 if type(value) is int else bytes([value[0] ^ 1]) + value[1:]

    bad = rewritten(good, owners[0], mutate)
    handle = client.DescriptorClient(owners[0].public_key().public_bytes_raw(), bad.pin)
    with pytest.raises(ValueError):
        handle.acquire(bad.packet)
    with pytest.raises(ValueError, match="No validated"):
        handle.metadata()


@pytest.mark.parametrize("position", [0, 1], ids=["cache-key-label", "cache-snapshot-label"])
def test_valid_opaque_cache_labels_require_the_specific_trusted_pin(owners, position):
    original = delivery(owners[0])

    def mutate(fields):
        fields[9][position] = token("different valid opaque cache label")

    changed = rewritten(original, owners[0], mutate)
    anchor = owners[0].public_key().public_bytes_raw()
    with pytest.raises(ValueError, match="pinned current"):
        client.verify_descriptor(changed.packet, anchor, original.pin)
    # A separately trusted initial pin can provision valid independent labels.
    # This assertion explicitly preserves the honest-owner equivalence premise;
    # it is not a ciphertext/plaintext-equivalence or malicious-owner guarantee.
    accepted = client.verify_descriptor(changed.packet, anchor, changed.pin)
    assert accepted.cache.fields()[position] == token("different valid opaque cache label")


@pytest.mark.parametrize(
    "fault",
    [
        "duplicate-IDs",
        "sorted-IDs",
        "short-IDs",
        "missing-mode",
        "extra-mode",
        "reordered-modes",
        "boolean-count",
        "boolean-epoch",
        "map",
        "string",
        "extension",
        "float",
    ],
)
def test_complete_grammar_and_ID_coverage_even_with_a_valid_signature(owners, fault):
    good = delivery(owners[0])

    def mutate(fields):
        if fault == "duplicate-IDs":
            fields[7] = fields[7][:8] + fields[7][:8] + fields[7][16:]
            fields[8] = hashlib.sha256(fields[7]).digest()
            fields[9][3] = client.cache_ids_digest(fields[7], fields[6])
        elif fault == "sorted-IDs":
            ids = sorted(
                int.from_bytes(fields[7][j : j + 8], "little") for j in range(0, len(fields[7]), 8)
            )
            fields[7] = b"".join(x.to_bytes(8, "little") for x in ids)
            fields[8] = hashlib.sha256(fields[7]).digest()
            fields[9][3] = client.cache_ids_digest(fields[7], fields[6])
        elif fault == "short-IDs":
            fields[7] = fields[7][:-8]
        elif fault == "missing-mode":
            fields[10].pop()
        elif fault == "extra-mode":
            fields[10].append(fields[10][0])
        elif fault == "reordered-modes":
            fields[10][0], fields[10][1] = fields[10][1], fields[10][0]
        else:
            position = 3 if fault == "boolean-epoch" else 6
            fields[position] = {
                "boolean-count": True,
                "boolean-epoch": True,
                "map": {b"x": 1},
                "string": "17",
                "extension": msgpack.ExtType(1, b"x"),
                "float": 17.0,
            }[fault]

    bad = rewritten(good, owners[0], mutate)
    with pytest.raises(ValueError):
        client.verify_descriptor(bad.packet, owners[0].public_key().public_bytes_raw(), bad.pin)


def test_signature_and_exact_current_pin_precede_payload_parsing(owners, monkeypatch):
    original = delivery(owners[0])
    outer = msgpack.unpackb(original.packet, raw=False)
    real = client._unpack

    def guarded(raw):
        assert raw != outer[1], "Untrusted/foreign payload parsed before authentication/currentness"
        return real(raw)

    monkeypatch.setattr(client, "_unpack", guarded)
    with pytest.raises(ValueError, match="Foreign"):
        client.verify_descriptor(
            original.packet, owners[1].public_key().public_bytes_raw(), original.pin
        )
    with pytest.raises(ValueError, match="pinned current"):
        client.verify_descriptor(
            original.packet,
            owners[0].public_key().public_bytes_raw(),
            replace(original.pin, payload_digest=token("other-current")),
        )


def test_stale_or_newer_store_packet_never_advances_current_pin(owners):
    old, new = delivery(owners[0]), delivery(owners[0], epoch=2, revision="revision-two")
    handle = client.DescriptorClient(owners[0].public_key().public_bytes_raw(), old.pin)
    handle.acquire(old.packet)
    with pytest.raises(ValueError):
        handle.acquire(new.packet)
    assert handle.metadata().pin == old.pin
    handle.advance_current(new.pin)
    with pytest.raises(ValueError):
        handle.metadata()
    with pytest.raises(ValueError):
        handle.acquire(old.packet)
    assert handle.acquire(new.packet).pin == new.pin


@pytest.mark.parametrize("fault", ["replay", "gap", "same-revision", "foreign-namespace"])
def test_only_trusted_sequential_owner_pin_transition(owners, fault):
    old = delivery(owners[0])
    new = delivery(owners[0], epoch=2, revision="revision-two")
    pin = {
        "replay": old.pin,
        "gap": replace(new.pin, epoch=3),
        "same-revision": replace(new.pin, revision=old.pin.revision),
        "foreign-namespace": replace(new.pin, namespace=token("foreign")),
    }[fault]
    handle = client.DescriptorClient(owners[0].public_key().public_bytes_raw(), old.pin)
    with pytest.raises(ValueError):
        handle.advance_current(pin)


def test_late_descriptor_cannot_republish_an_invalidated_context(owners, monkeypatch):
    old, new = delivery(owners[0]), delivery(owners[0], epoch=2, revision="revision-two")
    handle = client.DescriptorClient(owners[0].public_key().public_bytes_raw(), old.pin)
    ready, resume = threading.Event(), threading.Event()
    real, failures = client.verify_descriptor, []

    def delayed(*args):
        result = real(*args)
        ready.set()
        assert resume.wait(5)
        return result

    monkeypatch.setattr(client, "verify_descriptor", delayed)

    def acquire():
        try:
            handle.acquire(old.packet)
        except ValueError as error:
            failures.append(str(error))

    worker = threading.Thread(target=acquire)
    worker.start()
    try:
        assert ready.wait(5)
        handle.advance_current(new.pin)
    finally:
        resume.set()
        worker.join(5)
    assert not worker.is_alive() and failures == [
        "Owner current pin changed during descriptor acquisition"
    ]
    with pytest.raises(ValueError):
        handle.metadata()


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_owned_adapter_cannot_be_duplicated(owners, operation):
    saved = delivery(owners[0])
    handle = client.DescriptorClient(owners[0].public_key().public_bytes_raw(), saved.pin)
    with pytest.raises(TypeError):
        operation(handle)


def test_closed_adapter_rejects_all_metadata_operations(owners):
    saved = delivery(owners[0])
    handle = client.DescriptorClient(owners[0].public_key().public_bytes_raw(), saved.pin)
    handle.acquire(saved.packet)
    handle.close()
    for operation in (
        handle.metadata,
        lambda: handle.acquire(saved.packet),
        lambda: handle.advance_current(saved.pin),
    ):
        with pytest.raises(RuntimeError, match="Closed"):
            operation()


def test_fork_rejects_before_an_inherited_lock(owners):
    saved = delivery(owners[0])
    handle = client.DescriptorClient(owners[0].public_key().public_bytes_raw(), saved.pin)
    ready, resume = threading.Event(), threading.Event()

    def hold():
        with handle._lock:
            ready.set()
            assert resume.wait(10)

    worker = threading.Thread(target=hold)
    worker.start()
    read_fd, write_fd = os.pipe()
    child = None
    try:
        assert ready.wait(5)
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            ok = True
            for operation in (
                handle.metadata,
                lambda: handle.acquire(saved.packet),
                lambda: handle.advance_current(saved.pin),
                handle.close,
            ):
                try:
                    operation()
                    ok = False
                except RuntimeError:
                    pass
            os.write(write_fd, b"1" if ok else b"0")
            os._exit(0 if ok else 1)
        os.close(write_fd)
        write_fd = -1
        assert select.select([read_fd], [], [], 5)[0], "Inherited mutex caused a hang"
        assert os.read(read_fd, 1) == b"1"
        pid, status = os.waitpid(child, 0)
        assert pid == child and os.waitstatus_to_exitcode(status) == 0
        child = None
    finally:
        if child is not None:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        resume.set()
        worker.join(5)
        os.close(read_fd)
        if write_fd != -1:
            os.close(write_fd)
    assert not worker.is_alive()


@pytest.mark.parametrize(
    "packet",
    [
        bytearray(b"x"),
        b"x" * (client.MAX_DESCRIPTOR_BYTES + 1),
        msgpack.packb([client.ENVELOPE_TAG, b"x", bytes(63)]),
        b"\xc1",
    ],
)
def test_outer_packet_caps_and_fixed_envelope(owners, packet):
    saved = delivery(owners[0])
    with pytest.raises(ValueError):
        client.verify_descriptor(packet, owners[0].public_key().public_bytes_raw(), saved.pin)
