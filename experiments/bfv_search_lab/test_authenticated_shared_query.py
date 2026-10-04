"""Owner authentication/context faults around retained public native fixtures.

Only standard ephemeral Ed25519 signing keys are generated. HE keys and
ciphertexts are retained Q74 public data; no HE decryption/private work occurs.
"""

from dataclasses import replace
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import pickle

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import msgpack
import pytest

from benchmarks import native_shared_query_lab as lab
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab import seeded_bgv as seeded
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_bgv as shared
from experiments.bfv_search_lab.test_native_shared_query import CASE_IDS


def public_key(owner):
    return owner.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def owner_inputs(directory, entry, fixtures):
    ctx, tape, _pk, primes, pin = lab.load_case(directory, entry, fixtures)
    raw = json.loads(gzip.decompress(Path(pin["file"]).read_bytes()))
    metadata = native.PublicMetadata(ctx.profile, primes, ctx.key_id, ctx.ids)
    keys = (ctx.relin, *(key for _, key in ctx.rotations))
    key_body = native.pack_common(
        tuple(row for key in keys for column in key for row in column), ctx.profile.n, ctx.profile.q
    )
    return (
        ctx,
        tape,
        metadata,
        key_body,
        tuple(bytes.fromhex(x) for x in raw["owner_index_packets"]),
        bytes.fromhex(raw["query_seeded_packet"]),
    )


@pytest.fixture(scope="module")
def material():
    library_path = os.getenv("CUHEPY_SHARED_QUERY_LIBRARY")
    fixture_path = os.getenv("CUHEPY_SHARED_QUERY_FIXTURES")
    if not library_path or not fixture_path:
        pytest.skip("Explicit isolated library and retained public fixtures required")
    library, directory = native.NativeLibrary(library_path), Path(fixture_path)
    report, entries = lab.public_cases(directory)
    fixtures = lab.public_fixtures(directory, report)
    owner, foreign = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    factory = auth.OwnerFactory(public_key(owner), library)
    data = owner_inputs(directory, next(x for x in entries if x["id"] == CASE_IDS[-1]), fixtures)
    return (
        library,
        directory,
        {x["id"]: x for x in entries},
        fixtures,
        owner,
        foreign,
        factory,
        data,
    )


@pytest.fixture
def case(material):
    _library, _directory, _entries, _fixtures, owner, _foreign, factory, data = material
    ctx, tape, metadata, keys, index, query = data
    signed = auth.sign_enrollment(metadata, keys, index, 1, factory.policy_digest, owner)
    with factory.enroll(signed) as enrollment:
        signed_query = auth.sign_request(
            enrollment.snapshot_id,
            enrollment.epoch,
            factory.policy_digest,
            bytes([7]) * 32,
            query,
            owner,
        )
        with enrollment.request(signed_query) as request:
            yield ctx, tape, enrollment, request, signed, signed_query


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_authenticated_seeded_native_flow_preserves_every_retained_frame(material, case_id):
    _lib, directory, entries, fixtures, owner, _foreign, factory, _data = material
    ctx, tape, metadata, keys, index, query = owner_inputs(directory, entries[case_id], fixtures)
    signed = auth.sign_enrollment(metadata, keys, index, 1, factory.policy_digest, owner)
    with factory.enroll(signed) as enrollment:
        assert enrollment.metadata == metadata
        assert enrollment.public_wire == signed
        packet = auth.sign_request(
            enrollment.snapshot_id,
            1,
            factory.policy_digest,
            hashlib.sha256(case_id.encode()).digest(),
            query,
            owner,
        )
        with enrollment.request(packet) as request:
            assert request.original_wire == packet
            expected = request.reply(lab.body(ctx, tape), tape.response)
            assert request.produce_packet() == expected
            assert request.accepts_packet(expected)


@pytest.mark.parametrize(
    "fault", ["signature", "payload", "foreign_owner", "cross_domain", "trailing"]
)
def test_authentication_precedes_native_enrollment_or_seed_work(material, case, monkeypatch, fault):
    library, _directory, _entries, _fixtures, owner, foreign, factory, _data = material
    _ctx, _tape, _enrollment, _request, signed, signed_query = case
    tag, payload, signature = msgpack.unpackb(signed, raw=False)
    if fault == "signature":
        signature = signature[:-1] + bytes([signature[-1] ^ 1])
        packet = auth._pack([tag, payload, signature])
    elif fault == "payload":
        packet = auth._pack([tag, payload[:-1] + bytes([payload[-1] ^ 1]), signature])
    elif fault == "foreign_owner":
        packet = auth._sign(tag, payload, foreign)
    elif fault == "cross_domain":
        packet = signed_query
    else:
        packet = signed + b"\x00"

    def forbidden(*_args, **_kwargs):
        pytest.fail("Rejected authentication cannot start native enrollment/seed work")

    monkeypatch.setattr(library, "enroll", forbidden)
    monkeypatch.setattr(seeded, "expand", forbidden)
    with pytest.raises(ValueError):
        factory.enroll(packet)


@pytest.mark.parametrize(
    "fault",
    [
        "origin",
        "policy",
        "profile",
        "ids_duplicate",
        "ids_shape",
        "epoch_bool",
        "key_last_q",
        "index_missing",
        "index_extra",
        "index_last_q",
        "index_wrong_key",
        "index_wrong_seed",
    ],
)
def test_signed_but_invalid_enrollment_is_not_an_origin_or_grammar_bypass(
    material, case, monkeypatch, fault
):
    library, _directory, _entries, _fixtures, owner, _foreign, factory, _data = material
    ctx, _tape, _enrollment, _request, signed, _signed_query = case
    tag, payload, _signature = msgpack.unpackb(signed, raw=False)
    fields = msgpack.unpackb(payload, raw=False)
    if fault == "origin":
        fields[0][6] = b"unreviewed-public-key-origin"
    elif fault == "policy":
        fields[5] = bytes(32)
    elif fault == "profile":
        fields[0][1] += 1  # Full key/index geometry can no longer match.
    elif fault == "ids_duplicate":
        fields[3] = fields[3][:8] + fields[3][:8] + fields[3][16:]
    elif fault == "ids_shape":
        fields[3] = fields[3][:-1]
    elif fault == "epoch_bool":
        fields[4] = True
    elif fault == "key_last_q":
        fields[6] = fields[6][:-15] + ctx.profile.q.to_bytes(15, "little")
    elif fault == "index_missing":
        fields[7] = fields[7][:-1]
    elif fault == "index_extra":
        fields[7].append(fields[7][-1])
    else:
        seed_fields = msgpack.unpackb(fields[7][-1], raw=False)
        if fault == "index_last_q":
            seed_fields[3] = seed_fields[3][:-15] + ctx.profile.q.to_bytes(15, "little")
        elif fault == "index_wrong_key":
            seed_fields[1] = bytes(32)
        else:
            seed_fields[2] = bytes(31)
        fields[7][-1] = auth._pack(seed_fields)
    packet = auth._sign(tag, auth._pack(fields), owner)

    def forbidden(*_args, **_kwargs):
        pytest.fail("Malformed enrollment cannot reach native preparation")

    monkeypatch.setattr(library, "enroll", forbidden)
    with pytest.raises(ValueError):
        factory.enroll(packet)


@pytest.mark.parametrize(
    "fault",
    [
        "signature",
        "foreign_owner",
        "snapshot",
        "epoch",
        "epoch_bool",
        "policy",
        "nonce_short",
        "query_last_q",
        "query_wrong_key",
        "query_seed_short",
    ],
)
def test_signed_original_request_faults_precede_native_query(material, case, monkeypatch, fault):
    _lib, _dir, _entries, _fixtures, owner, foreign, _factory, _data = material
    ctx, _tape, enrollment, _request, _signed, signed_query = case
    tag, payload, signature = msgpack.unpackb(signed_query, raw=False)
    fields = msgpack.unpackb(payload, raw=False)
    if fault == "signature":
        packet = auth._pack([tag, payload, bytes(64)])
    elif fault == "foreign_owner":
        packet = auth._sign(tag, payload, foreign)
    else:
        if fault == "snapshot":
            fields[0] = bytes(32)
        elif fault == "epoch":
            fields[1] += 1
        elif fault == "epoch_bool":
            fields[1] = True
        elif fault == "policy":
            fields[2] = bytes(32)
        elif fault == "nonce_short":
            fields[3] = bytes(31)
        else:
            original = msgpack.unpackb(fields[4], raw=False)
            if fault == "query_last_q":
                original[3] = original[3][:-15] + ctx.profile.q.to_bytes(15, "little")
            elif fault == "query_wrong_key":
                original[1] = bytes(32)
            else:
                original[2] = bytes(31)
            fields[4] = auth._pack(original)
        packet = auth._sign(tag, auth._pack(fields), owner)

    def forbidden(*_args, **_kwargs):
        pytest.fail("Bad original request cannot reach native query arithmetic")

    monkeypatch.setattr(enrollment._context, "query", forbidden)
    with pytest.raises(ValueError):
        enrollment.request(packet)


@pytest.mark.parametrize("field", range(1, 7))
def test_every_unsigned_reply_context_binding(case, field):
    ctx, tape, _enrollment, request, _signed, _signed_query = case
    packet = request.reply(lab.body(ctx, tape), tape.response)
    fields = msgpack.unpackb(packet, raw=False)
    if field == 2:
        fields[field] += 1
    else:
        fields[field] = bytes(32)
    assert not request.accepts_packet(auth._pack(fields))


@pytest.mark.parametrize("bad_epoch", [True, 1.0])
def test_reply_epoch_requires_integer_type_even_when_equal(case, bad_epoch):
    ctx, tape, _enrollment, request, _signed, _signed_query = case
    fields = msgpack.unpackb(request.reply(lab.body(ctx, tape), tape.response), raw=False)
    assert fields[2] == bad_epoch
    fields[2] = bad_epoch
    assert not request.accepts_packet(auth._pack(fields))


@pytest.mark.parametrize(
    "fault",
    [
        "body_last_q",
        "body_last_plus_one",
        "body_truncated",
        "frame_tail",
        "trailing",
        "missing",
        "extra",
        "mutable",
        "nonce_missing",
    ],
)
def test_complete_reply_grammar_and_physical_tail(case, fault):
    ctx, tape, _enrollment, request, _signed, _signed_query = case
    packet = request.reply(lab.body(ctx, tape), tape.response)
    fields = msgpack.unpackb(packet, raw=False)
    if fault == "body_last_q":
        fields[7] = fields[7][:-15] + ctx.profile.q.to_bytes(15, "little")
    elif fault == "body_last_plus_one":
        value = (int.from_bytes(fields[7][-15:], "little") + 1) % ctx.profile.q
        fields[7] = fields[7][:-15] + value.to_bytes(15, "little")
    elif fault == "body_truncated":
        fields[7] = fields[7][:-1]
    elif fault == "frame_tail":
        fields[8] = fields[8][:-1] + bytes([fields[8][-1] ^ 1])
    elif fault == "missing":
        fields = fields[:-1]
    elif fault == "extra":
        fields.append(b"")
    elif fault == "nonce_missing":
        fields[5] = b""
    if fault == "trailing":
        packet += b"\x00"
    elif fault == "mutable":
        packet = bytearray(packet)
    else:
        packet = auth._pack(fields)
    assert not request.accepts_packet(packet)


def test_same_ciphertext_different_nonce_cannot_reuse_bound_reply(material, case):
    _lib, _dir, _entries, _fixtures, owner, _foreign, factory, _data = material
    ctx, tape, enrollment, request, _signed, signed_query = case
    query = msgpack.unpackb(msgpack.unpackb(signed_query, raw=False)[1], raw=False)[4]
    packet = auth.sign_request(
        enrollment.snapshot_id,
        enrollment.epoch,
        factory.policy_digest,
        bytes([8]) * 32,
        query,
        owner,
    )
    with enrollment.request(packet) as other:
        same_body = lab.body(ctx, tape)
        original = request.reply(same_body, tape.response)
        assert not other.accepts_packet(original)
        assert other.accepts_packet(other.reply(same_body, tape.response))


def test_public_predicate_does_not_call_producer_private_or_authorization(case, monkeypatch):
    ctx, tape, _enrollment, request, _signed, _signed_query = case
    packet = request.reply(lab.body(ctx, tape), tape.response)

    def forbidden(*_args, **_kwargs):
        pytest.fail("Public acceptance cannot replay, decrypt or authorize callbacks")

    for module, names in [
        (bgv, ("key_gen", "encrypt", "decrypt")),
        (shared, ("produce", "expected_frame")),
    ]:
        for name in names:
            monkeypatch.setattr(module, name, forbidden)
    monkeypatch.setattr(request._query, "produce", forbidden)
    assert request.accepts_packet(packet)
    assert request.accepts_packet(packet)  # Deliberately no replay-authority claim yet.


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_authenticated_owned_objects_cannot_be_copied_or_serialized(case, operation):
    _ctx, _tape, enrollment, request, _signed, _signed_query = case
    for obj in (enrollment, request):
        with pytest.raises(TypeError):
            operation(obj)


def test_closed_snapshot_rejects_request_before_seed_work(case, monkeypatch):
    _ctx, _tape, enrollment, _request, _signed, signed_query = case
    enrollment.close()

    def forbidden(*_args, **_kwargs):
        pytest.fail("Closed snapshot cannot prepare a query")

    monkeypatch.setattr(seeded, "expand", forbidden)
    with pytest.raises(RuntimeError):
        enrollment.request(signed_query)


def test_full_uint64_epoch_and_record_ids_round_trip(material):
    _lib, _dir, _entries, _fixtures, owner, _foreign, factory, data = material
    ctx, tape, metadata, keys, index, query = data
    ids = tuple((1 << 64) - 1 - i for i in range(len(metadata.ids)))
    metadata = replace(metadata, ids=ids)
    epoch = (1 << 64) - 1
    signed = auth.sign_enrollment(metadata, keys, index, epoch, factory.policy_digest, owner)
    with factory.enroll(signed) as enrollment:
        assert enrollment.metadata.ids == ids and enrollment.epoch == epoch
        signed_query = auth.sign_request(
            enrollment.snapshot_id, epoch, factory.policy_digest, bytes([9]) * 32, query, owner
        )
        with enrollment.request(signed_query) as request:
            assert request.accepts_packet(request.reply(lab.body(ctx, tape), tape.response))


def test_signed_nonminimal_seed_packet_encoding_rejected(material, case):
    _lib, _dir, _entries, _fixtures, owner, _foreign, factory, _data = material
    _ctx, _tape, enrollment, _request, _signed, signed_query = case
    fields = msgpack.unpackb(msgpack.unpackb(signed_query, raw=False)[1], raw=False)
    assert fields[4][0] == 0x94
    # array16 instead of canonical fixarray4 gives the same decoded fields.
    fields[4] = b"\xdc\x00\x04" + fields[4][1:]
    packet = auth.sign_request(
        enrollment.snapshot_id, enrollment.epoch, factory.policy_digest, fields[3], fields[4], owner
    )
    with pytest.raises(ValueError):
        enrollment.request(packet)
