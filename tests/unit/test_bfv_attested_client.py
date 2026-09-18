"""Nitro-gated protocol regressions with real crypto and synthetic test evidence.

Instrument both private decoders in attack tests: malformed provenance must be
rejected before BFV parsing or secret work. Synthetic roots are test-local only.
"""

import hashlib
import secrets
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

pytest.importorskip("cbor2")
pytest.importorskip("OpenSSL")
from Crypto.Signature import eddsa
from gmpy2 import mpz

from tests.unit.nitro_fixtures import PCRS, SyntheticNitro
from tests.unit.test_bfv_guarded_client import deny_private, rebind_response
from cuhepy.hamming import bfv_attested as attested
from cuhepy.hamming import bfv_nitro as nitro
from cuhepy.hamming.bfv import BFVClient
from cuhepy.hamming.bfv_security import (
    BFVExecutionPolicy,
    BFVProtocolError,
    _unpack,
    _pack,
)
from cuhepy.hamming.bfv_verified import BFVVerifiedClient, BFVVerifiedServer
from cuhepy.bfv.scheme import BFV, _coefficient_modulus
from cuhepy.types import BFVCiphertext


@pytest.fixture(scope="module")
def private():
    return BFVClient(3, 16, 97, 120, 15, response_modulus_bits=40, rns_modulus=True)


@pytest.fixture(scope="module")
def issuer():
    return SyntheticNitro()


@pytest.fixture
def trusted(issuer, monkeypatch):
    monkeypatch.setattr(nitro, "_AWS_ROOT_SHA256", issuer.root_digest)
    return issuer


def make_session(private, issuer, count=3, backend="native", enroll=True):
    """Create independent client/server contexts with one authorized owner."""
    if backend == "native":
        pytest.importorskip("cuhepy.bfv._cpu_ext._bfv_private")
    policy = BFVExecutionPolicy(params=private.params, embed_len=3, response_modulus_bits=40)
    auth = secrets.token_bytes(32)
    client = attested.BFVAttestedClient(
        private,
        auth,
        nitro.NitroAttestationPolicy(PCRS),
        index_epoch=7,
        policy=policy,
        private_backend=backend,
    )
    vectors = ([[0, 1, 0], [1, 0, 1], [0, 0, 0]] * ((count + 2) // 3))[:count]
    setup = client.prepare_index(vectors)
    server = attested.BFVAttestedServer.from_registration(
        client.registration_packet(setup), issuer, policy=policy, backend="optimized"
    )
    if enroll:
        client.accept_attestation(*server.attest(client.begin_attestation()))
    return client, server, setup, auth, vectors


@pytest.mark.parametrize("backend", ["python", "native"])
@pytest.mark.parametrize("count", [1, 5, 39])
def test_one_public_evaluation_identical_to_baseline(private, trusted, monkeypatch, backend, count):
    client, server, setup, auth, vectors = make_session(private, trusted, count, backend)
    query = client.begin_query([0, 1, 0])
    baseline = BFVVerifiedServer(setup, auth, policy=client.policy, backend="optimized")
    expected = baseline.search(query[38:-64])
    calls = []
    original = server._server.search

    def record(inner):
        calls.append(inner)
        return original(inner)

    monkeypatch.setattr(server._server, "search", record)
    with monkeypatch.context() as scope:
        deny_private(scope)
        response, receipt = server.search(query)
    assert calls == [query[38:-64]]
    assert response == expected
    assert server._server._client.keys is None
    assert len(receipt) == attested.NITRO_RECEIPT_BYTES == 198
    assert client.finish_query(response, receipt) == [
        sum(a != b for a, b in zip(v, [0, 1, 0], strict=True)) for v in vectors
    ]
    with pytest.raises(BFVProtocolError):
        client.finish_query(response, receipt)
    with pytest.raises(BFVProtocolError):
        server.search(query)


def test_default_client_rejects_fake_aws_identity(private, issuer):
    client, server, *_ = make_session(private, issuer, enroll=False)
    with pytest.raises(BFVProtocolError, match="enrollment rejected"):
        client.accept_attestation(*server.attest(client.begin_attestation()))
    with pytest.raises(BFVProtocolError, match="attestation is required"):
        client.begin_query([0, 1, 0])


@pytest.mark.parametrize(
    "change", ["signature", "missing", "context", "session", "query", "response", "extra"]
)
def test_receipt_failures_never_parse_or_decrypt(private, trusted, monkeypatch, change):
    client, server, *_ = make_session(private, trusted)
    response, receipt = server.search(client.begin_query([0, 1, 0]))
    positions = {"signature": 197, "context": 6, "session": 38, "query": 70, "response": 102}
    bad = b"" if change == "missing" else receipt + b"x" if change == "extra" else receipt
    if change in positions:
        p = positions[change]
        bad = receipt[:p] + bytes([receipt[p] ^ 1]) + receipt[p + 1 :]
    with monkeypatch.context() as scope:
        deny_private(scope)
        import cuhepy.hamming.bfv_security as framing

        scope.setattr(
            framing.msgpack, "unpackb", lambda *a, **kw: pytest.fail("Unapproved BFV parsing")
        )
        with pytest.raises(BFVProtocolError, match="before decryption"):
            client.finish_query(response, bad)
    assert client.finish_query(response, receipt) == [0, 3, 1]


def test_previous_rounding_oracle_blocked_before_private_work(private, trusted, monkeypatch):
    client, server, _, auth, _ = make_session(private, trusted)
    n, t = private.params.poly_modulus_degree, private.params.plain_modulus
    q = _coefficient_modulus(private.response_modulus_bits)
    deny_private(monkeypatch)
    for index in range(n):
        for offset in (0, 1):
            request = client.begin_query([0, 1, 0])
            _, receipt = server.search(request)
            c0 = (q // (2 * t) + offset,) + (mpz(0),) * (n - 1)
            c1 = [mpz(0)] * n
            c1[0 if index == 0 else n - index] = mpz(1)
            ct = BFVCiphertext((c0, tuple(c1)), q, private._pk()["key_id"])
            forged = rebind_response(
                request[38:-64],
                [BFV.ciphertext_to_ints(ct, private._pk())],
                private,
                auth,
                client.policy,
            )
            with pytest.raises(BFVProtocolError, match="before decryption"):
                client.finish_query(forged, receipt)
            client.cancel_pending_queries()


def test_parent_cannot_authorize_queries_with_transport_mac_key(private, trusted, monkeypatch):
    client, server, _, auth, _ = make_session(private, trusted)
    query = client.begin_query([0, 1, 0])
    fake_owner = eddsa.new(
        eddsa.import_private_key(auth), "rfc8032", context=attested._OWNER_CONTEXT
    )
    forged = query[:-64] + fake_owner.sign(
        attested._QUERY + client._context() + query[6:38] + hashlib.sha256(query[38:-64]).digest()
    )
    monkeypatch.setattr(
        server._server, "search", lambda *a: pytest.fail("Unauthorized BFV evaluation")
    )
    with pytest.raises(ValueError):
        server.search(forged)


def test_even_valid_receipt_must_match_a_pending_owner_query(private, trusted, monkeypatch):
    client, server, *_ = make_session(private, trusted)
    response, receipt = server.search(client.begin_query([0, 1, 0]))
    # Model a separately signed transcript for an unrelated request. It must
    # not authorize private work even though its signature is cryptographically valid.
    message = receipt[:70] + bytes(32) + receipt[102:134]
    forged = message + server._signer.sign(message)
    deny_private(monkeypatch)
    with pytest.raises(BFVProtocolError, match="before decryption"):
        client.finish_query(response, forged)


def test_registration_signature_precedes_bfv_import(private, trusted, monkeypatch):
    client, _, setup, _, _ = make_session(private, trusted)
    registration = _unpack(
        client.registration_packet(setup), limit=client.policy.max_setup_bytes + 1024
    )
    registration[3] += 1
    monkeypatch.setattr(
        BFV, "deserialize_public_key", lambda *a, **kw: pytest.fail("Unauthorized BFV key import")
    )
    with pytest.raises(ValueError):
        attested.BFVAttestedServer.from_registration(
            _pack(registration), trusted, policy=client.policy
        )


@pytest.mark.parametrize("change", ["proof", "nonce", "pins", "epoch", "execution_policy", "owner"])
def test_enrollment_binding_and_possession(private, trusted, change):
    client, server, *_ = make_session(private, trusted, enroll=False)
    hello = client.begin_attestation()
    document, proof = server.attest(hello)
    if change == "proof":
        proof = bytes(64)
    elif change == "nonce":
        client.begin_attestation()
    elif change == "pins":
        client.attestation_policy = nitro.NitroAttestationPolicy({**PCRS, 2: bytes([1]) * 48})
    elif change == "epoch":
        client.index_epoch += 1
    elif change == "execution_policy":
        client._session.policy = replace(client.policy, max_queries=128)
    else:
        client._owner_public = bytes(32)
    with pytest.raises(BFVProtocolError):
        client.accept_attestation(document, proof)
    with pytest.raises(BFVProtocolError):
        client.begin_query([0, 1, 0])


def test_expiry_replay_renewal_and_restart(private, trusted, monkeypatch):
    client, server, setup, *_ = make_session(private, trusted, enroll=False)
    hello = client.begin_attestation()
    document, proof = server.attest(hello)
    with pytest.raises(BFVProtocolError):
        server.attest(hello)
    client.accept_attestation(document, proof)
    with pytest.raises(BFVProtocolError):
        client.accept_attestation(document, proof)
    query = client.begin_query([0, 1, 0])
    response, receipt = server.search(query)
    client._deadline = 0
    with monkeypatch.context() as scope:
        deny_private(scope)
        with pytest.raises(BFVProtocolError, match="before decryption"):
            client.finish_query(response, receipt)
    client.accept_attestation(*server.attest(client.begin_attestation()))
    with pytest.raises(BFVProtocolError):
        client.finish_query(response, receipt)
    with pytest.raises(BFVProtocolError):
        server.search(query)
    server = attested.BFVAttestedServer.from_registration(
        client.registration_packet(setup), trusted, policy=client.policy, backend="optimized"
    )
    with pytest.raises(BFVProtocolError):
        server.search(client.begin_query([0, 1, 0]))
    client.accept_attestation(*server.attest(client.begin_attestation()))
    assert client.finish_query(*server.search(client.begin_query([0, 1, 0]))) == [0, 3, 1]


def test_handshake_and_search_deadlines_are_checked(private, trusted, monkeypatch):
    client, server, *_ = make_session(private, trusted, enroll=False)
    document, proof = server.attest(client.begin_attestation())
    client._hello_started -= 100
    with pytest.raises(BFVProtocolError):
        client.accept_attestation(document, proof)
    client.accept_attestation(*server.attest(client.begin_attestation()))
    query = client.begin_query([0, 1, 0])
    original = server._server.search

    def expire_during_search(inner):
        result = original(inner)
        server._deadline = 0
        return result

    monkeypatch.setattr(server._server, "search", expire_during_search)
    with pytest.raises(BFVProtocolError, match="expired during"):
        server.search(query)


def test_concurrent_finish_decrypts_once(private, trusted):
    client, server, *_ = make_session(private, trusted)
    response, receipt = server.search(client.begin_query([0, 1, 0]))

    def finish():
        try:
            return client.finish_query(response, receipt)
        except BFVProtocolError:
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda _: finish(), range(4))).count([0, 3, 1]) == 1


def test_restore_requires_fresh_attestation_and_exact_epoch_policy(private, trusted):
    client, server, setup, auth, _ = make_session(private, trusted)
    wrap = secrets.token_bytes(32)
    saved = client.protect_state(wrap)
    with pytest.raises(BFVProtocolError):
        BFVVerifiedClient.restore(setup, saved, auth, wrap, policy=client.policy)
    for epoch, pins in (
        (8, client.attestation_policy),
        (7, nitro.NitroAttestationPolicy({**PCRS, 0: bytes([9]) * 48})),
    ):
        with pytest.raises(BFVProtocolError):
            attested.BFVAttestedClient.restore(
                setup, saved, auth, wrap, pins, index_epoch=epoch, policy=client.policy
            )
    restored = attested.BFVAttestedClient.restore(
        setup, saved, auth, wrap, client.attestation_policy, index_epoch=7, policy=client.policy
    )
    with pytest.raises(BFVProtocolError, match="attestation is required"):
        restored.begin_query([0, 1, 0])
    restored.accept_attestation(*server.attest(restored.begin_attestation()))
    assert restored.finish_query(*server.search(restored.begin_query([0, 1, 0]))) == [0, 3, 1]
