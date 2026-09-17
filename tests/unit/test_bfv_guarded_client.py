"""Pre-decryption provenance checks, including the previously successful oracle.

Unlike the historical demonstration, attack cases here must NEVER call either
private decoder. The verifier is owner-controlled and receives public BFV data.
"""

import hashlib
import secrets
from concurrent.futures import ThreadPoolExecutor

import pytest
from Crypto.Signature import eddsa
from gmpy2 import mpz

from cuhepy.bfv.client import BFVClient
from cuhepy.bfv.security import (
    BFVExecutionPolicy,
    BFVProtocolError,
    _authenticate,
    _authenticated_body,
    _decode_ciphertexts,
    _encode_ciphertexts,
    _pack,
    _unpack,
)
from cuhepy.bfv.guarded_client import (
    BFVGuardedClient,
    BFVPublicVerifier,
    bfv_verifier_public_key,
    _CONTEXT,
    _MESSAGE_BYTES,
)
from cuhepy.bfv.verified_client import BFVVerifiedClient, BFVVerifiedServer
from cuhepy.bfv.scheme import BFV, _coefficient_modulus
from cuhepy.bfv.private import BFVPrivateDecoder
from cuhepy.types import BFVCiphertext


@pytest.fixture(scope="module")
def private():
    return BFVClient(3, 16, 97, 120, 15, response_modulus_bits=40, rns_modulus=True)


def make_session(private, count=3, backend="native"):
    if backend == "native":
        pytest.importorskip("cuhepy.bfv._cpu_ext._bfv_private")
    auth, signing = secrets.token_bytes(32), secrets.token_bytes(32)
    p = BFVExecutionPolicy(params=private.params, embed_len=3, response_modulus_bits=40)
    client = BFVGuardedClient(
        private, auth, bfv_verifier_public_key(signing), policy=p, private_backend=backend
    )
    vectors = ([[0, 1, 0], [1, 0, 1], [0, 0, 0]] * ((count + 2) // 3))[:count]
    setup = client.prepare_index(vectors)
    server = BFVVerifiedServer(setup, auth, policy=p, backend="optimized")
    verifier = BFVPublicVerifier(
        setup,
        auth,
        signing,
        expected_setup_digest=client.setup_digest,
        policy=p,
        backend="optimized",
    )
    return client, server, verifier, setup, auth, signing, vectors


def deny_private(monkeypatch):
    monkeypatch.setattr(
        BFV, "decrypt", lambda *a: pytest.fail("Forged response reached GMP decryption")
    )
    monkeypatch.setattr(
        BFVPrivateDecoder,
        "decode_packed",
        lambda *a: pytest.fail("Forged response reached native private decoding"),
    )


def rebind_response(query, ciphers, private, auth, policy):
    setup, ticket, _ = _unpack(
        _authenticated_body(query, auth, 2, policy.max_query_bytes), limit=policy.max_query_bytes
    )
    body = _pack(
        [setup, ticket, hashlib.sha256(query).digest(), _encode_ciphertexts(ciphers, private._pk())]
    )
    return _authenticate(body, auth, 3, policy.max_response_bytes)


@pytest.mark.parametrize("backend", ["python", "native"])
@pytest.mark.parametrize("count", [1, 5, 39])
def test_correct_receipt_and_public_only_verifier(private, backend, count, monkeypatch):
    client, server, verifier, _, _, _, vectors = make_session(private, count, backend)
    request = client.begin_query([0, 1, 0])
    with monkeypatch.context() as scope:
        deny_private(scope)
        response = server.search(request)
        receipt = verifier.approve(request, response)
    assert verifier._server._client.keys is None
    assert len(receipt) == 198
    assert client.finish_query(response, receipt) == [
        sum(a != b for a, b in zip(v, [0, 1, 0], strict=True)) for v in vectors
    ]
    with pytest.raises(BFVProtocolError):
        client.finish_query(response, receipt)


def test_previous_rounding_oracle_blocked_before_any_decryption(private, monkeypatch):
    client, server, verifier, _, auth, _, _ = make_session(private)
    n, t = private.params.poly_modulus_degree, private.params.plain_modulus
    q = _coefficient_modulus(private.response_modulus_bits)
    deny_private(monkeypatch)
    for index in range(n):
        for offset in (0, 1):
            request = client.begin_query([0, 1, 0])
            honest = server.search(request)
            receipt = verifier.approve(request, honest)
            c0 = (q // (2 * t) + offset,) + (mpz(0),) * (n - 1)
            c1 = [mpz(0)] * n
            c1[0 if index == 0 else n - index] = mpz(1)
            ct = BFVCiphertext((c0, tuple(c1)), q, private._pk()["key_id"])
            forged = rebind_response(
                request, [BFV.ciphertext_to_ints(ct, private._pk())], private, auth, client.policy
            )
            # Even a genuine receipt for this query cannot approve other bytes.
            with pytest.raises(BFVProtocolError, match="before decryption"):
                client.finish_query(forged, receipt)
            client.cancel_pending_queries()


def test_verifier_will_not_sign_a_plausible_false_result(private, monkeypatch):
    client, _, verifier, _, auth, _, _ = make_session(private)
    request = client.begin_query([0, 1, 0])
    q = _coefficient_modulus(private.response_modulus_bits)
    zero = (mpz(0),) * private.params.poly_modulus_degree
    ct = BFVCiphertext((zero, zero), q, private._pk()["key_id"])
    forged = rebind_response(
        request, [BFV.ciphertext_to_ints(ct, private._pk())], private, auth, client.policy
    )
    deny_private(monkeypatch)
    with pytest.raises(BFVProtocolError, match="recomputation"):
        verifier.approve(request, forged)


@pytest.mark.parametrize(
    "mutation", ["missing", "truncated", "extra", "wrong_signer", "circuit", "query"]
)
def test_bad_receipts_fail_before_parsing_or_private_work(private, mutation, monkeypatch):
    client, server, verifier, _, auth, _, _ = make_session(private)
    query = client.begin_query([0, 1, 0])
    response = server.search(query)
    receipt = verifier.approve(query, response)
    if mutation == "missing":
        bad = b""
    elif mutation == "truncated":
        bad = receipt[:-1]
    elif mutation == "extra":
        bad = receipt + b"x"
    elif mutation == "wrong_signer":
        signer = eddsa.new(eddsa.import_private_key(auth), "rfc8032", context=_CONTEXT)
        bad = receipt[:_MESSAGE_BYTES] + signer.sign(receipt[:_MESSAGE_BYTES])
    else:
        position = 6 if mutation == "circuit" else 6 + 64
        bad = receipt[:position] + bytes([receipt[position] ^ 1]) + receipt[position + 1 :]
    with monkeypatch.context() as scope:
        deny_private(scope)
        import cuhepy.bfv.security as framing

        scope.setattr(
            framing.msgpack, "unpackb", lambda *a, **kw: pytest.fail("Unapproved BFV body parsed")
        )
        with pytest.raises(BFVProtocolError, match="before decryption"):
            client.finish_query(response, bad)
    # An outsider cannot burn the legitimate request by sending bad signatures.
    assert client.finish_query(response, receipt) == [0, 3, 1]


def test_valid_receipt_for_server_created_query_is_not_owner_authorization(private, monkeypatch):
    client, server, verifier, _, auth, _, _ = make_session(private)
    owned = client.begin_query([0, 1, 0])
    fields = _unpack(
        _authenticated_body(owned, auth, 2, client.policy.max_query_bytes),
        limit=client.policy.max_query_bytes,
    )
    fields[2] = _encode_ciphertexts([private.encrypt_vec_one([1, 0, 1])], private._pk())
    attacker_query = _authenticate(_pack(fields), auth, 2, client.policy.max_query_bytes)
    result = server.search(attacker_query)
    receipt = verifier.approve(attacker_query, result)
    deny_private(monkeypatch)
    with pytest.raises(BFVProtocolError, match="before decryption"):
        client.finish_query(result, receipt)


def test_foreign_setup_rejected_before_public_key_import(private, monkeypatch):
    client, _, _, setup, auth, signing, _ = make_session(private)
    monkeypatch.setattr(
        BFV, "deserialize_public_key", lambda *a, **kw: pytest.fail("Unpinned setup parsed")
    )
    with pytest.raises(BFVProtocolError, match="owner-pinned"):
        BFVPublicVerifier(
            setup + b"x",
            auth,
            signing,
            expected_setup_digest=client.setup_digest,
            policy=client.policy,
        )
    with pytest.raises(ValueError, match="differ"):
        BFVPublicVerifier(
            setup, auth, auth, expected_setup_digest=client.setup_digest, policy=client.policy
        )


def test_verifier_replay_budget_and_concurrent_client_consumption(private):
    client, server, verifier, _, _, _, _ = make_session(private)
    request = client.begin_query([0, 1, 0])
    response = server.search(request)
    receipt = verifier.approve(request, response)
    with pytest.raises(BFVProtocolError, match="replayed"):
        verifier.approve(request, response)

    def finish():
        try:
            return client.finish_query(response, receipt)
        except BFVProtocolError:
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: finish(), range(4)))
    assert results.count([0, 3, 1]) == 1


def test_private_export_cannot_downgrade_gate_or_change_pin(private):
    client, server, verifier, setup, auth, signing, _ = make_session(private)
    wrap = secrets.token_bytes(32)
    saved = client.protect_state(wrap)
    with pytest.raises(BFVProtocolError):
        BFVVerifiedClient.restore(setup, saved, auth, wrap, policy=client.policy)
    with pytest.raises(BFVProtocolError):
        BFVGuardedClient.restore(
            setup,
            saved,
            auth,
            wrap,
            bfv_verifier_public_key(secrets.token_bytes(32)),
            policy=client.policy,
        )
    restored = BFVGuardedClient.restore(
        setup, saved, auth, wrap, bfv_verifier_public_key(signing), policy=client.policy
    )
    request = restored.begin_query([1, 0, 1])
    response = server.search(request)
    assert restored.finish_query(response, verifier.approve(request, response)) == [3, 0, 2]


def test_guarded_default_requires_review_profile(private):
    with pytest.raises(BFVProtocolError, match="pinned"):
        BFVGuardedClient(
            private, secrets.token_bytes(32), bfv_verifier_public_key(secrets.token_bytes(32))
        )


def test_small_order_verifier_pin_rejected_before_private_import(private, monkeypatch):
    monkeypatch.setattr(
        BFVVerifiedClient, "__init__", lambda *a, **kw: pytest.fail("Invalid pin imported a key")
    )
    with pytest.raises(ValueError, match="small-order"):
        BFVGuardedClient(private, secrets.token_bytes(32), b"\x01" + bytes(31))
