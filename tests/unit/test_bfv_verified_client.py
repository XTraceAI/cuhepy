"""Authenticated-session regressions and an explicit residual oracle attack.

The oracle demonstration intentionally succeeds if accept/reject feedback is
exposed. These tests must not be described as proving chosen-ciphertext security.
"""

import hashlib
import json
import random
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
import numpy as np
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
    protect_bfv_secret_key,
    restore_bfv_client,
)
from cuhepy.bfv.verified_client import (
    BFVVerifiedClient,
    BFVVerifiedServer,
    _FIELD,
    _HammingSummary,
)
from cuhepy.bfv.scheme import BFV, _coefficient_modulus
from cuhepy.types import BFVCiphertext


@pytest.fixture(scope="module")
def private():
    return BFVClient(3, 16, 97, 120, 15, response_modulus_bits=40, rns_modulus=True)


def policy(private, **limits):
    # Explicit insecure algebra-test policy. The default wrapper rejects this ring.
    return BFVExecutionPolicy(
        params=private.params,
        embed_len=private.embed_len,
        response_modulus_bits=private.response_modulus_bits,
        **limits,
    )


def session(private, vectors=None, **limits):
    auth = secrets.token_bytes(32)
    p = policy(private, **limits)
    client = BFVVerifiedClient(private, auth, policy=p)
    vectors = [[0, 1, 0], [1, 0, 1], [0, 0, 0]] if vectors is None else vectors
    setup = client.prepare_index(vectors)
    return client, BFVVerifiedServer(setup, auth, policy=p, backend="optimized"), setup, auth


def forged_response(client, request, authentication_key, ciphertexts):
    setup, ticket, _ = _unpack(
        _authenticated_body(request, authentication_key, 2, client.policy.max_query_bytes),
        limit=client.policy.max_query_bytes,
    )
    body = _pack(
        [
            setup,
            ticket,
            hashlib.sha256(request).digest(),
            _encode_ciphertexts(ciphertexts, client._client._pk()),
        ]
    )
    return _authenticate(body, authentication_key, 3, client.policy.max_response_bytes)


def fake_distances(private, distances):
    slots = [0] * private.params.poly_modulus_degree
    for i, value in enumerate(distances):
        tile, lane = divmod(i, private.vectors_per_ciphertext)
        row, col = divmod(lane, private.lanes_per_row)
        slots[row * (len(slots) // 2) + tile * private.lanes_per_row + col] = value
    ct = BFV.encrypt(BFV.batch_encode(slots, private.params), private._pk())
    return [
        BFV.ciphertext_to_ints(
            BFV.modulus_switch(ct, private.response_modulus_bits, private._pk()), private._pk()
        )
    ]


@pytest.mark.parametrize("count", [1, 5, 39])
@pytest.mark.parametrize("backend", ["optimized", "residue"])
def test_verified_distances_ids_and_public_only_server(private, count, backend, monkeypatch):
    if backend == "residue":
        pytest.importorskip("cuhepy.bfv._cpu_ext._bfv_rns")
    vectors = ([[0, 1, 0], [1, 0, 1], [0, 0, 0]] * 13)[:count]
    auth = secrets.token_bytes(32)
    client = BFVVerifiedClient(private, auth, policy=policy(private))
    ids = [f"document-{i}" for i in range(count)]
    setup = client.prepare_index(vectors, vector_ids=ids)
    server = BFVVerifiedServer(setup, auth, policy=policy(private), backend=backend)
    assert client.vector_ids == server.vector_ids == tuple(ids)
    assert server._client.keys is None
    assert client.verification_state_bytes == 32 * (3 + 2)
    request = client.begin_query([0, 1, 0])
    with monkeypatch.context() as guard:
        guard.setattr(
            BFV, "_phase", lambda *args: pytest.fail("Server accessed private arithmetic")
        )
        response = server.search(request)
    expected = [sum(a != b for a, b in zip([0, 1, 0], v, strict=True)) for v in vectors]
    assert client.finish_query(response) == expected


def test_private_summary_matches_independent_hamming_oracle():
    rng = random.Random(718)
    vectors = [[rng.randrange(2) for _ in range(17)] for _ in range(31)]
    summary = _HammingSummary(vectors, 17, secrets.token_bytes(16))
    assert _FIELD.bit_length() == 255
    for _ in range(30):
        query = [rng.randrange(2) for _ in range(17)]
        distances = [sum(a != b for a, b in zip(query, row, strict=True)) for row in vectors]
        assert summary.matches(distances, summary.expected(query))
        distances[0] += 1
        assert not summary.matches(distances, summary.expected(query))
    assert not summary.matches([], 0)


@pytest.mark.parametrize("scalar", [np.int64, mpz, bool])
def test_binary_integral_scalars_preserve_full_precision(private, scalar):
    client, server, _, _ = session(private)
    request = client.begin_query([scalar(0), scalar(1), scalar(0)])
    assert client.finish_query(server.search(request)) == [0, 3, 1]


@pytest.mark.parametrize("distances", [[0, 0, 0], [1, 1, 1], [3, 0, 1], [0, 3, 2]])
def test_authenticated_plausible_forgery_rejected(private, distances):
    client, _, _, auth = session(private)
    request = client.begin_query([0, 1, 0])  # Correct distances are [0,3,1].
    response = forged_response(client, request, auth, fake_distances(private, distances))
    with pytest.raises(BFVProtocolError, match="response rejected"):
        client.finish_query(response)
    assert not client._pending  # Failed authenticated attempts are still consumed.


def test_authenticated_wrong_result_cannot_be_resubmitted(private):
    client, server, _, auth = session(private)
    request = client.begin_query([0, 1, 0])
    honest = server.search(request)
    forged = forged_response(client, request, auth, fake_distances(private, [1, 1, 1]))
    with pytest.raises(BFVProtocolError):
        client.finish_query(forged)
    with pytest.raises(BFVProtocolError):
        client.finish_query(honest)


def test_replay_and_cross_query_rebinding(private):
    client, server, _, auth = session(private)
    request = client.begin_query([0, 1, 0])
    response = server.search(request)
    with pytest.raises(BFVProtocolError, match="replayed"):
        server.search(request)
    assert client.finish_query(response) == [0, 3, 1]
    with pytest.raises(BFVProtocolError):
        client.finish_query(response)
    request2 = client.begin_query([1, 0, 1])
    fields = _unpack(
        _authenticated_body(response, auth, 3, client.policy.max_response_bytes),
        limit=client.policy.max_response_bytes,
    )
    old = _decode_ciphertexts(fields[3], private._pk(), 1, client.policy.max_response_bytes)
    with pytest.raises(BFVProtocolError):
        client.finish_query(forged_response(client, request2, auth, old))


def test_same_key_different_index_session_rejected(private):
    client, server, _, auth = session(private)
    other = BFVVerifiedClient(private, auth, policy=policy(private))
    other.prepare_index([[0, 1, 0]])
    with pytest.raises(BFVProtocolError, match="another setup"):
        server.search(other.begin_query([0, 1, 0]))
    response = server.search(client.begin_query([0, 1, 0]))
    with pytest.raises(BFVProtocolError):
        other.finish_query(response)


def test_authentication_checked_before_parser_or_decryption(private, monkeypatch):
    client, server, setup, auth = session(private)
    response = server.search(client.begin_query([0, 1, 0]))
    import cuhepy.bfv.security as security

    with monkeypatch.context() as guard:
        guard.setattr(
            security.msgpack, "unpackb", lambda *a, **kw: pytest.fail("Unauthenticated body parsed")
        )
        guard.setattr(
            BFV, "decrypt", lambda *a: pytest.fail("Unauthenticated ciphertext decrypted")
        )
        with pytest.raises(BFVProtocolError):
            client.finish_query(response[:-1] + bytes([response[-1] ^ 1]))
        with pytest.raises(BFVProtocolError):
            BFVVerifiedServer(setup[:-1] + bytes([setup[-1] ^ 1]), auth, policy=policy(private))
    # An outsider's bad MAC does not consume the legitimate ticket.
    assert client.finish_query(response) == [0, 3, 1]


def test_setup_auth_covers_evaluation_keys_ids_and_configuration(private):
    _, _, setup, auth = session(private)
    header = 6 + 1 + 32
    fields = _unpack(setup[header:], limit=len(setup), array_limit=65536)
    for position in (1, 2, 4, 5):
        changed = fields[:]
        changed[position] = ["other"] if position == 4 else changed[position] + b" "
        tampered = setup[:header] + _pack(changed)
        with pytest.raises(BFVProtocolError):
            BFVVerifiedServer(tampered, auth, policy=policy(private))


def test_authenticated_malformed_response_has_no_partial_plaintext(private, monkeypatch):
    client, _, _, auth = session(private)
    request = client.begin_query([0, 1, 0])
    response = forged_response(client, request, auth, [])
    monkeypatch.setattr(BFV, "decrypt", lambda *a: pytest.fail("Wrong count reached decryption"))
    with pytest.raises(BFVProtocolError):
        client.finish_query(response)


def test_response_requires_negotiated_terminal_modulus(private, monkeypatch):
    client, _, _, auth = session(private)
    request = client.begin_query([0, 1, 0])
    response = forged_response(client, request, auth, [private.encrypt_vec_one([0, 0, 0])])
    monkeypatch.setattr(BFV, "decrypt", lambda *a: pytest.fail("Wrong modulus reached decryption"))
    with pytest.raises(BFVProtocolError):
        client.finish_query(response)


def test_query_budgets_are_bounded_and_cancellation_does_not_reset(private):
    client, server, _, _ = session(private, max_pending_queries=1, max_queries=2)
    request = client.begin_query([0, 1, 0])
    with pytest.raises(BFVProtocolError, match="budget"):
        client.begin_query([0, 1, 0])
    client.cancel_pending_queries()
    with pytest.raises(BFVProtocolError):
        client.finish_query(server.search(request))
    assert client.finish_query(server.search(client.begin_query([0, 1, 0]))) == [0, 3, 1]
    with pytest.raises(BFVProtocolError, match="budget"):
        client.begin_query([0, 1, 0])


def test_size_limits_and_pinned_parameters(private, monkeypatch):
    with pytest.raises(BFVProtocolError, match="pinned"):
        BFVVerifiedClient(private, secrets.token_bytes(32))
    with pytest.raises(ValueError):
        policy(private, max_vectors=0)
    client = BFVVerifiedClient(
        private, secrets.token_bytes(32), policy=policy(private, max_index_bytes=1)
    )
    monkeypatch.setattr(
        BFVClient, "encrypt_vec_packed", lambda *a: pytest.fail("Oversized index encrypted")
    )
    with pytest.raises(BFVProtocolError, match="size policy"):
        client.prepare_index([[0, 1, 0]])


def test_packet_limits_precede_authentication_and_parsing(private, monkeypatch):
    client, server, setup, auth = session(private)
    request = client.begin_query([0, 1, 0])
    response = server.search(request)
    import cuhepy.bfv.security as security

    monkeypatch.setattr(
        security.hmac, "new", lambda *a, **kw: pytest.fail("Oversized packet hashed")
    )
    for packet, kind in ((setup, 1), (request, 2), (response, 3)):
        with pytest.raises(BFVProtocolError):
            _authenticated_body(packet, auth, kind, len(packet) - 1)


@pytest.mark.parametrize("encoded", [b"\xc1", b"\x81\xa1x\xc0", b"\xdd\xff\xff\xff\xff"])
def test_authenticated_invalid_messagepack_never_decrypts(private, encoded, monkeypatch):
    client, _, _, auth = session(private)
    monkeypatch.setattr(BFV, "decrypt", lambda *a: pytest.fail("Malformed body decrypted"))
    with pytest.raises(BFVProtocolError):
        client.finish_query(_authenticate(encoded, auth, 3, client.policy.max_response_bytes))


def test_setup_policy_checked_before_public_key_import(private, monkeypatch):
    _, _, setup, auth = session(private)
    p = policy(private)
    fields = _unpack(
        _authenticated_body(setup, auth, 1, p.max_setup_bytes), limit=p.max_setup_bytes
    )
    fields[1] = json.dumps({**p.config(), "embed_len": 2}).encode()
    changed = _authenticate(_pack(fields), auth, 1, p.max_setup_bytes)
    monkeypatch.setattr(
        BFV, "deserialize_public_key", lambda *a, **kw: pytest.fail("Unpinned setup imported")
    )
    with pytest.raises(BFVProtocolError, match="pinned"):
        BFVVerifiedServer(changed, auth, policy=p)
    with pytest.raises(BFVProtocolError, match="import limit"):
        BFVVerifiedServer(setup, auth, policy=replace(p, max_public_key_bytes=1))


def test_summary_randomness_failure_aborts_preparation(private, monkeypatch):
    client = BFVVerifiedClient(private, secrets.token_bytes(32), policy=policy(private))
    monkeypatch.setattr(
        secrets, "token_bytes", lambda *a: (_ for _ in ()).throw(OSError("entropy unavailable"))
    )
    with pytest.raises(OSError, match="entropy"):
        client.prepare_index([[0, 1, 0]])
    assert client._summary is None and client._setup_digest is None


def test_summary_rejection_sampling_is_bounded(monkeypatch):
    import cuhepy.bfv.verified_client as verified

    monkeypatch.setattr(verified.hmac, "digest", lambda *a: b"\xff" * 32)
    with pytest.raises(RuntimeError, match="weight generation failed"):
        _HammingSummary([[0, 1, 0]], 3, secrets.token_bytes(16))


def test_original_client_key_replacement_does_not_retarget_session(private):
    client, server, _, _ = session(private)
    original = client._client._pk()
    # The caller can reuse their raw BFVClient; the verified session owns its snapshot.
    saved = private.public_key
    try:
        private.public_key = None
        assert client.finish_query(server.search(client.begin_query([0, 1, 0]))) == [0, 3, 1]
        assert client._client._pk() is original
    finally:
        private.public_key = saved


@pytest.mark.parametrize("kind", [1, 2, 3])
def test_packet_types_cannot_be_confused(private, kind):
    client, server, setup, auth = session(private)
    query = client.begin_query([0, 1, 0])
    response = server.search(query)
    packet = (setup, query, response)[kind - 1]
    with pytest.raises(BFVProtocolError):
        _authenticated_body(packet, auth, kind % 3 + 1, len(packet))


def test_concurrent_duplicate_causes_only_one_private_decryption(private, monkeypatch):
    client, server, _, _ = session(private)
    response = server.search(client.begin_query([0, 1, 0]))
    decrypt, calls, lock = BFV.decrypt, [], threading.Lock()

    def counted(*args):
        with lock:
            calls.append(1)
        return decrypt(*args)

    monkeypatch.setattr(BFV, "decrypt", counted)

    def finish():
        try:
            return client.finish_query(response)
        except BFVProtocolError:
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: finish(), range(4)))
    assert results.count([0, 3, 1]) == 1 and len(calls) == 1


def test_server_admission_releases_after_failure(private):
    client, server, _, _ = session(private)
    assert server._admission.acquire(blocking=False)
    with pytest.raises(BFVProtocolError, match="concurrency"):
        server.search(b"bad")
    server._admission.release()
    with pytest.raises(BFVProtocolError):
        server.search(b"bad")
    assert client.finish_query(server.search(client.begin_query([0, 1, 0]))) == [0, 3, 1]


def test_protected_private_state_roundtrip_and_pending_tickets_discarded(private):
    client, server, setup, auth = session(private, max_queries=3)
    wrap = secrets.token_bytes(32)
    old_response = server.search(client.begin_query([0, 1, 0]))
    protected = client.protect_state(wrap)
    restored = BFVVerifiedClient.restore(setup, protected, auth, wrap, policy=client.policy)
    with pytest.raises(BFVProtocolError):
        restored.finish_query(old_response)
    assert restored._started == 1 and not restored._pending
    assert restored.finish_query(server.search(restored.begin_query([0, 1, 0]))) == [0, 3, 1]
    assert restored.vector_ids == client.vector_ids
    with pytest.raises(ValueError, match="differ"):
        client.protect_state(auth)
    with pytest.raises(BFVProtocolError):
        BFVVerifiedClient.restore(
            setup, protected, auth, secrets.token_bytes(32), policy=client.policy
        )
    with pytest.raises(BFVProtocolError):
        BFVVerifiedClient.restore(
            setup, protected[:-1] + bytes([protected[-1] ^ 1]), auth, wrap, policy=client.policy
        )


def test_protected_key_binds_entire_public_bundle_before_loading(private, monkeypatch):
    key = secrets.token_bytes(32)
    protected = protect_bfv_secret_key(private, key)
    original = private.stringify_pk()
    assert restore_bfv_client(original, protected, key)._keys() == private._keys()
    data = json.loads(original)
    data["relin_key"][0][0][0] = format(
        (mpz(data["relin_key"][0][0][0], 16) + 1) % private._pk()["q"], "x"
    )
    changed = json.dumps(data)
    monkeypatch.setattr(
        BFV,
        "deserialize_public_key",
        lambda *a, **kw: pytest.fail("Public key parsed before storage authentication"),
    )
    for public, blob, secret in [
        (changed, protected, key),
        (original, protected, secrets.token_bytes(32)),
        (original, protected[:-1], key),
    ]:
        with pytest.raises(BFVProtocolError):
            restore_bfv_client(public, blob, secret)


def test_acceptance_feedback_still_allows_key_recovery(private):
    """Residual blocker: perfect plaintext-result checks are still a predicate oracle.

    For a known zero answer, c0=floor(q/(2t))+offset, c1=X^k probes
    whether a signed secret coefficient crosses the decryption boundary.
    All returned slots are 0 or 1, so range checks do not remove this oracle.
    Two accepted/rejected responses per coefficient recover the ternary secret.
    """
    client, _, _, auth = session(private, vectors=[[0, 0, 0]])
    n, t = private.params.poly_modulus_degree, private.params.plain_modulus
    q = _coefficient_modulus(private.response_modulus_bits)
    recovered = []
    for index in range(n):
        observed = []
        for offset in (0, 1):
            c0 = (q // (2 * t) + offset,) + (mpz(0),) * (n - 1)
            c1 = [mpz(0)] * n
            c1[0 if index == 0 else n - index] = mpz(1)
            forged = BFVCiphertext((c0, tuple(c1)), q, private._pk()["key_id"])
            request = client.begin_query([0, 0, 0])
            response = forged_response(
                client, request, auth, [BFV.ciphertext_to_ints(forged, private._pk())]
            )
            try:
                assert client.finish_query(response) == [0]
                observed.append(True)
            except BFVProtocolError:
                observed.append(False)
        signed = -1 if observed[1] else 0 if observed[0] else 1
        recovered.append(signed if index == 0 else -signed)
    assert tuple(recovered) == private._keys()["sk"]["s"]
