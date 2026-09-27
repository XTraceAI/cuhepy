"""Real signatures and synthetic Nitro evidence; test roots never enter the API."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import copy
import hashlib
import pickle

from Crypto.Signature import eddsa
from gmpy2 import mpz
import pytest

pytest.importorskip("cbor2")
pytest.importorskip("OpenSSL")

from cuhepy.hamming import bfv_nitro as nitro
from cuhepy.hamming.bfv_attested import _RECEIPT_CONTEXT as BFV_RECEIPT_DOMAIN
from tests.unit.nitro_fixtures import PCRS, SyntheticNitro
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import compact_bgv as compact, attested_bgv as attested
from experiments.bfv_search_lab import security_bgv as security
from experiments.bfv_search_lab.owner_bgv import OwnerClient, expand


@pytest.fixture(scope="module")
def material():
    for module in ("_native._bgv_trace", "_owner._bgv_private", "_owner._bgv_owner"):
        pytest.importorskip("experiments.bfv_search_lab." + module)
    pk, sk = bgv.key_gen(16, q_bits=120, rns_modulus=True)
    return pk, sk, trace.evaluation_keys(pk, sk, 4)


@pytest.fixture(scope="module")
def issuer():
    return SyntheticNitro()


@pytest.fixture
def trusted(issuer, monkeypatch):
    monkeypatch.setattr(nitro, "_AWS_ROOT_SHA256", issuer.root_digest)
    return issuer


def make_session(material, issuer, *, count=3, owner_index=False, rounded=False,
                 enrolled=True, **limits):
    pk, sk, keys = material
    policy = security.BGVExecutionPolicy(n=16, dimension=3, terminal_bits=32,
        owner_index=owner_index, query_drop_bits=20 if rounded else 0,
        response_drop_bits=14 if rounded else 0, **limits)
    vectors = ([[0, 1, 0], [1, 0, 1], [0, 0, 0]] * count)[:count]
    _, plains = bgv.coefficient_inputs([0, 1, 0], vectors, pk.n)
    if owner_index:
        owner = OwnerClient(pk, sk, native=True, rns=True)
        index = [expand(owner.encrypt(p), pk) for p in plains]
        owner.close()
    else:
        index = [bgv.encrypt(p, pk) for p in plains]
    client = attested.BGVAttestedClient(pk, sk, keys, index, count,
        nitro.NitroAttestationPolicy(PCRS), policy=policy, index_epoch=7)
    server = attested.BGVAttestedServer(client.registration_packet(), issuer, policy=policy)
    if enrolled:
        client.accept_attestation(*server.attest(client.begin_attestation()))
    return client, server, vectors


def deny_private(monkeypatch, client, *, parsing=True):
    def unexpected(*args, **kwargs):
        pytest.fail("Unauthenticated response reached parsing or private arithmetic")
    if parsing:
        monkeypatch.setattr(attested.wire, "_unpack_fields", unexpected)
        monkeypatch.setattr(attested.response_codec, "expand", unexpected)
    monkeypatch.setattr(client._decoder, "decode_packed", unexpected)
    monkeypatch.setattr(client._decoder._native, "decode_packed_many", unexpected)


@pytest.mark.parametrize("count", [1, 3, 39])
@pytest.mark.parametrize("owner_index", [False, True])
@pytest.mark.parametrize("rounded", [False, True])
def test_single_cpu_evaluation_matches_plaintext(material, trusted, monkeypatch, count, owner_index, rounded):
    client, server, vectors = make_session(material, trusted, count=count,
        owner_index=owner_index, rounded=rounded)
    calls, original = [], server._server.search_compact
    def record(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(server._server, "search_compact", record)
    query = client.begin_query([0, 1, 0])
    with monkeypatch.context() as scope:
        deny_private(scope, client, parsing=False)
        response, receipt = server.search(query)
    assert len(receipt) == 198 and calls == [True]
    assert server._server._device == "cpu"
    assert not hasattr(server, "sign") and not hasattr(server, "approve")
    answer = client.finish_query(response, receipt)
    expected = tuple(sum(a != b for a, b in zip(v, [0, 1, 0], strict=True)) for v in vectors)
    assert answer.distances == expected
    assert answer.top == tuple(sorted(enumerate(expected), key=lambda p: (p[1], p[0]))[:3])
    with pytest.raises(security.BGVProtocolError):
        client.finish_query(response, receipt)
    with pytest.raises(security.BGVProtocolError, match="replay"):
        server.search(query)
    client.close()


def test_real_root_rejects_synthetic_evidence(material, issuer):
    client, server, _ = make_session(material, issuer, enrolled=False)
    with pytest.raises(security.BGVProtocolError, match="enrollment rejected"):
        client.accept_attestation(*server.attest(client.begin_attestation()))
    with pytest.raises(security.BGVProtocolError, match="Fresh"):
        client.begin_query([0, 1, 0])
    client.close()


@pytest.mark.parametrize("field", ["domain", "context", "session", "query", "response", "signature",
                                   "missing", "extra", "body", "oversized", "type"])
def test_forgery_never_parses_or_decrypts(material, trusted, monkeypatch, field):
    client, server, _ = make_session(material, trusted, rounded=True)
    response, receipt = server.search(client.begin_query([0, 1, 0]))
    positions = {"domain": 0, "context": 6, "session": 38, "query": 70, "response": 102, "signature": 197}
    bad_receipt, bad_response = receipt, response
    if field in positions:
        pos = positions[field]
        bad_receipt = receipt[:pos] + bytes([receipt[pos] ^ 1]) + receipt[pos + 1:]
    elif field == "missing":
        bad_receipt = b""
    elif field == "extra":
        bad_receipt += b"x"
    elif field == "oversized":
        bad_response = bytes(client.policy.max_response_bytes + 1)
    elif field == "type":
        bad_response = bytearray(response)
    else:
        bad_response = response[:-1] + bytes([response[-1] ^ 1])
        # Rewrite the public digest too: the actual signature must still fail.
        bad_receipt = receipt[:102] + hashlib.sha256(bad_response).digest() + receipt[134:]
    with monkeypatch.context() as scope:
        deny_private(scope, client)
        with pytest.raises(security.BGVProtocolError, match="before decryption"):
            client.finish_query(bad_response, bad_receipt)
    assert client.finish_query(response, receipt).distances == (0, 3, 1)
    client.close()


def test_bgv_chosen_ciphertext_acceptance_oracle_is_blocked(material, trusted, monkeypatch):
    pk, sk, _ = material
    client, server, _ = make_session(material, trusted, count=1)
    response, receipt = server.search(client.begin_query([0, 1, 0]))
    p, recovered = client._decoder.modulus, []
    # Synthetic local regression: two validity predicates distinguish each
    # ternary coefficient. Range/distance checking is not authentication.
    for coefficient in range(pk.n):
        verdicts = []
        for offset in (8, 16):
            c0 = (mpz(offset),) + (mpz(0),) * (pk.n - 1)
            c1 = [mpz(0)] * pk.n
            c1[(-coefficient) % pk.n] = mpz(4 if coefficient == 0 else p - 4)
            cipher = compact.CompactCiphertext((c0, tuple(c1)), pk.key_id, p, 0)
            try:
                trace.decode([compact.decrypt(cipher, pk, sk)], 1, 3, pk)
                verdicts.append(True)
            except ValueError:
                verdicts.append(False)
            forged = compact.pack([cipher], 1, 3, pk)
            bad = receipt[:102] + hashlib.sha256(forged).digest() + receipt[134:]
            with monkeypatch.context() as scope:
                deny_private(scope, client)
                with pytest.raises(security.BGVProtocolError, match="before decryption"):
                    client.finish_query(forged, bad)
        recovered.append({(True, True): pk.q - 1, (False, False): mpz(0),
                          (True, False): mpz(1)}[tuple(verdicts)])
    assert tuple(recovered) == sk.s
    assert client.finish_query(response, receipt).distances == (0,)
    client.close()


@pytest.mark.parametrize("change", ["setup", "owner", "epoch", "policy", "signature"])
def test_registration_auth_precedes_key_import(material, trusted, monkeypatch, change):
    client, _, _ = make_session(material, trusted)
    registration, policy = client.registration_packet(), client.policy
    positions = {"setup": 50, "owner": 6, "epoch": 45, "signature": -1}
    if change == "policy":
        policy = replace(policy, max_queries=128)
    else:
        pos = positions[change] % len(registration)
        registration = registration[:pos] + bytes([registration[pos] ^ 1]) + registration[pos+1:]
    monkeypatch.setattr(attested, "unpack_setup", lambda *a: pytest.fail("Unauthenticated setup import"))
    with pytest.raises(ValueError):
        attested.BGVAttestedServer(registration, trusted, policy=policy)
    client.close()


def test_query_authorization_precedes_expansion(material, trusted, monkeypatch):
    client, server, _ = make_session(material, trusted)
    request = client.begin_query([0, 1, 0])
    monkeypatch.setattr(attested.owner, "expand", lambda *a: pytest.fail("Unauthorized query expanded"))
    for pos in (0, 6, 40, len(request) - 1):
        bad = request[:pos] + bytes([request[pos] ^ 1]) + request[pos+1:]
        with pytest.raises(ValueError):
            server.search(bad)
    client.close()


def test_wrong_domain_signature_and_nonpending_receipt(material, trusted, monkeypatch):
    client, server, _ = make_session(material, trusted)
    response, receipt = server.search(client.begin_query([0, 1, 0]))
    deny_private(monkeypatch, client)
    message = receipt[:70] + bytes(32) + receipt[102:134]
    with pytest.raises(security.BGVProtocolError):
        client.finish_query(response, message + server._signer.sign(message))
    # Same key and transcript, but a BFV signature domain must not cross schemes.
    wrong = eddsa.new(server._signer._key, "rfc8032", context=BFV_RECEIPT_DOMAIN)
    with pytest.raises(security.BGVProtocolError):
        client.finish_query(response, receipt[:134] + wrong.sign(receipt[:134]))
    client.close()


def test_reenrollment_discards_pending_and_old_requests(material, trusted, monkeypatch):
    client, server, _ = make_session(material, trusted)
    request = client.begin_query([0, 1, 0])
    response, receipt = server.search(request)
    hello = client.begin_attestation()
    evidence = server.attest(hello)
    client.accept_attestation(*evidence)
    for operation in (lambda: server.attest(hello), lambda: client.accept_attestation(*evidence),
                      lambda: server.search(request)):
        with pytest.raises(ValueError):
            operation()
    with monkeypatch.context() as scope:
        deny_private(scope, client)
        with pytest.raises(security.BGVProtocolError):
            client.finish_query(response, receipt)
    assert client.finish_query(*server.search(client.begin_query([0, 1, 0]))).distances == (0, 3, 1)
    client.close()


@pytest.mark.parametrize("side", ["client", "server", "during_evaluation"])
def test_session_expiry(material, trusted, monkeypatch, side):
    client, server, _ = make_session(material, trusted)
    request = client.begin_query([0, 1, 0])
    if side == "client":
        response, receipt = server.search(request)
        client._deadline = 0
        deny_private(monkeypatch, client)
        with pytest.raises(security.BGVProtocolError):
            client.finish_query(response, receipt)
    else:
        if side == "server":
            server._deadline = 0
        else:
            original = server._server.search_compact
            def expire(*args, **kwargs):
                result = original(*args, **kwargs)
                server._deadline = 0
                return result
            monkeypatch.setattr(server._server, "search_compact", expire)
        with pytest.raises(security.BGVProtocolError):
            server.search(request)
    client.close()


def test_budget_and_concurrent_finish(material, trusted, monkeypatch):
    client, server, _ = make_session(material, trusted, max_pending=1, max_queries=1)
    response, receipt = server.search(client.begin_query([0, 1, 0]))
    with pytest.raises(security.BGVProtocolError, match="budget"):
        client.begin_query([0, 1, 0])
    calls, original = [], client._decoder.decode_packed
    def record(*args):
        calls.append(True)
        return original(*args)
    monkeypatch.setattr(client._decoder, "decode_packed", record)
    def finish(_):
        try:
            return client.finish_query(response, receipt)
        except security.BGVProtocolError:
            return None
    with ThreadPoolExecutor(4) as pool:
        assert sum(r is not None for r in pool.map(finish, range(4))) == 1
    assert calls == [True]
    client.accept_attestation(*server.attest(client.begin_attestation()))
    with pytest.raises(security.BGVProtocolError, match="budget"):
        client.begin_query([0, 1, 0])
    for obj in (client, server):
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError):
                operation(obj)
    client.close()


def test_authenticated_parse_failure_still_consumes_ticket(material, trusted, monkeypatch):
    client, server, _ = make_session(material, trusted)
    response, receipt = server.search(client.begin_query([0, 1, 0]))
    # Model a faulty authorized evaluator. Trusted code correctness is an
    # assumption; even a signed malformed output must not create a retry oracle.
    response = b"not a compact packet"
    message = receipt[:102] + hashlib.sha256(response).digest()
    receipt = message + server._signer.sign(message)
    monkeypatch.setattr(client._decoder, "decode_packed", lambda *a: pytest.fail("Malformed authenticated input"))
    with pytest.raises(ValueError):
        client.finish_query(response, receipt)
    with pytest.raises(security.BGVProtocolError, match="before decryption"):
        client.finish_query(response, receipt)
    client.close()
