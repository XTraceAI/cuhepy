"""Exercise real certificate/signature validation with isolated synthetic roots.

These tests check public verification, not hardware isolation. Positive fixtures
patch the private trust anchor locally; a separate regression verifies that the
unmodified AWS-root path rejects exactly the same synthetic evidence.
"""

import hashlib
import time
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

pytest.importorskip("cbor2")
pytest.importorskip("OpenSSL")
import cbor2
from Crypto.Signature import eddsa

from tests.x_vec.nitro_fixtures import PCRS, SyntheticNitro, malformed_certificate
from xtrace_sdk.x_vec.crypto import bfv_nitro as nitro
from xtrace_sdk.x_vec.crypto.bfv_security import BFVProtocolError


@pytest.fixture(scope="module")
def issuer():
    return SyntheticNitro()


@pytest.fixture
def trusted(issuer, monkeypatch):
    monkeypatch.setattr(nitro, "_AWS_ROOT_SHA256", issuer.root_digest)
    return issuer


def evidence(issuer):
    """Use a real Ed25519 SPKI and fixed public test bindings."""
    key = eddsa.import_private_key(bytes(range(32))).public_key()
    nonce, context = bytes([3]) * 32, bytes([4]) * 32
    return issuer.attest(key.export_key(format="DER"), nonce, context), key, nonce, context


@pytest.mark.parametrize("tagged", [False, True])
def test_valid_chain_cose_and_application_bindings(trusted, tagged):
    doc, key, nonce, context = evidence(trusted)
    if not tagged:
        doc = doc[1:]
    result = nitro.verify_nitro_attestation(
        doc, nitro.NitroAttestationPolicy(PCRS), nonce=nonce, context=context
    )
    assert result.public_key == key.export_key(format="raw")
    assert result.certificate_expires_at > time.time()


def test_default_aws_root_rejects_synthetic_evidence(issuer):
    doc, _, nonce, context = evidence(issuer)
    assert issuer.root_digest != nitro._AWS_ROOT_SHA256
    with pytest.raises(BFVProtocolError):
        nitro.verify_nitro_attestation(
            doc, nitro.NitroAttestationPolicy(PCRS), nonce=nonce, context=context
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ca_authorized": False},
        {"expired": True},
        {"path_length": 0},
        {"unknown_critical": True},
    ],
)
def test_certificate_constraints_are_enforced(kwargs, monkeypatch):
    issuer = SyntheticNitro(**kwargs)
    monkeypatch.setattr(nitro, "_AWS_ROOT_SHA256", issuer.root_digest)
    doc, _, nonce, context = evidence(issuer)
    with pytest.raises(BFVProtocolError):
        nitro.verify_nitro_attestation(
            doc, nitro.NitroAttestationPolicy(PCRS), nonce=nonce, context=context
        )


@pytest.mark.parametrize("fault", ["duplicate_extension", "invalid_version"])
def test_malformed_certificate_uses_public_protocol_error(trusted, fault):
    _, key, nonce, context = evidence(trusted)
    claims = trusted.claims(key.export_key(format="DER"), nonce, context)
    claims["certificate"] = malformed_certificate(claims["certificate"], fault)
    document = trusted.sign(cbor2.dumps(claims))
    with pytest.raises(BFVProtocolError):
        nitro.verify_nitro_attestation(
            document, nitro.NitroAttestationPolicy(PCRS), nonce=nonce, context=context
        )


@pytest.mark.parametrize(
    "change",
    [
        "nonce",
        "context",
        "key",
        "small_order_key",
        "pcr",
        "missing_pcr",
        "debug",
        "old",
        "future",
        "digest",
        "timestamp_type",
        "bool_pcr",
        "certificate",
        "bundle",
    ],
)
def test_signed_but_unacceptable_claims_fail(trusted, change):
    doc, key, nonce, context = evidence(trusted)
    claims = trusted.claims(key.export_key(format="DER"), nonce, context)
    if change in ("nonce", "context"):
        claims["nonce" if change == "nonce" else "user_data"] = bytes(32)
    elif change == "key":
        claims["public_key"] = bytes(44)
    elif change == "small_order_key":
        claims["public_key"] = nitro._ED25519_SPKI_PREFIX + b"\x01" + bytes(31)
    elif change in ("pcr", "debug"):
        claims["pcrs"][0] = bytes(48) if change == "debug" else bytes([1]) * 48
    elif change == "missing_pcr":
        del claims["pcrs"][2]
    elif change in ("old", "future"):
        claims["timestamp"] += -400_000 if change == "old" else 60_000
    elif change == "digest":
        claims["digest"] = "SHA256"
    elif change == "timestamp_type":
        claims["timestamp"] = True
    elif change == "bool_pcr":
        value = claims["pcrs"].pop(1)
        claims["pcrs"][True] = value
    elif change == "certificate":
        claims["certificate"] = claims["cabundle"][1]
    else:
        claims["cabundle"] = []
    altered = trusted.sign(cbor2.dumps(claims))
    with pytest.raises(BFVProtocolError):
        nitro.verify_nitro_attestation(
            altered, nitro.NitroAttestationPolicy(PCRS), nonce=nonce, context=context
        )


@pytest.mark.parametrize(
    "change", ["signature", "algorithm", "unprotected", "trailing", "oversize"]
)
def test_cose_and_size_rejections(trusted, change):
    doc, key, nonce, context = evidence(trusted)
    if change == "signature":
        doc = doc[:-1] + bytes([doc[-1] ^ 1])
    elif change in ("algorithm", "unprotected"):
        doc = trusted.sign(
            cbor2.dumps(trusted.claims(key.export_key(format="DER"), nonce, context)),
            protected=cbor2.dumps({1: -7}) if change == "algorithm" else None,
            unprotected={1: -35} if change == "unprotected" else None,
        )
    elif change == "trailing":
        doc += b"\x00"
    else:
        doc = bytes(nitro.MAX_NITRO_DOCUMENT_BYTES + 1)
    with pytest.raises(BFVProtocolError):
        nitro.verify_nitro_attestation(
            doc, nitro.NitroAttestationPolicy(PCRS), nonce=nonce, context=context
        )


@pytest.mark.parametrize(
    "raw",
    [
        b"\xa2\x01\x01\x01\x02",
        b"\x9f\x01\xff",
        b"\x01\x02",
        b"\x81" * 50 + b"\x00",
        b"\xd8\x1c\x81\xd8\x1d\x00",
        b"\xc2\x41\x01",
        b"\xd9\xd9\xf7\x01",
        b"\xd8\x63\x01",
        b"\x5b\xff\xff\xff\xff\xff\xff\xff\xff",
        b"\xa1\xf5\x01\x00",
    ],
)
def test_bounded_cbor_rejects_ambiguous_or_dangerous_encodings(raw):
    with pytest.raises(BFVProtocolError):
        nitro._cbor(raw)


def test_policy_copies_pins_and_rejects_empty_debug_or_mutable_trust():
    pins = dict(PCRS)
    policy = nitro.NitroAttestationPolicy(pins)
    digest = policy.digest()
    pins[0] = bytes(48)
    assert policy.digest() == digest
    with pytest.raises(TypeError):
        policy.pcrs[0] = bytes(48)
    for invalid in ({}, {0: PCRS[0]}, {**PCRS, 0: bytes(48)}, {**PCRS, 3: b"x"}):
        with pytest.raises(ValueError):
            nitro.NitroAttestationPolicy(invalid)
    for kwargs in (
        {"max_age_seconds": 301},
        {"max_session_seconds": 0},
        {"max_clock_skew_seconds": True},
        {"handshake_timeout_seconds": 61},
    ):
        with pytest.raises(ValueError):
            replace(policy, **kwargs)


def test_missing_nsm_never_falls_back_to_local_claims():
    with pytest.raises(OSError):
        nitro.NitroNSM("/nonexistent/xtrace-libnsm.so")
    with pytest.raises(ValueError):
        nitro.NitroNSM("relative-libnsm.so")


def test_historical_real_aws_certificate_profile_and_signature():
    """Catch incompatibilities hidden by synthetic certificates with ideal extensions."""
    raw = (Path(__file__).parent / "fixtures/nitro/aws-2025-01-06.cose").read_bytes()
    doc, expiry = nitro._verified_document(raw, 1736179625)
    assert doc["timestamp"] == 1736179625472
    assert expiry > 1736179625
    # Historical evidence is not a fresh attestation of this application.
    with pytest.raises(BFVProtocolError):
        nitro._verified_document(raw, time.time())
    with pytest.raises(BFVProtocolError):
        nitro._verified_document(raw[:-1] + bytes([raw[-1] ^ 1]), 1736179625)


def test_nsm_c_abi_lengths_order_errors_and_close(tmp_path):
    """Compile a test-only ABI shim; no hardware evidence is fabricated by the SDK."""
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler required for the NSM ABI regression")
    source = Path(__file__).parent / "native/nitro_nsm_stub.c"
    library = tmp_path / "test-only-nsm.so"
    subprocess.run(
        [
            compiler,
            "-std=c11",
            "-shared",
            "-fPIC",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(source),
            "-o",
            str(library),
        ],
        check=True,
    )
    provider = nitro.NitroNSM(str(library))
    assert provider.random_seed() == bytes(range(32))
    assert provider.attest(b"k" * 44, b"n" * 32, b"c" * 32) == b"c" * 32 + b"n" * 32 + b"k" * 44
    for mode in (1, 2):
        provider._lib.test_mode(mode)
        with pytest.raises(BFVProtocolError):
            provider.random_seed()
    for mode in (1, 3):
        provider._lib.test_mode(mode)
        with pytest.raises(BFVProtocolError):
            provider.attest(b"k" * 44, b"n" * 32, b"c" * 32)
    provider.close()
    provider.close()
    assert provider._lib.test_closes() == 1
    with pytest.raises(BFVProtocolError):
        provider.random_seed()
    with pytest.raises(BFVProtocolError):
        provider.attest(b"k" * 44, b"n" * 32, b"c" * 32)
    provider._lib.test_mode(4)
    with pytest.raises(BFVProtocolError):
        nitro.NitroNSM(str(library))
