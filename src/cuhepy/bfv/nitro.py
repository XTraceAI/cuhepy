"""AWS Nitro evidence verification and the optional official NSM C-library adapter.

OpenSSL validates X.509 paths; cryptography verifies the COSE ES384 signature;
cbor2 supplies bounded CBOR decoding. This module adds the application's strict
wire, measurement, freshness and key-binding policy. It is not an independently
reviewed attestation implementation. No test root or debug bypass is exposed.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import io
import math
import threading
import time
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

from Crypto.Signature import eddsa

from cuhepy.bfv.security import BFVProtocolError, _bytes, _pack


MAX_NITRO_DOCUMENT_BYTES = 16 * 1024
# DER certificate fingerprint published in the AWS Nitro root-of-trust guide.
# The received CA bundle is UNTRUSTED until its root matches this local anchor.
_AWS_ROOT_SHA256 = bytes.fromhex("641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b")
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


@dataclass(frozen=True)
class NitroAttestationPolicy:
    """Owner-provisioned exact PCR pins and bounded evidence/session lifetimes.

    pcrs maps register numbers to 48-byte SHA-384 measurements. PCR0, PCR1 and
    PCR2 are mandatory and nonzero; optional additional pins are conjunctive.
    Durations are integer seconds. Evidence age is checked at enrollment;
    max_session_seconds limits subsequent receipt acceptance without renewal.
    Copying the map prevents caller mutation from silently changing trust.
    """

    pcrs: Mapping[int, bytes]
    max_age_seconds: int = 120
    max_session_seconds: int = 300
    max_clock_skew_seconds: int = 5
    handshake_timeout_seconds: int = 30

    def __post_init__(self) -> None:
        pins = dict(self.pcrs)
        if not {0, 1, 2}.issubset(pins) or len(pins) > 32:
            raise ValueError("Pin at least Nitro PCR0, PCR1 and PCR2")
        for index, digest in pins.items():
            if type(index) is not int or not 0 <= index < 32:
                raise ValueError("Invalid Nitro PCR number")
            _bytes(digest, 48)
            if digest == bytes(48):
                raise ValueError("Zero/debug Nitro measurements are not permitted")
        for name, maximum, minimum in (
            ("max_age_seconds", 300, 1),
            ("max_session_seconds", 300, 1),
            ("max_clock_skew_seconds", 30, 0),
            ("handshake_timeout_seconds", 60, 1),
        ):
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"Invalid Nitro duration: {name}")
        object.__setattr__(self, "pcrs", MappingProxyType(pins))

    def digest(self) -> bytes:
        """Bind private exports to the exact locally selected trust policy."""
        return hashlib.sha256(
            b"XTRACE-NITRO-POLICY-v1\0"
            + _pack(
                [
                    sorted(self.pcrs.items()),
                    self.max_age_seconds,
                    self.max_session_seconds,
                    self.max_clock_skew_seconds,
                    self.handshake_timeout_seconds,
                ]
            )
        ).digest()


@dataclass(frozen=True)
class NitroIdentity:
    """Verified receipt key and certificate expiry, obtained from signed evidence."""

    public_key: bytes
    certificate_expires_at: float


def _reject_tag(*args: Any) -> Any:
    """Reject CBOR semantic conversions, including references and bignums."""
    raise BFVProtocolError("CBOR semantic tags are not permitted here")


def _cbor(data: bytes) -> Any:
    """Decode one bounded, definite CBOR item without tags or duplicate keys."""
    import cbor2

    if type(data) is not bytes or not 0 < len(data) <= MAX_NITRO_DOCUMENT_BYTES:
        raise BFVProtocolError("Nitro CBOR exceeds its size limit")
    stream = io.BytesIO(data)
    try:
        # The public semantic-decoder mapping intercepts every tag, including
        # cbor2's built-ins. In particular, shared references cannot form cycles.
        decoder = cbor2.CBORDecoder(
            stream,
            max_depth=6,
            allow_indefinite=False,
            allow_duplicate_keys=False,
            semantic_decoders=defaultdict(lambda: _reject_tag),
            tag_hook=_reject_tag,
        )
        result = decoder.decode()
        if stream.read(1):
            raise BFVProtocolError("Trailing Nitro CBOR data")
        return result
    except (cbor2.CBORDecodeError, ValueError, TypeError, OverflowError) as exc:
        raise BFVProtocolError("Invalid Nitro CBOR") from exc


def _verified_document(document: bytes, now: float) -> tuple[dict[str, Any], float]:
    """Verify AWS's signature and complete certificate path at the client time.

    This private helper does not approve an application or a query. Its caller
    must additionally enforce measurements, nonce, context and receipt-key pins.
    The time argument exists for deterministic certificate regression fixtures;
    the public entrypoint always obtains the local clock itself.
    """
    from OpenSSL import crypto
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    import cbor2

    if (
        type(document) is not bytes
        or not 0 < len(document) <= MAX_NITRO_DOCUMENT_BYTES
        or not math.isfinite(now)
        or now < 0
    ):
        raise BFVProtocolError("Invalid Nitro document or verification time")
    try:
        # AWS permits both an untagged COSE_Sign1 array and its tag-18 form.
        cose = _cbor(document[1:] if document[:1] == b"\xd2" else document)
        if type(cose) is not list or len(cose) != 4:
            raise BFVProtocolError("Expected a Nitro COSE_Sign1 array")
        protected, unprotected, payload, signature = cose
        headers = _cbor(protected)
        if (
            type(headers) is not dict
            or len(headers) != 1
            or type(next(iter(headers))) is not int
            or headers != {1: -35}
            or type(unprotected) is not dict
            or unprotected
        ):
            raise BFVProtocolError("Nitro requires the protected ES384 algorithm")
        _bytes(signature, 96)
        doc = _cbor(payload)
        required = {"module_id", "timestamp", "digest", "pcrs", "certificate", "cabundle"}
        optional = {"nonce", "public_key", "user_data"}
        if (
            type(doc) is not dict
            or not required.issubset(doc)
            or set(doc) - required - optional
            or type(doc["module_id"]) is not str
            or not 1 <= len(doc["module_id"].encode()) <= 256
            or type(doc["timestamp"]) is not int
            or not 0 <= doc["timestamp"] < 1 << 64
            or doc["digest"] != "SHA384"
        ):
            raise BFVProtocolError("Invalid Nitro claims")
        pcrs = doc["pcrs"]
        if type(pcrs) is not dict or not 1 <= len(pcrs) <= 32:
            raise BFVProtocolError("Invalid Nitro measurements")
        for index, digest in pcrs.items():
            if type(index) is not int or not 0 <= index < 32:
                raise BFVProtocolError("Invalid Nitro PCR number")
            _bytes(digest, 48)
        for field in optional:
            value = doc.get(field)
            if value is not None and (type(value) is not bytes or len(value) > 1024):
                raise BFVProtocolError("Invalid optional Nitro field")
        bundle = doc["cabundle"]
        if type(bundle) is not list or not 1 <= len(bundle) <= 8:
            raise BFVProtocolError("Invalid Nitro certificate bundle")
        cert_bytes = [*bundle, doc["certificate"]]
        if any(type(v) is not bytes or not 1 <= len(v) <= 1024 for v in cert_bytes):
            raise BFVProtocolError("Invalid Nitro certificate size")
        if len(set(cert_bytes)) != len(cert_bytes):
            raise BFVProtocolError("Duplicate Nitro certificates")
        if not hmac.compare_digest(hashlib.sha256(bundle[0]).digest(), _AWS_ROOT_SHA256):
            raise BFVProtocolError("Untrusted Nitro root")
        certs = [x509.load_der_x509_certificate(v) for v in cert_bytes]
        if any(
            cert.public_bytes(serialization.Encoding.DER) != encoded
            for cert, encoded in zip(certs, cert_bytes, strict=True)
        ):
            raise BFVProtocolError("Noncanonical Nitro certificate")
        # Nitro's real leaf omits AKI/SKI. X509_STRICT would reject that valid
        # AWS profile. Normal OpenSSL path validation still enforces signatures,
        # validity, path lengths and critical constraints; explicitly require
        # CA authorization and leaf signing usage for this application as well.
        for index, cert in enumerate(certs):
            basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            is_ca = index < len(certs) - 1
            if (
                basic.ca != is_ca
                or (is_ca and not usage.key_cert_sign)
                or (not is_ca and (not usage.digital_signature or usage.key_cert_sign))
            ):
                raise BFVProtocolError("Invalid Nitro certificate key usage")
        store = crypto.X509Store()
        store.add_cert(crypto.X509.from_cryptography(certs[0]))
        store.set_flags(crypto.X509StoreFlags.CHECK_SS_SIGNATURE)
        store.set_time(datetime.fromtimestamp(now, UTC))
        # Delegate path constraints, CA/key usage, signatures and validity to
        # OpenSSL. Checking only a sequence of certificate signatures is unsafe.
        chain = crypto.X509StoreContext(
            store,
            crypto.X509.from_cryptography(certs[-1]),
            [crypto.X509.from_cryptography(c) for c in certs[1:-1]],
        ).get_verified_chain()
        verified = [c.to_cryptography() for c in chain]
        if len(verified) != len(certs):
            raise BFVProtocolError("Unused Nitro certificates")
        public_key = certs[-1].public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP384R1
        ):
            raise BFVProtocolError("Nitro signing key must use P-384")
        signed = cbor2.dumps(["Signature1", protected, b"", payload])
        der_signature = utils.encode_dss_signature(
            int.from_bytes(signature[:48], "big"), int.from_bytes(signature[48:], "big")
        )
        public_key.verify(der_signature, signed, ec.ECDSA(hashes.SHA384()))
        expires = min(c.not_valid_after_utc.timestamp() for c in verified)
        return doc, expires
    except (
        ValueError,
        TypeError,
        OverflowError,
        InvalidSignature,
        UnsupportedAlgorithm,
        crypto.Error,
        crypto.X509StoreContextError,
        x509.ExtensionNotFound,
        x509.DuplicateExtension,
        x509.InvalidVersion,
    ) as exc:
        raise BFVProtocolError("Nitro attestation rejected") from exc


def verify_nitro_attestation(
    document: bytes, policy: NitroAttestationPolicy, *, nonce: bytes, context: bytes
) -> NitroIdentity:
    """Approve fresh AWS evidence for exact owner pins, nonce and BFV context.

    Inputs are raw COSE bytes, a local policy, and locally retained 32-byte
    nonce/context digests. Returns a verified Ed25519 key and certificate expiry.
    There is no network fetching, trust-on-first-use or caller-selected root.
    """
    now = time.time()
    doc, expires = _verified_document(document, now)
    if (
        not now - policy.max_age_seconds
        <= doc["timestamp"] / 1000
        <= (now + policy.max_clock_skew_seconds)
    ):
        raise BFVProtocolError("Nitro attestation is not fresh")
    for index, expected in policy.pcrs.items():
        actual = doc["pcrs"].get(index)
        if type(actual) is not bytes or not hmac.compare_digest(actual, expected):
            raise BFVProtocolError("Nitro code measurement mismatch")
    if doc.get("nonce") != _bytes(nonce, 32) or doc.get("user_data") != _bytes(context, 32):
        raise BFVProtocolError("Nitro attestation context mismatch")
    spki = doc.get("public_key")
    if type(spki) is not bytes or len(spki) != 44 or not spki.startswith(_ED25519_SPKI_PREFIX):
        raise BFVProtocolError("Expected a Nitro-bound Ed25519 receipt key")
    key = eddsa.import_public_key(spki[12:])
    if (key.pointQ * 8).is_point_at_infinity():
        raise BFVProtocolError("Invalid Nitro receipt key")
    return NitroIdentity(spki[12:], expires)


class NitroNSM:
    """Use AWS's libnsm.so inside an enclave; fail closed if it is unavailable.

    The path is trusted local configuration, never a network field. The official
    NSM C ABI supplies random bytes and evidence; no ioctl protocol is recreated
    here. Keep the library and application in the measured enclave image.
    """

    def __init__(self, library: str = "/usr/local/lib/libnsm.so") -> None:
        if not Path(library).is_absolute():
            raise ValueError("Use an absolute, trusted NSM library path")
        self._lock = threading.Lock()
        self._lib = ctypes.CDLL(library)
        self._lib.nsm_lib_init.argtypes = []
        self._lib.nsm_lib_init.restype = ctypes.c_int
        self._lib.nsm_lib_exit.argtypes = [ctypes.c_int]
        self._lib.nsm_lib_exit.restype = None
        self._lib.nsm_get_attestation_doc.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self._lib.nsm_get_attestation_doc.restype = ctypes.c_int
        self._lib.nsm_get_random.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self._lib.nsm_get_random.restype = ctypes.c_int
        self._fd = self._lib.nsm_lib_init()
        if self._fd < 0:
            raise BFVProtocolError("Nitro NSM device unavailable")

    def random_seed(self) -> bytes:
        """Get an independent 32-byte receipt-signing seed from NSM randomness."""
        with self._lock:
            buffer = ctypes.create_string_buffer(32)
            length = ctypes.c_size_t(32)
            if (
                self._fd < 0
                or self._lib.nsm_get_random(self._fd, buffer, ctypes.byref(length)) != 0
                or length.value != 32
            ):
                raise BFVProtocolError("Nitro NSM randomness unavailable")
            return buffer.raw

    def attest(self, public_key: bytes, nonce: bytes, context: bytes) -> bytes:
        """Ask NSM to bind the in-enclave receipt key and the owner's challenge."""
        _bytes(public_key, 44)
        _bytes(nonce, 32)
        _bytes(context, 32)
        with self._lock:
            output = ctypes.create_string_buffer(MAX_NITRO_DOCUMENT_BYTES)
            length = ctypes.c_uint32(MAX_NITRO_DOCUMENT_BYTES)
            status = (
                self._lib.nsm_get_attestation_doc(
                    self._fd,
                    context,
                    len(context),
                    nonce,
                    len(nonce),
                    public_key,
                    len(public_key),
                    output,
                    ctypes.byref(length),
                )
                if self._fd >= 0
                else -1
            )
            if status != 0 or not 0 < length.value <= MAX_NITRO_DOCUMENT_BYTES:
                raise BFVProtocolError("Nitro NSM attestation unavailable")
            return output.raw[: length.value]

    def close(self) -> None:
        """Close the device once, excluding concurrent NSM calls."""
        with self._lock:
            if self._fd >= 0:
                self._lib.nsm_lib_exit(self._fd)
                self._fd = -1
