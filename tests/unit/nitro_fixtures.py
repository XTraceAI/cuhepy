"""Synthetic Nitro-format evidence for OFFLINE TESTS ONLY, never an AWS identity.

Tests explicitly replace the verifier's private root fingerprint with this
fixture's root. The production SDK has no synthetic-root configuration switch.
All private keys here are newly generated test keys and are never persisted.
"""

import hashlib
import secrets
import time
from datetime import UTC, datetime, timedelta

import cbor2
from Crypto.Util.asn1 import DerObject, DerSequence
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID, ObjectIdentifier


PCRS = {i: hashlib.sha384(f"XTrace synthetic PCR{i}".encode()).digest() for i in (0, 1, 2)}


def malformed_certificate(encoded, fault):
    """Mutate real DER to exercise parser errors before certificate verification.

    The modified leaf signature is invalid too. Verification must reject these
    bytes through the public protocol error, without leaking a parser exception.
    """
    certificate = DerSequence().decode(encoded)
    body = DerSequence().decode(certificate[0])
    if fault == "duplicate_extension":
        wrapper = DerObject().decode(body[-1])
        extensions = DerSequence().decode(wrapper.payload)
        extensions.append(extensions[0])
        wrapper.payload = extensions.encode()
        body[-1] = wrapper.encode()
    elif fault == "invalid_version":
        body[0] = b"\xa0\x03\x02\x01\x03"  # Unsupported X.509 version 4.
    else:
        raise ValueError("Unknown test certificate fault")
    certificate[0] = body.encode()
    return certificate.encode()


class SyntheticNitro:
    """Issue cryptographically signed test certificates and COSE evidence.

    ca_authorized, expired, path_length and unknown_critical create certificate
    path failures whose signatures are otherwise valid. changes mutates signed
    claims, enabling tests of policy checks independently of signature validity.
    """

    def __init__(
        self,
        *,
        ca_authorized=True,
        expired=False,
        path_length=1,
        unknown_critical=False,
        changes=None,
    ):
        self.changes = changes or {}
        self.root_key, self.ca_key, self.leaf_key = [
            ec.generate_private_key(ec.SECP384R1()) for _ in range(3)
        ]
        now = datetime.now(UTC)

        def issue(name, key, issuer, signer, ca, length, expiry):
            """Create an explicit X.509 path with AKI, SKI and key-usage constraints."""
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
            builder = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer.subject if issuer else subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=2))
                .not_valid_after(expiry)
                .add_extension(x509.BasicConstraints(ca=ca, path_length=length), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=not ca,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=ca,
                        crl_sign=ca,
                        encipher_only=None,
                        decipher_only=None,
                    ),
                    critical=True,
                )
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),
                    critical=False,
                )
            )
            if unknown_critical and name.endswith("leaf"):
                builder = builder.add_extension(
                    x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4.99"), b"\x05\x00"),
                    critical=True,
                )
            return builder.sign(signer, hashes.SHA384())

        self.root = issue(
            "TEST ONLY root",
            self.root_key,
            None,
            self.root_key,
            True,
            path_length,
            now + timedelta(days=1),
        )
        self.ca = issue(
            "TEST ONLY intermediate",
            self.ca_key,
            self.root,
            self.root_key,
            ca_authorized,
            0 if ca_authorized else None,
            now + timedelta(days=1),
        )
        self.leaf = issue(
            "TEST ONLY leaf",
            self.leaf_key,
            self.ca,
            self.ca_key,
            False,
            None,
            now + timedelta(hours=-1 if expired else 1),
        )
        self.root_digest = hashlib.sha256(self.der(self.root)).digest()

    @staticmethod
    def der(cert):
        """Return a test certificate's canonical DER bytes."""
        return cert.public_bytes(serialization.Encoding.DER)

    def random_seed(self):
        """Generate an ordinary local test signing seed; this is not NSM entropy."""
        return secrets.token_bytes(32)

    def claims(self, public_key, nonce, context):
        """Build realistic signed claims, including a complete untrusted CA bundle."""
        return {
            "module_id": "TEST-ONLY-NOT-AWS",
            "timestamp": int(time.time() * 1000),
            "digest": "SHA384",
            "pcrs": dict(PCRS),
            "certificate": self.der(self.leaf),
            "cabundle": [self.der(self.root), self.der(self.ca)],
            "public_key": public_key,
            "nonce": nonce,
            "user_data": context,
            **self.changes,
        }

    def sign(self, payload, *, protected=None, unprotected=None, tagged=True):
        """Sign exact payload bytes using COSE ES384's fixed-width signature format."""
        protected = cbor2.dumps({1: -35}) if protected is None else protected
        structure = cbor2.dumps(["Signature1", protected, b"", payload])
        signature = self.leaf_key.sign(structure, ec.ECDSA(hashes.SHA384()))
        r, s = utils.decode_dss_signature(signature)
        envelope = [
            protected,
            {} if unprotected is None else unprotected,
            payload,
            r.to_bytes(48, "big") + s.to_bytes(48, "big"),
        ]
        return cbor2.dumps(cbor2.CBORTag(18, envelope) if tagged else envelope)

    def attest(self, public_key, nonce, context):
        """Return fake-root evidence which the unmodified AWS verifier must reject."""
        return self.sign(cbor2.dumps(self.claims(public_key, nonce, context)))
