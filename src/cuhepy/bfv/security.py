"""Bounded authentication and private storage for the experimental BFV protocol.

The transport key authenticates a peer, not its computation. The private
verification seed must never be shared with the evaluator. No security level
or constant-time guarantee for BFV is implied by these wrappers.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import msgpack
from Crypto.Cipher import AES

from cuhepy.bfv.scheme import (
    MAX_PUBLIC_KEY_CHARS,
    _load_key_json,
    _read_ciphertext_wire,
)
from cuhepy.types import BFVParameters, BFVPublicKey, EncryptedVector

if TYPE_CHECKING:
    from cuhepy.bfv.client import BFVClient


class BFVProtocolError(ValueError):
    """Local protocol rejection. Do not transmit decryption-dependent failures."""


@dataclass(frozen=True)
class BFVExecutionPolicy:
    """Locally pinned arithmetic and resource policy, not a security certificate.

    Defaults pin the measured RNS configuration. Override parameters only through
    trusted application configuration (e.g. explicit tiny-ring tests), never
    from a received setup packet. Limits apply per protocol instance; deployments
    still need aggregate quotas and transport limits before buffering packets.
    """

    params: BFVParameters = BFVParameters(rns_modulus=True)
    embed_len: int = 512
    response_modulus_bits: int = 50
    max_vectors: int = 65536
    max_setup_bytes: int = 384 * 1024 * 1024
    max_public_key_bytes: int = MAX_PUBLIC_KEY_CHARS
    max_index_bytes: int = 256 * 1024 * 1024
    max_query_bytes: int = 1024 * 1024
    max_response_bytes: int = 16 * 1024 * 1024
    max_pending_queries: int = 8
    max_queries: int = 65536
    max_concurrent_searches: int = 1

    def __post_init__(self) -> None:
        from cuhepy.bfv.client import BFVClient

        BFVClient(**self.config(), skip_key_gen=True)
        for name, value in vars(self).items():
            if name.startswith("max_") and (type(value) is not int or value < 1):
                raise ValueError("BFV execution limits must be positive integers")
        if self.max_vectors >= 1 << 64 or self.max_queries >= 1 << 64:
            raise ValueError("BFV execution counts must fit in 64 bits")

    def config(self) -> dict[str, Any]:
        from cuhepy.bfv.scheme import _parameter_dict

        return {
            "embed_len": self.embed_len,
            **_parameter_dict(self.params),
            "response_modulus_bits": self.response_modulus_bits,
            "device": "cpu",
        }

    def check_client(self, client: BFVClient) -> None:
        if json.loads(client.stringify_config()) != self.config():
            raise BFVProtocolError("BFV parameters do not match the locally pinned policy")


def _key(key: bytes) -> bytes:
    if type(key) is not bytes or len(key) != 32:
        raise ValueError("Use an independently generated 32-byte key")
    return key


_MAGIC = b"XBFVA1"
_HEADER_BYTES = len(_MAGIC) + 1 + 32


def _authenticate(body: bytes, key: bytes, kind: int, limit: int) -> bytes:
    prefix = _MAGIC + bytes([kind])
    if len(body) + _HEADER_BYTES > limit:
        raise BFVProtocolError("BFV packet exceeds the local size limit")
    mac = hmac.new(_key(key), prefix, hashlib.sha256)
    mac.update(body)
    return prefix + mac.digest() + body


def _authenticated_body(packet: bytes, key: bytes, kind: int, limit: int) -> bytes:
    if type(packet) is not bytes or not _HEADER_BYTES <= len(packet) <= limit:
        raise BFVProtocolError("BFV packet rejected")
    prefix = _MAGIC + bytes([kind])
    if packet[: len(prefix)] != prefix:
        raise BFVProtocolError("BFV packet rejected")
    mac = hmac.new(_key(key), prefix, hashlib.sha256)
    mac.update(memoryview(packet)[_HEADER_BYTES:])
    if not hmac.compare_digest(mac.digest(), packet[len(prefix) : _HEADER_BYTES]):
        raise BFVProtocolError("BFV packet rejected")
    # Parse only after authentication. The peer still needs structural checks.
    return packet[_HEADER_BYTES:]


def _pack(value: Any) -> bytes:
    return msgpack.packb(value, use_bin_type=True)


def _unpack(data: bytes, *, limit: int, array_limit: int = 8) -> Any:
    if type(data) is not bytes or len(data) > limit:
        raise BFVProtocolError("BFV encoded object exceeds its size limit")
    try:
        return msgpack.unpackb(
            data,
            raw=False,
            max_bin_len=limit,
            max_str_len=256,
            max_array_len=max(8, array_limit),
            max_map_len=0,
            max_ext_len=0,
        )
    except (ValueError, TypeError, msgpack.UnpackException) as exc:
        raise BFVProtocolError("BFV encoded object rejected") from exc


def _record(value: Any, length: int) -> list[Any]:
    if type(value) is not list or len(value) != length:
        raise BFVProtocolError("Invalid BFV record")
    return value


def _bytes(value: Any, length: int) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise BFVProtocolError("Invalid BFV identifier")
    return value


def _encode_ciphertexts(values: list[EncryptedVector], pk: BFVPublicKey) -> bytes:
    return _pack(
        [
            [v.to_bytes((v.bit_length() + 7) // 8, "little") for v in _read_ciphertext_wire(ct, pk)]
            for ct in values
        ]
    )


def _decode_ciphertexts(
    data: bytes, pk: BFVPublicKey, count: int, limit: int
) -> list[EncryptedVector]:
    rows = _unpack(data, limit=limit, array_limit=count)
    if type(rows) is not list or len(rows) != count:
        raise BFVProtocolError("Unexpected BFV ciphertext count")
    result = []
    for row in rows:
        _record(row, 8)
        if any(type(v) is not bytes for v in row):
            raise BFVProtocolError("BFV wire fields must be byte strings")
        result.append(_read_ciphertext_wire(row, pk))
    return result


_STORAGE_MAGIC = b"XBFVK1"


def protect_bfv_state(plaintext: bytes, wrapping_key: bytes, binding: bytes) -> bytes:
    """AES-256-GCM private export bound to an authenticated public context.

    Supply a wrapping key from separate trusted storage/KMS. This protects the
    stored bytes, not Python/GMP memory or copies made by the caller.
    """
    _key(wrapping_key)
    _bytes(binding, 32)
    if type(plaintext) is not bytes or len(plaintext) > 1024 * 1024:
        raise ValueError("BFV private state exceeds the 1 MiB limit")
    nonce = secrets.token_bytes(12)
    cipher = AES.new(wrapping_key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(_STORAGE_MAGIC + binding)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return _STORAGE_MAGIC + nonce + tag + ciphertext


def unprotect_bfv_state(packet: bytes, wrapping_key: bytes, binding: bytes) -> bytes:
    """Authenticate private storage before returning any plaintext or parsing it."""
    _key(wrapping_key)
    _bytes(binding, 32)
    header = len(_STORAGE_MAGIC) + 28
    if (
        type(packet) is not bytes
        or not header <= len(packet) <= header + 1024 * 1024
        or packet[: len(_STORAGE_MAGIC)] != _STORAGE_MAGIC
    ):
        raise BFVProtocolError("BFV private state rejected")
    offset = len(_STORAGE_MAGIC)
    cipher = AES.new(wrapping_key, AES.MODE_GCM, nonce=packet[offset : offset + 12], mac_len=16)
    cipher.update(_STORAGE_MAGIC + binding)
    try:
        return cipher.decrypt_and_verify(packet[header:], packet[offset + 12 : header])
    except ValueError:
        raise BFVProtocolError("BFV private state rejected") from None


def protect_bfv_secret_key(client: BFVClient, wrapping_key: bytes) -> bytes:
    """Protect secret/configuration; the binding covers the complete public JSON."""
    public = client.stringify_pk().encode()
    private = _pack([client.stringify_config().encode(), client.stringify_sk().encode()])
    return protect_bfv_state(private, wrapping_key, hashlib.sha256(public).digest())


def restore_bfv_client(public_json: str, protected: bytes, wrapping_key: bytes) -> BFVClient:
    """Restore against exactly the saved public bundle, including evaluation keys."""
    from cuhepy.bfv.client import BFVClient

    if (
        type(public_json) is not str
        or len(public_json) > MAX_PUBLIC_KEY_CHARS
        or not public_json.isascii()
    ):
        raise BFVProtocolError("BFV public key exceeds its import limit")
    plaintext = unprotect_bfv_state(
        protected, wrapping_key, hashlib.sha256(public_json.encode()).digest()
    )
    config, secret = _record(_unpack(plaintext, limit=1024 * 1024), 2)
    if type(config) is not bytes or type(secret) is not bytes:
        raise BFVProtocolError("Invalid BFV private state")
    candidate = BFVClient(**_load_key_json(config.decode(), 4096), skip_key_gen=True)
    candidate.load_stringified_keys(public_json, secret.decode())
    return candidate
