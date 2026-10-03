"""E109 owner-local statement adapter for an external proof control.

This diagnostic keeps homemade HE unchanged. It does not provide a service,
durable request lifecycle, attestation, or private side-channel assurance.
The caller pins the compiled relation, context, and original request locally.
"""

import hashlib
import json
from dataclasses import dataclass

from experiments.bfv_search_lab import native_opening_constraints as constraints


@dataclass(frozen=True)
class Pins:
    context_digest: str
    instance_sha256: str
    original_query: bytes


def statement(compiled, ctx, pins, response):
    """Derive all public field words and the full-byte transcript locally.

    No server-supplied field inputs, circuit, metadata, or domain are used.
    Context admission and full index/key hashing are paid on every call.
    """
    if (type(pins) is not Pins or type(pins.original_query) is not bytes
            or type(response) is not bytes or ctx.digest() != pins.context_digest
            or compiled.context_digest != pins.context_digest
            or len(pins.instance_sha256) != 64
            or any(x not in "0123456789abcdef" for x in pins.instance_sha256)):
        raise ValueError("Changed independently pinned owner statement")
    public = constraints.public_inputs(compiled, ctx, pins.original_query, response)
    binding = {
        "protocol": "cuhepy-native-proof-control-v1",
        "context_sha256": pins.context_digest,
        "instance_sha256": pins.instance_sha256,
        "original_query_hex": pins.original_query.hex(),
        "full_response_hex": response.hex(),
        # Context digest includes owner key, epoch, corpus IDs, layout and keys.
        "context_digest_includes_full_index_keys_and_layout": True,
    }
    domain = hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return public, domain


def release(compiled, ctx, pins, response, proof, verify, decode):
    """Check the actual proof before invoking the diagnostic private callback.

    ``verify`` is a locally selected backend with locally pinned generators and
    instance commitment, never a server-provided acceptance flag. Neither that
    interface nor this function establishes cryptographic security by itself.
    """
    if type(proof) is not bytes or not 0 < len(proof) <= 1 << 20:
        raise ValueError("Wrong bounded proof packet")
    public, domain = statement(compiled, ctx, pins, response)
    if verify(proof, public, domain) is not True:
        raise ValueError("Cryptographic proof rejected before private callback")
    return decode(response)
