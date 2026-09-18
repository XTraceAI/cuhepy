"""Run a synthetic owner-side search against the real Nitro enclave service.

Run on the owner machine with trusted EIF measurements. No private material or
decryption feedback is sent to the relay. Use a fresh, empty enclave for each
invocation because registration is deliberately immutable.
"""

import argparse
import json
import random
import secrets
from pathlib import Path

from cuhepy.hamming.bfv_assurance import bfv_review_policy
from cuhepy.hamming.bfv_attested import BFVAttestedClient
from cuhepy.hamming.bfv import BFVClient
from cuhepy.hamming.bfv_nitro import NitroAttestationPolicy

from .transport import NitroRemote


def load_measurements(path: Path) -> NitroAttestationPolicy:
    """Read owner-trusted nitro-cli build/describe-eif JSON; never fetch peer pins."""
    with path.open("rb") as stream:
        raw = stream.read(16 * 1024 + 1)
    if len(raw) > 16 * 1024:
        raise ValueError("Measurement file is too large")
    record = json.loads(raw)
    measurements = record["Measurements"]
    # nitro-cli 1.4.5 emits the Rust Debug spelling, including literal braces.
    # Accept that documented output and the plain spelling, never a prefix match.
    if measurements.get("HashAlgorithm", "").lower() not in ("sha384", "sha384 { ... }"):
        raise ValueError("Expected SHA-384 EIF measurements")
    pins = {
        int(name[3:]): bytes.fromhex(value)
        for name, value in measurements.items()
        if name.startswith("PCR") and name[3:].isdigit()
    }
    return NitroAttestationPolicy(pins)


def main():
    """Create synthetic keys/data locally, verify attestation, then decrypt results."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pins", type=Path, required=True, help="Trusted nitro-cli EIF measurement JSON"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--vectors", type=int, default=32)
    parser.add_argument("--queries", type=int, default=3)
    parser.add_argument("--epoch", type=int, default=1)
    args = parser.parse_args()
    policy = bfv_review_policy()
    if not 1 <= args.vectors <= policy.max_vectors or not 1 <= args.queries <= policy.max_queries:
        parser.error("Synthetic workload exceeds the local BFV policy")
    pins = load_measurements(args.pins)
    rng = random.Random(1337)  # Only synthetic plaintext uses a deterministic seed.
    vectors = [[rng.randrange(2) for _ in range(512)] for _ in range(args.vectors)]
    client = BFVAttestedClient(
        BFVClient(**policy.config()),
        secrets.token_bytes(32),
        pins,
        index_epoch=args.epoch,
        policy=policy,
    )
    remote = NitroRemote(args.host, args.port, policy=policy)
    setup = client.prepare_index(vectors)
    remote.register(client.registration_packet(setup))
    client.accept_attestation(*remote.attest(client.begin_attestation()))
    print("AWS evidence, approved measurements and receipt-key possession verified.")
    for _ in range(args.queries):
        query = [rng.randrange(2) for _ in range(512)]
        distances = client.finish_query(*remote.search(client.begin_query(query)))
        expected = [sum(a != b for a, b in zip(query, vector, strict=True)) for vector in vectors]
        if distances != expected:
            raise RuntimeError("Synthetic Hamming result mismatch")
        nearest = sorted(range(len(distances)), key=lambda i: (distances[i], i))[:3]
        print(
            "Verified local top results:", [(client.vector_ids[i], distances[i]) for i in nearest]
        )


if __name__ == "__main__":
    main()
