#!/usr/bin/env python3
"""Compare one Nitro-protocol evaluation with the same-ciphertext BFV baseline.

--mode local uses a SYNTHETIC TEST CA and measures protocol overhead only. It
cannot measure Nitro isolation, NSM or EC2 overhead. --mode aws requires an
empty real enclave plus owner-trusted EIF pins; its server timer includes RPC.
Only generated synthetic plaintext is seeded; no keys or ciphertexts are logged.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import resource
import secrets
import statistics
import subprocess
import sys
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from bfv_client_matrix import REPO_ROOT, make_data, time_call
sys.path.insert(0, str(REPO_ROOT))
from xtrace_sdk.x_vec.crypto.bfv_assurance import bfv_review_policy
from xtrace_sdk.x_vec.crypto.bfv_attested_client import BFVAttestedClient, BFVAttestedServer
from xtrace_sdk.x_vec.crypto.bfv_client import BFVClient
from xtrace_sdk.x_vec.crypto.bfv_verified_client import BFVVerifiedServer
from xtrace_sdk.x_vec.crypto.bfv_nitro import NitroAttestationPolicy


def main():
    """Record explicit evidence provenance, raw samples, sizes and exact equality."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("local", "aws"), required=True)
    parser.add_argument("--pins", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--num-vectors", type=int, default=1024)
    parser.add_argument("--repeats", type=int, default=4)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    policy = bfv_review_policy()
    if not 1 <= args.num_vectors <= policy.max_vectors or not 2 <= args.repeats <= 128:
        parser.error("Use a bounded vector count and 2..128 repeats")
    if args.mode == "aws" and args.pins is None:
        parser.error("AWS mode requires owner-trusted --pins")
    with ExitStack() as stack:
        if args.mode == "local":
            # This benchmark-only trust substitution is intentionally absent
            # from the SDK's public API and the measured service image.
            from tests.x_vec.nitro_fixtures import PCRS, SyntheticNitro
            from xtrace_sdk.x_vec.crypto import bfv_nitro
            issuer = SyntheticNitro()
            stack.enter_context(patch.object(bfv_nitro, "_AWS_ROOT_SHA256", issuer.root_digest))
            pins = NitroAttestationPolicy(PCRS)
            print("LOCAL SYNTHETIC EVIDENCE: protocol measurements, no TEE hardware", file=sys.stderr, flush=True)
        else:
            from experiments.bfv_nitro.client import load_measurements
            pins = load_measurements(args.pins)
        vectors, query, expected = make_data(args.num_vectors, 512, 1337)
        setup_times = {}
        setup_times["key_generation_s"], raw = time_call(lambda: BFVClient(**policy.config()))
        auth = secrets.token_bytes(32)
        client = BFVAttestedClient(raw, auth, pins, index_epoch=1, policy=policy)
        setup_times["index_encrypt_export_s"], setup = time_call(lambda: client.prepare_index(vectors))
        setup_times["registration_encode_s"], registration = time_call(lambda: client.registration_packet(setup))
        setup_times["baseline_import_s"], baseline = time_call(lambda: BFVVerifiedServer(setup, auth, policy=policy))
        if args.mode == "local":
            setup_times["protocol_import_s"], endpoint = time_call(lambda: BFVAttestedServer.from_registration(registration, issuer, policy=policy))
        else:
            from experiments.bfv_nitro.transport import NitroRemote
            endpoint = NitroRemote(args.host, args.port, policy=policy)
            setup_times["remote_registration_s"], _ = time_call(lambda: endpoint.register(registration))
        enrollment = []
        for _ in range(args.repeats):
            hello = client.begin_attestation()
            issue_s, (document, proof) = time_call(lambda: endpoint.attest(hello))
            verify_s, _ = time_call(lambda: client.accept_attestation(document, proof))
            enrollment.append({"issue_or_rpc_s": issue_s, "client_verify_s": verify_s, "document_bytes": len(document), "possession_bytes": len(proof), "challenge_bytes": len(hello)})
        runs = []
        for repeat in range(args.repeats):
            encrypt_s, request = time_call(lambda: client.begin_query(query))
            baseline_call = lambda: baseline.search(request[38:-64])
            protocol_call = lambda: endpoint.search(request)
            # Alternate order to reduce a systematic warm-cache advantage.
            if repeat % 2:
                protocol_s, (response, receipt) = time_call(protocol_call)
                baseline_s, reference = time_call(baseline_call)
            else:
                baseline_s, reference = time_call(baseline_call)
                protocol_s, (response, receipt) = time_call(protocol_call)
            if response != reference:
                raise RuntimeError("Nitro-protocol output differs from exact BFV baseline")
            finish_s, distances = time_call(lambda: client.finish_query(response, receipt))
            if distances != expected:
                raise RuntimeError("Incorrect Hamming distances")
            runs.append({"repeat": repeat, "query_encrypt_sign_s": encrypt_s, "baseline_local_search_s": baseline_s, "protocol_search_or_rpc_s": protocol_s, "client_finish_s": finish_s})
            print(f"trial {repeat}: baseline {baseline_s:.6f}s, protocol/RPC {protocol_s:.6f}s, client {finish_s:.6f}s", file=sys.stderr, flush=True)
        summaries = {
            key: {"first_s": runs[0][key], "warm_median_s": statistics.median(r[key] for r in runs[1:]), "warm_samples_s": [r[key] for r in runs[1:]]}
            for key in runs[0] if key != "repeat"
        }
        paths = [Path(__file__), *REPO_ROOT.glob("src/xtrace_sdk/x_vec/crypto/bfv*.py"), *REPO_ROOT.glob("src/xtrace_sdk/x_vec/crypto/bfv_cpu_ext/*.so"), *REPO_ROOT.glob("experiments/bfv_nitro/*.py")]
        output = {
            "mode": args.mode,
            "hardware_attestation": args.mode == "aws",
            "measurement_notes": "All variants evaluate identical ciphertexts; exactly one evaluation produces a protocol response. Local mode substitutes a test CA and includes real certificate, owner-signature and receipt checks, but no NSM, vsock, hardware isolation or EC2. AWS protocol timers include network/relay; the reference runs locally and ratios are meaningful only on matched hardware. One cold and remaining warm trials; no tail-latency claim. No production-security certification.",
            "environment": {"utc": datetime.now(UTC).isoformat(), "python": platform.python_version(), "platform": platform.platform(), "cpu": next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown'), "versions": {name: importlib.metadata.version(name) for name in ("gmpy2", "pycryptodome", "cbor2", "pyOpenSSL", "cryptography")}, "revision": subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, check=True, text=True, capture_output=True).stdout.strip()},
            "config": policy.config(), "vectors": len(vectors), "setup_timings": setup_times,
            "enrollment": enrollment, "runs": runs, "summary": summaries,
            "sizes": {"setup_bytes": len(setup), "registration_bytes": len(registration), "query_bytes": len(request), "response_bytes": len(response), "receipt_bytes": len(receipt), "query_response_receipt_bytes": len(request) + len(response) + len(receipt)},
            "whole_process_peak_rss_kib_linux": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "identical_ciphertexts": True, "all_distances_correct": True,
            "source_sha256": {str(path.resolve().relative_to(REPO_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(set(paths))},
        }
        text = json.dumps(output, indent=2) + "\n"
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(text)
        print(text, end="")


if __name__ == "__main__":
    main()
