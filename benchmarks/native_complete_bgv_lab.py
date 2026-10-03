"""Frozen complete-query native correctness cohort, without timing claims.

Run from the repository with --backend pointing to the isolated `make complete`
extension and --output to a new JSON path. The public fixture hash is pinned;
the independent schoolbook answer is used only outside admission.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from experiments.bfv_search_lab import native_boundary_oracle as oracle
from experiments.bfv_search_lab import native_complete_checked_bgv as native

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = (
    ROOT.parent / "research-data/system-selection-20261003/gpu-admission-design/public-inputs.json"
)
PUBLIC_SHA = "ef2f41bf503da27fc7661732b9a692be38cf09f0f6dc83974fcf5e59c1e6c939"


def tuples(value):
    return tuple(tuples(v) for v in value) if type(value) is list else value


def run(backend):
    raw = PUBLIC.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PUBLIC_SHA:
        raise ValueError("Frozen public fixture hash mismatch")
    data = json.loads(raw)
    context = oracle.Context(**{k: tuples(v) for k, v in data["context"].items()})
    enrollment = native.Enrollment(
        native.NativeContext.from_reference(context),
        backend=native.load_backend(backend),
        block_size=2,
    )
    records = []
    for i, query in enumerate(data["queries"]):
        packet = bytes.fromhex(query["packet_hex"])
        expected = oracle.replay(context, packet).packet
        replayed = enrollment.replay(packet)
        request = enrollment.begin(
            packet, hashlib.sha256(b"q56-frozen-request" + bytes([i])).digest()
        )
        blocks = request.produce_blocks()
        releases = []
        admitted = request.admit_once(
            blocks, claimed_response=expected, release_sentinel=releases.append
        )
        if not expected == replayed == admitted.packet or releases != [expected]:
            raise AssertionError("Complete original-query packet mismatch")
        records.append(
            {
                "query": i,
                "query_sha256": hashlib.sha256(packet).hexdigest(),
                "response_sha256": admitted.response_digest.hex(),
                "response_bytes": len(expected),
                "all_terminal_bytes_equal": True,
                "block_coverage": admitted.block_coverage,
                "product_body_bytes": admitted.product_body_bytes,
            }
        )
    return {
        "kind": "q56_frozen_complete_native_correctness",
        "queries": records,
        "fixture_sha256": PUBLIC_SHA,
        "backend_sha256": hashlib.sha256(Path(backend).read_bytes()).hexdigest(),
        "resource_ledger": enrollment.resource_ledger(),
        "new_private_operations": 0,
        "actual_attestation": False,
        "performance_measurement": False,
        "originality_claim": False,
        "security_parameter_approval": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # Claim the fresh output path before work; retain the marker on failure.
    with args.output.open("x") as output:
        output.write(json.dumps({"kind": "started_q56_frozen_cohort"}) + "\n")
    receipt = run(args.backend)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        json.dumps(
            {
                "complete_queries": len(receipt["queries"]),
                "all_complete_packets_equal": True,
                "output": str(args.output),
            }
        )
    )
