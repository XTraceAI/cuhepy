"""E112 bounded protocol/cost discriminator; no enclave or signing service."""

# ruff: noqa: E402 -- direct script with repo-local diagnostic imports.
import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from benchmarks.native_boundary_lab import load_fixture
from experiments.bfv_search_lab import native_boundary_oracle as oracle
from experiments.bfv_search_lab import native_opening_constraints as opening


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(fixture_path):
    assert sha(fixture_path) == "0a49605dd8d26d0e73e38c681013e83a64801df4c95b62fab80bf7b81beeb4a1"
    fixture, ctx, *_ = load_fixture(fixture_path)
    compiled = opening.compile_constraints(ctx, mode="folded", tight_quotients=False)
    query = bytes.fromhex(fixture["queries"][0]["packet_hex"])
    replay = oracle.replay(ctx, query)
    public = opening.public_inputs(compiled, ctx, query, replay.packet)
    witness = opening.make_witness(compiled, ctx, query, replay.packet, transcript=replay)
    assert opening.satisfy(compiled, public, witness)
    # Known omission control: an unrelated affine-only tape is not authenticated
    # by a digest/receipt for the honest canonical tape. No signature is forged.
    forged = list(witness)
    source = compiled.ranges[0]
    delta = 7-forged[source.bits[0]]
    forged[source.bits[0]] = 7
    forged[source.slack[0]] = (forged[source.slack[0]]-delta) % compiled.field
    for quotient in compiled.quotients:
        difference = (opening._evaluate(quotient.numerator, public, forged)
                      -opening._evaluate(quotient.numerator, public, witness)) % compiled.field
        adjustment = difference*pow(quotient.modulus, -1, compiled.field) % compiled.field
        bit = quotient.value.bits[0]
        forged[bit] = (forged[bit]+adjustment) % compiled.field
        if quotient.value.slack:
            at = quotient.value.slack[0]
            forged[at] = (forged[at]-adjustment) % compiled.field
    forged = tuple(forged)
    assert opening.satisfy(compiled, public, forged, omit_boolean=True)
    assert not opening.satisfy(compiled, public, forged)
    honest_digest = sha_bytes(opening.serialize_witness(compiled, witness))
    other_digest = sha_bytes(opening.serialize_witness(compiled, forged))
    assert honest_digest != other_digest
    counts = compiled.counts()
    return {"kind": "E112_protocol_cost_and_unbound_tape_omission_control_only",
            "fixture_sha256": sha(fixture_path), "complete_constraints": counts["total_R1CS_constraints"],
            "affine_only_constraints": counts["linear_constraints"],
            "boolean_constraints_shifted_to_trusted_checker": compiled.variable_count,
            "literal_field_witness_bytes": len(opening.serialize_witness(compiled, witness)),
            "minimum_canonical_bit_tape_bytes_model": (compiled.variable_count+7)//8,
            "padded_backend_bit_tape_bytes_model": 32768//8,
            "query_bytes": len(query), "full_response_bytes": len(replay.packet),
            "public_field_inputs_bytes": compiled.public_count*32,
            "unbound_tape_control": {"affine_rows_accept_unrelated_nonboolean_tape": True,
                                    "complete_relation_rejects": True,
                                    "honest_tape_digest": honest_digest, "unrelated_tape_digest": other_digest,
                                    "actual_cryptographic_affine_proof_or_signature_executed": False,
                                    "logical_obligation_not_backend_exploit": True},
            "actual_oracle_commitment_equality_required": True,
            "pinned_Spartan_external_trusted_witness_commitment_API_available": False,
            "generic_gets_identical_partition_packing_and_preprocessing": True,
            "unknown_paid_costs": ["all-coordinate PCS commitment reconstruction/MSMs/blinds",
                                   "affine-only proof and commitment-equality adapter",
                                   "trusted parse/range/slack/common-lift and row linkage",
                                   "full context enrollment/hash invalidation and residency",
                                   "actual attestation/receipt transport and signature checks",
                                   "durable one-use attempts/epochs/retries/rollback storage",
                                   "full replay/Slalom-style/approved plaintext-TEE comparison",
                                   "large graph and peak memory", "end-to-end monitored timing"],
            "actual_TEE_or_GPU_attestation_executed": False, "timing_benchmark": False,
            "security_or_performance_advantage_established": False,
            "return_to_plan": "known_partition_not_original;_stop_service_until_actual_commitment_binding_and_paid_control"}


def sha_bytes(body):
    return hashlib.sha256(body).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--freeze", required=True, type=Path)
    args = parser.parse_args()
    if sys.flags.optimize:
        raise RuntimeError("Correctness diagnostic requires Python assertions enabled")
    source = sha(Path(__file__))
    prereg = REPO/"docs/research/tee-oracle-partition-preregistration-20261003.md"
    with args.freeze.open("x") as out:
        json.dump({"utc_before_control": datetime.now(UTC).isoformat(), "source_sha256": source,
                   "preregistration_sha256": sha(prereg), "fixture_sha256": sha(args.fixture)}, out, indent=2)
    result = run(args.fixture)
    assert sha(Path(__file__)) == source
    result["source_sha256"] = source
    with args.output.open("x") as out:
        json.dump(result, out, indent=2)
        out.write("\n")
    print(json.dumps({"output": str(args.output), "unknown_costs": len(result["unknown_paid_costs"])}))


if __name__ == "__main__":
    main()
