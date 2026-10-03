"""E109 capped actual proof control. No timing benchmark or production service."""

# ruff: noqa: E402 -- support direct script execution with repo-local imports.

import argparse
import hashlib
import json
import resource
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from benchmarks.native_boundary_lab import load_fixture
from experiments.bfv_search_lab import native_boundary_oracle as oracle
from experiments.bfv_search_lab import native_opening_constraints as constraints
from experiments.bfv_search_lab import proof_backend_adapter as adapter

FIXTURE_SHA = "0a49605dd8d26d0e73e38c681013e83a64801df4c95b62fab80bf7b81beeb4a1"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dump(path, value):
    if path.exists():
        assert json.loads(path.read_text()) == value
        return
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def fields(path, values):
    body = b"".join(x.to_bytes(32, "little") for x in values)
    if path.exists():
        assert path.read_bytes() == body
        return
    with path.open("xb") as stream:
        stream.write(body)


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (8 << 30, 8 << 30))


def run(args):
    if sys.flags.optimize:
        raise RuntimeError("Correctness diagnostic requires Python assertions enabled")
    if sha(args.fixture) != FIXTURE_SHA:
        raise ValueError("Changed frozen E106 fixture")
    if args.finalize_existing:
        assert args.capture.is_dir() and not args.output.exists()
    else:
        args.capture.mkdir(exist_ok=False)
    old = json.loads((REPO/"benchmarks/results/publication-native-opening-20261003.json").read_text())
    for path, digest in old["metadata"]["source_sha256"].items():
        if path.endswith(".py") and sha(REPO/path) != digest:
            raise ValueError("Changed E108 relation/exporter source: "+path)
    instance = old["evaluation"]["costs"]["folded-width"]["instance_stream"]
    instance_file = Path(instance["path"])
    assert sha(instance_file) == instance["sha256"]
    fixture, ctx, *_ = load_fixture(args.fixture)
    compiled = constraints.compile_constraints(ctx, mode="folded", tight_quotients=False)
    source_paths = ["experiments/bfv_search_lab/proof_backend_adapter.py",
                    "experiments/bfv_search_lab/test_proof_backend_adapter.py",
                    "experiments/bfv_search_lab/proof_backend_control/src/main.rs",
                    "experiments/bfv_search_lab/proof_backend_control/Cargo.toml",
                    "experiments/bfv_search_lab/proof_backend_control/Cargo.lock",
                    "benchmarks/proof_backend_lab.py"]
    # Pin the actual loaded repository Python/native preprocessing closure too.
    for module in tuple(sys.modules.values()):
        name = getattr(module, "__file__", None)
        if name:
            path = Path(name).resolve()
            if path.is_relative_to(REPO) and path.suffix in (".py", ".so") and ".venv" not in path.parts:
                source_paths.append(str(path.relative_to(REPO)))
    source_paths = sorted(set(source_paths))
    frozen = {"utc_before_cohort": datetime.now(UTC).isoformat(),
              "evidence_parent": "95f857b9c4a788eeafd28e1e5816a3ad04b45d56",
              "fixture_sha256": FIXTURE_SHA, "instance": instance,
              "binary_sha256": sha(args.binary),
              "source_sha256": {p: sha(REPO/p) for p in source_paths},
              "timing_benchmark": False}
    if args.finalize_existing:
        original = json.loads((args.capture/"source-freeze.json").read_text())
        assert original["binary_sha256"] == frozen["binary_sha256"]
        for path, digest in original["source_sha256"].items():
            assert sha(args.capture/"source-at-cohort"/path) == digest
        frozen["original_proof_cohort_source_freeze"] = original
        frozen["finalizes_existing_proofs_no_new_prove_attempt"] = True
        dump(args.capture/f"finalization-source-freeze-{args.finalization_id}.json", frozen)
    else:
        dump(args.capture/"source-freeze.json", frozen)
    statements, cards, negatives, retained = [], [], [], []
    golden = old["evaluation"]["query_cards"]
    for i, item in enumerate(fixture["queries"]):
        query = bytes.fromhex(item["packet_hex"])
        replay = oracle.replay(ctx, query)  # Public honest prover only.
        assert hashlib.sha256(replay.packet).hexdigest() == golden[i]["response_sha256"]
        pins = adapter.Pins(ctx.digest(), instance["sha256"], query)
        public, domain = adapter.statement(compiled, ctx, pins, replay.packet)
        witness = constraints.make_witness(compiled, ctx, query, replay.packet, transcript=replay)
        assert constraints.satisfy(compiled, public, witness)
        public_file, witness_file = args.capture/f"public-{i}.bin", args.capture/f"witness-{i}.bin"
        fields(public_file, public)
        fields(witness_file, witness)
        statements.append({"id": i, "public_file": str(public_file),
                           "witness_file": str(witness_file), "domain_hex": domain})
        cards.append({"query": item["bits"], "response_packet_bytes": len(replay.packet),
                      "query_packet_bytes": len(query), "domain": domain,
                      "public_field_bytes": public_file.stat().st_size,
                      "literal_witness_bytes_not_proof": witness_file.stat().st_size,
                      "original_query_sha256": sha_bytes(query),
                      "response_sha256": sha_bytes(replay.packet)})
        retained.append((pins, replay.packet))

    pins, packet = retained[0]
    compact = oracle.parse_response(ctx, packet)
    for at in range(32):
        output = [list(map(list, pair)) for pair in compact]
        output[at//16][at//8 % 2][at % 8] = (output[at//16][at//8 % 2][at % 8]+1) % ctx.p
        altered = oracle.serialize(ctx, tuple(tuple(tuple(p) for p in pair) for pair in output))
        public, domain = adapter.statement(compiled, ctx, pins, altered)
        path = args.capture/f"negative-output-{at}.bin"
        fields(path, public)
        negatives.append({"label": f"full_response_coefficient_{at}", "proof_id": 0,
                          "public_file": str(path), "domain_hex": domain})
    # Domain-only tests explicitly isolate the metadata/full-byte binding.
    for label in ("epoch", "context", "instance", "layout", "key", "original_bytes", "response_bytes"):
        domain = sha_bytes((statements[0]["domain_hex"]+label).encode())
        negatives.append({"label": "domain_"+label, "proof_id": 0,
                          "public_file": statements[0]["public_file"], "domain_hex": domain})
    for i in range(1, 8):
        negatives.append({"label": f"proof_replay_other_query_{i}", "proof_id": 0,
                          "public_file": statements[i]["public_file"],
                          "domain_hex": statements[i]["domain_hex"]})
    public, domain = adapter.statement(compiled, ctx, pins, packet)
    changed = list(public)
    changed[0] = (changed[0]+1) % compiled.field
    path = args.capture/"negative-public.bin"
    fields(path, changed)
    negatives.append({"label": "backend_public_input_substitution", "proof_id": 0,
                      "public_file": str(path), "domain_hex": domain})
    manifest = {"instance_file": str(instance_file), "variables": compiled.variable_count,
                "constraints": compiled.variable_count+len(compiled.linear_rows),
                "inputs": compiled.public_count, "max_nonzeros": compiled.counts()["A_nonzeros"],
                "output_directory": str(args.capture/"backend"),
                "statements": statements, "negatives": negatives}
    manifest_path = args.capture/"owner-manifest.json"
    dump(manifest_path, manifest)
    if args.finalize_existing:
        status = json.loads((args.capture/"process-receipt.json").read_text())
    else:
        status = execute_cohort(args, manifest_path)
        dump(args.capture/"process-receipt.json", status)
    if status["returncode"] != 0:
        raise RuntimeError("Bounded proof control stopped; retained process receipt and logs")
    backend = args.capture/"backend"
    result = json.loads((backend/"backend-result.json").read_text())
    backend_pins = {"binary": {"path": str(args.binary), "sha256": sha(args.binary)},
                    **{name: {"path": str(backend/name), "sha256": sha(backend/name)}
                       for name in ("public-generators.bin", "owner-instance-commitment.bin")}}
    verifier_calls = args.capture/f"verifier-calls-{args.finalization_id}"
    verifier_calls.mkdir(exist_ok=False)
    call_count = 0

    def verify(proof, public, domain):
        nonlocal call_count
        for value in backend_pins.values():
            if sha(Path(value["path"])) != value["sha256"]:
                raise ValueError("Changed locally pinned proof backend object")
        # Owner-only temp paths; rederive field inputs/domain for EVERY call.
        pfile = verifier_calls/f"{call_count}-public.bin"
        wfile = verifier_calls/f"{call_count}-proof.bin"
        pfile.write_bytes(b"".join(x.to_bytes(32, "little") for x in public))
        wfile.write_bytes(proof)
        call = subprocess.run([str(args.binary), "verify", str(backend/"public-generators.bin"),
                               str(backend/"owner-instance-commitment.bin"), str(pfile), domain,
                               str(wfile), "owner-local-v1"], capture_output=True, timeout=60,
                              preexec_fn=limits, check=False)
        (verifier_calls/f"{call_count}.stdout").write_bytes(call.stdout)
        (verifier_calls/f"{call_count}.stderr").write_bytes(call.stderr)
        dump(verifier_calls/f"{call_count}.json", {"returncode": call.returncode,
             "domain": domain, "public_sha256": sha(pfile), "proof_sha256": sha(wfile),
             "backend_pins": backend_pins})
        call_count += 1
        if call.returncode:
            raise RuntimeError("Local verifier process failed; no private callback")
        return json.loads(call.stdout)["accepted"]

    callback_calls = []
    def decode(body):
        callback_calls.append(sha_bytes(body))
        return oracle.decrypt_and_rank(ctx, oracle.parse_response(ctx, body), tuple(fixture["secret"]))

    for i, (pins, body) in enumerate(retained):
        proof = (backend/f"proof-{i}.bin").read_bytes()
        _, scores, top = adapter.release(compiled, ctx, pins, body, proof, verify, decode)
        expected = tuple(sum(a != b for a, b in zip(fixture["queries"][i]["bits"], row, strict=True)) for row in fixture["rows"])
        assert scores == expected and list(map(list, top)) == golden[i]["modes"]["folded-width"]["stable_top3"]
        cards[i].update({"exact_distances": list(scores), "stable_top3": list(map(list, top)),
                         "separate_local_verifier_release_passed": True,
                         "proof_sha256": sha(backend/f"proof-{i}.bin")})
    before = len(callback_calls)
    rejected = []
    pins, body = retained[0]
    proof = (backend/"proof-0.bin").read_bytes()
    for label, changed_ctx, changed_pins, response, bad_proof in [
        ("wrong_epoch", replace(ctx, epoch="untrusted-epoch"), pins, body, proof),
        ("wrong_key", replace(ctx, key_id="0"*64), pins, body, proof),
        ("wrong_original_query", ctx, retained[1][0], body, proof),
        ("different_full_response", ctx, pins, retained[1][1], proof),
        ("trailing_response_byte", ctx, pins, body+b"\0", proof),
        ("truncated_proof", ctx, pins, body, proof[:-1]),
    ]:
        try:
            adapter.release(compiled, changed_ctx, changed_pins, response, bad_proof, verify, decode)
        except ValueError:
            rejected.append({"label": label, "private_callback_calls": len(callback_calls)-before})
        else:
            raise AssertionError("Wrong local release accepted")
        assert len(callback_calls) == before
    assert len(callback_calls) == 8
    for value in backend_pins.values():
        assert sha(Path(value["path"])) == value["sha256"]
    frozen["finalization_source_unchanged"] = frozen["source_sha256"] == {p: sha(REPO/p) for p in source_paths}
    assert frozen["finalization_source_unchanged"]
    output = {"metadata": frozen, "backend": result, "query_cards": cards,
              "local_pre_callback_rejections": rejected,
              "honest_private_callback_calls": len(callback_calls),
              "separate_verifier_call_count": call_count, "backend_pins": backend_pins,
              "costs": compiled.counts(), "cryptographic_proof_backend_executed": True,
              "native_execution": "unchanged_frozen_E106_response_hash_control_not_new_native_run",
              "scope": "N8_frozen_toy_known_scalar_proof_control_not_original_protocol_or_production_assurance",
              "unknowns": ["BitZ/ring/GlueLUT adapters", "serial idle timing", "large native graph",
                           "adaptive/lifetime reduction", "private sidechannels", "durable lifecycle",
                           "actual TEE/GPU attestation", "low-state owner/client preprocessing"]}
    dump(args.output, output)
    print(json.dumps({"output": str(args.output), "proof_bytes": [x["proof_bytes"] for x in result["cards"]],
                      "backend_negative_count": len(result["negatives"]), "release_negative_count": len(rejected)}))


def execute_cohort(args, manifest_path):
    with (args.capture/"backend.stdout").open("xb") as out, (args.capture/"backend.stderr").open("xb") as err:
        try:
            process = subprocess.run([str(args.binary), str(manifest_path)], stdout=out, stderr=err,
                                     timeout=1200, preexec_fn=limits, check=False)
            status = {"returncode": process.returncode, "resource_cap_reached": False}
        except subprocess.TimeoutExpired:
            status = {"returncode": None, "resource_cap_reached": True}
    return status


def sha_bytes(body):
    return hashlib.sha256(body).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--finalize-existing", action="store_true",
                        help="Recheck retained proofs after finalization failure; never prove again")
    parser.add_argument("--finalization-id", default="02", choices=("02", "03"))
    run(parser.parse_args())


if __name__ == "__main__":
    main()
