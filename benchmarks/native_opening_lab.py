"""E108 complete native scalar constraints and deterministic paid counts.

Frozen E106 public inputs/native-agreed bytes are reused. No timing panel or
external cryptographic proof backend. Only a checked toy diagnostic uses the
already disclosed fixture secret after the complete arithmetic gate.
"""
# Standalone benchmark bootstrap must precede repository imports.
# ruff: noqa: E402

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime
import hashlib
import json
import msgpack
from pathlib import Path
import struct
import sys

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from benchmarks.native_boundary_lab import load_fixture
from experiments.bfv_search_lab import native_boundary_oracle as oracle
from experiments.bfv_search_lab import native_opening_constraints as constraints

FIXTURE_SHA = "0a49605dd8d26d0e73e38c681013e83a64801df4c95b62fab80bf7b81beeb4a1"
PARENT = "be8e275d5b06e14c78652ce6e19856836c618a2f"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def export_instance(compiled, path):
    """Declared transparent format: each entry is matrix:u8,row:u32,col:u32,F:32.

    This is a reference R1CS matrix stream, NOT a commitment/proof packet.
    Its entire preprocessing/materialization cost is in the ledger.
    """
    counts = Counter()
    with path.open("xb") as out:
        for matrix, row, column, coefficient in constraints.r1cs_entries(compiled):
            out.write(struct.pack("<BII", "ABC".index(matrix), row, column))
            out.write(coefficient.to_bytes(32, "little"))
            counts[matrix] += 1
    assert dict(counts) == {"A": compiled.counts()["A_nonzeros"], "B": compiled.counts()["B_nonzeros"]}
    return {"path": str(path), "sha256": sha(path), "bytes": path.stat().st_size,
            "entry_bytes": 41, "matrix_nonzeros": dict(counts),
            "wire_semantics": "full_static_transparent_instance_not_cryptographic_proof"}


def check_export(compiled, path, public, witness):
    """Independent streamed sparse Az*Bz=Cz evaluator; no HE graph calls."""
    z = witness+(1,)+public
    rows = compiled.variable_count+len(compiled.linear_rows)
    accumulators = [[0]*rows for _ in range(3)]
    with path.open("rb") as inp:
        while entry := inp.read(41):
            assert len(entry) == 41
            matrix, row, column = struct.unpack("<BII", entry[:9])
            assert matrix < 3 and row < rows and column < len(z)
            coefficient = int.from_bytes(entry[9:], "little")
            assert coefficient < compiled.field
            accumulators[matrix][row] += coefficient*z[column]
    a, b, c = accumulators
    return all((x*y-result) % compiled.field == 0 for x, y, result in zip(a, b, c, strict=True))


def release(compiled, ctx, pinned_query, packet, witness, envelope, decode):
    """Local diagnostic only: independently pinned metadata then full field gate.

    The transparent tape is linear checked, not a succinct authenticated proof.
    The trust in local context/instance/input pins is explicit. No attestation,
    durable retry state or private-side-channel assurance is supplied.
    """
    expected = (ctx.digest(), oracle.binding(ctx, pinned_query))
    if (type(envelope) is not tuple or len(envelope) != 2
            or any(type(value) is not str for value in envelope) or envelope != expected):
        raise ValueError("Wrong independently pinned owner statement")
    if not constraints.check_statement(compiled, ctx, pinned_query, packet, witness):
        raise ValueError("Full scalar arithmetic relation rejected")
    return decode(packet)


def mutations(compiled, public, witness):
    """One range-preserving-container bit flip in EVERY logical coordinate."""
    tally = Counter()
    for value in compiled.ranges:
        altered = list(witness)
        altered[value.bits[0]] ^= 1
        assert not constraints.satisfy(compiled, public, tuple(altered)), value.label
        tally[value.label.split(":")[0]] += 1
    return dict(tally)


def boundary_mutations(compiled, ctx, query, other_query, replay, witness):
    """Whole packet and independently pinned metadata gate, no HE secret used."""
    envelope = (ctx.digest(), oracle.binding(ctx, query))
    cases = [("original_query_swap", ctx, other_query, replay.packet)]
    for label, changed in (("epoch", replace(ctx, epoch="wrong-epoch")),
                           ("IDs", replace(ctx, ids=ctx.ids[::-1])),
                           ("index_order", replace(ctx, index=ctx.index[::-1])),
                           ("key", replace(ctx, key_id="0"*64)),
                           ("layout", replace(ctx, dimension=2))):
        cases.append((label, changed, query, replay.packet))
    for label in ("missing_group", "duplicate_group", "reordered_groups", "wrong_modulus", "float_header", "noncanonical_coefficient", "nonminimal_msgpack", "extra_body_byte"):
        fields = msgpack.unpackb(replay.packet, raw=False)
        if label == "missing_group":
            fields[1].pop()
        elif label == "duplicate_group":
            fields[1].append(fields[1][0])
        elif label == "reordered_groups":
            fields[1].reverse()
        elif label == "wrong_modulus":
            fields[0][3] = (ctx.p-2).to_bytes(4, "little")
        elif label == "float_header":
            fields[0][1] = float(ctx.n)
        elif label == "noncanonical_coefficient":
            fields[1][0][0] = oracle.pack_bits((ctx.p,)+(0,)*(ctx.n-1), ctx.p.bit_length())
        elif label == "extra_body_byte":
            fields[1][0][0] += b"\x00"
        body = msgpack.packb(fields, use_bin_type=True)
        if label == "nonminimal_msgpack":
            assert body[0] == 0x92
            body = b"\xdc\x00\x02"+body[1:]
        cases.append((label, ctx, query, body))
    compact = oracle.parse_response(ctx, replay.packet)
    for coordinate in range(32):
        group, local = divmod(coordinate, 2*ctx.n)
        component, index = divmod(local, ctx.n)
        changed = [[list(poly) for poly in pair] for pair in compact]
        changed[group][component][index] = (changed[group][component][index]+1) % ctx.p
        body = oracle.serialize(ctx, tuple(tuple(tuple(poly) for poly in pair) for pair in changed))
        cases.append((f"terminal_output:{coordinate}", ctx, query, body))
    for label, owner, original, body in cases:
        calls = []
        try:
            release(compiled, owner, original, body, witness, envelope, calls.append)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Complete wire/metadata mutation accepted: {label}")
        assert not calls
    return {"rejected_cases": len(cases), "case_labels": [x[0] for x in cases], "private_callback_calls": 0}


def run(fixture_path, capture):
    if sha(fixture_path) != FIXTURE_SHA:
        raise ValueError("Changed E106 frozen toy fixture")
    fixture, ctx, *_ = load_fixture(fixture_path)
    old = json.loads((REPO/"benchmarks/results/publication-native-boundary-20261003.json").read_text())
    golden = old["query_cards"]
    compiled = {"baseline-tight": constraints.compile_constraints(ctx, mode="baseline"),
                "folded-tight": constraints.compile_constraints(ctx, mode="folded"),
                "folded-width": constraints.compile_constraints(ctx, mode="folded", tight_quotients=False)}
    instance = {mode: export_instance(value, capture/f"{mode}-instance.r1cs-stream") for mode, value in compiled.items()}
    cards, negatives = [], []
    for query_index, item in enumerate(fixture["queries"]):
        packet = bytes.fromhex(item["packet_hex"])
        replay = oracle.replay(ctx, packet)  # Independent honest prover/control only.
        card = {"query": item["bits"], "original_query_sha256": hashlib.sha256(packet).hexdigest(),
                "response_sha256": hashlib.sha256(replay.packet).hexdigest(), "response_packet_bytes": len(replay.packet),
                "native_agreement_scope": "unchanged_E106_fixture_and_exact_pinned_native_response_hash_not_new_native_execution",
                "modes": {}}
        assert card["response_sha256"] == golden[query_index]["response_sha256"]
        expected_scores = tuple(sum(a != b for a, b in zip(item["bits"], row, strict=True)) for row in fixture["rows"])
        for mode, circuit in compiled.items():
            public = constraints.public_inputs(circuit, ctx, packet, replay.packet)
            witness = constraints.make_witness(circuit, ctx, packet, replay.packet, transcript=replay)
            assert constraints.satisfy(circuit, public, witness)
            assert check_export(circuit, Path(instance[mode]["path"]), public, witness)
            recovered = constraints.recover_preterminal(circuit, ctx, witness)
            assert recovered == tuple(x for pair in replay.preterminal for poly in pair for x in poly)
            envelope = (ctx.digest(), oracle.binding(ctx, packet))
            compact, phases, scores, top = release(circuit, ctx, packet, replay.packet, witness, envelope,
                lambda body: (oracle.parse_response(ctx, body), *oracle.decrypt_and_rank(ctx, oracle.parse_response(ctx, body), tuple(fixture["secret"]))))
            assert scores == expected_scores and list(scores) == golden[query_index]["exact_distances"]
            assert list(map(list, top)) == golden[query_index]["stable_top3"]
            packed = oracle.pack_bits(witness, 1)
            witness_path = capture/f"{mode}-query{query_index}-transparent-bits.bin"
            witness_path.write_bytes(packed)
            assert oracle.unpack_bits(packed, len(witness), 1, 2) == witness
            card["modes"][mode] = {"sparse_R1CS_and_direct_field_checks_agree": True,
                                   "all_recovered_preterminal_coefficients": len(recovered),
                                   "all_terminal_coefficients": sum(len(poly) for pair in compact for poly in pair),
                                   "exact_scores": scores, "stable_top3": top,
                                   "all_diagnostic_plaintext_coefficients_mod17": tuple(tuple(x % ctx.t for x in phase) for phase in phases),
                                   "transparent_bit_tape_bytes": len(packed), "scalar_assignment_bytes_32_per_variable": 32*len(witness),
                                   "tape_sha256": sha(witness_path), "actual_proof_bytes": None}
            # Failed relation and metadata cannot reach even a diagnostic callback.
            calls = []
            bad = list(witness)
            bad[circuit.ranges[0].bits[0]] ^= 1
            for what, tape, pin in (("bad_source", tuple(bad), envelope), ("context_binding", witness, ("0"*64, envelope[1])),
                                   ("query_binding", witness, (envelope[0], "0"*64))):
                try:
                    release(circuit, ctx, packet, replay.packet, tape, pin, calls.append)
                except ValueError:
                    pass
                else:
                    raise AssertionError("Rejected statement reached callback")
                negatives.append({"query": query_index, "mode": mode, "case": what, "callback_calls": len(calls)})
            assert not calls
            if query_index == 0:
                card["modes"][mode]["all_coordinate_mutation_rejections"] = mutations(circuit, public, witness)
                card["modes"][mode]["boundary_rejections"] = boundary_mutations(circuit, ctx, packet, bytes.fromhex(fixture["queries"][1]["packet_hex"]), replay, witness)
                fake, _ = oracle.false_digit_cut(ctx, replay.cuts[0], ctx.relin)
                try:
                    constraints.make_witness(circuit, ctx, packet, replay.packet,
                                             transcript=replace(replay, cuts=(fake,)+replay.cuts[1:]))
                except ValueError:
                    card["modes"][mode]["honest_output_false_canonical_kernel_unrepresentable"] = True
                else:
                    raise AssertionError("False canonical digits were representable")
        cards.append(card)
    costs = {}
    for mode, circuit in compiled.items():
        count = circuit.counts()
        count["quotient_width_histogram"] = dict(sorted(Counter(count.pop("quotient_widths")).items()))
        count["spartan_artifact_row_padding_power_of_two"] = 1 << (count["total_R1CS_constraints"]-1).bit_length()
        count["spartan_artifact_variable_padding_power_of_two"] = 1 << (max(count["witness_variables"], circuit.public_count+1)-1).bit_length()
        count["instance_stream"] = instance[mode]
        count["locally_paid_expanded_query_and_parsed_output_coefficients"] = 48
        count["locally_paid_RHS_rows"] = 256 if circuit.mode == "folded" else 0
        count["public_inputs_not_server_trusted"] = True
        count["current_host_pin_traverses_full_index_and_keys"] = True
        count["sublinear_or_low_state_verifier_implemented"] = False
        costs[mode] = count
    return {"query_cards": cards, "costs": costs, "pre_callback_rejections": negatives,
            "shared_generic_ratio": 1, "cryptographic_proof_backend_executed": False,
            "range_and_modular_row_proofs": "all_bits_boolean_plus_exact_source_and_remainder_Q_slack;_quotients_have_declared_tight_slack_or_unsigned_width_with_actual_nowrap_bound",
            "unknown_costs": ["PCS/generators/computationcommitment registration and memory", "prover/verification time and RSS", "proof/challenges/openings and network transport", "ROM/extractability/adaptive lifetime/attempt composition", "private release sidechannels", "real attestation and durable lifecycle", "large native graph adaptation", "current repeated full owner-context validation/hash traversal and index/key residency"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--capture-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.capture_dir.exists():
        raise ValueError("Never overwrite frozen result or capture")
    args.capture_dir.mkdir(parents=True)
    result = run(args.fixture, args.capture_dir)
    sources = ["experiments/bfv_search_lab/native_opening_constraints.py", "experiments/bfv_search_lab/test_native_opening_constraints.py",
               "benchmarks/native_opening_lab.py", "experiments/bfv_search_lab/native_boundary_oracle.py", "experiments/bfv_search_lab/native_boundary_controls.py",
               "experiments/bfv_search_lab/target_prime_lift.py", "docs/research/native-proof-interface-preregistration.md", "docs/research/native-proof-interface-control-amendment.md", "docs/research/native-proof-interface-quotient-amendment.md"]
    record = {"metadata": {"utc": datetime.now(UTC).isoformat(), "evidence_parent": PARENT,
                           "kind": "E108_frozen_native_toy_complete_transparent_scalar_R1CS_and_exact_counts_not_cryptographic_proof",
                           "fixture": str(args.fixture), "fixture_sha256": sha(args.fixture),
                           "source_sha256": {path: sha(REPO/path) for path in sources},
                           "native_golden_raw_sha256": sha(REPO/"benchmarks/results/publication-native-boundary-20261003.json"),
                           "no_new_native_or_GPU_or_binary_rebuild": True},
              "evaluation": result, "summary": {"queries": 8, "exact_record_distances": 72, "preterminal_coefficients_per_mode": 256,
                                                  "terminal_coefficients_per_mode": 256, "modes": 3, "original_main_mechanisms": 0,
                                                  "timing_panels": 0, "approved_parameters": 0, "external_proof_runs": 0}}
    args.output.write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps({"summary": record["summary"], "counts": {k: {x: v[x] for x in ("witness_variables", "total_R1CS_constraints", "A_nonzeros", "B_nonzeros", "public_inputs", "quotient_width_histogram")} for k, v in result["costs"].items()}}))


if __name__ == "__main__":
    main()
