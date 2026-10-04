#!/usr/bin/env python3
"""Q76.4a retained public replay correctness. No new HE work or timing."""

# ruff: noqa: E402 -- standalone research runner.
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import resource
import subprocess
import sys
import tarfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks import native_shared_query_lab as lab
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import lifecycle_shared_query as life
from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab import replay_shared_query as replay
from experiments.bfv_search_lab import test_authenticated_shared_query as fixtures


def retained_bytes(record):
    path = Path(record["file"])
    data = path.read_bytes()
    if len(data) != record["bytes"] or lab.sha(data) != record["sha256"]:
        raise ValueError("Pinned retained input changed")
    return data


def historical_enrollment(record, report):
    packet = retained_bytes(record["enrollment"])
    owner = bytes.fromhex(report["standard_owner_public_key"])
    payload = auth._verify(
        packet, Ed25519PublicKey.from_public_bytes(owner), auth.ENROLL_TAG, native.PACKET_CAP
    )
    fields = auth._unpack(payload, limit=native.PACKET_CAP, array_cap=1024)
    metadata = auth._metadata(auth._profile(fields[0]), fields[1], fields[2], fields[3])
    assert metadata.profile.n == 16384 and metadata.profile.dimension == 512
    assert metadata.primes == (1152921504606748673, 1152921504606683137)
    assert (
        metadata.profile.p == 33548413 and metadata.profile.t == 1031 and metadata.profile.eta == 21
    )
    assert len(metadata.ids) == record["records"] and metadata.groups == record["groups"]
    assert metadata.key_id == record["HE_key_id"] and fields[4] == record["epoch"]
    assert fields[5].hex() == report["authentication_policy_digest"]
    assert hashlib.sha256(auth.ENROLL_TAG + owner + payload).hexdigest() == record["snapshot_id"]
    return fields, metadata


def historical_query_and_frame(record, report, metadata):
    owner = Ed25519PublicKey.from_public_bytes(bytes.fromhex(report["standard_owner_public_key"]))
    packet = retained_bytes(record["original_request"])
    payload = auth._verify(
        packet, owner, auth.QUERY_TAG, metadata.profile.n * native.COMMON_WIDTH + 1024
    )
    fields = auth._unpack(
        payload, limit=metadata.profile.n * native.COMMON_WIDTH + 768, array_cap=5
    )
    assert fields[0].hex() == record["snapshot_id"] and fields[1] == record["epoch"]
    assert fields[2].hex() == report["authentication_policy_digest"]
    binding = auth.RequestBinding(
        fields[0],
        fields[1],
        fields[2],
        hashlib.sha256(
            auth.QUERY_TAG + bytes.fromhex(report["standard_owner_public_key"]) + payload
        ).digest(),
        fields[3],
        hashlib.sha256(b"".join(x.to_bytes(8, "little") for x in metadata.ids)).digest(),
    )
    reply = auth._unpack(
        retained_bytes(record["complete_reply"]), limit=native.PACKET_CAP, array_cap=9
    )
    assert len(reply) == 9 and reply[0] == auth.REPLY_TAG and reply[1:7] == binding.fields()
    assert (
        len(reply[7]) == metadata.body_size and lab.sha(reply[7]) == record["whole_GMP_body_sha256"]
    )
    assert record["exact_native_GMP_all_source_output_bytes_equal"]
    assert record["exact_native_GMP_full_terminal_frame_equal"]
    assert (
        record["complete_public_admission_then_durable_callback_claim"]
        and record["state"] == "delivered"
    )
    return fields[4], reply[8]


def resign_enrollment(old_fields, old_pin, factory, owner, path):
    """Save a small public reconstruction receipt rather than duplicate huge inputs.

    Replace only payload field5 (policy), then save the new public signature.
    The previous source checkpoint contains the complete original signed input.
    No signing/HE secret is needed to reconstruct and verify the new envelope.
    """
    fields = list(old_fields)
    fields[5] = factory.policy_digest
    payload = auth._pack(fields)
    packet = auth._sign(auth.ENROLL_TAG, payload, owner)
    tag, _payload, signature = auth._unpack(packet, limit=native.PACKET_CAP, array_cap=3)
    receipt = {
        "schema_version": 1,
        "original_enrollment": old_pin,
        "rule": "canonical payload list, replace only field5, canonical signed envelope",
        "replacement_field5_policy_digest": factory.policy_digest.hex(),
        "tag": tag.hex(),
        "standard_owner_public_key": fixtures.public_key(owner).hex(),
        "signature": signature.hex(),
        "reconstructed_packet_bytes": len(packet),
        "reconstructed_packet_sha256": lab.sha(packet),
        "secret_serialized": False,
    }
    lab.json_new(path, receipt)
    # Check the persisted descriptor can recover precisely the signed packet.
    saved = json.loads(path.read_text())
    reconstruction = auth._pack(
        [bytes.fromhex(saved["tag"]), payload, bytes.fromhex(saved["signature"])]
    )
    assert reconstruction == packet
    auth._verify(reconstruction, factory._anchor, auth.ENROLL_TAG, native.PACKET_CAP)
    return packet


def execute_case(out, label, enrollment, owner, seeded_query, expected, inputs):
    nonce = hashlib.sha256(b"Q76.4a-retained-replay-v1:" + label.encode()).digest()
    original = auth.sign_request(
        enrollment.snapshot_id,
        enrollment.epoch,
        enrollment._factory.policy_digest,
        nonce,
        seeded_query,
        owner,
    )
    request_path = out / (label + ".request")
    lab.write_new(request_path, original)
    with life.LocalJournal(
        out / (label + ".sqlite"),
        fixtures.public_key(owner),
        enrollment._factory.policy_digest,
        bytes([14]) * 32,
    ) as journal:
        journal.install(enrollment)
        packet, authorization = replay.PreparedReplayAuthorizer(journal).execute(
            enrollment, original
        )
        fields = auth._unpack(packet, limit=native.PACKET_CAP, array_cap=8)
        assert len(fields) == 8 and fields[0] == replay.REPLY_TAG and fields[7] == expected
        assert authorization.frame == expected
        delivered = []
        life.LocalReleaseGuard(journal).deliver(
            authorization, delivered.append
        )  # Public bytes only.
        assert delivered == [expected]
        try:
            life.LocalReleaseGuard(journal).deliver(authorization, delivered.append)
        except life.ConsumedRequestError:
            pass
        else:
            raise AssertionError("Repeated callback claim was accepted")
        summary = journal.summary()
        assert summary == {"attempts": 1, "authorizations": 1, "callback_claims": 1}
        state = journal.status(nonce)["state"]
        assert state == "delivered"
    reply_path = out / (label + ".reply")
    lab.write_new(reply_path, packet)
    m, p = enrollment.metadata, enrollment.metadata.profile
    return {
        "label": label,
        "records": len(m.ids),
        "groups": m.groups,
        "HE_key_id": m.key_id,
        "snapshot_id": enrollment.snapshot_id.hex(),
        "epoch": enrollment.epoch,
        "native_stats": asdict(enrollment.stats),
        "original_retained_inputs": inputs,
        "original_request": lab.pin(request_path),
        "complete_replay_reply": lab.pin(reply_path),
        "full_compact_frame_bytes": len(expected),
        "full_compact_frame_sha256": lab.sha(expected),
        "both_components_all_coordinates_headers_and_tails_byte_equal": True,
        "canonical_digit_and_terminal_arithmetic_retained": True,
        "source_witness_allocated_or_sent_bytes": 0,
        "dedicated_final_Q_buffer_bytes_not_total_peak": 2 * m.groups * p.n * native.COMMON_WIDTH,
        "coefficient_body_bytes": 2 * m.groups * m.terminal_row_size,
        "local_summary": summary,
        "state": state,
        "private_work": 0,
        "process_high_water_RSS_bytes_not_native_peak_or_timing": resource.getrusage(
            resource.RUSAGE_SELF
        ).ru_maxrss
        * 1024,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--source-report", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=False)
    baseline = json.loads(args.baseline.read_text())
    assert lab.pin(args.source_report) == baseline["source_report"]
    assert lab.pin(args.fixtures / "Q74-correctness.json") == baseline["small_report"]
    preflight = json.loads(args.preflight.read_text())
    assert preflight["all_selected_tests_passed"] and preflight["fresh_HE_key_contexts"] == 0
    assert all(lab.pin(Path(row["file"])) == row for row in preflight["executed_sources"])
    assert lab.pin(args.library) == preflight["normal_library"]
    report, entries = lab.public_cases(args.fixtures)
    public = lab.public_fixtures(args.fixtures, report)
    large = json.loads(args.source_report.read_text())
    assert large["complete"] and large["complete_searches"] == 6 and len(large["results"]) == 6
    expected_labels = [f"m{count}-q{q}" for count in (8224, 16384, 32768) for q in (0, 1)]
    assert [row["label"] for row in large["results"]] == expected_labels
    sources = sorted(
        set(lab.source_files())
        | {
            Path(__file__),
            ROOT / "experiments/bfv_search_lab/_shared_query/shared_query_replay.cpp",
            ROOT / "docs/research/native-shared-query-replay-registration-20261004.json",
        }
    )
    frozen = [lab.pin(path) for path in sources]
    archive = args.out_dir / "executed-source.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for path in sources:
            tar.add(path, arcname=str(path.relative_to(ROOT)), recursive=False)
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        assert len(members) == len(frozen)
        for row, member in zip(frozen, members, strict=True):
            assert lab.sha(tar.extractfile(member).read()) == row["sha256"]
    library = native.NativeLibrary(args.library)
    owner = Ed25519PrivateKey.generate()  # One supporting signature key; never serialized.
    factory = replay.ReplayFactory(fixtures.public_key(owner), library)
    started = {
        "task": "Q76.4a",
        "utc": datetime.now(UTC).isoformat(),
        "git_HEAD": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "source": frozen,
        "source_archive": lab.pin(archive),
        "library": lab.pin(args.library),
        "baseline": lab.pin(args.baseline),
        "preflight": lab.pin(args.preflight),
        "standard_owner_public_key": fixtures.public_key(owner).hex(),
        "authentication_policy_digest": factory.policy_digest.hex(),
        "retained_case_cap": 22,
        "fresh_HE_key_contexts": 0,
        "private_HE_work": 0,
        "supporting_standard_Ed25519_contexts": 1,
        "timing_panels": 0,
        "source_report": lab.pin(args.source_report),
        "small_report": lab.pin(args.fixtures / "Q74-correctness.json"),
    }
    lab.json_new(args.out_dir / "started.json", started)
    results = []
    try:
        for entry in entries:
            _ctx, tape, metadata, keys, index, query = fixtures.owner_inputs(
                args.fixtures, entry, public
            )
            packet = auth.sign_enrollment(metadata, keys, index, 1, factory.policy_digest, owner)
            path = args.out_dir / (entry["id"] + ".enrollment")
            lab.write_new(path, packet)
            with factory.enroll(packet) as enrollment:
                result = execute_case(
                    args.out_dir,
                    entry["id"],
                    enrollment,
                    owner,
                    query,
                    tape.response,
                    {"fixture": entry["fixture"], "current_enrollment": lab.pin(path)},
                )
                results.append(result)
                print(
                    json.dumps({"completed": result["label"], "full_frame_equal": True}), flush=True
                )
        del packet, keys, index  # Do not retain small context payloads through large preparation.
        for count in (8224, 16384, 32768):
            rows = [r for r in large["results"] if r["records"] == count]
            old_fields, metadata = historical_enrollment(rows[0], large)
            descriptor = args.out_dir / f"m{count}.enrollment-reconstruction.json"
            packet = resign_enrollment(
                old_fields, rows[0]["enrollment"], factory, owner, descriptor
            )
            del old_fields
            with factory.enroll(packet) as enrollment:
                del packet
                assert enrollment.metadata == metadata
                for row in rows:
                    assert row["enrollment"] == rows[0]["enrollment"]
                    query, expected = historical_query_and_frame(row, large, metadata)
                    result = execute_case(
                        args.out_dir,
                        row["label"],
                        enrollment,
                        owner,
                        query,
                        expected,
                        {
                            "historical_signed_enrollment": row["enrollment"],
                            "historical_signed_request": row["original_request"],
                            "GMP_validated_complete_reply": row["complete_reply"],
                            "current_enrollment_reconstruction": lab.pin(descriptor),
                            "historical_signatures_and_all_file_hashes_verified": True,
                        },
                    )
                    results.append(result)
                    print(
                        json.dumps({"completed": result["label"], "full_frame_equal": True}),
                        flush=True,
                    )
        assert len(results) == 22 and all(lab.pin(Path(row["file"])) == row for row in frozen)
        lab.json_new(
            args.out_dir / "Q76.4a-retained-replay.json",
            {
                **started,
                "utc_completed": datetime.now(UTC).isoformat(),
                "complete": True,
                "retained_cases": 22,
                "small_cases": 16,
                "source_scale_cases": 6,
                "results": results,
                "scope": "Matched prepared replay/local authorization public correctness; no new HE/decryption/timing/attestation/security or originality approval",
                "next": "Q76.4b protected prefix/product/suffix then cache and independent certificate",
            },
        )
    except BaseException as error:
        lab.json_new(
            args.out_dir / "failed.json",
            {
                "utc": datetime.now(UTC).isoformat(),
                "complete": False,
                "error_type": type(error).__name__,
                "message": str(error),
                "completed_retained_cases": len(results),
                "results": results,
            },
        )
        raise


if __name__ == "__main__":
    main()
