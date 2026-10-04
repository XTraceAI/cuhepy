#!/usr/bin/env python3
"""Q76.4b retained aggregate correctness/local lifecycle, never a timing panel."""

# ruff: noqa: E402 -- standalone research runner.
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import UTC, datetime
import json
from pathlib import Path
import resource
import subprocess
import sys
import tarfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks import native_shared_query_lab as lab
from benchmarks import replay_shared_query_lab as saved
from experiments.bfv_search_lab import aggregate_reference as reference
from experiments.bfv_search_lab import aggregate_shared_query as aggregate
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import lifecycle_shared_query as life
from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab import test_authenticated_shared_query as fixtures


def execute_case(
    out, label, enrollment, owner, seeded_query, expected_body, expected_frame, inputs
):
    nonce = bytes.fromhex(lab.sha(b"Q76.4b-retained-aggregate-v1:" + label.encode()))
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
    with enrollment.request(original) as request:
        # This is paid untrusted producer work. Verification below independently
        # expands the authenticated original query and performs its exact checks.
        packet = request.produce_packet()
    fields = auth._unpack(packet, limit=native.PACKET_CAP, array_cap=9)
    assert (
        fields[0] == aggregate.REPLY_TAG
        and fields[7] == expected_body
        and fields[8] == expected_frame
    )
    with life.LocalJournal(
        out / (label + ".sqlite"),
        fixtures.public_key(owner),
        enrollment._factory.policy_digest,
        bytes([15]) * 32,
    ) as journal:
        journal.install(enrollment)
        authorization = life.LocalAuthorizer(journal).admit(enrollment, original, packet)
        assert authorization is not None and authorization.frame == expected_frame
        delivered = []
        life.LocalReleaseGuard(journal).deliver(authorization, delivered.append)
        assert delivered == [expected_frame]
        try:
            life.LocalReleaseGuard(journal).deliver(authorization, delivered.append)
        except life.ConsumedRequestError:
            pass
        else:
            raise AssertionError("Repeated callback claim accepted")
        summary = journal.summary()
        assert summary == {"attempts": 1, "authorizations": 1, "callback_claims": 1}
        state = journal.status(nonce)["state"]
        assert state == "delivered"
    path = out / (label + ".reply")
    lab.write_new(path, packet)
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
        "complete_aggregate_reply": lab.pin(path),
        "aggregate_body_bytes": len(expected_body),
        "aggregate_body_sha256": lab.sha(expected_body),
        "all_canonical_aggregate_coefficients_byte_equal": True,
        "public_aggregate_coefficients_compared": 3 * m.groups * p.n,
        "full_compact_frame_bytes": len(expected_frame),
        "full_compact_frame_sha256": lab.sha(expected_frame),
        "both_components_all_coordinates_headers_and_tails_byte_equal": True,
        "genuine_original_query_prefix_paid": True,
        "protected_products_per_feature": 3,
        "genuine_canonical_relinearization_and_terminal_suffix_paid": True,
        "source_expansion_witness_allocated_or_sent_bytes": 0,
        "dedicated_final_Q_buffer_bytes_not_total_peak": 2 * m.groups * p.n * native.COMMON_WIDTH,
        "coefficient_body_bytes": 2 * m.groups * m.terminal_row_size,
        "private_HE_work": 0,
        "local_summary": summary,
        "state": state,
        "process_high_water_RSS_bytes_not_native_peak_or_timing": resource.getrusage(
            resource.RUSAGE_SELF
        ).ru_maxrss
        * 1024,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("library", "fixtures", "source-report", "baseline", "preflight", "out-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=False)
    base = json.loads(args.baseline.read_text())
    assert lab.pin(args.source_report) == base["source_report"]
    assert lab.pin(args.fixtures / "Q74-correctness.json") == base["small_report"]
    preflight = json.loads(args.preflight.read_text())
    assert preflight["all_selected_tests_passed"] and preflight["fresh_HE_key_contexts"] == 0
    assert all(lab.pin(Path(row["file"])) == row for row in preflight["executed_sources"])
    assert lab.pin(args.library) == preflight["normal_library"]
    old_report, entries = lab.public_cases(args.fixtures)
    public = lab.public_fixtures(args.fixtures, old_report)
    source_report = json.loads(args.source_report.read_text())
    assert source_report["complete"] and source_report["complete_searches"] == 6
    assert [row["label"] for row in source_report["results"]] == [
        f"m{count}-q{q}" for count in (8224, 16384, 32768) for q in (0, 1)
    ]
    sources = sorted(
        set(lab.source_files())
        | {
            Path(__file__),
            Path(saved.__file__),
            ROOT / "docs/research/native-shared-query-aggregate-registration-20261004.json",
            *ROOT.glob("experiments/bfv_search_lab/_shared_query/*.cpp"),
        }
    )
    frozen = [lab.pin(p) for p in sources]
    archive = args.out_dir / "executed-source.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for p in sources:
            tar.add(p, arcname=str(p.relative_to(ROOT)), recursive=False)
    with tarfile.open(archive, "r:gz") as tar:
        for row, member in zip(frozen, tar.getmembers(), strict=True):
            assert lab.sha(tar.extractfile(member).read()) == row["sha256"]
    library = native.NativeLibrary(args.library)
    owner = Ed25519PrivateKey.generate()  # One standard supporting signature context.
    factory = aggregate.AggregateFactory(fixtures.public_key(owner), library)
    started = {
        "task": "Q76.4b",
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
        "randomized_checks": 0,
        "source_report": lab.pin(args.source_report),
        "small_report": lab.pin(args.fixtures / "Q74-correctness.json"),
    }
    lab.json_new(args.out_dir / "started.json", started)
    results = []
    try:
        for entry in entries:
            ctx, tape, metadata, keys, index, query = fixtures.owner_inputs(
                args.fixtures, entry, public
            )
            expected = reference.small_aggregates(ctx)
            assert expected == reference.from_saved_transcript(metadata, keys, lab.body(ctx, tape))
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
                    expected,
                    tape.response,
                    {
                        "fixture": entry["fixture"],
                        "current_enrollment": lab.pin(path),
                        "reference": "independent full small schoolbook prefix and four tensor products; independent GMP recovery agrees",
                    },
                )
                results.append(result)
                print(
                    json.dumps(
                        {"completed": result["label"], "all_aggregate_and_frame_bytes_equal": True}
                    ),
                    flush=True,
                )
        del packet, keys, index
        for count in (8224, 16384, 32768):
            rows = [row for row in source_report["results"] if row["records"] == count]
            old_fields, metadata = saved.historical_enrollment(rows[0], source_report)
            keys = old_fields[6]
            descriptor = args.out_dir / f"m{count}.enrollment-reconstruction.json"
            packet = saved.resign_enrollment(
                old_fields, rows[0]["enrollment"], factory, owner, descriptor
            )
            del old_fields
            with factory.enroll(packet) as enrollment:
                del packet
                assert metadata == enrollment.metadata
                for row in rows:
                    assert row["enrollment"] == rows[0]["enrollment"]
                    query, expected_frame = saved.historical_query_and_frame(
                        row, source_report, metadata
                    )
                    # Re-read the pinned complete tape for the separately bounded
                    # GMP recovery. This is public correctness work, not a timing.
                    old_reply = auth._unpack(
                        saved.retained_bytes(row["complete_reply"]),
                        limit=native.PACKET_CAP,
                        array_cap=9,
                    )
                    assert old_reply[8] == expected_frame
                    expected = reference.from_saved_transcript(metadata, keys, old_reply[7])
                    del old_reply
                    result = execute_case(
                        args.out_dir,
                        row["label"],
                        enrollment,
                        owner,
                        query,
                        expected,
                        expected_frame,
                        {
                            "historical_signed_enrollment": row["enrollment"],
                            "historical_signed_request": row["original_request"],
                            "GMP_validated_complete_reply": row["complete_reply"],
                            "current_enrollment_reconstruction": lab.pin(descriptor),
                            "historical_signatures_and_file_hashes_verified": True,
                            "reference": "saved genuine C2; subtract independent whole-Q GMP key-switch(C2) from both saved independently validated final-Q components",
                        },
                    )
                    results.append(result)
                    print(
                        json.dumps(
                            {
                                "completed": result["label"],
                                "all_aggregate_and_frame_bytes_equal": True,
                            }
                        ),
                        flush=True,
                    )
            del keys
        assert len(results) == 22 and all(lab.pin(Path(row["file"])) == row for row in frozen)
        lab.json_new(
            args.out_dir / "Q76.4b-retained-aggregate.json",
            {
                **started,
                "utc_completed": datetime.now(UTC).isoformat(),
                "complete": True,
                "retained_cases": 22,
                "small_cases": 16,
                "source_scale_cases": 6,
                "results": results,
                "all_public_aggregate_coefficients_compared": sum(
                    row["public_aggregate_coefficients_compared"] for row in results
                ),
                "scope": "Known exact aggregate control/local lifecycle public correctness; no new HE/private/timing/attestation/security or originality approval",
                "next": "Q76.4c permitted authenticated cache then independent certificate",
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
