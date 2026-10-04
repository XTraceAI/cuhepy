#!/usr/bin/env python3
"""Q76.2 retained signed-enrollment/query/full-reply gate; no HE keys or timing."""

# ruff: noqa: E402 -- standalone research runner.
from __future__ import annotations

import argparse
from datetime import datetime, UTC
import gzip
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import msgpack

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks import native_shared_query_lab as lab
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import native_shared_query as native


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=False)
    library = native.NativeLibrary(args.library)
    owner = Ed25519PrivateKey.generate()  # Supporting standard signature key only.
    public = owner.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    factory = auth.OwnerFactory(public, library)
    report, entries = lab.public_cases(args.fixtures)
    fixtures = lab.public_fixtures(args.fixtures, report)
    sources = sorted(
        set(lab.source_files())
        | {
            Path(__file__),
            ROOT / "docs/research/native-shared-query-auth-registration-20261004.json",
        }
    )
    frozen = [lab.pin(path) for path in sources]
    started = {
        "task": "Q76.2",
        "utc": datetime.now(UTC).isoformat(),
        "git_HEAD": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "source": frozen,
        "library": lab.pin(args.library),
        "owner_public_key": public.hex(),
        "policy_digest": factory.policy_digest.hex(),
        "standard_signing_key_contexts": 1,
        "new_HE_key_contexts": 0,
        "private_HE_work": 0,
        "timing_panels": 0,
        "retained_report": lab.pin(args.fixtures / "Q74-correctness.json"),
    }
    lab.json_new(args.out_dir / "started.json", started)
    results = []
    try:
        for entry in entries:
            ctx, tape, _pk, primes, fixture_pin = lab.load_case(args.fixtures, entry, fixtures)
            raw = json.loads(gzip.decompress(Path(fixture_pin["file"]).read_bytes()))
            metadata = native.PublicMetadata(ctx.profile, primes, ctx.key_id, ctx.ids)
            keys = (ctx.relin, *(key for _, key in ctx.rotations))
            key_body = native.pack_common(
                tuple(row for key in keys for column in key for row in column),
                ctx.profile.n,
                ctx.profile.q,
            )
            index = tuple(bytes.fromhex(x) for x in raw["owner_index_packets"])
            original_query = bytes.fromhex(raw["query_seeded_packet"])
            enrollment_packet = auth.sign_enrollment(
                metadata, key_body, index, 1, factory.policy_digest, owner
            )
            with factory.enroll(enrollment_packet) as enrollment:
                query_packet = auth.sign_request(
                    enrollment.snapshot_id,
                    1,
                    factory.policy_digest,
                    secrets.token_bytes(32),
                    original_query,
                    owner,
                )
                with enrollment.request(query_packet) as request:
                    proof_body = lab.body(ctx, tape)
                    packet = request.reply(proof_body, tape.response)
                    assert request.produce_packet() == packet and request.accepts_packet(packet)
                    fields = msgpack.unpackb(packet, raw=False)
                    for at in range(1, 7):
                        bad = fields.copy()
                        bad[at] = bad[at] + 1 if at == 2 else bytes(32)
                        assert not request.accepts_packet(auth._pack(bad))
                    bad = fields.copy()
                    bad[2] = True  # Equal to epoch1 in Python, invalid in this grammar.
                    assert not request.accepts_packet(auth._pack(bad))
                    for at in (7, 8):
                        bad = fields.copy()
                        bad[at] = bad[at][:-1] + bytes([bad[at][-1] ^ 1])
                        assert not request.accepts_packet(auth._pack(bad))
                    assert not request.accepts_packet(packet + b"\x00")
                    signed_fields = msgpack.unpackb(query_packet, raw=False)
                    signed_fields[2] = bytes(64)
                    try:
                        enrollment.request(auth._pack(signed_fields))
                    except ValueError:
                        pass
                    else:
                        raise AssertionError("Bad owner signature accepted")
                    results.append(
                        {
                            "id": entry["id"],
                            "key_context": ctx.key_id,
                            "fixture": fixture_pin,
                            "enrollment": lab.write_new(
                                args.out_dir / (entry["id"] + ".enrollment"), enrollment_packet
                            ),
                            "request": lab.write_new(
                                args.out_dir / (entry["id"] + ".request"), query_packet
                            ),
                            "reply": lab.write_new(args.out_dir / (entry["id"] + ".reply"), packet),
                            "binding": {
                                "snapshot_id": enrollment.snapshot_id.hex(),
                                "request_digest": request.binding.request_digest.hex(),
                            },
                            "original_seeded_index_packet_bytes": sum(map(len, index)),
                            "expanded_common_Q_index_bytes": 2
                            * ctx.profile.n
                            * native.COMMON_WIDTH
                            * ctx.profile.dimension
                            * ctx.groups,
                            "original_seeded_query_packet_bytes": len(original_query),
                            "expanded_common_Q_query_bytes": 2
                            * ctx.profile.n
                            * native.COMMON_WIDTH,
                            "owner_enrollment_wire_bytes": len(enrollment_packet),
                            "signed_original_query_wire_bytes": len(query_packet),
                            "server_to_verifier_complete_reply_bytes": len(packet),
                            "client_compact_frame_bytes": len(tape.response),
                            "whole_GMP_tape_and_compact_frame_exact": True,
                            "context_or_boolean_epoch_faults_rejected": 7,
                            "body_frame_and_trailing_faults_rejected": 3,
                            "bad_request_signature_rejected": True,
                            "scope": "Public local predicate, no replay/current-snapshot authority or private callback",
                        }
                    )
                    print(entry["id"], flush=True)
        assert [lab.pin(Path(x["file"])) for x in frozen] == frozen
    except BaseException as error:
        lab.json_new(
            args.out_dir / "failed.json",
            {
                "type": type(error).__name__,
                "error": str(error),
                "completed": False,
                "completed_retained_cases": len(results),
                "results": results,
            },
        )
        raise
    complete = {
        **started,
        "utc_completed": datetime.now(UTC).isoformat(),
        "complete": True,
        "retained_complete_cases": len(results),
        "retained_HE_key_contexts": len({x["key_context"] for x in results}),
        "context_faults": sum(x["context_or_boolean_epoch_faults_rejected"] for x in results),
        "body_frame_grammar_faults": sum(
            x["body_frame_and_trailing_faults_rejected"] for x in results
        ),
        "request_signature_faults": len(results),
        "results": results,
        "scope": "Owner-authenticated small public native prototype; no HE secrets/signing key serialized, private release, lifecycle, actual attestation, source-scale gate, security/parameter approval or original main",
    }
    lab.json_new(args.out_dir / "Q76.2-authenticated-core.json", complete)
    print(
        json.dumps(
            {
                k: complete[k]
                for k in [
                    "retained_complete_cases",
                    "context_faults",
                    "body_frame_grammar_faults",
                    "request_signature_faults",
                    "new_HE_key_contexts",
                    "private_HE_work",
                    "timing_panels",
                ]
            }
        )
    )


if __name__ == "__main__":
    main()
