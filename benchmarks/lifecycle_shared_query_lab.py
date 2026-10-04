#!/usr/bin/env python3
"""Q76.3a retained public lifecycle cohort; no HE keys/private work/timing."""

# ruff: noqa: E402 -- standalone research runner.
from __future__ import annotations

import argparse
from datetime import datetime, UTC
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import msgpack

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks import native_shared_query_lab as lab
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import lifecycle_shared_query as life
from experiments.bfv_search_lab import native_shared_query as native


def digest(value):
    return hashlib.sha256(value).digest()


def reject_replay(authorizer, enrollment, request, packet):
    try:
        authorizer.admit(enrollment, request, packet)
    except life.ConsumedRequestError:
        return
    raise AssertionError("Consumed original request replay accepted")


def reject_dispatch(guard, token, callback):
    try:
        guard.deliver(token, callback)
    except life.ConsumedRequestError:
        return
    raise AssertionError("Consumed callback claim replay accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=False)
    library = native.NativeLibrary(args.library)
    report, entries = lab.public_cases(args.fixtures)
    assert len(entries) == 16
    fixtures = lab.public_fixtures(args.fixtures, report)
    owner = Ed25519PrivateKey.generate()  # Standard authentication only.
    public = owner.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    factory = auth.OwnerFactory(public, library)
    sources = sorted(
        set(lab.source_files())
        | {
            Path(__file__),
            ROOT / "docs/research/native-shared-query-lifecycle-registration-20261004.json",
        }
    )
    frozen = [lab.pin(path) for path in sources]
    started = {
        "task": "Q76.3a",
        "utc": datetime.now(UTC).isoformat(),
        "git_HEAD": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "source": frozen,
        "library": lab.pin(args.library),
        "retained_report": lab.pin(args.fixtures / "Q74-correctness.json"),
        "owner_public_key": public.hex(),
        "policy_digest": factory.policy_digest.hex(),
        "lifecycle_code_digest": lab.pin(Path(life.__file__)),
        "standard_signing_key_contexts": 1,
        "new_HE_key_contexts": 0,
        "private_HE_work": 0,
        "timing_panels": 0,
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
            database = args.out_dir / (entry["id"] + ".sqlite")
            scope = digest(entry["id"].encode())
            hooks, request_rows = [], []
            with (
                factory.enroll(enrollment_packet) as enrollment,
                life.LocalJournal(database, public, factory.policy_digest, scope) as journal,
            ):
                journal.install(enrollment)
                authorizer, guard = life.LocalAuthorizer(journal), life.LocalReleaseGuard(journal)

                def hook(frame, expected_frame=tape.response, received=hooks):
                    assert frame == expected_frame
                    received.append(digest(frame).hex())  # Public ciphertext digest only.
                    return b"discarded-public-test-value"

                for label in (
                    "good",
                    "body",
                    "frame",
                    "snapshot",
                    "epoch_bool",
                    "trailing",
                    "callback_fail",
                ):
                    nonce = digest(entry["id"].encode() + b":" + label.encode())
                    original = auth.sign_request(
                        enrollment.snapshot_id,
                        1,
                        factory.policy_digest,
                        nonce,
                        original_query,
                        owner,
                    )
                    with enrollment.request(original) as request:
                        packet = request.reply(lab.body(ctx, tape), tape.response)
                        if label == "good":
                            assert request.produce_packet() == packet
                    fields = msgpack.unpackb(packet, raw=False)
                    if label in ("body", "frame"):
                        at = 7 if label == "body" else 8
                        fields[at] = fields[at][:-1] + bytes([fields[at][-1] ^ 1])
                    elif label == "snapshot":
                        fields[1] = bytes(32)
                    elif label == "epoch_bool":
                        fields[2] = True
                    packet = packet + b"\x00" if label == "trailing" else auth._pack(fields)
                    token = authorizer.admit(enrollment, original, packet)
                    if label in ("good", "callback_fail"):
                        assert token is not None and token.frame == tape.response
                        if label == "good":
                            assert guard.deliver(token, hook) is None
                        else:

                            def failed_hook(frame, active_hook=hook):
                                active_hook(frame)
                                raise ValueError("Public test hook failure")

                            try:
                                guard.deliver(token, failed_hook)
                            except life.CallbackFailed:
                                pass
                            else:
                                raise AssertionError("Failed hook did not stay consumed")
                        reject_dispatch(guard, token, hook)
                    else:
                        assert token is None
                    reject_replay(authorizer, enrollment, original, packet)
                    state = journal.status(nonce)
                    expected = (
                        "delivered"
                        if label == "good"
                        else "callback_failed"
                        if label == "callback_fail"
                        else "rejected"
                    )
                    assert state["state"] == expected
                    request_rows.append(
                        {
                            "label": label,
                            "nonce": nonce.hex(),
                            "state": expected,
                            "authorized_once": state["authorized_once"],
                            "callback_once": state["callback_once"],
                            "request": lab.write_new(
                                args.out_dir / (entry["id"] + "-" + label + ".request"), original
                            ),
                            "reply": lab.write_new(
                                args.out_dir / (entry["id"] + "-" + label + ".reply"), packet
                            ),
                            "request_replay_denied": True,
                            "callback_replay_denied": label in ("good", "callback_fail"),
                        }
                    )
                assert journal.summary() == {
                    "attempts": 7,
                    "authorizations": 2,
                    "callback_claims": 2,
                }
                assert len(hooks) == 2
                original_identity = journal.journal_id
            with life.LocalJournal(database, public, factory.policy_digest, scope) as restarted:
                assert restarted.journal_id == original_identity
                assert restarted.summary() == {
                    "attempts": 7,
                    "authorizations": 2,
                    "callback_claims": 2,
                }
                # Valid persisted records still cannot cause a hook after restart.
                reject_dispatch(life.LocalReleaseGuard(restarted), token, hook)
            assert len(hooks) == 2
            results.append(
                {
                    "id": entry["id"],
                    "key_context": ctx.key_id,
                    "fixture": fixture_pin,
                    "enrollment": lab.write_new(
                        args.out_dir / (entry["id"] + ".enrollment"), enrollment_packet
                    ),
                    "database": lab.pin(database),
                    "journal_id": original_identity.hex(),
                    "requests": request_rows,
                    "public_test_hooks": len(hooks),
                    "native_tape_and_full_frame_match_retained_GMP": True,
                    "restart_retains_consumption": True,
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
                "complete": False,
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
        "retained_HE_key_contexts": len({row["key_context"] for row in results}),
        "protocol_requests": sum(len(row["requests"]) for row in results),
        "bad_replies_rejected_and_consumed": len(results) * 5,
        "durable_authorizations": len(results) * 2,
        "public_test_hook_calls": sum(row["public_test_hooks"] for row in results),
        "failed_hooks_consumed": len(results),
        "results": results,
        "scope": "Trusted local nonrollback lifecycle; no real attestation/remote release, fresh HE keys/private HE work, source-scale assurance, parameter approval or original main",
    }
    lab.json_new(args.out_dir / "Q76.3a-lifecycle.json", complete)
    print(
        json.dumps(
            {
                key: complete[key]
                for key in (
                    "retained_complete_cases",
                    "protocol_requests",
                    "bad_replies_rejected_and_consumed",
                    "durable_authorizations",
                    "public_test_hook_calls",
                    "failed_hooks_consumed",
                    "new_HE_key_contexts",
                    "private_HE_work",
                    "timing_panels",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
