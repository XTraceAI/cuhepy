#!/usr/bin/env python3
"""Q76.3b one-key/six-search source correctness, never a timing panel."""

# ruff: noqa: E402 -- standalone research runner.
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, UTC
import hashlib
import json
from pathlib import Path
import resource
import subprocess
import sys
import tarfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import gmpy2
from gmpy2 import mpz
import msgpack
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks import native_shared_query_lab as lab
from cuhepy.bfv.scheme import _ring_product, _rns_coefficient_primes
from experiments.bfv_search_lab import authenticated_shared_query as auth
from experiments.bfv_search_lab import lifecycle_shared_query as life
from experiments.bfv_search_lab import native_shared_query as native
from experiments.bfv_search_lab import seeded_bgv as seeded
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import shared_query_bgv as shared
from experiments.bfv_search_lab import shared_query_gmp as reference
from experiments.bfv_search_lab.shared_query_bounds import Profile

PRIMES = (1152921504606748673, 1152921504606683137)
N, DIMENSION, T, ETA, P = 16384, 512, 1031, 21, 33548413
COUNTS = (8224, 16384, 32768)
SEARCH_CAP = 6


def synthetic_rows():
    """Public binary fixture with deliberate exact ties, using no HE entropy."""
    width = DIMENSION // 8
    data = bytearray(hashlib.shake_256(b"Q76.3b-public-binary-index-v1").digest(COUNTS[-1] * width))
    query_words = (
        int.from_bytes(bytes([0x55]) * width, "little"),
        int.from_bytes(bytes([0xA3]) * width, "little"),
    )
    for positions, word in (((0, 1, 2), query_words[0]), ((3, 4, 5), query_words[1])):
        for position in positions:
            data[position * width : (position + 1) * width] = word.to_bytes(width, "little")
    # Nontrivial records at both group boundaries, rather than zero fixtures.
    return bytes(data), query_words


def plaintext_distances(row_bytes, count, query_word, dimension=DIMENSION):
    width = dimension // 8
    return tuple(
        (
            int.from_bytes(row_bytes[at * width : (at + 1) * width], "little") ^ query_word
        ).bit_count()
        for at in range(count)
    )


def private_diagnostics(metadata, body, frame, pk, sk, expected):
    """Owner-only variable-time diagnostics, called inside a claimed local hook.

    The runner never invokes this until complete public authorization and the
    durable callback claim. No key is serialized and no result is sent to a
    server. This diagnostic is not the Q78 production private implementation.
    """
    p, groups = metadata.profile, metadata.groups
    envelope = p.envelope()
    fields = msgpack.unpackb(frame, raw=False)
    assert fields[0] == [
        "cuhepy-lab-bgv-compact-v1",
        p.n,
        p.t,
        p.p.to_bytes((p.p.bit_length() + 7) // 8, "little"),
        bytes.fromhex(metadata.key_id),
        len(metadata.ids),
        p.dimension,
    ]
    assert len(fields[1]) == groups and len(expected) == len(metadata.ids)
    secret_p = tuple(mpz(p.p - 1) if value == pk.q - 1 else value for value in sk.s)
    distances, full_peak, terminal_peak, tail_count = [], 0, 0, 0
    stride, start = p.n * reference.WIDTH, metadata.sources * p.n * reference.WIDTH
    for group in range(groups):
        full = tuple(reference._row(body, start + (2 * group + c) * stride, p.n) for c in range(2))
        product = _ring_product(full[1], sk.s, pk.q)
        raw_phase = tuple((a + b) % pk.q for a, b in zip(full[0], product, strict=True))
        full_phase = tuple(
            int(value if value <= pk.q // 2 else value - pk.q) for value in raw_phase
        )
        assert max(map(abs, full_phase)) <= envelope["output_phase_bound"]
        full_peak = max(full_peak, max(map(abs, full_phase)))
        compact = []
        for encoded in fields[1][group]:
            assert type(encoded) is bytes and len(encoded) == metadata.terminal_row_size
            integer = mpz.from_bytes(encoded, "little")
            assert integer.bit_length() <= p.n * p.p.bit_length()
            row = gmpy2.unpack(integer, p.p.bit_length())
            row.extend([mpz(0)] * (p.n - len(row)))
            assert len(row) == p.n and all(0 <= value < p.p for value in row)
            compact.append(tuple(row))
        assert len(compact) == 2
        product = _ring_product(compact[1], secret_p, mpz(p.p))
        raw_phase = tuple((a + b) % p.p for a, b in zip(compact[0], product, strict=True))
        terminal_phase = tuple(
            int(value if value <= p.p // 2 else value - p.p) for value in raw_phase
        )
        assert max(map(abs, terminal_phase)) <= envelope["terminal_phase_bound"]
        terminal_peak = max(terminal_peak, max(map(abs, terminal_phase)))
        occupied = min(p.n, len(metadata.ids) - group * p.n)
        for lane in range(p.n):
            full_dot, compact_dot = full_phase[lane] % p.t, terminal_phase[lane] % p.t
            assert full_dot == compact_dot
            dot = compact_dot if compact_dot <= p.t // 2 else compact_dot - p.t
            if lane >= occupied:
                assert dot == 0
                tail_count += 1
            else:
                assert -p.dimension <= dot <= p.dimension and (p.dimension - dot) % 2 == 0
                distance = (p.dimension - dot) // 2
                assert distance == expected[group * p.n + lane]
                distances.append(distance)
    assert tuple(distances) == expected
    order = sorted(range(len(distances)), key=lambda i: (distances[i], i))[:3]
    expected_order = sorted(range(len(expected)), key=lambda i: (expected[i], i))[:3]
    assert order == expected_order
    return {
        "all_full_Q_and_compact_P_coefficients_checked": 2 * groups * p.n,
        "all_physical_plaintext_positions_checked_per_modulus": groups * p.n,
        "all_distances_checked": len(distances),
        "unused_tail_positions_zero": tail_count,
        "stable_top3_positions": order,
        "stable_top3_ids": [metadata.ids[i] for i in order],
        "stable_top3_distances": [distances[i] for i in order],
        "observed_full_phase_max_abs": full_peak,
        "observed_terminal_phase_max_abs": terminal_peak,
        "observed_phase_is_local_diagnostic_not_public_admission_criterion": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=False)
    preflight = json.loads(args.preflight.read_text())
    assert preflight["final_passed"] == 59 and preflight["new_HE_keys"] == 0
    assert all(lab.pin(Path(row["file"])) == row for row in preflight["executed_sources"])
    p = Profile(N, DIMENSION, PRIMES[0] * PRIMES[1], P, T, ETA, "owner", "canonical30")
    p.require_safe()
    assert _rns_coefficient_primes(N, 120) == PRIMES
    library = native.NativeLibrary(args.library)
    owner = Ed25519PrivateKey.generate()  # Standard authentication, not HE arithmetic.
    owner_public = owner.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    factory = auth.OwnerFactory(owner_public, library)
    sources = sorted(set(lab.source_files()) | {Path(__file__), args.preflight.resolve()})
    frozen = [lab.pin(path) for path in sources]
    archive = args.out_dir / "executed-source.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for path in sources:
            name = (
                str(path.relative_to(ROOT))
                if path.is_relative_to(ROOT)
                else "preflight/GMP-preflight-return.json"
            )
            tar.add(path, arcname=name, recursive=False)
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        assert len(members) == len(frozen)
        for row, member in zip(frozen, members, strict=True):
            assert hashlib.sha256(tar.extractfile(member).read()).hexdigest() == row["sha256"]
    started = {
        "task": "Q76.3b",
        "utc": datetime.now(UTC).isoformat(),
        "git_HEAD": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "source": frozen,
        "source_archive": lab.pin(archive),
        "library": lab.pin(args.library),
        "preflight": lab.pin(args.preflight),
        "registration": lab.pin(
            ROOT / "docs/research/native-shared-query-registration-20261004.json"
        ),
        "selected_profile": asdict(p),
        "ordered_primes": list(PRIMES),
        "standard_owner_public_key": owner_public.hex(),
        "authentication_policy_digest": factory.policy_digest.hex(),
        "fresh_HE_key_contexts_max": 1,
        "search_cap": SEARCH_CAP,
        "timing_panels": 0,
        "private_diagnostics_only_after_durable_public_authorization": True,
    }
    lab.json_new(args.out_dir / "started.json", started)
    rows, query_words = synthetic_rows()
    lab.write_new(args.out_dir / "public-binary-rows.bin", rows)
    lab.json_new(
        args.out_dir / "public-binary-queries.json",
        [word.to_bytes(DIMENSION // 8, "little").hex() for word in query_words],
    )
    # Consume the single fresh-key attempt before generation. Failed/crashed
    # jobs cannot be silently restarted; a changed registration is required.
    lab.json_new(
        args.out_dir / "key-budget-consumed.json",
        {"fresh_HE_key_attempts": 1, "secret_key_serialized": False},
    )
    results, searches = [], 0
    try:
        pk, sk = bgv.key_gen(N, T, 120, ETA, rns_modulus=True)
        assert int(pk.q) == p.q
        print("one-fresh-HE-key-generated", flush=True)
        keys = shared.evaluation_keys(pk, sk, DIMENSION)
        key_body = native.pack_common(
            tuple(
                tuple(map(int, row))
                for key in (keys.relin, *(key for _, key in keys.rotations))
                for pair in key
                for row in pair
            ),
            N,
            p.q,
        )
        public_key = native.pack_common((tuple(map(int, pk.a)), tuple(map(int, pk.b))), N, p.q)
        lab.write_new(args.out_dir / "public-key.bin", public_key)
        lab.write_new(args.out_dir / "evaluation-keys.bin", key_body)
        del keys, public_key
        array = np.frombuffer(rows, dtype=np.uint8).reshape(COUNTS[-1], DIMENSION // 8)
        database = args.out_dir / "source-lifecycle.sqlite"
        with life.LocalJournal(
            database,
            owner_public,
            factory.policy_digest,
            hashlib.sha256(b"Q76.3b-source-index-scope").digest(),
        ) as journal:
            for epoch, count in enumerate(COUNTS, start=1):
                print("prepare-index", count, flush=True)
                ids = tuple((1 << 64) - 1 - i for i in range(count))
                metadata = native.PublicMetadata(p, PRIMES, pk.key_id, ids)
                packets, expanded = (
                    [],
                    bytearray(2 * metadata.groups * DIMENSION * N * native.COMMON_WIDTH),
                )
                stride = 2 * N * native.COMMON_WIDTH
                for group in range(metadata.groups):
                    start, end = group * N, min((group + 1) * N, count)
                    for feature in range(DIMENSION):
                        bits = (array[start:end, feature // 8] >> (feature % 8)) & 1
                        plaintext = [1 - 2 * int(bit) for bit in bits] + [0] * (N - (end - start))
                        packet = seeded.encrypt(plaintext, pk, sk)
                        packets.append(packet)
                        slot = group * DIMENSION + feature
                        expanded[slot * stride : (slot + 1) * stride] = auth._expand_seeded(
                            packet, metadata
                        )
                index_body = bytes(expanded)
                del expanded, plaintext, bits, packet
                signed = auth.sign_enrollment(
                    metadata, key_body, tuple(packets), epoch, factory.policy_digest, owner
                )
                del packets
                enrollment_pin = lab.write_new(args.out_dir / f"m{count}.enrollment", signed)
                gmp = reference.GMPPublicContext(metadata, key_body, index_body)
                with factory.enroll(signed) as enrollment:
                    journal.install(enrollment)
                    assert enrollment.stats.cached_public_row_bytes <= 1 << 30
                    for query_number, query_word in enumerate(query_words):
                        searches += 1
                        assert searches <= SEARCH_CAP
                        label = f"m{count}-q{query_number}"
                        lab.json_new(
                            args.out_dir / (label + ".attempt.json"),
                            {"search_attempt": searches, "fresh_HE_key_contexts": 1},
                        )
                        query_bits = tuple((query_word >> i) & 1 for i in range(DIMENSION))
                        query_packet = seeded.encrypt(shared.encode_query(query_bits, N, T), pk, sk)
                        query_body = auth._expand_seeded(query_packet, metadata)
                        nonce = hashlib.sha256(b"Q76.3b:" + label.encode()).digest()
                        original = auth.sign_request(
                            enrollment.snapshot_id,
                            epoch,
                            factory.policy_digest,
                            nonce,
                            query_packet,
                            owner,
                        )
                        print(label, "independent-GMP-produce", flush=True)
                        gmp_tape = gmp.produce(query_body)
                        with enrollment.request(original) as request:
                            print(label, "native-produce-and-compare", flush=True)
                            native_body = request._query.produce()
                            assert native_body == gmp_tape.body
                            assert (
                                request._query.expected_response(native_body) == gmp_tape.response
                            )
                            reply = request.reply(native_body, gmp_tape.response)
                        print(label, "public-admission", flush=True)
                        authorization = life.LocalAuthorizer(journal).admit(
                            enrollment, original, reply
                        )
                        assert authorization is not None
                        expected = plaintext_distances(rows, count, query_word)
                        private_results = []

                        def owner_hook(
                            frame,
                            current_meta=metadata,
                            current_body=native_body,
                            expected_scores=expected,
                            consumed_nonce=nonce,
                            completed=private_results,
                            current_secret=sk,
                        ):
                            status = journal.status(consumed_nonce)
                            assert (
                                status["state"] == "dispatch_started"
                                and status["authorized_once"] == status["callback_once"] == 1
                            )
                            completed.append(
                                private_diagnostics(
                                    current_meta,
                                    current_body,
                                    frame,
                                    pk,
                                    current_secret,
                                    expected_scores,
                                )
                            )

                        print(label, "claimed-owner-private-diagnostics", flush=True)
                        assert (
                            life.LocalReleaseGuard(journal).deliver(authorization, owner_hook)
                            is None
                        )
                        assert len(private_results) == 1
                        state = journal.status(nonce)
                        assert state["state"] == "delivered"
                        row = {
                            "label": label,
                            "records": count,
                            "query_number": query_number,
                            "groups": metadata.groups,
                            "HE_key_id": pk.key_id,
                            "snapshot_id": enrollment.snapshot_id.hex(),
                            "epoch": epoch,
                            "native_stats": asdict(enrollment.stats),
                            "enrollment": enrollment_pin,
                            "original_request": lab.write_new(
                                args.out_dir / (label + ".request"), original
                            ),
                            "complete_reply": lab.write_new(
                                args.out_dir / (label + ".reply"), reply
                            ),
                            "whole_GMP_body_sha256": hashlib.sha256(gmp_tape.body).hexdigest(),
                            "exact_native_GMP_all_source_output_bytes_equal": True,
                            "exact_native_GMP_full_terminal_frame_equal": True,
                            "complete_public_admission_then_durable_callback_claim": True,
                            "owner_private_diagnostics": private_results[0],
                            "state": state["state"],
                            "process_high_water_RSS_bytes_not_native_peak_or_timing": resource.getrusage(
                                resource.RUSAGE_SELF
                            ).ru_maxrss
                            * 1024,
                        }
                        lab.json_new(args.out_dir / (label + ".return.json"), row)
                        results.append(row)
                        print(label, "complete", flush=True)
                        del (
                            gmp_tape,
                            native_body,
                            reply,
                            authorization,
                            private_results,
                            owner_hook,
                            expected,
                        )
                del signed, gmp, index_body
            assert journal.summary() == {"attempts": 6, "authorizations": 6, "callback_claims": 6}
        assert searches == SEARCH_CAP and len(results) == SEARCH_CAP
        assert [lab.pin(Path(row["file"])) for row in frozen] == frozen
        # Secrets are confined to this process and are never archive members.
        del sk, owner
    except BaseException as error:
        lab.json_new(
            args.out_dir / "failed.json",
            {
                "complete": False,
                "error_type": type(error).__name__,
                "search_attempts": searches,
                "completed_searches": len(results),
                "fresh_HE_key_attempts": 1,
                "results": results,
                "silent_restart_or_new_key_not_authorized": True,
            },
        )
        raise
    complete = {
        **started,
        "utc_completed": datetime.now(UTC).isoformat(),
        "complete": True,
        "fresh_HE_key_contexts": 1,
        "search_attempts": searches,
        "complete_searches": len(results),
        "all_distance_comparisons": sum(row["records"] for row in results),
        "secret_keys_serialized": 0,
        "results": results,
        "scope": "Source-scale whole-Q arithmetic/full-frame/owner-only private correctness under local lifecycle; no timing/actual TEE/security or parameter approval/original main result",
        "next": "Q76.4_matched_controls_then_Q76.5_certificate_handoff",
    }
    lab.json_new(args.out_dir / "Q76.3b-source-correctness.json", complete)
    print("Q76.3b complete six searches; no timing or security approval", flush=True)


if __name__ == "__main__":
    main()
