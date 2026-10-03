#!/usr/bin/env python3
"""Fixed source-profile correctness fixture for the native complete controls.

No timing or production parameter claim. The local owner and plaintext truth
stay outside the verifier. Public/reference operations use existing homemade
CPU arithmetic; the reference shares low-level RNS routines with the new code,
so equality is supplemented by independent plaintext Hamming distances.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import sys
from typing import Any, Callable
import msgpack

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experiments.bfv_search_lab import butterfly_bgv as butterfly  # noqa: E402
from experiments.bfv_search_lab import compact_bgv as compact  # noqa: E402
from experiments.bfv_search_lab import native_bgv  # noqa: E402
from experiments.bfv_search_lab import owner_bgv  # noqa: E402
from experiments.bfv_search_lab import shallow_bgv as bgv  # noqa: E402
from experiments.bfv_search_lab import trace_bgv as trace  # noqa: E402
from experiments.bfv_search_lab import native_complete_checked_bgv as complete  # noqa: E402

N = 16384
COUNT = 8192
DIMENSION = 512
PADDED = 512
QUERY_DROP = 0  # Preserve the four-field owner-seeded source query format.
TERMINAL_BITS = 25
PLAINTEXT_SEED = 202610030156
QUERY_COUNT = 3
EPOCH = "Q56-native-source-correctness-20261003"


@dataclass(frozen=True)
class SourceFixture:
    """In-memory local-owner fixture; never serialize this entire object."""

    context: Any
    pk: bgv.PublicKey
    index: tuple[bgv.Ciphertext, ...]
    keys: trace.EvaluationKeys
    query_packets: tuple[bytes, ...]
    truths: tuple[tuple[int, ...], ...]
    owner: owner_bgv.OwnerClient = field(repr=False, compare=False)
    public_metadata: dict[str, Any]

    def close(self) -> None:
        self.owner.close()

    def __reduce_ex__(self, protocol):
        raise TypeError("The local-owner source fixture cannot be serialized")


def build_source_fixture(
    context_factory: Callable[..., Any] | None = None,
    *,
    progress: Callable[[str], None] | None = None,
) -> SourceFixture:
    """Build one frozen geometry with fixed plaintext and fresh OS HE entropy.

    ``context_factory`` receives only public keys/index/metadata, through keyword
    arguments. It never receives the secret key or owner. The caller provides
    the native controller's explicit enrollment constructor.
    """
    announce = progress or (lambda _: None)
    rng = random.Random(PLAINTEXT_SEED)
    words = tuple(rng.getrandbits(DIMENSION) for _ in range(COUNT))
    query_words = tuple(rng.getrandbits(DIMENSION) for _ in range(QUERY_COUNT))
    truth = tuple(tuple((word ^ query).bit_count() for word in words) for query in query_words)
    plaintext_body = b"".join(word.to_bytes(DIMENSION // 8, "little") for word in words)
    query_body = b"".join(word.to_bytes(DIMENSION // 8, "little") for word in query_words)
    announce("Generating one fresh owner key and public evaluation keys")
    pk, sk = bgv.key_gen(N, t=1031, q_bits=120, rns_modulus=True)
    keys = trace.evaluation_keys(pk, sk, PADDED, 30)
    if format(pk.q, "x") != "ffffffffffc00020000003bffc0001":
        raise AssertionError("Source Q120 native modulus differs from the frozen profile")
    announce("Encoding and public-key encrypting 8192 rows into 256 index tiles")
    rows = [[(word >> bit) & 1 for bit in range(DIMENSION)] for word in words]
    _, plaintexts = bgv.coefficient_inputs([0] * DIMENSION, rows, N)
    index = tuple(bgv.encrypt(plaintext, pk) for plaintext in plaintexts)
    del rows, plaintexts, plaintext_body
    if len(index) != 256:
        raise AssertionError("Source index coverage changed")
    owner = owner_bgv.OwnerClient(pk, sk, native=True, rns=True)
    del sk
    try:
        owner.prepare_terminal(TERMINAL_BITS)
        announce("Creating three fresh owner-seeded source-format queries")
        packets = []
        for word in query_words:
            query = [(word >> bit) & 1 for bit in range(DIMENSION)]
            encoded, _ = bgv.coefficient_inputs(query, [], N)
            original = owner.encrypt(encoded)
            packets.append(original)
        factory = context_factory or complete.NativeContext.from_bgv
        context = factory(
            pk=pk,
            keys=keys,
            index=index,
            count=COUNT,
            dimension=DIMENSION,
            query_drop=QUERY_DROP,
            p=int(compact.terminal_modulus(pk.q, pk.t, TERMINAL_BITS)),
            epoch=EPOCH,
        )
        metadata = {
            "n": N,
            "t": pk.t,
            "q_hex": format(pk.q, "x"),
            "eta": pk.eta,
            "padded": PADDED,
            "dimension": DIMENSION,
            "count": COUNT,
            "index_tiles": len(index),
            "response_groups": 1,
            "unused_score_positions": N - COUNT,
            "query_count": QUERY_COUNT,
            "query_drop": QUERY_DROP,
            "query_rounding_added_bound": 0,
            "terminal_bits": TERMINAL_BITS,
            "terminal_modulus": int(compact.terminal_modulus(pk.q, pk.t, TERMINAL_BITS)),
            "key_id": pk.key_id,
            "epoch": EPOCH,
            "plaintext_seed": PLAINTEXT_SEED,
            "plaintext_body_sha256": hashlib.sha256(
                b"".join(word.to_bytes(DIMENSION // 8, "little") for word in words)
            ).hexdigest(),
            "query_plaintext_body_sha256": hashlib.sha256(query_body).hexdigest(),
            "query_packet_sha256": [hashlib.sha256(packet).hexdigest() for packet in packets],
            "index_law": "fresh public-key encryption",
            "query_law": "fresh owner-seeded encryption, original four-field source packet",
            "secret_serialized": False,
            "scientific_timing": False,
        }
        return SourceFixture(context, pk, index, keys, tuple(packets), truth, owner, metadata)
    except BaseException:
        owner.close()
        raise


@dataclass(frozen=True)
class ReferenceOutput:
    packet: bytes
    reduced_bounds: tuple[int, ...]
    original_bounds: tuple[int, ...]
    distances: tuple[int, ...]
    top: tuple[tuple[int, int], ...]


def reference_outputs(
    fixture: SourceFixture, *, progress: Callable[[str], None] | None = None
) -> tuple[ReferenceOutput, ...]:
    """Existing public CPU evaluator, then local-owner plaintext comparison.

    This is an external correctness comparator. Its expected packet must never
    be substituted for the controller's product checks or admission decision.
    """
    announce = progress or (lambda _: None)
    server = native_bgv.NativeServer(fixture.pk, fixture.keys, residue=True, device="cpu")
    prepared = server.prepare_index(list(fixture.index), COUNT)
    results = []
    for number, packet in enumerate(fixture.query_packets):
        announce(f"Public CPU reference and outside-verifier owner decode: query {number + 1}/3")
        expanded = owner_bgv.expand(packet, fixture.pk)
        original = butterfly.response_bounds(
            expanded, list(fixture.index), COUNT, fixture.pk, fixture.keys
        )
        output = server.search_compact(expanded, prepared, joint=True, bits=TERMINAL_BITS)
        expected_packet = compact.pack(output, COUNT, DIMENSION, fixture.pk)
        # This deterministic locally generated reference is the only object sent
        # to this diagnostic owner. No server-controlled candidate reaches it.
        result = fixture.owner.finish(output, COUNT, DIMENSION, all_distances=True)
        distances = tuple(result.distances)
        truth = fixture.truths[number]
        top = tuple((i, truth[i]) for i in sorted(range(COUNT), key=lambda i: (truth[i], i))[:3])
        if distances != truth or tuple(result.top) != top:
            raise AssertionError(
                "Source-profile local reference differs from independent plaintext truth"
            )
        results.append(
            ReferenceOutput(
                expected_packet,
                tuple(c.phase_bound for c in output),
                tuple(original),
                distances,
                top,
            )
        )
    return tuple(results)


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(4 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_public_fixture(fixture: SourceFixture, path: Path) -> dict[str, Any]:
    """Stream the exact public enrolled arithmetic; never serialize the owner."""
    context = fixture.context
    packer = msgpack.Packer(use_bin_type=True)
    metadata = {
        name: getattr(context, name)
        for name in (
            "n",
            "t",
            "primes",
            "padded",
            "dimension",
            "digit_bits",
            "query_drop",
            "p",
            "key_id",
            "epoch",
            "ids",
        )
    }
    metadata["q_hex"] = format(context.q, "x")
    metadata["context_digest"] = context.digest().hex()
    metadata["polynomial_encoding"] = "N canonical full-Q little-endian 15-byte coefficients"

    def polynomial(poly):
        return b"".join(c.to_bytes(15, "little") for c in poly)

    with path.open("xb") as file:

        def write(value):
            file.write(packer.pack(value))

        def pair(value):
            file.write(packer.pack_array_header(2))
            for poly in value:
                write(polynomial(poly))

        def key(value):
            file.write(packer.pack_array_header(len(value)))
            for column in value:
                pair(column)

        file.write(packer.pack_map_header(4))
        write("metadata")
        write(metadata)
        write("index")
        file.write(packer.pack_array_header(len(context.index)))
        for cipher in context.index:
            pair(cipher)
        write("relin")
        key(context.relin)
        write("rotations")
        file.write(packer.pack_array_header(len(context.rotations)))
        for exponent, columns in context.rotations:
            file.write(packer.pack_array_header(2))
            write(exponent)
            key(columns)
        file.flush()
        os.fsync(file.fileno())
    return {
        "path": str(path),
        "sha256": file_sha(path),
        "bytes": path.stat().st_size,
        "secret_material": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-library", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.out_dir.resolve()
    permitted = (
        ROOT.parent / "research-data/native-verification-system-20261003/native/source-geometry"
    )
    if output != permitted.resolve():
        raise ValueError("Use the new source-geometry folder; older evidence is frozen")
    registration = json.loads(args.preregistration.read_text())
    if (
        registration["profile"]
        != {
            "n": N,
            "count": COUNT,
            "dimension": DIMENSION,
            "padded": PADDED,
            "t": 1031,
            "q_bits": 120,
            "digit_bits": 30,
            "query_drop": QUERY_DROP,
            "terminal_bits": TERMINAL_BITS,
            "query_count": QUERY_COUNT,
            "plaintext_seed": PLAINTEXT_SEED,
        }
        or registration["max_main"] != 1
        or registration["max_retry"] != 0
    ):
        raise ValueError("Source registration differs from the fixed correctness cohort")
    for record in registration["inputs"]:
        path = Path(record["path"])
        if hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
            raise ValueError(f"Pinned input changed: {path}")
    output.mkdir(parents=True, exist_ok=True)
    attempt = output / "attempt.json"
    ledger_path = output / "ledger.jsonl"
    result_path = output / "results.json"
    if any(p.exists() for p in (attempt, ledger_path, result_path)):
        raise ValueError("Never repeat or overwrite the source correctness cohort")
    with attempt.open("x") as file:
        json.dump(
            {
                "max_main": 1,
                "max_retry": 0,
                "scientific_timing": False,
                "preregistration_sha256": hashlib.sha256(
                    args.preregistration.read_bytes()
                ).hexdigest(),
            },
            file,
        )
        file.write("\n")
        file.flush()
        os.fsync(file.fileno())

    def record(stage, **fields):
        item = {"stage": stage, **fields}
        with ledger_path.open("a") as file:
            file.write(json.dumps(item, sort_keys=True) + "\n")
            file.flush()
            os.fsync(file.fileno())
        print(stage, flush=True)

    fixture = None
    try:
        record("begin", scientific_timing=False, secret_serialized=False)
        fixture = build_source_fixture(progress=lambda message: record(message))
        record("fixture-created", public_metadata=fixture.public_metadata)
        public_record = save_public_fixture(fixture, output / "public-fixture.msgpack")
        for number, packet in enumerate(fixture.query_packets):
            (output / f"query-{number}.msgpack").write_bytes(packet)
        record("exact-public-fixture-retained", artifact=public_record)
        references = reference_outputs(fixture, progress=lambda message: record(message))
        backend = complete.load_backend(args.native_library)
        enrollment = complete.Enrollment(
            fixture.context, backend=backend, block_size=64, max_requests=8
        )
        resources = enrollment.resource_ledger()
        record("native-enrollment-ready", resources=resources)
        results = []
        for number, (query, expected) in enumerate(
            zip(fixture.query_packets, references, strict=True)
        ):
            (output / f"reference-response-{number}.msgpack").write_bytes(expected.packet)
            record("source-query-begin", query=number)
            replay = enrollment.replay(query)
            if replay != expected.packet:
                raise AssertionError(
                    "Prepared native replay differs from the historical public CPU packet"
                )
            request_id = hashlib.sha256(
                b"Q56-source-request-v1\0" + number.to_bytes(4, "little")
            ).digest()
            request = enrollment.begin(query, request_id)
            blocks = request.produce_blocks()
            sentinels = []
            result = request.admit_once(
                blocks, claimed_response=expected.packet, release_sentinel=sentinels.append
            )
            if result.packet != expected.packet or sentinels != [expected.packet]:
                raise AssertionError(
                    "Checked native full packet/sentinel differs from authoritative public bytes"
                )
            # Local fixture gate pins EVERY response byte before private work.
            final = fixture.owner.finish_packed_fixture(
                result.packet,
                expected.packet,
                COUNT,
                DIMENSION,
                bounds=list(expected.reduced_bounds),
                bits=TERMINAL_BITS,
                all_distances=True,
            )
            if tuple(final.distances) != fixture.truths[number] or tuple(final.top) != expected.top:
                raise AssertionError(
                    "Admitted source response differs from independent plaintext truth"
                )
            row = {
                "query": number,
                "query_sha256": hashlib.sha256(query).hexdigest(),
                "response_sha256": hashlib.sha256(result.packet).hexdigest(),
                "statement_digest": result.statement_digest.hex(),
                "query_bytes": len(query),
                "response_bytes": len(result.packet),
                "product_body_bytes": result.product_body_bytes,
                "block_coverage": result.block_coverage,
                "suffix_counts": result.suffix_counts,
                "all_distances_correct": COUNT,
                "top3": [list(pair) for pair in expected.top],
                "original_phase_bounds": expected.original_bounds,
                "reduced_phase_bounds": expected.reduced_bounds,
                "sentinel_calls": len(sentinels),
                "native_replay_equal": True,
                "historical_public_cpu_packet_equal": True,
            }
            results.append(row)
            record("source-query-complete", **row)
        report = {
            "scope": "one-key three-query source-geometry correctness cohort",
            "scientific_timing": False,
            "latency_winner_claim": False,
            "parameter_security_approval": False,
            "attestation_or_receipt": False,
            "secret_serialized": False,
            "owner_decryptions_outside_verifier": 2 * QUERY_COUNT,
            "public_metadata": fixture.public_metadata,
            "resource_ledger": resources,
            "public_fixture": public_record,
            "queries": results,
            "all_distances_correct": COUNT * QUERY_COUNT,
            "native_complete_terminal_coordinates": N * 2 * QUERY_COUNT,
            "preregistration_sha256": hashlib.sha256(args.preregistration.read_bytes()).hexdigest(),
            "shared_arithmetic_reference_limit": "Historical public CPU backend and new complete backend share low-level RNS arithmetic; plaintext truth is independent.",
        }
        with result_path.open("x") as file:
            json.dump(report, file, indent=2, sort_keys=True)
            file.write("\n")
        record(
            "complete",
            all_distances_correct=COUNT * QUERY_COUNT,
            terminal_coordinates=N * 2 * QUERY_COUNT,
        )
    except BaseException as error:
        record("failed", error_type=type(error).__name__, error=str(error), retry_permitted=False)
        raise
    finally:
        if fixture is not None:
            fixture.close()


if __name__ == "__main__":
    main()
