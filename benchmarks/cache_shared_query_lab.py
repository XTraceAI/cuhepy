"""Q76.4c retained public cache correctness/accounting, deliberately not timing.

No HE implementation is imported. Small expected encoded scores are decoded
with public t/d; large saved HE evidence supplies top3 only. Complete cache
distances use an independent plaintext reference. Support keys are fresh but
never serialized; replaying this runner does not restore their key context.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import gzip
import hashlib
import json
from pathlib import Path
import secrets
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def pin(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return {"file": str(path), "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def verify(path, baseline):
    actual = pin(path)
    assert actual in baseline["retained_inputs"], (path, "Not a registered pinned input")
    return actual


def write_json(path, value):
    assert not path.exists()
    path.write_text(json.dumps(value, indent=2) + "\n")


def scores_reference(rows, dimension, query, literal=False):
    if literal:
        return tuple(
            sum(((row >> bit) & 1) != ((query >> bit) & 1) for bit in range(dimension))
            for row in rows
        )
    return tuple((row ^ query).bit_count() for row in rows)


def inspect_query(owner, rows, ids, query, label, *, literal=False):
    got = owner.query(query)
    scores = scores_reference(rows, owner.current_context.dimension, query, literal)
    positions = tuple(sorted(range(len(rows)), key=lambda i: (scores[i], i))[:3])
    top = tuple((scores[i], ids[i]) for i in positions)
    assert got.scores == scores and got.top3_positions == positions and got.top3 == top
    packed = b"".join(struct.pack("<H", value) for value in got.scores)
    return {
        "label": label,
        "records": len(rows),
        "dimension": owner.current_context.dimension,
        "all_distances_compared": len(rows),
        "all_scores_equal_independent_plaintext": True,
        "top3_positions": list(got.top3_positions),
        "top3": [list(x) for x in got.top3],
        "all_score_UInt16_bytes_sha256": hashlib.sha256(packed).hexdigest(),
        "context_encoding_sha256": hashlib.sha256(got.context.encode()).hexdigest(),
    }


def preserve_delivery(out, label, delivery):
    packet, descriptor = out / f"{label}.packet.bin", out / f"{label}.descriptor.bin"
    assert not packet.exists() and not descriptor.exists()
    packet.write_bytes(delivery.packet)
    descriptor.write_bytes(delivery.descriptor)
    return {
        "packet": pin(packet),
        "descriptor": pin(descriptor),
        "context_encoding_bytes": len(delivery.context.encode()),
        "raw_body_bytes": delivery.context.raw_body_bytes,
        "snapshot_id": delivery.context.snapshot_id.hex(),
        "epoch": delivery.context.epoch,
    }


def main():
    from experiments.bfv_search_lab.authenticated_cache import (
        CacheClient,
        NativePopcount,
        seal_snapshot,
        seal_update,
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--execution-freeze", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists(), "Keep failed attempts; never overwrite a cohort"
    baseline = json.loads(args.baseline.read_text())
    freeze = json.loads(args.execution_freeze.read_text())
    for entry in freeze["executed_sources"] + [freeze["normal_library"]]:
        assert pin(Path(entry["file"])) == entry
    assert pin(args.library.resolve()) == freeze["normal_library"]
    assert not any(
        name.startswith(("cuhepy.bgv", "cuhepy.bfv", "src.cuhepy", "xtrace_sdk"))
        for name in sys.modules
    )
    # Preflight all retained inputs before generating the single support context.
    for entry in baseline["retained_inputs"]:
        assert pin(Path(entry["file"])) == entry
    work = ROOT.parent
    small_dir = work / "research-data/shared-query-admission-20261004/q74"
    report = json.loads((small_dir / "Q74-correctness.json").read_text())
    public = json.loads(gzip.decompress((small_dir / "public-fixtures.json.gz").read_bytes()))
    selected = [
        x
        for x in report["results"]
        if x["profile"]["index_mode"] == "owner" and x["profile"]["policy"] == "canonical30"
    ]
    assert len(selected) == 16
    source_dir = work / "research-data/q76-source-scale-20261004/source-cohort1"
    source = json.loads((source_dir / "Q76.3b-source-correctness.json").read_text())
    packed_rows = (source_dir / "public-binary-rows.bin").read_bytes()
    public_queries = json.loads((source_dir / "public-binary-queries.json").read_text())
    assert len(packed_rows) == 32768 * 64 and len(public_queries) == 2
    source_rows = tuple(
        int.from_bytes(packed_rows[at : at + 64], "little") for at in range(0, len(packed_rows), 64)
    )
    source_queries = tuple(int.from_bytes(bytes.fromhex(word), "little") for word in public_queries)
    assert source["complete_searches"] == 6 and source["complete"]
    args.output.mkdir()
    key = AESGCMSIV.generate_key(bit_length=256)
    signer = Ed25519PrivateKey.generate()
    anchor = signer.public_key().public_bytes_raw()
    native = NativePopcount(args.library)
    summary = {
        "task": "Q76.4c",
        "utc": datetime.now(UTC).isoformat(),
        "scope": "Retained public cache correctness and canonical body accounting only",
        "registration": baseline["registration"],
        "baseline": pin(args.baseline),
        "execution_freeze": pin(args.execution_freeze),
        "library": pin(args.library.resolve()),
        "standard_owner_public_key": anchor.hex(),
        "supporting_standard_Ed25519_contexts": 1,
        "supporting_standard_AES256_contexts": 1,
        "AES_or_signing_secret_keys_serialized": False,
        "fresh_HE_keys": 0,
        "private_HE_work": 0,
        "timing_panels": 0,
        "CUDA_runs": 0,
        "HE_backend_imports": False,
        "snapshots": [],
        "queries": [],
        "updates": [],
        "complete": False,
    }
    write_json(args.output / "started.json", summary)
    key_id = secrets.token_bytes(32)
    for case in selected:
        saved_path = small_dir / case["fixture"]["file"]
        saved = json.loads(gzip.decompress(saved_path.read_bytes()))
        origin = next(x for x in public if x["public_key"]["key_id"] == case["key_context"])
        dimension, t = origin["geometry"]["dimension"], origin["geometry"]["t"]
        assert t > 2 * dimension
        query_number = int(case["id"].split("-q")[1].split("-")[0])
        rows = tuple(
            sum(bit << j for j, bit in enumerate(row))
            for row in origin["synthetic_rows"][: case["records"]]
        )
        query = sum(bit << j for j, bit in enumerate(origin["synthetic_query_bits"][query_number]))
        ids = tuple(saved["context"]["ids"])
        reference = scores_reference(rows, dimension, query, literal=True)
        centered = tuple(
            value if value <= t // 2 else value - t for value in saved["expected_scores"]
        )
        assert all(
            -dimension <= value <= dimension and (dimension - value) % 2 == 0 for value in centered
        )
        decoded = tuple((dimension - value) // 2 for value in centered)
        assert decoded == reference
        delivery = seal_snapshot(
            rows,
            ids,
            dimension,
            key,
            signer,
            namespace=secrets.token_bytes(32),
            key_id=key_id,
            snapshot_id=secrets.token_bytes(32),
            epoch=1,
        )
        owner = CacheClient(native, key, anchor, delivery.context)
        owner.acquire(delivery.packet, delivery.descriptor)
        row = inspect_query(owner, rows, ids, query, case["id"], literal=True)
        row["saved_full_encoded_HE_scores_publicly_decoded_equal"] = True
        row["retained_fixture"] = verify(saved_path, baseline)
        summary["queries"].append(row)
        packet = preserve_delivery(args.output, case["id"], delivery)
        packet["inventory"] = owner.inventory()
        summary["snapshots"].append(packet)
        owner.close()
    for count in (8224, 16384, 32768):
        rows = source_rows[:count]
        ids = tuple((1 << 64) - 1 - i for i in range(count))
        delivery = seal_snapshot(
            rows,
            ids,
            512,
            key,
            signer,
            namespace=secrets.token_bytes(32),
            key_id=key_id,
            snapshot_id=secrets.token_bytes(32),
            epoch=1,
        )
        owner = CacheClient(native, key, anchor, delivery.context)
        owner.acquire(delivery.packet, delivery.descriptor)
        packet = preserve_delivery(args.output, f"m{count}", delivery)
        packet["inventory"] = owner.inventory()
        summary["snapshots"].append(packet)
        for q, word in enumerate(source_queries):
            label = f"m{count}-q{q}"
            row = inspect_query(owner, rows, ids, word, label)
            historical = next(x for x in source["results"] if x["label"] == label)[
                "owner_private_diagnostics"
            ]
            assert row["top3_positions"] == historical["stable_top3_positions"]
            assert [x[1] for x in row["top3"]] == historical["stable_top3_ids"]
            assert [x[0] for x in row["top3"]] == historical["stable_top3_distances"]
            row["saved_HE_top3_equal"] = True
            row["new_complete_private_HE_score_vector_comparison"] = False
            summary["queries"].append(row)
        changes = tuple((i, source_queries[i % 2] ^ 1) for i in range(32))
        assert all(rows[i] != word for i, word in changes)
        patch = seal_update(
            changes, key, signer, delivery.context, snapshot_id=secrets.token_bytes(32)
        )
        owner.pin_current(patch.context)
        try:
            owner.query(source_queries[0])
        except ValueError:
            pass
        else:
            raise AssertionError("Old cache remained active after trusted epoch advance")
        owner.apply_update(patch.packet, patch.descriptor)
        revised = list(rows)
        for i, word in changes:
            revised[i] = word
        revised = tuple(revised)
        for q, word in enumerate(source_queries):
            row = inspect_query(owner, revised, ids, word, f"m{count}-update32-q{q}")
            assert row["top3_positions"] == ([0, 2, 4] if q == 0 else [1, 3, 5])
            row["update_context"] = patch.context.snapshot_id.hex()
            summary["queries"].append(row)
        data = preserve_delivery(args.output, f"m{count}-patch32", patch)
        data["updated_rows"] = 32
        data["patch_plaintext_body_bytes"] = 2 + 32 * (4 + 64)
        data["inventory"] = owner.inventory()
        # raw_body_bytes in a patch's context is the full snapshot geometry,
        # not its patch body. Keep both explicit, never call it the wire size.
        data["full_snapshot_geometry_bytes_not_patch_body"] = data.pop("raw_body_bytes")
        summary["updates"].append(data)
        owner.close()
    native.close()
    assert len(summary["snapshots"]) == 19 and len(summary["updates"]) == 3
    assert len(summary["queries"]) == 28
    summary["complete"] = True
    summary["utc_completed"] = datetime.now(UTC).isoformat()
    summary["all_distance_comparisons"] = sum(
        x["all_distances_compared"] for x in summary["queries"]
    )
    assert summary["all_distance_comparisons"] == 229980
    summary["small_cases"] = 16
    summary["saved_source_queries"] = 6
    summary["post_update_queries"] = 6
    summary["fresh_support_keys_reproduce_answers_but_do_not_restore_archived_key_context"] = True
    summary["scope_qualification"] = (
        "Native/cache answers equal independent plaintext; only 16 saved small encoded score vectors and six saved large top3 are compared to historical HE evidence. No new HE decryption or complete saved large private vector check. Signatures/AEAD protect cache delivery; this control does not authenticate HE output or deploy freshness/attestation."
    )
    write_json(args.output / "Q76.4c-retained-cache.json", summary)
    print(
        json.dumps(
            {
                "complete": True,
                "queries": 28,
                "all_distances": summary["all_distance_comparisons"],
                "snapshots": 19,
                "patches": 3,
                "new_HE_or_timing": 0,
            }
        )
    )


if __name__ == "__main__":
    main()
