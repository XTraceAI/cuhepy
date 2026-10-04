"""Q76.5 retained static handoff, not an HE or timing benchmark.

Reuses 16 small plus six saved source-scale cases across three legal modes.
Checks public metadata, independent certificates and compact descriptors, and
cross-checks resource counts against archived packets/stats. No HE/native
backend is imported or executed; one fresh standard signing context is used.
Historical correctness is referenced, not rerun or counted as a new HE result.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import gzip
import hashlib
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import msgpack

from experiments.bfv_search_lab import shared_query_certificate as cert
from experiments.bfv_search_lab import shared_query_client_context as client


def pin(path):
    path = Path(path).resolve(strict=True)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return {"file": str(path), "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def _verify_pin(entry):
    assert pin(entry["file"]) == entry, "Retained public input changed"


def _read_bin_header(stream, maximum):
    # Prefix extraction from a complete SHA-pinned historical enrollment only.
    # This is not a general wire verifier or an independent signature check.
    code = stream.read(1)
    widths = {b"\xc4": 1, b"\xc5": 2, b"\xc6": 4}
    if code not in widths:
        raise ValueError("Historical enrollment is not canonical binary MessagePack")
    raw = stream.read(widths[code])
    if len(raw) != widths[code]:
        raise ValueError("Truncated historical prefix")
    size = int.from_bytes(raw, "big")
    if not 1 <= size <= maximum:
        raise ValueError("Historical prefix exceeds selected cap")
    return size


def _enrollment_prefix(entry):
    """Extract complete public IDs without materializing hundreds of MiB of keys."""
    _verify_pin(entry)
    with Path(entry["file"]).open("rb") as stream:
        assert stream.read(1) == b"\x93"
        tag_length = _read_bin_header(stream, 64)
        assert stream.read(tag_length) == b"cuhepy-q76-owner-enrollment-v1"
        payload_size = _read_bin_header(stream, 1 << 31)
        unpacker = msgpack.Unpacker(
            raw=False,
            max_array_len=8,
            max_bin_len=262144,
            max_map_len=0,
            max_str_len=0,
            max_ext_len=0,
        )
        read = 0

        def get(operation):
            nonlocal read
            while True:
                try:
                    return operation()
                except msgpack.OutOfData:
                    size = min(4096, payload_size - read)
                    assert size > 0 and read <= 270336
                    raw = stream.read(size)
                    assert len(raw) == size
                    read += size
                    unpacker.feed(raw)

        assert get(unpacker.read_array_header) == 8
        return tuple(get(unpacker.unpack) for _ in range(6))


def _cache_context(snapshot, anchor):
    entry = snapshot["descriptor"]
    _verify_pin(entry)
    raw = Path(entry["file"]).read_bytes()
    assert len(raw) == 288
    body, signature = raw[:-64], raw[-64:]
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(anchor)).verify(signature, body)
    prefix = b"cuhepy/cache-delivery/v1\0" + b"\x01" + b"cuhepy/cache-context/v1\0"
    assert body.startswith(prefix)
    at = len(prefix)
    namespace, key_id, snapshot_id = (body[at + j * 32 : at + (j + 1) * 32] for j in range(3))
    at += 96
    epoch, count, dimension = struct.unpack("<QIH", body[at : at + 14])
    at += 14
    ordered_ids_digest = body[at : at + 32]
    packet_digest = body[at + 32 : at + 64]
    assert (
        at + 64 == len(body)
        and snapshot_id.hex() == snapshot["snapshot_id"]
        and epoch == snapshot["epoch"]
    )
    _verify_pin(snapshot["packet"])
    assert packet_digest.hex() == snapshot["packet"]["sha256"]
    return (
        namespace,
        count,
        dimension,
        client.CacheBinding(key_id, snapshot_id, epoch, ordered_ids_digest),
    )


def main(owner=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--freeze", type=Path, required=True)
    args = parser.parse_args()
    workspace, output = args.workspace.resolve(strict=True), args.output
    assert not output.exists(), "Never overwrite retained evidence"
    frozen = json.loads(args.freeze.read_text())
    for entry in frozen["executed_sources"] + frozen["retained_handoff_inputs"]:
        _verify_pin(entry)
    output.mkdir(parents=True)
    root = workspace / "research-data"
    small_root = root / "shared-query-admission-20261004/q74"
    full_small = json.loads(
        (
            root
            / "q76-authenticated-factory-20261004/retained-cohort1/Q76.2-authenticated-core.json"
        ).read_text()
    )
    full_large = json.loads(
        (
            root / "q76-source-scale-20261004/source-cohort1/Q76.3b-source-correctness.json"
        ).read_text()
    )
    replay = json.loads(
        (root / "q76-replay-20261004/retained-cohort1/Q76.4a-retained-replay.json").read_text()
    )
    aggregate = json.loads(
        (
            root / "q76-aggregate-20261004/retained-cohort1/Q76.4b-retained-aggregate.json"
        ).read_text()
    )
    cache = json.loads(
        (root / "q76-cache-20261004/retained-cohort1/Q76.4c-retained-cache.json").read_text()
    )
    small_profiles = json.loads(
        gzip.decompress((small_root / "public-fixtures.json.gz").read_bytes())
    )
    assert all(report["complete"] for report in (full_small, full_large, replay, aggregate, cache))
    small = {row["id"]: row for row in full_small["results"]}
    large = {row["label"]: row for row in full_large["results"]}
    replays = {row["label"]: row for row in replay["results"]}
    aggregates = {row["label"]: row for row in aggregate["results"]}
    snapshots = {
        Path(row["descriptor"]["file"]).name.removesuffix(".descriptor.bin"): row
        for row in cache["snapshots"]
    }
    assert (
        len(small) == 16
        and len(large) == 6
        and set(small) | set(large) == set(replays) == set(aggregates)
    )
    # Exactly one fresh standard Ed25519 signing context. No HE/symmetric key
    # or previous private context is restored or serialized by this metadata run.
    if owner is None:
        owner = Ed25519PrivateKey.generate()
    elif not isinstance(owner, Ed25519PrivateKey):
        raise ValueError("Explicit standard cohort signing context required")
    anchor = owner.public_key().public_bytes_raw()
    result = {
        "task": "Q76.5",
        "utc": datetime.now(UTC).isoformat(),
        "freeze": pin(args.freeze),
        "scope": "Retained static declarations, compact public client metadata and component resource counts",
        "standard_owner_public_key": anchor.hex(),
        "fresh_standard_Ed25519_contexts": 1,
        "fresh_HE_keys_encryptions_decryptions_native_evaluations_builds_timing_CUDA": 0,
        "fresh_symmetric_contexts": 0,
        "private_keys_serialized": False,
        "results": [],
    }
    historical_input_pins = {}
    for label in sorted(set(small) | set(large)):
        is_small = label in small
        full = small[label] if is_small else large[label]
        records = replays[label]["records"]
        if is_small:
            fixture = full["fixture"]
            _verify_pin(fixture)
            saved = json.loads(gzip.decompress(Path(fixture["file"]).read_bytes()))["context"]
            index = int(label[1])
            profile = cert.geometry(index)
            ids = tuple(saved["ids"])
            assert profile.primes == tuple(small_profiles[index]["ordered_primes"])
            assert (
                saved["profile"]["n"],
                saved["profile"]["dimension"],
                saved["profile"]["q"],
                saved["profile"]["p"],
            ) == (profile.n, profile.dimension, profile.q, profile.p)
            prefix = _enrollment_prefix(full["enrollment"])
            snapshot = full["binding"]["snapshot_id"]
            policy = full_small["policy_digest"]
            library = full_small["library"]
            enrollment = full["enrollment"]
        else:
            profile = cert.geometry(2)
            prefix = _enrollment_prefix(full["enrollment"])
            assert (
                full_large["selected_profile"]["q"] == profile.q
                and tuple(full_large["ordered_primes"]) == profile.primes
            )
            ids = tuple(x[0] for x in struct.iter_unpack("<Q", prefix[3]))
            snapshot = full["snapshot_id"]
            policy = full_large["authentication_policy_digest"]
            library = full_large["library"]
            enrollment = full["enrollment"]
            assert ids == tuple(cert.UINT64_MAX - i for i in range(records))
        raw_ids = b"".join(struct.pack("<Q", x) for x in ids)
        assert len(ids) == records and prefix[3] == raw_ids and tuple(prefix[1]) == profile.primes
        key_id = prefix[2]
        assert prefix[5].hex() == policy and prefix[4] == (1 if is_small else full["epoch"])
        assert (
            key_id.hex()
            == (full["key_context"] if is_small else full["HE_key_id"])
            == replays[label]["HE_key_id"]
            == aggregates[label]["HE_key_id"]
        )
        cache_label = label if is_small else label.split("-q")[0]
        snapshot_cache = snapshots[cache_label]
        namespace, cache_count, dimension, cache_binding = _cache_context(
            snapshot_cache, cache["standard_owner_public_key"]
        )
        assert cache_count == records and dimension == profile.dimension
        assert cache_binding.ordered_ids_digest == client.cache_ids_digest(raw_ids, records)
        modes, packets, descriptions = [], [], []
        for number, mode in enumerate(cert.MODES):
            previous = (full, replays[label], aggregates[label])[number]
            previous_report = (full_small if is_small else full_large, replay, aggregate)[number]
            mode_snapshot = snapshot if number == 0 else previous["snapshot_id"]
            mode_policy = policy if number == 0 else previous_report["authentication_policy_digest"]
            mode_library = library if number == 0 else previous_report["library"]
            _verify_pin(mode_library)
            historical_input_pins[mode_library["file"]] = mode_library
            selected = cert.TrustedPlan(
                profile,
                records,
                key_id,
                hashlib.sha256(raw_ids).digest(),
                bytes.fromhex(mode_snapshot),
                bytes.fromhex(mode_policy),
                bytes.fromhex(mode_library["sha256"]),
                mode,
            )
            packet = cert.make_certificate(selected)
            checked = cert.check_certificate(
                packet, selected, expected_digest=cert.certificate_digest(packet)
            )
            path = output / f"{label}.mode{number}.certificate.json"
            path.write_bytes(packet)
            packets.append(packet)
            modes.append(
                client.ModeBinding(
                    mode,
                    prefix[4] if number == 0 else previous["epoch"],
                    selected.snapshot_id,
                    selected.policy_digest,
                    selected.code_digest,
                    checked.digest,
                )
            )
            resources = cert.counted_resources(selected)
            if number != 0 or not is_small:
                stats = previous["native_stats"]
                for observed, expected in (
                    ("body_bytes", "full_witness_body_bytes"),
                    ("source_polynomials", "source_polynomials"),
                    ("public_rows", "public_RNS_rows"),
                    ("setup_forward_prime_NTTs", "setup_forward_prime_NTTs"),
                    ("cached_public_row_bytes", "resident_RNS_row_component_bytes"),
                    ("map_and_shift_bytes", "resident_map_shift_component_bytes"),
                ):
                    assert stats[observed] == resources[expected]
            if number == 0 and is_small:
                assert full["expanded_common_Q_index_bytes"] == resources["index_common_bytes"]
                assert (
                    full["expanded_common_Q_query_bytes"]
                    == resources["original_query_common_bytes"]
                )
            if number == 1:
                assert (
                    previous["source_witness_allocated_or_sent_bytes"]
                    == resources["mode_internal_claim_body_bytes"]
                    == 0
                )
            if number == 2:
                assert (
                    previous["aggregate_body_bytes"] == resources["mode_internal_claim_body_bytes"]
                )
            if number != 0:
                assert (
                    previous["coefficient_body_bytes"] == resources["client_coefficient_body_bytes"]
                )
            assert (
                snapshot_cache["packet"]["bytes"] + snapshot_cache["descriptor"]["bytes"]
                == resources["cache_complete_acquisition_bytes"]
            )
            descriptions.append(
                {
                    "mode": mode,
                    "certificate": pin(path),
                    "certificate_digest": checked.digest.hex(),
                    "terminal_support": checked.terminal_support,
                    "resources": resources,
                    "native_graph_nodes_reported_not_proved_by_certificate": None
                    if number == 0 and is_small
                    else previous["native_stats"]["graph_nodes"],
                }
            )
        logical_revision = hashlib.sha256(
            b"Q76.5 retained logical view v1\0" + cache_binding.snapshot_id + key_id
        ).digest()
        compact = client.seal_descriptor(
            ids,
            owner,
            namespace=namespace,
            revision=logical_revision,
            epoch=cache_binding.epoch,
            geometry=profile,
            key_id=key_id,
            cache=cache_binding,
            modes=tuple(modes),
            certificates=tuple(packets),
        )
        with client.DescriptorClient(anchor, compact.pin) as consumer:
            metadata = consumer.acquire(compact.packet)
            assert (
                metadata.ids == ids
                and metadata.key_id == key_id
                and metadata.cache == cache_binding
            )
            assert tuple(metadata.mode(mode) for mode in cert.MODES) == tuple(modes)
        descriptor = output / f"{label}.client-descriptor.msgpack"
        descriptor.write_bytes(compact.packet)
        pin_path = output / f"{label}.trusted-current-pin.json"
        pin_path.write_text(
            json.dumps(
                {
                    "namespace": compact.pin.namespace.hex(),
                    "revision": compact.pin.revision.hex(),
                    "epoch": compact.pin.epoch,
                    "payload_digest": compact.pin.payload_digest.hex(),
                },
                indent=2,
            )
            + "\n"
        )
        historical_input_pins[enrollment["file"]] = enrollment
        result["results"].append(
            {
                "label": label,
                "records": records,
                "dimension": profile.dimension,
                "complete_ordered_ID_bytes": len(raw_ids),
                "client_descriptor": pin(descriptor),
                "trusted_pin": pin(pin_path),
                "modes": descriptions,
                "cache_descriptor": snapshot_cache["descriptor"],
                "all_complete_IDs_and_mode_contexts_checked": True,
                "logical_equivalence": "honest owner premise supported by retained correctness, not a new ciphertext equivalence proof",
                "historic_HE_correctness_rerun_or_private_context_restored": False,
            }
        )
    assert (
        len(result["results"]) == 22 and sum(len(row["modes"]) for row in result["results"]) == 66
    )
    result.update(
        {
            "utc_completed": datetime.now(UTC).isoformat(),
            "complete": True,
            "retained_small_cases": 16,
            "retained_source_scale_cases": 6,
            "static_case_mode_combinations": 66,
            "historical_public_enrollment_and_library_pins": list(historical_input_pins.values()),
            "metadata_does_not_decrypt_authorize_or_attest": True,
            "historical_prefix_extraction_is_not_a_new_full_wire_signature_verifier": True,
            "model_NATIVE_refinement_RLWE_KDM_parameter_and_deployment_assurance_unfinished": True,
        }
    )
    (output / "Q76.5-retained-certificate.json").write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                "retained_cases": 22,
                "static_case_mode_combinations": 66,
                "fresh_HE_work": 0,
                "maximum_client_descriptor_bytes": max(
                    row["client_descriptor"]["bytes"] for row in result["results"]
                ),
            }
        )
    )


if __name__ == "__main__":
    main()
