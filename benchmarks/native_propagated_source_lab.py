#!/usr/bin/env python3
"""Q67 large local arithmetic correctness; no native admission/timing claim."""

# ruff: noqa: E402 -- standalone research runner.

from contextlib import closing
from datetime import UTC, datetime
import argparse
import hashlib
import json
from pathlib import Path
import random
import sys
import tarfile

import msgpack

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import native_bgv as historical
from experiments.bfv_search_lab import native_propagated_gadget_bgv as native
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace


def save(path, data):
    with path.open("xb") as f:
        f.write(data)
    return {
        "file": path.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    marker, output = (
        args.out_dir / "Q67-started.json",
        args.out_dir / "Q67-source-correctness.json",
    )
    if marker.exists() or output.exists():
        parser.error("New immutable output directory required")
    registration = (
        ROOT / "docs/research/gadget-cut-native-source-registration-20261003.json"
    )
    reg = json.loads(registration.read_text())
    n, count, dimension, padded = reg["N"], reg["vectors"], reg["dimension"], reg["D"]
    paths = [
        Path(__file__),
        registration,
        ROOT / "benchmarks/dictionary_layout_lab.py",
        ROOT / "src/cuhepy/bfv/scheme.py",
        ROOT / "src/cuhepy/types.py",
    ]
    paths.extend(
        ROOT / f"experiments/bfv_search_lab/{name}.py"
        for name in (
            "native_propagated_gadget_bgv",
            "propagated_gadget_bgv",
            "native_bgv",
            "shallow_bgv",
            "trace_bgv",
            "butterfly_bgv",
            "compact_bgv",
            "owner_bgv",
            "native_owner_bgv",
            "seeded_bgv",
        )
    )
    paths.extend(sorted((ROOT / "src/cuhepy/bfv/_cpu_ext").glob("*.h")))
    paths.extend(sorted((ROOT / "experiments/bfv_search_lab/_gadget").glob("*")))
    paths.extend(
        ROOT / f"experiments/bfv_search_lab/_native/{name}.h"
        for name in ("trace_server", "residue_trace")
    )
    paths = [p for p in paths if p.is_file()]
    result = metadata(paths)
    backend_hash = hashlib.sha256(args.backend.read_bytes()).hexdigest()
    rng = random.Random(reg["plaintext_seed"])
    words = [rng.getrandbits(dimension) for _ in range(count)]
    query_words = [rng.getrandbits(dimension) for _ in range(reg["queries"])]
    files = [
        save(
            args.out_dir / "inputs-before-keygen.msgpack",
            msgpack.packb(
                {
                    "row_words": [v.to_bytes(dimension // 8, "little") for v in words],
                    "query_words": [
                        v.to_bytes(dimension // 8, "little") for v in query_words
                    ],
                },
                use_bin_type=True,
            ),
        )
    ]
    marker.write_text(
        json.dumps(
            {
                "utc": datetime.now(UTC).isoformat(),
                "registration_sha256": hashlib.sha256(
                    registration.read_bytes()
                ).hexdigest(),
                "source_sha256": result["source_sha256"],
                "backend_sha256": backend_hash,
                "inputs": files[0],
                "before_any_HE_key_creation": True,
            },
            indent=2,
        )
        + "\n"
    )
    with tarfile.open(args.out_dir / "Q67-executed-source.tar.gz", "x:gz") as archive:
        for path in paths:
            archive.add(path, arcname=str(path.relative_to(ROOT)))

    def progress(message):
        print(message, flush=True)

    progress("Creating one fresh homemade Q120 key and public switching keys")
    pk, sk = bgv.key_gen(n, t=reg["t"], q_bits=120, eta=reg["eta"], rns_modulus=True)
    assert format(pk.q, "x") == reg["Q_hex"]
    keys = trace.evaluation_keys(pk, sk, padded, digit_bits=30)
    rows = [[(v >> j) & 1 for j in range(dimension)] for v in words]
    _, plaintexts = bgv.coefficient_inputs([0] * dimension, rows, n)
    progress("Encrypting 8192 rows into 256 index tiles")
    index = [bgv.encrypt(p, pk) for p in plaintexts]
    del rows, plaintexts
    backend = native.load_backend(args.backend)
    alt = native.NativePlan(pk, keys, backend)
    canonical = native.NativePlan(pk, keys, backend, propagate=False)
    old = historical.NativeServer(pk, keys, residue=True, device="cpu")
    progress("Preparing immutable public index plans")
    prepared, canonical_index, old_index = (
        alt.prepare(index, count),
        canonical.prepare(index, count),
        old.prepare_index(index, count),
    )
    public = {
        "metadata": {
            "n": n,
            "count": count,
            "dimension": dimension,
            "padded": padded,
            "t": pk.t,
            "eta": pk.eta,
            "q_hex": format(pk.q, "x"),
            "p": reg["P"],
            "key_id": pk.key_id,
            "digit_bits": 30,
            "fresh_OS_key": True,
            "polynomial_format": "N canonical little-endian 15-byte coefficients",
        },
        "index": [
            tuple(native.fixed(p, n, int(pk.q)) for p in c.components) for c in index
        ],
        "keys": [
            tuple(tuple(native.fixed(p, n, int(pk.q)) for p in pair) for pair in k)
            for k in (keys.relin, *(k for _, k in keys.rotations))
        ],
    }
    files.append(
        save(
            args.out_dir / "public-source-fixture.msgpack",
            msgpack.packb(public, use_bin_type=True),
        )
    )
    del public
    records = []
    with closing(owner.OwnerClient(pk, sk, native=True, rns=True)) as client:
        client.prepare_terminal(25)
        for i, word in enumerate(query_words):
            progress(
                f"Locally trusted public evaluators and outside-controller diagnostics: query {i + 1}/3"
            )
            plain, _ = bgv.coefficient_inputs(
                [(word >> j) & 1 for j in range(dimension)], [], n
            )
            packet = client.encrypt(plain)
            query = owner.expand(packet, pk)
            files.append(save(args.out_dir / f"query-{i}.bin", packet))
            actual = alt.search(query, prepared)
            control = canonical.search(query, canonical_index)
            historical_output = old.search(query, old_index, joint=True)
            assert [c.components for c in control] == [
                c.components for c in historical_output
            ]
            assert len(actual) == len(control) == 1
            truth = [(word ^ v).bit_count() for v in words]
            physical_truth = [0] * n
            for position, distance in enumerate(truth):
                tile, lane = divmod(position, n // padded)
                physical_truth[lane * padded + tile] = (
                    padded * (dimension - 2 * distance) % pk.t
                )
            # Local synthetic diagnostic only, not response admission. Both
            # public computations are under the experiment owner's control.
            assert bgv.decrypt(actual[0], pk, sk) == physical_truth
            assert bgv.decrypt(control[0], pk, sk) == physical_truth
            reduced, reference = (
                [compact.compact(c, pk, 25) for c in actual],
                [compact.compact(c, pk, 25) for c in control],
            )
            assert (
                client.decrypt_compact(reduced[0])
                == client.decrypt_compact(reference[0])
                == physical_truth
            )
            finish = client.finish(reduced, count, dimension, all_distances=True)
            assert tuple(finish.distances) == tuple(truth)
            expected_top = [
                (row, truth[row])
                for row in sorted(range(count), key=lambda row: (truth[row], row))[:3]
            ]
            assert tuple(finish.top) == tuple(expected_top)
            frames = {}
            for tag, ciphers, compact_ciphers in (
                ("propagated", actual, reduced),
                ("canonical", control, reference),
            ):
                qpacket = msgpack.packb(
                    [
                        tuple(native.fixed(p, n, int(pk.q)) for p in c.components)
                        for c in ciphers
                    ],
                    use_bin_type=True,
                )
                files.append(
                    save(args.out_dir / f"query-{i}-{tag}-full-Q.msgpack", qpacket)
                )
                frame = compact.pack(compact_ciphers, count, dimension, pk)
                frames[tag] = frame
                files.append(save(args.out_dir / f"query-{i}-{tag}-compact.bin", frame))
            records.append(
                {
                    "query": i,
                    "key_id": pk.key_id,
                    "exact_distances": len(truth),
                    "all_physical_coordinates": n,
                    "canonical_matches_historical_full_Q": True,
                    "propagated_full_Q_differs": actual[0].components
                    != control[0].components,
                    "compact_frame_differs": frames["propagated"]
                    != frames["canonical"],
                    "compact_frame_bytes": len(frames["propagated"]),
                    "top3": expected_top,
                    "public_propagated_bound": actual[0].phase_bound,
                    "terminal_bound": reduced[0].phase_bound,
                    "full_native_admission_performed": False,
                    "locally_trusted_arithmetic_only": True,
                }
            )
    del sk
    result.update(
        kind="Q67_one_fresh_source_context_native_public_arithmetic_correctness",
        backend_sha256=backend_hash,
        registration_sha256=hashlib.sha256(registration.read_bytes()).hexdigest(),
        cases=records,
        files=files,
        unique_query_distances=sum(r["exact_distances"] for r in records),
        unique_query_physical_coordinates=sum(
            r["all_physical_coordinates"] for r in records
        ),
        exact_H_word_body_bytes=backend.state_sizes(alt.handle)[0],
        exact_pair_digit_word_body_bytes=backend.state_sizes(alt.handle)[1],
        scientific_timing=False,
        full_native_admission_implemented=False,
        scope="Complete local public evaluator and outside-controller owner truth only; one fresh key, three held-out query words. Every full-Q/terminal coordinate checked, public source/whole packets retained. No latency, protected-service, original primitive, parameter/private-side-channel or deployed assurance claim.",
    )
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "unique_query_distances",
                    "unique_query_physical_coordinates",
                    "exact_H_word_body_bytes",
                    "exact_pair_digit_word_body_bytes",
                    "full_native_admission_implemented",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
