#!/usr/bin/env python3
"""E64 complete toy native/GMP/phase oracles for the separate supported relation.

Seven sparse/dense/mixed/legacy/multiple-reply layouts and all16 binary queries.
Actual coefficient bodies; toy arithmetic correctness, not useful timing or
cryptographic assurance. Full native verification precedes secret diagnostics.
"""

# ruff: noqa: E402 -- standalone research entry point.

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import coordinate_factory as coordinates
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import decryption_support as support
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import native_linear_check as checks
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import score_layout
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import supported_decoder as decoder
from experiments.bfv_search_lab import verification_lifetime as lifetime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    cases, attempts = [], lifetime.AttemptBudget(128)
    descriptors = ((32, ("",), (19,), tree.layout),
                   (32, ("0", "1"), (12, 4), tree.layout),
                   (32, ("0", "10", "11"), (6, 3, 1), tree.layout),
                   (32, ("0", "1"), (35, 9), tree.layout),
                   (32, ("0", "1"), (12, 4), score_layout.layout),
                   (32, ("0", "1"), (16, 16), score_layout.layout),
                   (32, ("0", "1"), (0, 4), score_layout.layout))
    for n, paths, counts, constructor in descriptors:
        s = space.space(constructor(tree.context(n, paths, 17), (4,) * len(paths), counts), tuple(range(len(paths))))
        words = tuple(tuple((i * 3 + group) % 16 for i in range(count)) for group, count in enumerate(counts))
        groups = [[[int(word >> j & 1) for j in range(4)] for word in row] for row in words]
        output_ids, cursor = [], 0
        for count in counts:
            output_ids.append(tuple(1000 - cursor - i for i in range(count)))
            cursor += count
        pk, sk = masked.key_gen(s, q_bits=32, eta=1)
        epoch, binding = secrets.token_bytes(32), hashlib.sha256(repr((words, output_ids)).encode()).hexdigest()
        with closing(owner.OwnerClient(pk, sk)) as client:
            index, _ = masked.enroll(s, groups, epoch, client)
            server, factory = native.NativeIndex(index, pk), coordinates.Factory(s, groups, epoch, client)
            gate = decoder.Gate(index, pk, tuple(output_ids), binding, attempts)
            reference = checks.NativeVectorCheck(index, pk, budget=16)
            assert gate.certificate == support.matrix_oracle(s.layout)
            phase, scores_hash = audit.Audit(index, pk, sk), hashlib.sha256()
            max_phase = 0
            for word in range(16):
                ticket, answer, _ = factory.prepare(word.to_bytes(16, "little"))
                gate.prepare_answer(answer)
                reference.prepare_answer(answer)
                values = tuple((1 - 2 * (word >> j & 1)) % 17 for _ in paths for j in range(4))
                request = ticket.consume(values, epoch)
                output = server.evaluate(answer, request)
                assert output == masked.evaluate(index, answer, request, pk) and reference.verify_once(request, output)
                measured = phase.measure(request, answer, output)
                assert measured["all_integer_phase_coefficients_match_ciphertext"]
                max_phase = max(max_phase, measured["maximum_unreduced_integer_phase"])
                reply = decoder.project(output, s, pk, epoch)
                body = decoder.pack(reply, pk)
                dots = gate.open_body_once(request, body, sk, reply.phase_bounds)
                assert dots == tuple(tuple(row) for row in tree.unpack(s.layout, [bgv.decrypt(c, pk, sk) for c in output]))
                scores = tuple((int(value) + word.bit_count()) % 17 for row in dots for value in row)
                expected = tuple((word ^ old).bit_count() for row in words for old in row)
                ids = tuple(i for row in output_ids for i in row)
                assert scores == expected and sorted(zip(scores, ids, strict=True))[:3] == sorted(zip(expected, ids, strict=True))[:3]
                scores_hash.update(bytes(scores))
                assert len(body) == gate.certificate.body_bytes_model(32)
            full_bytes = (gate.certificate.full_coefficient_count * 32 + 7) // 8
            cases.append({"n": n, "paths": paths, "counts": counts, "layout": type(s.layout).__module__,
                          "kept_c0": gate.certificate.kept_c0, "full_body_bytes": full_bytes,
                          "projected_body_bytes": len(body), "all_binary_queries": 16,
                          "all_scores_hash": scores_hash.hexdigest(), "max_abs_integer_phase": max_phase,
                          "native_GMP_all_coefficients_equal": True, "full_gate_before_secret_diagnostics": True,
                          "supported_gate_before_dedicated_secret_decoder": True,
                          "every_decoder_basis_column_checked": True, "every_score_id_and_stable_top3_exact": True})
    paths = [Path(__file__), *(ROOT / f"experiments/bfv_search_lab/{name}.py" for name in (
        "supported_decoder", "decryption_support", "coefficient_body", "coordinate_factory", "crt_masked_bgv",
        "crt_native_bgv", "crt_query_space", "crt_linear_check", "native_linear_check", "dyadic_crt",
        "score_layout", "owner_bgv", "integer_phase_audit", "shallow_bgv", "verification_lifetime")),
        ROOT / "src/cuhepy/bfv/scheme.py"]
    paths.extend(p for folder in ("_subring", "_fingerprint") for p in (ROOT / "experiments/bfv_search_lab" / folder).glob("*.so"))
    result = metadata(paths)
    result.update(kind="supported_decoder_exact_oracle", cases=cases, global_attempt_limit=attempts.limit,
                  global_attempts_used=attempts.used,
                  scope="E64 separate owner-pinned supported-C0/full-C1 relation and dedicated phase decoder. "
                        "Tiny N32/t17/Q32-bit/eta1 profiles test exactness, not encryption/security assurance or useful runtime. "
                        "Known CRT/support/sample-extraction/fingerprint ingredients; no original primitive, new GPU, durable state, "
                        "private-side-channel assurance or reviewed full protocol claim.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "encrypted_queries": attempts.used}))


if __name__ == "__main__":
    main()
