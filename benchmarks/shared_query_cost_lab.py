#!/usr/bin/env python3
"""Q75 retained whole-vector controls and fixed paid symbolic grammar.

No new key generation, timing or unapproved randomized checker. A known
composition is given exactly the candidate program. Output records model
tradeoffs and unknown complete costs, never a measured service winner.
"""

# ruff: noqa: E402 -- standalone research runner.

import argparse
from dataclasses import asdict, replace
from datetime import UTC, datetime
import gzip
import hashlib
import io
import json
from math import prod
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cuhepy.bfv.scheme import _rns_coefficient_primes
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import noise_cut_fusion as fusion
from experiments.bfv_search_lab import noise_cut_relation as relation
from experiments.bfv_search_lab import noise_cut_shape as shape
from experiments.bfv_search_lab import shared_query_bgv as shared
from experiments.bfv_search_lab import shared_query_cost as cost
from experiments.bfv_search_lab.shared_query_bounds import Profile


def write_json(path, value):
    with path.open("x") as f:
        json.dump(value, f, indent=2)
        f.write("\n")
    return {
        "file": path.name,
        "bytes": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def tuples(value):
    return tuple(tuples(v) for v in value) if type(value) is list else value


def restore(body):
    v, tape = body["context"], body["transcript"]
    ctx = shared.Context(
        Profile(**v["profile"]),
        v["key_id"],
        tuples(v["query"]),
        tuples(v["index"]),
        tuples(v["ids"]),
        tuples(v["relin"]),
        tuples(v["rotations"]),
    )
    transcript = shared.Transcript(
        tape["statement_digest"],
        tuple(
            relation.Source(s["group"], s["level"], s["node"], tuples(s["polynomial"]))
            for s in tape["sources"]
        ),
        tuples(tape["full_output"]),
        bytes.fromhex(tape["response"]),
    )
    return ctx, transcript


def tiny_check(ctx, tape):
    rel = shared.compile_relation(ctx)
    assert shared.accepts(ctx, rel, tape)
    graph, layout = shared.symbolic_graph(ctx.profile, ctx.groups, karatsuba=True, paired=True)
    assert layout == rel.source_layout
    constants = {fusion.Public(name): row for name, row in shared.public_constants(ctx).items()}
    rewrites = {
        "direct_generic": shape.direct_graph(graph),
        "same_bounded_generic_fusion": fusion.fuse(graph).graph,
    }
    checked = 0
    changed = tape.sources[0]
    bad_sources = (
        replace(
            changed,
            polynomial=((changed.polynomial[0] + 1) % ctx.profile.q, *changed.polynomial[1:]),
        ),
        *tape.sources[1:],
    )
    pair = tape.full_output[-1]
    bad_outputs = (
        *tape.full_output[:-1],
        ((*pair[0][:-1], (pair[0][-1] + 1) % ctx.profile.q), pair[1]),
    )
    for label, sources, outputs in (
        ("honest", tape.sources, tape.full_output),
        ("source_fault", bad_sources, tape.full_output),
        ("unused_output_fault", tape.sources, bad_outputs),
    ):
        bindings = fusion.bindings(rel, sources, outputs)
        expected = relation.residuals(rel, sources, outputs)
        for rewrite, g in rewrites.items():
            coeffs = fusion.coefficients(g, constants)
            actual = fusion.evaluate(g, bindings, coeffs)
            assert actual == expected
            for prime in map(int, _rns_coefficient_primes(ctx.profile.n, 120)):
                limb = fusion.evaluate(
                    replace(g, q=prime),
                    {k: tuple(x % prime for x in row) for k, row in bindings.items()},
                    {k: tuple(x % prime for x in row) for k, row in coeffs.items()},
                )
                assert limb == tuple(tuple(x % prime for x in row) for row in expected)
            assert any(any(row) for row in actual) == (label != "honest")
            checked += 1
    return {
        "statement_digest": ctx.digest,
        "key_id": ctx.key_id,
        "policy": ctx.profile.policy,
        "index_mode": ctx.profile.index_mode,
        "records": len(ctx.ids),
        "whole_vector_rewrite_fault_cases": checked,
        "each_actual_limb_same_common_Q_digits_exact": True,
        "known_control_identical_program": True,
        "no_HE_replay_private_key_or_fresh_key_generation": True,
    }


def exhaustive(points):
    """Separate all-pairs finite oracle, no selector call inside it."""
    kept = []
    for point in points:
        dominated = False
        for other in points:
            if point.name == other.name:
                continue
            differences = [x[1] - y[1] for x, y in zip(other.costs, point.costs, strict=True)]
            if max(differences) <= 0 and min(differences) < 0:
                dominated = True
                break
        if not dominated:
            kept.append(point.name)
    return sorted(kept)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    regpath = ROOT / "docs/research/shared-query-cost-registration-20261004.json"
    reg = json.loads(regpath.read_text())
    run = args.input_dir / "Q74-correctness.json"
    assert hashlib.sha256(run.read_bytes()).hexdigest() == reg["Q74_sha256"]
    source_paths = sorted(
        set(ROOT.glob("experiments/bfv_search_lab/*.py"))
        | set(ROOT.glob("src/**/*.py"))
        | {Path(__file__), regpath}
    )
    source = []
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for path in source_paths:
            body = path.read_bytes()
            name = str(path.relative_to(ROOT))
            source.append(
                {"file": name, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
            )
            member = tarfile.TarInfo(name)
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
    packed = gzip.compress(stream.getvalue(), mtime=0)
    with (args.out_dir / "executed-source.tar.gz").open("xb") as f:
        f.write(packed)
    write_json(
        args.out_dir / "started.json",
        {
            "utc": datetime.now(UTC).isoformat(),
            "registration_sha256": hashlib.sha256(regpath.read_bytes()).hexdigest(),
            "source": source,
            "source_archive_sha256": hashlib.sha256(packed).hexdigest(),
            "Q74_sha256": reg["Q74_sha256"],
            "new_key_contexts": 0,
            "timing_panels": 0,
        },
    )
    prior = json.loads(run.read_text())
    tiny = []
    for r in prior["results"]:
        if "-q0-" not in r["id"] or r["records"] != r["profile"]["n"] + 1:
            continue
        receipt = r["fixture"]
        path = args.input_dir / receipt["file"]
        blob = path.read_bytes()
        assert (
            len(blob) == receipt["bytes"] and hashlib.sha256(blob).hexdigest() == receipt["sha256"]
        )
        ctx, tape = restore(json.loads(gzip.decompress(blob)))
        tiny.append(tiny_check(ctx, tape))
    assert len(tiny) == 8
    write_json(
        args.out_dir / "tiny-whole-vector-controls.json",
        {
            "cases": tiny,
            "relation_contexts": len(tiny),
            "whole_vector_rewrite_fault_cases": sum(
                x["whole_vector_rewrite_fault_cases"] for x in tiny
            ),
            "scope": "Eight retained contexts, no new encrypted keys. Direct/fused paired Karatsuba and known control; honest/one-source/unused-output faults, whole-Q and both actual limbs. Not a private/native/backend timing.",
        },
    )
    rows = []
    replay = []
    failures = []
    for bits, policies in ((180, reg["selected_policy_grammar"]), (120, ["canonical30"])):
        primes = tuple(map(int, _rns_coefficient_primes(16384, bits)))
        q = prod(primes)
        p = int(compact.terminal_modulus(q, 1031, 25))
        for count in reg["records"]:
            for mode in ("owner", "public_key") if bits == 180 else ("owner",):
                points = []
                for policy in policies:
                    profile = Profile(16384, 512, q, p, 1031, 21, mode, policy)
                    for rewrite in reg["rewrite_grammar"]:
                        for residency in reg["residency_grammar"]:
                            try:
                                card = cost.compile_card(
                                    profile, count, len(primes), rewrite, residency
                                )
                            except fusion.LimitReached as error:
                                failures.append(
                                    {
                                        "profile": asdict(profile),
                                        "records": count,
                                        "rewrite": rewrite,
                                        "residency": residency,
                                        "error": str(error),
                                        "no_truncated_or_optimal_answer": True,
                                    }
                                )
                                continue
                            points.append(card["point"])
                            card["point"] = asdict(card["point"])
                            rows.append(
                                {
                                    "requested_Q_bits": bits,
                                    "ordered_primes": primes,
                                    "records": count,
                                    "profile": asdict(profile),
                                    "card": card,
                                    "equally_specialized_known_combination_identical": True,
                                }
                            )
                    print(f"Q{bits} {count} {mode} {policy}", flush=True)
                actual = sorted(p.name for p in cost.frontier(tuple(points)))
                assert actual == exhaustive(points)
                selector = {
                    "requested_Q_bits": bits,
                    "records": count,
                    "index_mode": mode,
                    "finite_points": len(points),
                    "frontier_names": actual,
                    "exhaustive_oracle_matches": True,
                    "scope": "Only registered integer resource coordinates and admitted cards; no calibrated latency winner or global optimality.",
                }
                write_json(args.out_dir / f"frontier-Q{bits}-m{count}-{mode}.json", selector)
                canonical = Profile(16384, 512, q, p, 1031, 21, mode, "canonical30")
                replay.append(
                    {
                        "requested_Q_bits": bits,
                        "records": count,
                        "index_mode": mode,
                        "prepared_replay": cost.replay_card(canonical, count, len(primes)),
                        "plaintext_cache": {
                            "packed_feature_bytes": (count * 512 + 7) // 8,
                            "ordered_64bit_ID_bytes": 8 * count,
                            "online_query_bytes": 0,
                            "online_response_bytes": 0,
                            "owner_acquisition_update_authentication_latency_unknown": True,
                            "allowed_and_mandatory_comparator": True,
                        },
                        "checked_product_trusted_expansion_suffix": {
                            "raw_three_component_Q_body_bytes": 3
                            * ((count + 16383) // 16384)
                            * ((16384 * q.bit_length() + 7) // 8),
                            "scope": "Product-boundary packet only. Query expansion and all relinearization/terminal work move inside protected side and must be paid. Same optimized evaluator/NTT/cache choices; complete native cost unknown. No speed ratio.",
                        },
                    }
                )
    report = {
        "task": "Q75",
        "new_encrypted_key_contexts": 0,
        "timing_panels": 0,
        "large_HE_runs": 0,
        "known_control_contains_algebra": True,
        "graph_resource_cards": len(rows),
        "compile_failures": failures,
        "tiny_whole_vector_controls": tiny,
        "rows": rows,
        "controls": replay,
        "claim_decisions": {
            "C1": "Small complete copied-context affine/frame invariant supported; authoritative native/lifecycle theorem unimplemented.",
            "C2": "New expansion/gadget/asymptotic algebra rejected: exactly the equally specialized known graph. Finite verified-cost compiler is an implementation/control, not an accepted new algorithm.",
            "C3": "Complete systems frontier remains unmeasured. A follow-up must show useful state/latency/update tradeoffs versus prepared replay and permitted cache, then a separately defensible closest-system distinction.",
        },
        "selection": "Do not select derived Q180 on witness bytes alone. Retain owner canonical Q120 as the lowest-modulus admitted engineering candidate; its shared-query compiler versus equally prepared replay is one remaining complete-system question, not accepted originality. Larger-Q bounded-state path is supporting Pareto work until measured complete cost justifies it.",
        "all_unknown_service_costs_remain_unknown": True,
        "source": source,
        "scope": "Registered sufficient exact resource models, finite Pareto comparison and known-control containment. No service latency, measured memory, security approval, protected service or paper-ready originality claim.",
    }
    write_json(args.out_dir / "Q75-paid-resource-screen.json", report)
    print(
        json.dumps(
            {
                k: report[k]
                for k in (
                    "graph_resource_cards",
                    "known_control_contains_algebra",
                    "new_encrypted_key_contexts",
                    "timing_panels",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
