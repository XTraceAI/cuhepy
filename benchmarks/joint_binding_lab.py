#!/usr/bin/env python3
"""E101 exact complete BGV relation and paid controls; no timing measurements."""

# ruff: noqa: E402 -- standalone lab runner.

from __future__ import annotations

import argparse
from contextlib import closing
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.dictionary_layout_lab import metadata
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import decryption_support as support
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import joint_binding_oracle as oracle
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import packed_query_expansion as packed
from experiments.bfv_search_lab import seed_composition_relation as literal
from experiments.bfv_search_lab import shallow_bgv as bgv


def toy_relin():
    rng, n, q, bits = random.Random(101), 2, 17 * 41, 2
    def pair():
        return tuple(tuple(rng.randrange(q) for _ in range(n)) for _ in range(2))
    index = (tuple(pair() for _ in range(2)),)
    key = tuple(pair() for _ in range((q.bit_length() + bits - 1)//bits))
    query = pair()
    graph = oracle.compile_graph(n=n, q=q, digit_bits=bits, index=index, relin_key=key)
    return graph, query, b"p" * 32, index, key


def relin_case():
    graph, query, parent, index, key = toy_relin()
    certificate = oracle.honest_certificate(graph, query, parent)
    expected = []
    for a0, a1 in index[0]:
        u0, u1 = query
        v0, v2 = oracle.convolution(a0, u0, graph.q), oracle.convolution(a1, u1, graph.q)
        v1 = tuple((x+y) % graph.q for x, y in zip(oracle.convolution(a0, u1, graph.q),
                                                oracle.convolution(a1, u0, graph.q), strict=True))
        split = oracle.digits(v2, graph.q, graph.digit_bits)
        item = []
        for k, base in enumerate((v0, v1)):
            products = [oracle.convolution(d, key[j][k], graph.q) for j, d in enumerate(split)]
            item.append(tuple((value + sum(p[i] for p in products)) % graph.q for i, value in enumerate(base)))
        expected.append(tuple(item))
    assert certificate.output == tuple(expected) and oracle.verify_exact(graph, query, parent, certificate)
    bad, kernel = oracle.false_witness_kernel(graph, query, parent, certificate, 17)
    # Change only the first prime limb of one final coefficient.
    delta = 41 * pow(41, -1, 17)
    value = (certificate.output[0][0][0] + delta) % graph.q
    changed = replace(certificate, output=(((value, *certificate.output[0][0][1:]), certificate.output[0][1]),
                                           *certificate.output[1:]))
    error = oracle.residuals(graph, query, parent, changed)
    assert any(x % 17 for x in error) and not any(x % 41 for x in error)
    assert not oracle.verify_exact(graph, query, parent, changed)
    return {"n": graph.n, "Q": graph.q, "primes": [17, 41], "digit_bits": graph.digit_bits,
            "index": index, "key": key, "original_query": query, "parent_digest_hex": parent.hex(),
            "certificate": {**asdict(certificate), "statement": certificate.statement.hex()},
            "full_integer_reference_matches": True, "false_witness_kernel": kernel,
            "single_limb_mutation_rejected": True, "other_limb_alone_would_accept": True,
            "scope": "N2 arithmetic, not native ABI, encrypted scores or approved HE parameters."}


def actual_packed_case():
    """Real E73 messages, independent generic compiler, exact plaintext scores."""
    layout = tree.layout(tree.context(16, ("",), 17), (2,), (5,))
    space, words = crt.space(layout, (0,)), ((0, 3, 2, 1, 0),)
    groups = [[[word >> j & 1 for j in range(2)] for word in words[0]]]
    ids = ((1000, 999, 998, 997, 996),)
    pk, sk = masked.key_gen(space, q_bits=32, eta=1)
    keys = packed.key_gen(space, pk, sk, digit_bits=4)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(space, groups, b"s" * 32, client)
        raw_index = tuple(tuple(tuple(tuple(map(int, p)) for p in cipher.components) for cipher in column)
                          for column in index.columns)
        raw_keys = tuple((exponent, tuple(tuple(tuple(map(int, p)) for p in pair) for pair in key))
                         for exponent, key in keys.rotations)
        graph = oracle.compile_graph(n=pk.n, q=int(pk.q), digit_bits=keys.digit_bits,
                                     index=raw_index, rotations=raw_keys,
                                     kept_c0=support.certify(space.layout).kept_c0)
        cases = []
        for word in range(4):
            values = tuple((1-2*(word >> j & 1)) % 17 for j in range(2))
            request, _ = packed.make_query(space, index.epoch, word.to_bytes(16, "little"), values, client)
            query = tuple(tuple(map(int, p)) for p in request.ciphertext.components)
            # Owner-pinned ordered IDs and actual existing public context.
            parent = hashlib.sha256(repr((ids, literal.context(index, request, pk, keys))).encode()).digest()
            certificate = oracle.honest_certificate(graph, query, parent)
            trace = literal.make_trace(index, request, pk, keys)
            assert certificate.output == trace.projected_output
            assert certificate.cut_digits == tuple(cut.gadget for cut in trace.switches)
            assert oracle.verify_exact(graph, query, parent, certificate)
            output = packed.evaluate(index, packed.expand(request, space, pk, keys), pk, keys)
            assert trace.full_output == tuple(tuple(tuple(map(int, p)) for p in c.components) for c in output)
            # Secret arithmetic follows the exact public check. This is a toy
            # differential test, not a new authenticated receiver.
            dots = tree.unpack(space.layout, [bgv.decrypt(cipher, pk, sk) for cipher in output])
            assert dots == crt.scores(space, groups, values)
            scores = tuple((int(value)+word.bit_count()) % 17 for row in dots for value in row)
            expected = tuple((word ^ old).bit_count() for row in words for old in row)
            stable = tuple(x for group in ids for x in group)
            top = sorted(zip(scores, stable, strict=True))[:3]
            assert scores == expected and top == sorted(zip(expected, stable, strict=True))[:3]
            _, kernel = oracle.false_witness_kernel(graph, query, parent, certificate, int(pk.q))
            cases.append({"query_word": word, "original_ciphertext": query, "parent_digest_hex": parent.hex(),
                          "certificate": {**asdict(certificate), "statement": certificate.statement.hex()},
                          "distances": scores, "stable_top3": top, "false_witness_kernel": kernel})
    return {"n": pk.n, "Q": int(pk.q), "t": pk.t, "eta": pk.eta, "columns": space.columns,
            "public_encrypted_index": raw_index, "public_rotation_keys": raw_keys,
            "digit_bits": keys.digit_bits, "kept_c0": support.certify(space.layout).kept_c0,
            "plaintext_fixture_words": words, "stable_ids": ids, "cases": cases,
            "generic_compiler_matches_E78_and_E73": True, "all_scores_and_stable_ties_exact": True,
            "canonical_cuts": len(graph.cuts), "features": graph.feature_count,
            "field_residual_coordinates": len(oracle.constraint_rows(graph)),
            "projected_output_coefficients": sum(sum(row) for row in graph.output_shape),
            "canonical_projected_output_body_bytes": (sum(sum(row) for row in graph.output_shape)*int(pk.q).bit_length()+7)//8,
            "scope": "Small real toy HE fixture. Prime Q32, not production native RNS or approved security."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.json_out.exists():
        parser.error("Use a fresh immutable result path")
    prereg = ROOT / "docs/research/joint-binding-preregistration.md"
    receipt = json.loads((ROOT.parent / "research-data/joint-binding-20261003/preregistration.json").read_text())
    assert hashlib.sha256(prereg.read_bytes()).hexdigest() == receipt["sha256"]
    paths = [Path(__file__), prereg, ROOT / "experiments/bfv_search_lab/joint_binding_oracle.py",
             ROOT / "experiments/bfv_search_lab/test_joint_binding_oracle.py"]
    paths += [ROOT / "experiments/bfv_search_lab" / (name + ".py") for name in
              ("seed_composition_relation", "packed_query_expansion", "crt_masked_bgv", "shallow_bgv",
               "dyadic_crt", "decryption_support", "crt_query_space", "reduction_oracles", "owner_bgv")]
    paths += [ROOT / "src/cuhepy/bfv/scheme.py", ROOT / "src/cuhepy/types.py"]
    paths += [ROOT / "benchmarks/dictionary_layout_lab.py"]
    result = metadata(paths)
    cards = [oracle.cost_card(n, h, r, qb, db, relin=mode)
             for n in (32, 8192) for h in (1, 2, 4) for r in (1, 2, 128)
             for qb, db in ((32, 4), (120, 30)) for mode in (False, True) if not mode or h == 1]
    result.update(kind="E101_generic_complete_BGV_relation_known_control", preregistration_receipt=receipt,
                  actual_packed_case=actual_packed_case(), RNS_relin_algebra=relin_case(),
                  exact_residual_exhaustion=oracle.uniform_field_exhaustion(),
                  two_attempt_feedback_exhaustion=oracle.feedback_exhaustion(),
                  linked_weight_cancellation={"error": [1, -1, 0], "all_equal_weights_accept": True,
                                             "uniform_field_control_probability": [1, 5]},
                  cost_cards=cards, model_card_count=len(cards),
                  decision="STOP_literal_shared_canonical_cut_recipe_known_generic_containment",
                  scope="Exact/count discriminator. No latency, public proof, compact opening, durable release, "
                        "terminal-conversion/BFV graph, parameter approval or original main construction.")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.json_out), "actual_HE_queries": 4,
                      "all_scores_and_stable_ties_exact": True, "exact_residual_checks": 15500,
                      "false_output_preserving_witnesses": 5, "model_cards": len(cards),
                      "decision": result["decision"]}))


if __name__ == "__main__":
    main()
