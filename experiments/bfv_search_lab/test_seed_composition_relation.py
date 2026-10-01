"""E78 independent complete trace and original-input/digit/branch mutations."""

from contextlib import closing
from dataclasses import replace

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import packed_query_expansion as packed
from experiments.bfv_search_lab import seed_affine_gate as affine
from experiments.bfv_search_lab import seed_composition_relation as relation
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.test_supported_decoder import CASES, inputs


def fixture(descriptor=CASES[1]):
    s, words, groups, ids, binding = inputs(*descriptor)
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    keys = packed.key_gen(s, pk, sk)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, b"s" * 32, client)
        values = tuple((1 - 2 * (3 >> j & 1)) % 17 for _ in s.dimensions for j in range(4))
        request, _ = packed.make_query(s, index.epoch, bytes(16), values, client)
    return index, request, pk, sk, keys, words, groups, ids, binding


def encrypted_case(descriptor):
    index, _, pk, sk, keys, words, groups, ids, _ = fixture(descriptor)
    switches, ranges = 0, 0
    with closing(owner.OwnerClient(pk, sk)) as client:
        for word in range(16):
            values = tuple((1 - 2 * (word >> j & 1)) % 17 for _ in index.space.dimensions for j in range(4))
            request, _ = packed.make_query(index.space, index.epoch, word.to_bytes(16, "little"), values, client)
            trace = relation.make_trace(index, request, pk, keys)
            assert relation.check_trace(index, request, pk, keys, trace)
            expanded = packed.expand(request, index.space, pk, keys)
            output = packed.evaluate(index, expanded, pk, keys)
            assert trace.expanded == tuple(tuple(tuple(map(int, p)) for p in c.components) for c in expanded.ciphertexts)
            assert trace.full_output == tuple(tuple(tuple(map(int, p)) for p in c.components) for c in output)
            dots = tree.unpack(index.space.layout, [bgv.decrypt(c, pk, sk) for c in output])
            assert dots == crt.scores(index.space, groups, values)
            scores = tuple((int(v) + word.bit_count()) % 17 for row in dots for v in row)
            expected = tuple((word ^ old).bit_count() for row in words for old in row)
            assert scores == expected
            flat_ids = tuple(v for row in ids for v in row)
            assert sorted(zip(scores, flat_ids, strict=True))[:3] == sorted(zip(expected, flat_ids, strict=True))[:3]
            switches += len(trace.switches)
            ranges += sum(len(step.gadget) * pk.n for step in trace.switches)
    return {"n": pk.n, "columns": index.space.columns, "factor": keys.factor,
            "q": int(pk.q), "q_bits": pk.q.bit_length(), "digit_bits": keys.digit_bits,
            "replies": index.space.layout.cost.response_ciphertexts, "exact_queries": 16,
            "canonical_switch_witnesses_checked": switches, "digit_coefficients_checked": ranges,
            "independent_trace_equals_canonical_existing_implementation": True,
            "every_score_ID_top3_exact": True,
            "counts": relation.count_designs(pk.n, index.space.columns, index.space.layout.cost.response_ciphertexts,
                                             pk.q.bit_length(), keys.digit_bits)}


@pytest.mark.parametrize("descriptor", CASES)
def test_all_layouts_original_query_full_trace_canonical_digits_and_exact_scores(descriptor):
    assert encrypted_case(descriptor)["exact_queries"] == 16


@pytest.mark.parametrize("fault", ["original_c0", "original_c1", "epoch", "token", "index", "keys", "context",
                                  "missing_branch", "branch_id", "digits", "range", "switch", "expanded", "C1", "C2", "projection"])
def test_true_output_with_corrupted_witness_or_original_is_rejected(fault, monkeypatch):
    index, request, pk, _, keys, *_ = fixture()
    trace = relation.make_trace(index, request, pk, keys)
    if fault.startswith("original"):
        at = int(fault[-1])
        components = list(request.ciphertext.components)
        components[at] = ((components[at][0] + 1) % pk.q,) + components[at][1:]
        request = replace(request, ciphertext=replace(request.ciphertext, components=tuple(components)))
    elif fault in ("epoch", "token"):
        request = replace(request, **{("token_id" if fault == "token" else "epoch"): b"z" * (16 if fault == "token" else 32)})
    elif fault == "index":
        column = list(index.columns[0])
        first = column[0]
        a, b = first.components
        column[0] = replace(first, components=(((a[0] + 1) % pk.q,) + a[1:], b))
        index = replace(index, columns=(tuple(column), *index.columns[1:]))
    elif fault == "keys":
        exponent, key = keys.rotations[0]
        b, a = key[0]
        changed = ((((b[0] + 1) % pk.q,) + b[1:], a), *key[1:])
        keys = replace(keys, rotations=((exponent, changed), *keys.rotations[1:]))
    elif fault == "context":
        trace = replace(trace, public_context="0" * 64)
    elif fault == "missing_branch":
        trace = replace(trace, switches=trace.switches[:-1])
    elif fault in ("branch_id", "digits", "range", "switch"):
        step = trace.switches[0]
        if fault == "branch_id":
            step = replace(step, branch=9)
        elif fault in ("digits", "range"):
            value = (step.gadget[0][0] + 1) % (1 << keys.digit_bits) if fault == "digits" else 1 << keys.digit_bits
            step = replace(step, gadget=((value,) + step.gadget[0][1:], *step.gadget[1:]))
        else:
            step = replace(step, switched=(((step.switched[0][0] + 1) % int(pk.q),) + step.switched[0][1:], step.switched[1]))
        trace = replace(trace, switches=(step, *trace.switches[1:]))
    elif fault == "expanded":
        trace = replace(trace, expanded=trace.expanded[:-1])
    elif fault in ("C1", "C2"):
        parts = list(trace.full_output[0])
        parts[int(fault[1])] = parts[int(fault[1])][:-1]
        trace = replace(trace, full_output=(tuple(parts), *trace.full_output[1:]))
    else:
        trace = replace(trace, projected_output=())
    calls = []
    monkeypatch.setattr(bgv, "decrypt", lambda *_: calls.append(True))
    assert not relation.check_trace(index, request, pk, keys, trace)
    assert not calls


def test_field_recomposition_accepts_Q_alias_but_canonical_integer_relation_rejects():
    p, Q, bits = (0, 1, 2, 3), 97, 2
    alternative = relation.digits(tuple(x + Q for x in p), bits, 255)
    # Same length as the Q97 gadget, all digits are in [0,4).
    assert len(alternative) == (Q.bit_length() + bits - 1) // bits
    assert all(sum(row[i] * (1 << bits)**j for j, row in enumerate(alternative)) % Q == x for i, x in enumerate(p))
    assert not relation.canonical_recomposition(p, alternative, bits, Q)


def test_fixed_C1_all_digits_and_C1_branches_are_query_independent():
    index, request, pk, _, keys, *_ = fixture()
    trace = relation.make_trace(index, request, pk, keys)
    zero = replace(request, ciphertext=replace(request.ciphertext, components=((mpz(0),) * pk.n, request.ciphertext.components[1])))
    delta = relation.make_trace(index, zero, pk, keys)
    assert trace.switches == delta.switches
    for j, (full, offset) in enumerate(zip(trace.expanded, delta.expanded, strict=True)):
        assert tuple((x - y) % int(pk.q) for x, y in zip(full[0], offset[0], strict=True)) == affine.selection(request.ciphertext.components[0], j, keys.factor, pk.q)
        assert full[1] == offset[1]
    # Synthetic inputs are ciphertext algebra; this test never decrypts them.


def test_typed_DAG_full_inputs_and_strong_control_counts_have_no_free_beta():
    dag = relation.relation_dag(32, 4, 1, 32, 4)
    assert dag[-1].inputs == ("offset", "index", "c0", "context")
    assert all(node.phase == "seed" for node in dag if node.coefficient_type == "digit")
    counts = relation.count_designs(32, 4, 1, 32)
    a, b, c = counts["designs"]
    assert a["canonical_gadget_coefficients"] == b["canonical_gadget_coefficients"] == 768
    assert c["transposed_seed_state_ratio_to_E77_expanded_fingerprints"] == 3.125
    assert c["if_full_certified_offset_delivered_extra_body_bytes"] == b["full_accepted_output_body_bytes"]
    assert isinstance(a["proof_bytes_and_PCS_commit_open_work"], str)
