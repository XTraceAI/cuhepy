"""E81 exact scores for bounded aliases, no-wrap/RNS and full-gate negatives."""

from contextlib import closing
from dataclasses import replace

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import admissible_trace_oracle as admitted
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import packed_query_expansion as packed
from experiments.bfv_search_lab import seed_composition_relation as canonical
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.test_seed_composition_relation import fixture
from experiments.bfv_search_lab.test_supported_decoder import CASES, inputs


def encrypted_case(descriptor):
    s, words, groups, ids, _ = inputs(*descriptor)
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    keys = packed.key_gen(s, pk, sk, digit_bits=5)
    epoch = b"a" * 32
    policies = ("canonical", "max_representative", "alternating", "max_digit_sum")
    differences, queries, noncanonical, max_phase = 0, 0, 0, 0
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, epoch, client)
        for word in range(16):
            values = tuple((1 - 2 * (word >> j & 1)) % 17 for _ in s.dimensions for j in range(4))
            request, _ = packed.make_query(s, epoch, word.to_bytes(16, "little"), values, client)
            canonical_trace = canonical.make_trace(index, request, pk, keys)
            bound = packed.output_bound(index, pk, keys)
            for policy in policies:
                trace = admitted.make_trace(index, request, pk, keys, policy=policy)
                assert admitted.check_trace(index, request, pk, keys, trace)  # Before private diagnostics.
                if policy == "canonical":
                    assert trace.full_output == canonical_trace.full_output
                    assert canonical.check_trace(index, request, pk, keys, admitted.canonical_view(index, request, pk, keys, trace))
                else:
                    assert not canonical.check_trace(index, request, pk, keys, admitted.canonical_view(index, request, pk, keys, trace))
                    noncanonical += sum(not canonical.canonical_recomposition(step.rotated_c1, step.gadget, keys.digit_bits, int(pk.q)) for step in trace.switches)
                    differences += trace.full_output != canonical_trace.full_output
                outputs = tuple(bgv.Ciphertext(tuple(tuple(mpz(v) for v in p) for p in c), pk.key_id, bound) for c in trace.full_output)
                # Independent private phase diagnostic AFTER the public relation;
                # never used to decide whether to accept an unverified response.
                for c in trace.full_output:
                    phase = tuple((a + b + d) % int(pk.q) for a, b, d in zip(c[0], canonical.product(c[1], sk.s, int(pk.q)),
                                                                                 canonical.product(canonical.product(c[2], sk.s, int(pk.q)), sk.s, int(pk.q)), strict=True))
                    observed = max(abs(x if x <= pk.q // 2 else x - int(pk.q)) for x in phase)
                    assert observed <= bound
                    max_phase = max(max_phase, observed)
                dots = tree.unpack(s.layout, [bgv.decrypt(c, pk, sk) for c in outputs])
                assert dots == crt.scores(s, groups, values)
                scores = tuple((int(v) + word.bit_count()) % 17 for row in dots for v in row)
                expected = tuple((word ^ old).bit_count() for row in words for old in row)
                assert scores == expected
                flat_ids = tuple(v for row in ids for v in row)
                assert sorted(zip(scores, flat_ids, strict=True))[:3] == sorted(zip(expected, flat_ids, strict=True))[:3]
                queries += 1
    return {"n": pk.n, "q": int(pk.q), "t": pk.t, "eta": pk.eta, "columns": s.columns,
            "factor": keys.factor, "digit_bits": keys.digit_bits, "replies": s.layout.cost.response_ciphertexts,
            "exact_trace_queries_including_canonical": queries, "canonical_queries": 16,
            "admitted_alternative_queries": queries - 16, "alternative_full_outputs_differing_from_canonical": differences,
            "noncanonical_switch_witnesses": noncanonical, "maximum_observed_private_phase_abs": max_phase,
            "same_public_output_phase_bound": bound, "all_outputs_scores_IDs_top3_exact": True,
            "counts": admitted.count_delta(pk.n, s.columns, s.layout.cost.response_ciphertexts, pk.q.bit_length(), keys.digit_bits)}


@pytest.mark.parametrize("descriptor", CASES)
def test_actual_BGV_bound_preserves_exact_scores_for_all_public_alias_policies(descriptor):
    result = encrypted_case(descriptor)
    assert result["admitted_alternative_queries"] == 48 and result["noncanonical_switch_witnesses"] > 0


def test_exhaustive_all_scalar_secrets_bounded_errors_and_boxed_digit_vectors():
    result = admitted.exhaustive_scalar()
    assert result["cases"] == 62208 and result["noncanonical_alias_cases"] == 38637
    assert result["every_integer_phase_and_exact_decode_matches"]


def test_unbounded_integer_alias_and_independent_RNS_digits_change_decoded_message():
    result = admitted.negative_controls()
    assert result["unbounded_decoded"] != result["expected"]
    assert result["RNS_decoded"] != result["RNS_expected"]
    assert result["RNS_global_centered_phase"] == -79
    # A single globally shared digit vector is not the independent limb pair.
    assert not admitted.admissible_recomposition((0,), tuple((x,) for x in (1, 3, 0, 0)), 2, 221)


@pytest.mark.parametrize("fault", ["bound", "recomposition", "partial_output", "context"])
def test_invalid_admitted_trace_is_rejected_before_private_arithmetic(fault, monkeypatch):
    index, request, pk, _, keys, *_ = fixture()
    trace = admitted.make_trace(index, request, pk, keys, policy="max_representative")
    if fault in ("bound", "recomposition"):
        step = trace.switches[0]
        value = 1 << keys.digit_bits if fault == "bound" else (step.gadget[0][0] + 1) % (1 << keys.digit_bits)
        step = replace(step, gadget=((value,) + step.gadget[0][1:], *step.gadget[1:]))
        trace = replace(trace, switches=(step, *trace.switches[1:]))
    elif fault == "partial_output":
        trace = replace(trace, full_output=())
    else:
        trace = replace(trace, public_context="wrong")
    calls = []
    monkeypatch.setattr(bgv, "decrypt", lambda *_: calls.append(True))
    assert not admitted.check_trace(index, request, pk, keys, trace) and not calls


def test_relaxation_does_not_claim_removal_of_digit_box_or_existing_phase_bound():
    counts = admitted.count_delta(16384, 32, 1, 73, 5)
    assert counts["same_digit_box_bit_constraints_upper"] > counts["canonical_less_than_Q_comparisons_potentially_removed"]
    assert counts["Q_or_key_or_wire_increase_relative_same_base_canonical_control"] == 0
    assert not counts["proof_constraint_time_bytes_gain_measured"]
