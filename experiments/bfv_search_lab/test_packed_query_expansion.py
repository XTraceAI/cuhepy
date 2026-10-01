"""E73 full-ring demultiplexing, cross terms and original-query binding gap."""

from contextlib import closing
from dataclasses import replace
import secrets

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import convolution_certificate_oracle as polynomial
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import encrypted_query_gate as gate
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import packed_query_expansion as packed
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import score_layout
from experiments.bfv_search_lab import verification_lifetime as lifetime
from experiments.bfv_search_lab.test_supported_decoder import CASES, inputs


def independent_products(index, expanded, pk):
    outputs = []
    for reply in range(index.space.layout.cost.response_ciphertexts):
        factors = [[], [], []]
        for column, query in zip(index.columns, expanded.ciphertexts, strict=True):
            a0, a1 = (tuple(map(int, p)) for p in column[reply].components)
            b0, b1 = (tuple(map(int, p)) for p in query.components)
            factors[0].append((a0, b0))
            factors[1].extend(((a0, b1), (a1, b0)))
            factors[2].append((a1, b1))
        outputs.append(tuple(polynomial.certify(tuple(g), int(pk.q)).output for g in factors))
    return tuple(outputs)


@pytest.mark.parametrize("descriptor", CASES)
def test_all_binary_queries_local_expansion_then_projected_gate(descriptor):
    s, words, groups, ids, binding = inputs(*descriptor)
    pk, sk = masked.key_gen(s, q_bits=40, eta=1)
    keys = packed.key_gen(s, pk, sk)
    epoch, attempts = secrets.token_bytes(32), lifetime.AttemptBudget(16)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, epoch, client)
        receiver = gate.Gate(index, pk, ids, binding, attempts,
                             query_phase_bound=packed.expanded_bound(s, pk, keys))
        for word in range(16):
            values = tuple((1-2*(word >> j & 1)) % 17 for _ in s.dimensions for j in range(4))
            original, _ = packed.make_query(s, epoch, word.to_bytes(16, "little"), values, client)
            coefficients = packed.plaintext(s, values)
            expected = tuple(tuple(x % pk.t for x in crt.expand(s, short)) for short in crt.corrections(s, values))
            assert packed.plaintext_oracle(s, coefficients) == expected
            # Owner/client-side expansion of its own original ciphertext.
            expanded = packed.expand(original, s, pk, keys)
            assert tuple(tuple(bgv.decrypt(c, pk, sk)) for c in expanded.ciphertexts) == expected
            receiver.pin_query(expanded)
            # Independent server expansion is deterministic at ciphertext level.
            assert packed.expand(original, s, pk, keys) == expanded
            output = packed.evaluate(index, expanded, pk, keys)
            assert tuple(tuple(tuple(map(int, p)) for p in c.components) for c in output) == independent_products(index, expanded, pk)
            body = gate.pack(gate.project(output, index, pk, expected_bound=packed.output_bound(index, pk, keys)), pk)
            dots = receiver.open_body_once(original.token_id, body, sk)
            assert dots == tuple(tuple(row) for row in crt.scores(s, groups, values))
            scores = tuple((x+word.bit_count()) % 17 for row in dots for x in row)
            expected_scores = tuple((word ^ old).bit_count() for row in words for old in row)
            flat_ids = tuple(i for row in ids for i in row)
            assert scores == expected_scores
            assert sorted(zip(scores, flat_ids, strict=True))[:3] == sorted(zip(expected_scores, flat_ids, strict=True))[:3]
    assert attempts.used == 16


@pytest.mark.parametrize("features,shared", (((3, 3), 0), ((4, 4), 1)))
def test_non_power_two_columns_and_mixed_subring_degrees(features, shared):
    layout = tree.layout(tree.context(32, ("0", "1"), 17), features, (6, 3))
    s = crt.space(layout, (0, 1), shared=shared)
    pk, sk = masked.key_gen(s, q_bits=40, eta=1)
    keys = packed.key_gen(s, pk, sk)
    assert keys.factor == 4
    if shared:
        assert s.column_degrees == (1, 2, 2, 2)
    with closing(owner.OwnerClient(pk, sk)) as client:
        for word in range(16):
            values = tuple((word+3*j) % 17 for j in range(s.dimension))
            original, _ = packed.make_query(s, bytes(32), word.to_bytes(16, "little"), values, client)
            expanded = packed.expand(original, s, pk, keys)
            assert tuple(tuple(bgv.decrypt(c, pk, sk)) for c in expanded.ciphertexts) == tuple(tuple(x % pk.t for x in crt.expand(s, short)) for short in crt.corrections(s, values))


def test_fitting_rule_rejects_aliased_residues_without_shrinking_ring():
    layout = score_layout.layout(tree.context(32, ("0", "1"), 17), (17, 17), (1, 1))
    s = crt.space(layout, (0, 1))
    assert s.column_degrees == (2,)*17 and s.layout.context.n == 32
    with pytest.raises(ValueError, match="residues"):
        packed.factor(s)


def test_multiplication_gate_on_untrusted_expansion_does_not_bind_original_query():
    s, _, groups, ids, binding = inputs(*CASES[1])
    pk, sk = masked.key_gen(s, q_bits=40, eta=1)
    keys = packed.key_gen(s, pk, sk)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, bytes(32), client)
        original, _ = packed.make_query(s, bytes(32), bytes(16), (1,)*s.dimension, client)
    correct = packed.expand(original, s, pk, keys)
    first = correct.ciphertexts[0]
    c0 = ((first.components[0][0]+1) % pk.q, *first.components[0][1:])
    malicious = replace(correct, ciphertexts=(replace(first, components=(c0, first.components[1])), *correct.ciphertexts[1:]))
    output = packed.evaluate(index, malicious, pk, keys)
    naive = gate.Gate(index, pk, ids, binding, lifetime.AttemptBudget(1), query_phase_bound=packed.expanded_bound(s, pk, keys))
    # DELIBERATELY unsafe adapter: treating server data as trusted original.
    naive.pin_query(malicious)
    reply = gate.Reply(tuple(tuple(int(c.components[0][i]) for i in kept) for c, kept in
                            zip(output, naive.certificate.kept_c0, strict=True)),
                      tuple(tuple(map(int, c.components[1])) for c in output),
                      tuple(tuple(map(int, c.components[2])) for c in output))
    accepted_wrong = naive.open_body_once(original.token_id, gate.pack(reply, pk), sk)
    assert accepted_wrong != tuple(tuple(row) for row in crt.scores(s, groups, (1,)*s.dimension))
    assert accepted_wrong is not None
    # Valid boundary: client pins its own deterministic expansion instead.
    safe = gate.Gate(index, pk, ids, binding, lifetime.AttemptBudget(1), query_phase_bound=packed.expanded_bound(s, pk, keys))
    safe.pin_query(correct)
    assert safe.open_body_once(original.token_id, gate.pack(reply, pk), sk) is None


def test_expansion_keys_original_query_context_and_correctness_bounds():
    s, _, groups, _, _ = inputs(*CASES[1])
    pk, sk = masked.key_gen(s, q_bits=40, eta=1)
    keys = packed.key_gen(s, pk, sk)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, bytes(32), client)
        original, _ = packed.make_query(s, bytes(32), bytes(16), (1,)*s.dimension, client)
    for bad in (replace(keys, key_id="00"*32), replace(keys, factor=8),
                replace(keys, switch_error_bound=1), replace(keys, rotations=keys.rotations[:-1])):
        with pytest.raises(ValueError):
            packed.expand(original, s, pk, bad)
    with pytest.raises(ValueError):
        packed.expand(replace(original, space_binding=bytes(32)), s, pk, keys)
    assert packed.output_bound(index, pk, keys) == pk.n*s.columns*(pk.t//2+pk.t*pk.eta)*packed.expanded_bound(s, pk, keys)
    assert packed.cost(s, pk, keys)["ring_products_per_expansion"] == 60
    low_q = replace(pk, q=mpz(2*packed.output_bound(index, pk, keys)))
    with pytest.raises(ValueError):
        packed.output_bound(index, low_q, keys)
