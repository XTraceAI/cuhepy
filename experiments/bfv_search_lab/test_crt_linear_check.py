"""Full-output verification and explicit limits of trusted preprocessing."""

from contextlib import closing
from dataclasses import replace
import itertools
import random

import pytest

from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import reduction_oracles as reduction
from experiments.bfv_search_lab.test_crt_masked_bgv import EPOCH, SEED, TOKEN, fixture


def prepared():
    s, rows = fixture()
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, rows, EPOCH, client)
        ticket, answer, _ = masked.prepare(s, rows, EPOCH, TOKEN, SEED, client)
    request = ticket.consume((31, 62, 93), EPOCH)
    return pk, index, answer, request, masked.evaluate(index, answer, request, pk)


def test_adjoint_preparation_matches_independent_signed_coefficient_shifts():
    pk, index, _, _, _ = prepared()
    gate = check.EpochCheck(index, pk, rng=random.Random(7200))
    for rho, fingerprints in zip(gate._challenges(), gate._fingerprints, strict=True):
        for column, hs in zip(index.columns, fingerprints, strict=True):
            for k, expected in enumerate(hs):
                monomial = tuple(int(i == k * index.space.stride) for i in range(pk.n))
                actual = 0
                for c, pair in zip(column, rho, strict=True):
                    for p, weights in zip(c.components, pair, strict=True):
                        shifted = reduction.ring_product(tuple(map(int, p)), monomial)
                        actual += sum(a * b for a, b in zip(shifted, weights, strict=True))
                assert actual % pk.q == expected


def test_every_full_ciphertext_coefficient_is_checked_before_decryption():
    pk, index, answer, request, result = prepared()
    gate = check.EpochCheck(index, pk, budget=256, rng=random.Random(7201))
    token = 0
    for r, cipher in enumerate(result):
        for component, poly in enumerate(cipher.components):
            for i in range(pk.n):
                token_id = token.to_bytes(16, "little")
                token += 1
                gate.prepare_answer(replace(answer, token_id=token_id))
                changed = list(poly)
                changed[i] = (changed[i] + 1) % pk.q
                parts = list(cipher.components)
                parts[component] = tuple(changed)
                out = list(result)
                out[r] = replace(cipher, components=tuple(parts))
                assert not gate.verify_once(replace(request, token_id=token_id), tuple(out))


@pytest.mark.parametrize("mutation", ("bound", "key", "shape", "canonical", "epoch", "delta", "rounded"))
def test_context_bound_canonical_and_terminal_output_mutations(mutation):
    pk, index, answer, request, result = prepared()
    gate = check.EpochCheck(index, pk, rng=random.Random(7202))
    gate.prepare_answer(answer)
    out = list(result)
    first = out[0]
    if mutation == "bound":
        out[0] = replace(first, phase_bound=first.phase_bound + 1)
    elif mutation == "key":
        out[0] = replace(first, key_id="0" * 64)
    elif mutation == "shape":
        out.pop()
    elif mutation == "canonical":
        out[0] = replace(first, components=((first.components[0][0] + pk.q, *first.components[0][1:]), first.components[1]))
    elif mutation == "epoch":
        request = replace(request, epoch=b"x" * 32)
    elif mutation == "delta":
        request = replace(request, delta=(97, 0, 0))
    else:
        # Even if rounded coefficients are canonical under q, they do not
        # satisfy the exact relation. No unchecked compact ciphertext path.
        out[0] = replace(first, components=tuple(tuple(x // 256 for x in p) for p in first.components))
    assert not gate.verify_once(request, tuple(out))
    with pytest.raises(RuntimeError, match="consumed"):
        gate.verify_once(request, result)


def test_epoch_budget_counts_invalid_requests_and_rejects_duplicate_tokens():
    pk, index, answer, request, result = prepared()
    gate = check.EpochCheck(index, pk, budget=2, rng=random.Random(7203))
    gate.prepare_answer(answer)
    with pytest.raises(RuntimeError, match="Duplicate"):
        gate.prepare_answer(answer)
    assert not gate.verify_once(replace(request, token_id=b"?" * 16), result)
    assert gate.verify_once(request, result)
    with pytest.raises(RuntimeError, match="consumed"):
        gate.verify_once(replace(request, token_id=b"!" * 16), result)
    with pytest.raises(ValueError, match="epoch"):
        gate.prepare_answer(replace(answer, epoch=b"z" * 32))


def test_changed_index_is_detected_and_poisoned_trusted_answer_is_not():
    pk, index, answer, request, result = prepared()
    first = index.columns[0][0]
    changed = replace(first, components=(((first.components[0][0] + 1) % pk.q, *first.components[0][1:]), first.components[1]))
    bad_index = replace(index, columns=((changed, *index.columns[0][1:]), *index.columns[1:]))
    gate = check.EpochCheck(index, pk, rng=random.Random(7204))
    gate.prepare_answer(answer)
    assert not gate.verify_once(request, masked.evaluate(bad_index, answer, request, pk))
    first = answer.ciphertexts[0]
    changed = replace(first, components=(((first.components[0][0] + 1) % pk.q, *first.components[0][1:]), first.components[1]))
    poisoned = replace(answer, ciphertexts=(changed, *answer.ciphertexts[1:]))
    gate = check.EpochCheck(index, pk, rng=random.Random(7204))
    gate.prepare_answer(poisoned)  # Deliberately violating its trusted-input contract.
    assert gate.verify_once(request, masked.evaluate(index, poisoned, request, pk))


def test_reused_secret_challenge_union_bound_and_public_challenge_counterexample():
    q = 5
    errors = ((1, 0), (1, 1), (1, 2))
    for attempts in range(1, 4):
        successes = sum(any(sum(a * b for a, b in zip(e, rho, strict=True)) % q == 0 for e in errors[:attempts])
                        for rho in itertools.product(range(q), repeat=2))
        assert successes <= attempts * q
    # Once the weights are public, a nonzero error in their kernel is trivial.
    for rho in itertools.product(range(q), repeat=2):
        if rho != (0, 0):
            error = (rho[1], -rho[0] % q)
            assert error != (0, 0) and sum(a * b for a, b in zip(error, rho, strict=True)) % q == 0
    pk, index, _, _, _ = prepared()
    with pytest.raises(ValueError, match="prime"):
        check.EpochCheck(index, replace(pk, q=15))
