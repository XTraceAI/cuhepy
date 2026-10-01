"""E71 exact encrypted queries, public stages and one-use release controls."""

from contextlib import closing
from dataclasses import replace
import secrets

import pytest

from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import convolution_batch_certificate as batch
from experiments.bfv_search_lab import convolution_certificate_oracle as polynomial
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import encrypted_query_certificate as protocol
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import verification_lifetime as lifetime
from experiments.bfv_search_lab.test_supported_decoder import CASES, inputs


@pytest.mark.parametrize("descriptor", CASES)
def test_all_binary_queries_three_components_full_scores_and_stable_ids(descriptor):
    s, words, groups, ids, _ = inputs(*descriptor)
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    epoch, attempts = secrets.token_bytes(32), lifetime.AttemptBudget(16)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, epoch, client)
        for word in range(16):
            token_id = word.to_bytes(16, "little")
            # This ticket needs no query plaintext, ciphertext or HE secret.
            receiver = protocol.Receiver(index, pk, token_id, attempts)
            values = tuple((1-2*(word >> j & 1)) % 17 for _ in s.dimensions for j in range(4))
            request, _ = protocol.make_query(s, epoch, token_id, values, client)
            output = protocol.evaluate(index, request, pk)
            groups_of_products = protocol.factor_groups(index, request, pk)
            independent = tuple(polynomial.certify(g, int(pk.q)) for g in groups_of_products)
            assert tuple(tuple(int(x) for x in p) for c in output for p in c.components) == tuple(c.output for c in independent)
            assert all(polynomial.cyclic_quotient_control(g, int(pk.q)) == c for g, c in zip(groups_of_products, independent, strict=True))
            body = protocol.pack_output(output, index, pk)
            challenge = receiver.freeze_once(request, body)
            dots = receiver.open_once(protocol.prove(index, request, pk, challenge), sk)
            assert dots == tuple(tuple(row) for row in space.scores(s, groups, values))
            scores = tuple((x+word.bit_count()) % 17 for row in dots for x in row)
            expected = tuple((word ^ old).bit_count() for row in words for old in row)
            flat_ids = tuple(i for row in ids for i in row)
            assert scores == expected
            assert sorted(zip(scores, flat_ids, strict=True))[:3] == sorted(zip(expected, flat_ids, strict=True))[:3]
            assert len(body) == protocol.body_cost(index, pk, 4)["full_three_component_response_body_bytes"]
    assert attempts.used == 16


def _fixture():
    s, _, groups, _, _ = inputs(*CASES[1])
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    epoch = secrets.token_bytes(32)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, epoch, client)
        request, _ = protocol.make_query(s, epoch, bytes(16), (1,)*s.dimension, client)
    output = protocol.evaluate(index, request, pk)
    return index, pk, sk, request, protocol.pack_output(output, index, pk)


def test_malformed_original_context_or_body_never_reaches_private_decryption(monkeypatch):
    index, pk, sk, request, body = _fixture()
    private_calls = []
    monkeypatch.setattr(bgv, "decrypt", lambda *args: private_calls.append(True))
    first = request.ciphertexts[0]
    attempts = lifetime.AttemptBudget(16)
    mutations = ((request, body[:-1]), (request, body+b"\0"),
                 (replace(request, epoch=b"x"*32), body),
                 (replace(request, token_id=b"x"*16), body),
                 (replace(request, space_binding=b"x"*32), body),
                 (replace(request, ciphertexts=(replace(first, key_id="00"*32), *request.ciphertexts[1:])), body),
                 (replace(request, ciphertexts=(replace(first, phase_bound=first.phase_bound+1), *request.ciphertexts[1:])), body))
    for original, candidate in mutations:
        receiver = protocol.Receiver(index, pk, bytes(16), attempts)
        assert receiver.freeze_once(original, candidate) is None
        with pytest.raises(RuntimeError, match="consumed"):
            receiver.open_once(b"", sk)
    assert attempts.used == len(mutations) and not private_calls


def test_frozen_output_false_output_and_quotient_reject_before_private_key(monkeypatch):
    index, pk, sk, request, body = _fixture()
    private_calls = []
    # Deterministic selected regression: all weights select c0; points=0 are
    # never negacyclic roots. Neither selected forgery can accidentally pass.
    monkeypatch.setattr(protocol.secrets, "randbelow", lambda q: 0)
    monkeypatch.setattr(batch, "challenge", lambda frozen, q, rounds, rng: tuple((1,)+(0,)*(len(frozen.values)-1) for _ in range(rounds)))
    monkeypatch.setattr(bgv, "decrypt", lambda *args: private_calls.append(True))
    attempts = lifetime.AttemptBudget(4)
    receiver = protocol.Receiver(index, pk, bytes(16), attempts)
    words = codec.unpack(body, 3*pk.n, int(pk.q))
    forged = codec.pack(((words[0]+1) % pk.q, *words[1:]), int(pk.q))
    challenge = receiver.freeze_once(request, forged)
    assert receiver.open_once(protocol.prove(index, request, pk, challenge), sk) is None
    with pytest.raises(RuntimeError, match="consumed"):
        receiver.open_once(b"", sk)
    receiver = protocol.Receiver(index, pk, bytes(16), attempts)
    challenge = receiver.freeze_once(request, body)
    proof = protocol.prove(index, request, pk, challenge)
    words = codec.unpack(proof, 4*(pk.n-1), int(pk.q))
    bad_proof = codec.pack(((words[0]+1) % pk.q, *words[1:]), int(pk.q))
    assert receiver.open_once(bad_proof, sk) is None
    assert not private_calls


def test_output_cannot_be_replaced_after_weights_and_budget_spans_receivers():
    index, pk, sk, request, body = _fixture()
    attempts = lifetime.AttemptBudget(2)
    receiver = protocol.Receiver(index, pk, bytes(16), attempts)
    challenge = receiver.freeze_once(request, body)
    with pytest.raises(RuntimeError, match="frozen"):
        receiver.freeze_once(request, body[:-1])
    assert receiver.open_once(protocol.prove(index, request, pk, challenge), sk) is not None
    next_receiver = protocol.Receiver(index, pk, bytes(16), attempts)
    with pytest.raises(RuntimeError, match="Global"):
        next_receiver.freeze_once(request, body)
    assert attempts.used == 2


@pytest.mark.parametrize("mutation", ("truncate", "extend"))
def test_malformed_quotient_burns_second_stage_before_private_decryption(monkeypatch, mutation):
    index, pk, sk, request, body = _fixture()
    receiver = protocol.Receiver(index, pk, bytes(16), lifetime.AttemptBudget(1))
    challenge = receiver.freeze_once(request, body)
    proof = protocol.prove(index, request, pk, challenge)
    private_calls = []
    monkeypatch.setattr(bgv, "decrypt", lambda *args: private_calls.append(True))
    malformed = proof[:-1] if mutation == "truncate" else proof+b"\0"
    assert receiver.open_once(malformed, sk) is None
    with pytest.raises(RuntimeError, match="consumed"):
        receiver.open_once(proof, sk)
    assert not private_calls


def test_true_output_one_bad_quotient_exposes_only_one_rounds_predicate():
    q, n = 97, 8
    groups = ((tuple(((1,)*n, (2,)*n) for _ in range(2))),)
    frozen = batch.freeze(tuple(polynomial.certify(g, q).output for g in groups), q)
    weights = ((1,),)*4
    honest = batch.quotients(groups, weights, q)
    bad_first = ((honest[0][0]+1) % q, *honest[0][1:])
    witnesses = (bad_first, *honest[1:])
    accepts = 0
    for point in range(q):
        decisions = batch.verify_at_points(groups, frozen, weights, witnesses, (point, 0, 1, 2), q)
        assert decisions == (pow(point, n, q)+1 == q)
        accepts += decisions
    assert accepts == n  # N/Q, despite four otherwise honest checking rounds.


def test_fresh_correctness_bound_is_independent_of_query_values():
    index, pk, _, request, _ = _fixture()
    expected = pk.n*index.space.columns*(pk.t//2+pk.t*pk.eta)**2
    assert all(c.phase_bound == expected for c in protocol.evaluate(index, request, pk))
    with pytest.raises(ValueError, match="Outside bounded"):
        protocol.Receiver(replace(index, columns=()), pk, bytes(16), lifetime.AttemptBudget(1))
