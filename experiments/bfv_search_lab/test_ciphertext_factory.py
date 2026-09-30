"""Exact factory outputs and regressions for its additional premises/leakage."""

from collections import Counter
from contextlib import closing
from dataclasses import replace
import secrets

import pytest

from experiments.bfv_search_lab import ciphertext_factory as factory
from experiments.bfv_search_lab import crt_linear_check as checks
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import seeded_bgv as seeded
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def plan(shared=True):
    w = Workload((0, 1, 2, 3, 8, 9, 10, 11), tuple(range(8)), 4)
    choice = oracle.choices(w, oracle.median_tree(w, 1 if shared else 0), 17)[-1 if shared else 1]
    return oracle.compile_choice(w, choice, Profile(32, 17, eta=1), (1, 1) if shared else (1,))


def test_factory_without_plaintext_matrix_preserves_complete_adaptive_scores(monkeypatch):
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    p = plan()
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        groups = [[list(row) for row in g] for g in p.groups]
        index, _ = masked.enroll(p.query_space, groups, secrets.token_bytes(32), client)
        producer = factory.Factory(index, client, budget=16)
        def forbidden(*args, **kwargs):
            raise AssertionError("Encrypted factory tried to evaluate a plaintext matrix")
        monkeypatch.setattr(space, "scores", forbidden)
        pool = [producer.prepare(i.to_bytes(16, "little")) for i in range(16)]
        gate = checks.EpochCheck(index, pk, budget=16)
        server = native.NativeIndex(index, pk)
        phase = audit.Audit(index, pk, sk, maximum_answer_bound=max(producer.answer_bounds))
        for _, answer, body in pool:
            assert len(body) == p.resources.response_body_bytes
            assert tuple(c.phase_bound for c in answer.ciphertexts) == producer.answer_bounds
            gate.prepare_answer(answer)
        word = 0
        for i, (ticket, answer, _) in enumerate(pool):
            values, offsets = oracle.query(p.client_view(), word)
            request = ticket.consume(values, index.epoch)
            result = server.evaluate(answer, request)
            assert result == masked.evaluate(index, answer, request, pk)
            assert gate.verify_once(request, result)
            assert phase.measure(request, answer, result)["all_integer_phase_coefficients_match_ciphertext"]
            actual = oracle.decode(p.client_view(), [bgv.decrypt(c, pk, sk) for c in result], offsets)
            assert actual == p.workload.expected(word)
            word = (p.workload.top_k(actual)[0][1] + i + 1) % 16
        with pytest.raises(RuntimeError, match="consumed"):
            producer.prepare(bytes(16))


def test_forged_factory_response_rejected_before_decryption():
    p = plan(False)
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        groups = [[list(row) for row in g] for g in p.groups]
        index, _ = masked.enroll(p.query_space, groups, secrets.token_bytes(32), client)
        ticket, answer, _ = factory.Factory(index, client).prepare(bytes(16))
        values, _ = oracle.query(p.client_view(), 0)
        request = ticket.consume(values, index.epoch)
        result = native.NativeIndex(index, pk).evaluate(answer, request)
        old = result[0]
        a, b = old.components
        changed = ((a[0] + 1) % pk.q, *a[1:])
        result = (replace(old, components=(changed, b)), *result[1:])
        gate = checks.EpochCheck(index, pk)
        gate.prepare_answer(answer)
        assert not gate.verify_once(request, result)
        with pytest.raises(RuntimeError, match="consumed"):
            ticket.consume(values, index.epoch)


def test_extra_noise_budget_rejects_before_factory_prepare():
    p = plan(False)
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        groups = [[list(row) for row in g] for g in p.groups]
        index, _ = masked.enroll(p.query_space, groups, secrets.token_bytes(32), client)
        columns = tuple(tuple(replace(c, phase_bound=int(pk.q // 90)) for c in column) for column in index.columns)
        index = replace(index, columns=columns)
        with pytest.raises(ValueError, match="universal complete-response phase"):
            factory.Factory(index, client)


def test_publishing_zero_seed_would_reveal_private_mask_and_query(monkeypatch):
    # Tiny negative example only: NO secret key is used by the recovery step.
    # Production Factory never exports this deliberately captured local seed.
    w = Workload((0, 1, 0, 1), tuple(range(4)), 2)
    p = oracle.compile_choice(w, oracle.choices(w, oracle.median_tree(w, 0), 5)[1], Profile(32, 5, eta=1), (1,))
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        groups = [[list(row) for row in g] for g in p.groups]
        index, _ = masked.enroll(p.query_space, groups, secrets.token_bytes(32), client)
        captured, original = [], client.encrypt
        def capture(plain):
            packet = original(plain)
            captured.append(packet)
            return packet
        monkeypatch.setattr(client, "encrypt", capture)
        ticket, answer, _ = factory.Factory(index, client).prepare(bytes(16))
        # The public C1 of a ZERO ciphertext is wholly revealed by its seed.
        seed = seeded._parse(captured[0], pk)[1]
        public_zero_c1 = owner._uniform_bulk(seed, pk)
        c1 = index.columns[0][0].components[1]
        coefficient = next(i for i, x in enumerate(c1) if x != 0)
        recovered = int((answer.ciphertexts[0].components[1][coefficient] - public_zero_c1[coefficient]) *
                        pow(int(c1[coefficient]), -1, int(pk.q)) % pk.q)
        centered = recovered if recovered <= pk.q // 2 else recovered - int(pk.q)
        recovered_mask = centered % pk.t
        values, _ = oracle.query(p.client_view(), 1)
        request = ticket.consume(values, index.epoch)
        assert (request.delta[0] + recovered_mask) % pk.t == values[0] % pk.t
        assert values[0] == -1  # Recovers the query's first bit exactly.


def test_ideal_uniform_ciphertext_shift_is_mask_independent_not_an_rlwe_proof():
    q, public_column = 7, (3, 5)
    distributions = []
    for r in range(5):
        distributions.append(Counter(((public_column[0] * r + a) % q,
                                      (public_column[1] * r + b) % q)
                                     for a in range(q) for b in range(q)))
    assert all(d == distributions[0] for d in distributions)
    assert len(distributions[0]) == q * q and set(distributions[0].values()) == {1}


def test_factory_private_pad_norm_is_not_published_in_metadata():
    p = plan(False)
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(p.query_space, [[list(row) for row in g] for g in p.groups], secrets.token_bytes(32), client)
        producer = factory.Factory(index, client)
        bounds = [tuple(c.phase_bound for c in producer.prepare(i.to_bytes(16, "little"))[1].ciphertexts) for i in range(8)]
        assert len(set(bounds)) == 1
        assert bounds[0] == producer.answer_bounds
