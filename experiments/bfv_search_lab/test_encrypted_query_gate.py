"""E72 independent transpose, exact release and pre-secret rejection controls."""

from contextlib import closing
from dataclasses import replace
from itertools import product
import secrets

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import encrypted_query_certificate as encrypted
from experiments.bfv_search_lab import encrypted_query_gate as gate
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import verification_lifetime as lifetime
from experiments.bfv_search_lab.test_supported_decoder import CASES, inputs


def test_negacyclic_adjoint_matches_literal_signed_integer_matrix():
    for n in (2, 4, 8, 16):
        a = tuple(3*i-7 for i in range(n))
        w = tuple(5*i+1 for i in range(n))
        matrix = tuple(tuple(a[(row-col) % n]*(1 if row >= col else -1)
                             for col in range(n)) for row in range(n))
        literal = tuple(sum(matrix[i][j]*w[i] for i in range(n)) % 97 for j in range(n))
        assert gate.adjoint(a, w, 97) == literal


@pytest.mark.parametrize("descriptor", CASES)
def test_one_registration_all_binary_queries_full_decrypt_scores_ids(descriptor):
    s, words, groups, ids, binding = inputs(*descriptor)
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    epoch, attempts = secrets.token_bytes(32), lifetime.AttemptBudget(16)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, epoch, client)
        receiver = gate.Gate(index, pk, ids, binding, attempts)
        assert not hasattr(receiver, "index") and not hasattr(receiver, "sk")
        for word in range(16):
            values = tuple((1-2*(word >> j & 1)) % 17 for _ in s.dimensions for j in range(4))
            request, _ = encrypted.make_query(s, epoch, word.to_bytes(16, "little"), values, client)
            receiver.pin_query(request)
            output = encrypted.evaluate(index, request, pk)
            reply = gate.project(output, index, pk)
            body = gate.pack(reply, pk)
            assert gate.parse(body, receiver.certificate, pk) == reply
            dots = receiver.open_body_once(request.token_id, body, sk)
            assert dots == tuple(tuple(row) for row in crt.scores(s, groups, values))
            assert dots == tuple(tuple(row) for row in tree.unpack(s.layout, [bgv.decrypt(c, pk, sk) for c in output]))
            scores = tuple((x+word.bit_count()) % 17 for row in dots for x in row)
            expected = tuple((word ^ old).bit_count() for row in words for old in row)
            flat_ids = tuple(i for row in ids for i in row)
            assert scores == expected
            assert sorted(zip(scores, flat_ids, strict=True))[:3] == sorted(zip(expected, flat_ids, strict=True))[:3]
            assert len(body) == gate.body_cost(index, pk, 4)["projected_three_component_response_body_bytes"]
    assert attempts.used == 16


def fixture(monkeypatch=None, *, budget=16):
    s, _, groups, ids, binding = inputs(*CASES[1])
    pk, sk = masked.key_gen(s, q_bits=32, eta=1)
    epoch, attempts = secrets.token_bytes(32), lifetime.AttemptBudget(budget)
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(s, groups, epoch, client)
        requests = tuple(encrypted.make_query(s, epoch, j.to_bytes(16, "little"), (1,)*s.dimension, client)[0]
                         for j in range(budget))
    if monkeypatch is not None:
        monkeypatch.setattr(gate.secrets, "randbelow", lambda q: 1)
    receiver = gate.Gate(index, pk, ids, binding, attempts)
    return index, pk, sk, attempts, requests, receiver


@pytest.mark.parametrize("component", ("c0", "c1", "c2", "truncate", "extend"))
def test_every_transmitted_component_and_malformed_body_rejects_before_secret(monkeypatch, component):
    index, pk, sk, attempts, requests, receiver = fixture(monkeypatch)
    request = requests[0]
    receiver.pin_query(request)
    reply = gate.project(encrypted.evaluate(index, request, pk), index, pk)
    body = gate.pack(reply, pk)
    if component in ("truncate", "extend"):
        bad = body[:-1] if component == "truncate" else body+b"\0"
    else:
        count = len(reply.c0_supported[0])+2*pk.n
        words = list(codec.unpack(body, count, int(pk.q)))
        at = {"c0": 0, "c1": len(reply.c0_supported[0])+pk.n-1,
              "c2": len(reply.c0_supported[0])+2*pk.n-1}[component]
        words[at] = (words[at]+1) % pk.q
        bad = codec.pack(tuple(words), int(pk.q))
    private_calls = []
    monkeypatch.setattr(gate, "_decode", lambda *args: private_calls.append(True))
    assert receiver.open_body_once(request.token_id, bad, sk) is None
    with pytest.raises(RuntimeError, match="consumed"):
        receiver.open_body_once(request.token_id, body, sk)
    assert not private_calls and attempts.used == 2


def test_changed_encrypted_input_is_not_the_pinned_original(monkeypatch):
    index, pk, sk, _, requests, receiver = fixture()
    request = requests[0]
    receiver.pin_query(request)
    # Choose a deterministic nonzero compiled entry, not a probabilistic test.
    column, component, at = next((j, k, i) for j, hint in enumerate(receiver._hints[0])
                                for k, row in enumerate(hint) for i, x in enumerate(row) if x)
    ciphers = list(request.ciphertexts)
    parts = [list(row) for row in ciphers[column].components]
    parts[component][at] = (parts[component][at]+1) % pk.q
    ciphers[column] = replace(ciphers[column], components=tuple(tuple(row) for row in parts))
    substitute = replace(request, ciphertexts=tuple(ciphers))
    body = gate.pack(gate.project(encrypted.evaluate(index, substitute, pk), index, pk), pk)
    private_calls = []
    monkeypatch.setattr(gate, "_decode", lambda *args: private_calls.append(True))
    assert receiver.open_body_once(request.token_id, body, sk) is None
    assert not private_calls


def test_context_ids_and_budget_across_epoch_gates(monkeypatch):
    index, pk, sk, attempts, requests, receiver = fixture(budget=2)
    request = requests[0]
    for bad in (replace(request, epoch=b"x"*32), replace(request, space_binding=bytes(32)),
                replace(request, ciphertexts=(replace(request.ciphertexts[0], key_id="00"*32), *request.ciphertexts[1:]))):
        with pytest.raises(ValueError):
            receiver.pin_query(bad)
    receiver.pin_query(request)
    with pytest.raises(RuntimeError, match="consumed"):
        receiver.pin_query(request)
    private_calls = []
    monkeypatch.setattr(gate, "_decode", lambda *args: private_calls.append(True))
    assert receiver.open_body_once(request.token_id, b"bad", sk) is None
    with pytest.raises(RuntimeError, match="consumed"):
        receiver.open_body_once(request.token_id, b"bad", sk)
    # A trusted epoch refresh cannot reset the shared allowance.
    next_index = replace(index, epoch=b"z"*32)
    next_receiver = gate.Gate(next_index, pk, receiver.output_ids, receiver.owner_plan_binding, attempts)
    next_request = replace(requests[1], epoch=next_index.epoch)
    next_receiver.pin_query(next_request)
    with pytest.raises(RuntimeError, match="Global"):
        next_receiver.open_body_once(next_request.token_id, b"bad", sk)
    assert attempts.used == 2 and not private_calls


def test_tiny_field_aggregate_feedback_matches_union_bound_without_extra_proof_input():
    # Two independent rows, q=3, two output coordinates: 81 private matrices.
    # Correct answers reveal no checker information. On the all-reject path
    # the next error can be fixed adaptively; first wrong acceptance stops.
    q, accepted = 3, 0
    for entries in product(range(q), repeat=4):
        rows = (entries[:2], entries[2:])
        assert all(sum(a*b for a, b in zip(row, (0, 0), strict=True)) % q == 0 for row in rows)
        first = all(row[0] == 0 for row in rows)
        second = all(row[1] == 0 for row in rows) if not first else False
        accepted += first or second
    assert accepted == 17
    assert accepted*q**2 <= 2*q**4  # 17/81 <= 2/9, not an HE security proof.


def test_algebraic_round_count_uses_exact_modulus_not_rounded_bitlength():
    assert gate.rounds_for(3, 1, 4) == 3
    assert gate.rounds_for(97, 1024, 128) == 21
    with pytest.raises(ValueError):
        gate.rounds_for(2, 1, 4)


def test_literal_compiled_row_matches_all_three_ciphertext_component_matrices():
    index, pk, _, _, requests, receiver = fixture()
    request = requests[0]
    output = encrypted.evaluate(index, request, pk)
    row, hints = receiver._rows[0], receiver._hints[0]
    expected = sum(sum(int(z)*int(b) for z, b in zip(v, c, strict=True))
                   for pair, cipher in zip(hints, request.ciphertexts, strict=True)
                   for v, c in zip(pair, cipher.components, strict=True)) % pk.q
    literal = 0
    for weights, cipher in zip(row, output, strict=True):
        for w, p in zip(weights, cipher.components, strict=True):
            literal += sum(int(a)*int(b) for a, b in zip(w, p, strict=True))
    assert literal % pk.q == expected
    for j, (z0, z1) in enumerate(hints):
        independently = [[], []]
        for input_component in range(2):
            for at in range(pk.n):
                total = 0
                for reply, weights in enumerate(row):
                    a0, a1 = index.columns[j][reply].components
                    factors = ((0, a0), (1, a1)) if input_component == 0 else ((1, a0), (2, a1))
                    for k, a in factors:
                        total += sum(int(weights[k][i])*int(a[(i-at) % pk.n])*(1 if i >= at else -1)
                                     for i in range(pk.n))
                independently[input_component].append(mpz(total % pk.q))
        assert (tuple(independently[0]), tuple(independently[1])) == (z0, z1)
