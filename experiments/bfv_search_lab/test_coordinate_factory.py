"""The stronger producer control preserves fresh-noise and one-use semantics."""

from contextlib import closing
import secrets

import pytest

from experiments.bfv_search_lab import coordinate_factory
from experiments.bfv_search_lab import crt_linear_check as checks
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import integer_phase_audit as audit
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def fixture():
    w = Workload((0, 1, 2, 3, 8, 9, 10, 11), tuple(range(8)), 4)
    choice = oracle.choices(w, oracle.median_tree(w, 1), 17)[-1]
    return oracle.compile_choice(w, choice, Profile(32, 17, eta=1), (1, 1))


def test_vectorized_private_scores_and_encrypted_full_query_path():
    p = fixture()
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    epoch = secrets.token_bytes(32)
    groups = [[list(row) for row in group] for group in p.groups]
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(p.query_space, groups, epoch, client)
        producer = coordinate_factory.Factory(p.query_space, groups, epoch, client, budget=16)
        server, gate = native.NativeIndex(index, pk), checks.EpochCheck(index, pk, budget=16)
        phase = audit.Audit(index, pk, sk)
        for word in range(16):
            values, offsets = oracle.query(p.client_view(), word)
            assert producer.scores(values) == space.scores(p.query_space, groups, values)
            ticket, answer, packet_bytes = producer.prepare(word.to_bytes(16, "little"))
            assert packet_bytes > 0
            assert all(c.phase_bound == pk.t // 2 + pk.t * pk.eta for c in answer.ciphertexts)
            gate.prepare_answer(answer)
            request = ticket.consume(values, epoch)
            result = server.evaluate(answer, request)
            assert result == masked.evaluate(index, answer, request, pk)
            assert gate.verify_once(request, result)
            assert phase.measure(request, answer, result)["all_integer_phase_coefficients_match_ciphertext"]
            actual = oracle.decode(p.client_view(), [bgv.decrypt(c, pk, sk) for c in result], offsets)
            assert actual == p.workload.expected(word)
        with pytest.raises(RuntimeError, match="consumed"):
            producer.prepare(bytes(16))


def test_failure_burns_identifier_and_invalid_coordinates_reject(monkeypatch):
    p = fixture()
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    epoch = secrets.token_bytes(32)
    groups = [[list(row) for row in group] for group in p.groups]
    with closing(owner.OwnerClient(pk, sk)) as client:
        producer = coordinate_factory.Factory(p.query_space, groups, epoch, client)
        def fail(*args):
            raise ValueError("injected local encryption failure")
        monkeypatch.setattr(client, "encrypt", fail)
        with pytest.raises(ValueError, match="injected"):
            producer.prepare(bytes(16))
        with pytest.raises(RuntimeError, match="consumed"):
            producer.prepare(bytes(16))
        groups[0][0][0] = 256
        with pytest.raises(ValueError, match="ternary"):
            coordinate_factory.Factory(p.query_space, groups, epoch, client)
