"""Exact selected phases and fail-before-SK guards; unsupported projections fail."""

from contextlib import closing
from dataclasses import replace
import secrets
from types import SimpleNamespace

from gmpy2 import mpz
import pytest

from experiments.bfv_search_lab import affine_dictionary as affine
from experiments.bfv_search_lab import coordinate_factory as coordinates
from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import decryption_projection as projection
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import score_layout
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import verification_lifetime as lifetime
from experiments.bfv_search_lab.representation_contract import Workload


def plan(count):
    w = Workload(tuple(i % 16 for i in range(count)), tuple(count - i for i in range(count)), 4)
    mapping = affine.prepare(list(w.rows), w.dimension, 17)
    s = space.space(score_layout.layout(tree.context(32, ("",), 17), (mapping.features,), (count,)), (0,))
    return SimpleNamespace(workload=w, mapping=mapping, query_space=s,
                           groups=(affine.index_features(mapping, list(w.rows)),))


@pytest.mark.parametrize("count", (1, 4, 40))
def test_native_projected_relation_and_dedicated_decode_match_full_cipher_every_score(count):
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    p = plan(count)
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    epoch = secrets.token_bytes(32)
    groups = [[list(row) for row in group] for group in p.groups]
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(p.query_space, groups, epoch, client)
        factory = coordinates.Factory(p.query_space, groups, epoch, client)
        server = native.NativeIndex(index, pk)
        gate = lifetime.AttemptBudget(16).bind(projection.ProjectedCheck(index, pk, budget=16))
        for word in range(8):
            token, answer, _ = factory.prepare(word.to_bytes(16, "little"))
            gate.prepare_answer(answer)
            weights, offset = affine.query_features(p.mapping, word)
            values = tuple(x % pk.t for x in weights)
            request = token.consume(values, epoch)
            output = server.evaluate(answer, request)
            assert output == masked.evaluate(index, answer, request, pk)
            reply = projection.project(output, p.query_space, pk)
            body = codec.pack(reply.coefficients, int(pk.q))
            assert projection.parse(body, p.query_space, pk, reply.phase_bounds) == reply
            partial = projection.open_body_once(gate, request, body, pk, sk, reply.phase_bounds)
            assert partial is not None
            full = [bgv.decrypt(c, pk, sk) for c in output]
            assert partial == tuple(tuple(poly[:active]) for poly, active in zip(full, projection.active_counts(p.query_space), strict=True))
            scores = tuple(affine.decode(p.mapping, list(x for row in partial for x in row), offset))
            assert scores == p.workload.expected(word) and p.workload.top_k(scores) == p.workload.top_k(p.workload.expected(word))
            assert len(reply.coefficients) == count + len(output) * pk.n


def test_any_supplied_c0_or_c1_tamper_and_malformed_reply_burn_before_sk(monkeypatch):
    p = plan(4)
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    epoch = secrets.token_bytes(32)
    groups = [[list(row) for row in group] for group in p.groups]
    with closing(owner.OwnerClient(pk, sk)) as client:
        index, _ = masked.enroll(p.query_space, groups, epoch, client)
        factory = coordinates.Factory(p.query_space, groups, epoch, client)
        server = native.NativeIndex(index, pk)
        budget = lifetime.AttemptBudget(8)
        gate = budget.bind(projection.ProjectedCheck(index, pk, budget=8))
        secret_called = []
        monkeypatch.setattr(projection, "_selected_phase", lambda *args: secret_called.append(True))
        for i in range(4):
            token, answer, _ = factory.prepare(i.to_bytes(16, "little"))
            gate.prepare_answer(answer)
            weights, _ = affine.query_features(p.mapping, i)
            values = tuple(x % pk.t for x in weights)
            request = token.consume(values, epoch)
            reply = projection.project(server.evaluate(answer, request), p.query_space, pk)
            wrong = (replace(reply, c0_active=(tuple([mpz((reply.c0_active[0][0] + 1) % pk.q), *reply.c0_active[0][1:]]),)) if i == 0
                     else replace(reply, c1=(reply.c1[0][:-1] + ((reply.c1[0][-1] + 1) % pk.q,),)) if i == 1
                     else replace(reply, c0_active=(reply.c0_active[0][:-1],)) if i == 2 else None)
            assert projection.open_once(gate, request, wrong, pk, sk) is None
            with pytest.raises(RuntimeError, match="consumed"):
                token.consume(values, epoch)
        assert not secret_called and budget.used == 4
        token, answer, _ = factory.prepare((4).to_bytes(16, "little"))
        gate.prepare_answer(answer)
        weights, _ = affine.query_features(p.mapping, 4)
        request = token.consume(tuple(x % pk.t for x in weights), epoch)
        assert projection.open_body_once(gate, request, b"x", pk, sk, (1,)) is None
        assert not secret_called and budget.used == 5


def test_split_crt_or_legacy_layout_cannot_silently_use_coefficient_projection():
    ctx = tree.context(32, ("0", "1"), 17)
    s = space.space(score_layout.layout(ctx, (1, 1), (4, 4)), (0, 1))
    with pytest.raises(ValueError, match="one complete"):
        projection.active_counts(s)
    legacy = space.space(tree.layout(tree.context(32, ("",), 17), (4,), (4,)), (0,))
    with pytest.raises(ValueError, match="one complete"):
        projection.active_counts(legacy)


def test_all_c1_positions_have_a_selected_score_dependency_and_mod_t_is_unsafe():
    for n in (8, 16, 32):
        for target in (0, n - 1):
            for omitted in range(n):
                assert projection.c1_dependency_witness(n, omitted, target) in (1, 65536)
    result = projection.plaintext_field_projection_counterexample()
    assert result["original_decoded"] == 3 and result["altered_decoded"] == 1
