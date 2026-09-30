"""Exact public reconstruction and full-gate mutations before secret decryption."""

from contextlib import closing
from dataclasses import replace
import secrets

import pytest

from experiments.bfv_search_lab import component_recipe as recipe
from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab.representation_contract import Profile, Workload


@pytest.mark.parametrize("mode", ("cached", "streaming"))
def test_reconstructed_component_exact_for_adaptive_shared_crt_queries(mode):
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    w = Workload((0, 1, 2, 3, 8, 9, 10, 11), tuple(range(8)), 4)
    choice = oracle.choices(w, oracle.median_tree(w, 1), 17)[-1]
    p = oracle.compile_choice(w, choice, Profile(32, 17, eta=1), (1, 1))
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    epoch = secrets.token_bytes(32)
    with closing(owner.OwnerClient(pk, sk)) as client:
        groups = [[list(row) for row in g] for g in p.groups]
        index, seeds, _ = recipe.enroll(p.query_space, groups, epoch, client)
        restore, server = recipe.Reconstructor(seeds, pk, mode=mode), native.NativeIndex(index, pk)
        gate = check.EpochCheck(index, pk, budget=32)
        pool = [recipe.prepare(p.query_space, groups, epoch, i.to_bytes(16, "little"), secrets.token_bytes(32), client)
                for i in range(16)]
        for _, answer, _ in pool:
            gate.prepare_answer(answer)
        word = 0
        for i, (ticket, answer, answer_seeds) in enumerate(pool):
            values, offsets = oracle.query(p.client_view(), word)
            request = ticket.consume(values, epoch)
            full = server.evaluate(answer, request)
            body = recipe.c0_body(full, pk)
            assert len(body) == p.resources.response_body_bytes // 2
            actual = restore.verify_and_restore(gate, request, body, answer_seeds)
            assert actual == full == masked.evaluate(index, answer, request, pk)
            assert oracle.decode(p.client_view(), [bgv.decrypt(c, pk, sk) for c in actual], offsets) == w.expected(word)
            word = (w.top_k(w.expected(word))[0][1] + i + 1) % 16


@pytest.mark.parametrize("mutation", ("c0", "answer_seed", "index_seed", "truncated", "epoch"))
def test_recipe_mutations_rejected_by_same_complete_gate_and_cannot_retry(mutation):
    pytest.importorskip("experiments.bfv_search_lab._subring._crt_subring")
    w = Workload(tuple(range(8)), tuple(range(8)), 3)
    p = oracle.compile_choice(w, oracle.choices(w, oracle.median_tree(w, 0), 17)[0], Profile(32, 17, eta=1), (1,))
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    epoch = secrets.token_bytes(32)
    with closing(owner.OwnerClient(pk, sk)) as client:
        groups = [[list(row) for row in g] for g in p.groups]
        index, seeds, _ = recipe.enroll(p.query_space, groups, epoch, client)
        ticket, answer, answer_seeds = recipe.prepare(p.query_space, groups, epoch, bytes(16), secrets.token_bytes(32), client)
        values, _ = oracle.query(p.client_view(), 2)
        request = ticket.consume(values, epoch)
        full = native.NativeIndex(index, pk).evaluate(answer, request)
        body = recipe.c0_body(full, pk)
        gate = check.EpochCheck(index, pk, budget=2)
        gate.prepare_answer(answer)
        if mutation == "c0":
            body = bytes([body[0] ^ 1]) + body[1:]
        elif mutation == "answer_seed":
            answer_seeds = (bytes(32),)
        elif mutation == "index_seed":
            seeds = replace(seeds, columns=((bytes(32),), *seeds.columns[1:]))
        elif mutation == "truncated":
            body = body[:-1]
        else:
            request = replace(request, epoch=b"x" * 32)
        restore = recipe.Reconstructor(seeds, pk, mode="streaming")
        with pytest.raises(ValueError, match="recipe|rejected"):
            restore.verify_and_restore(gate, request, body, answer_seeds)
        with pytest.raises(RuntimeError, match="consumed"):
            gate.verify_once(request, full)
