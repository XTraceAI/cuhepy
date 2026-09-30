"""Epoch changes and failed calls must not reset the whole feedback budget."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace

import pytest

from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import representation_oracle as oracle
from experiments.bfv_search_lab import representation_updates as updates
from experiments.bfv_search_lab import verification_lifetime as lifetime
from experiments.bfv_search_lab.representation_contract import Profile, Workload


def test_real_checker_refreshes_rejections_and_unknown_ids_share_budget():
    w = Workload((0, 1, 2, 3), (0, 1, 2, 3), 3)
    choice = oracle.choices(w, oracle.median_tree(w, 0), 17)[1]
    p = oracle.compile_choice(w, choice, Profile(32, 17, eta=1), (1,))
    pk, sk = masked.key_gen(p.query_space, q_bits=32, eta=1)
    budget = lifetime.AttemptBudget(3)
    with closing(owner.OwnerClient(pk, sk)) as client:
        pool = updates.RepairPool(p, client)
        for revision in range(3):
            token = pool.prepare(revision.to_bytes(16, "little"))
            gate = budget.bind(check.EpochCheck(pool.index, pk))
            gate.prepare_answer(token.answer)
            values, _ = oracle.query(pool.plan.client_view(), 0)
            request = token.consume(values, pool.index.epoch)
            output = masked.evaluate(pool.index, token.answer, request, pk)
            if revision == 0:
                assert gate.verify_once(request, output)
            elif revision == 1:
                assert not gate.verify_once(request, ())
            else:
                assert not gate.verify_once(replace(request, token_id=b"?" * 16), output)
            pool.edit({0: (revision + 1) % 4}, method="full_reencrypt")
        assert budget.used == 3
        another = budget.bind(check.EpochCheck(pool.index, pk))
        with pytest.raises(RuntimeError, match="Global"):
            another.verify_once(request, output)


def test_one_shared_budget_is_atomic_across_local_threads():
    class Checker:
        def verify_once(self, *args):
            return False
    budget = lifetime.AttemptBudget(8)
    def attempt(_):
        try:
            budget.bind(Checker()).verify_once(None, ())
        except RuntimeError:
            return False
        return True
    with ThreadPoolExecutor(max_workers=8) as executor:
        assert sum(executor.map(attempt, range(32))) == 8
    assert budget.used == 8


def test_checker_exception_still_spends_global_attempt():
    class Checker:
        def verify_once(self, *args):
            raise ValueError("injected checker failure")
    budget = lifetime.AttemptBudget(1)
    with pytest.raises(ValueError, match="injected"):
        budget.bind(Checker()).verify_once(None, ())
    with pytest.raises(RuntimeError, match="Global"):
        budget.bind(Checker()).verify_once(None, ())
