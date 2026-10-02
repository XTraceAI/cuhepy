"""E94 conditional fresh-owner-query phase control; no production protocol.

The frozen owner index and adaptive plaintext query are fixed BEFORE fresh
independent query CBD coins. No distributional assumption is made about the
reused index/source key. Public policies do not prove these sampling premises.
The lifetime ledger is volatile and counts generated queries, not responses.
"""

from __future__ import annotations

from dataclasses import dataclass
import threading

from experiments.bfv_search_lab.committed_precision_epoch import tail_threshold
from experiments.bfv_search_lab.source_phase_budget import envelope


@dataclass(frozen=True)
class Policy:
    n: int
    t: int
    eta: int
    columns: int
    replies: int
    max_fresh_queries: int
    kappa: int
    source_key_id: str
    index_epoch: str


@dataclass(frozen=True)
class Bound:
    events: int
    deterministic_mean: int
    fresh_query_twice_proxy: int
    fresh_query_tail: int
    whole_lifetime_phase: int
    all_support_phase: int


def derive(policy):
    if type(policy) is not Policy:
        raise ValueError("Expected an owner-approved lifetime policy")
    b = envelope(policy.n, policy.t, policy.eta, policy.columns)
    if (type(policy.replies) is not int or not 1 <= policy.replies <= 1 << 20
            or type(policy.max_fresh_queries) is not int or not 1 <= policy.max_fresh_queries <= 1 << 32
            or type(policy.kappa) is not int or not 1 <= policy.kappa <= 256
            or any(type(x) is not str or not 1 <= len(x) <= 64 for x in
                   (policy.source_key_id, policy.index_epoch))):
        raise ValueError("Invalid coefficient/query lifetime or original binding")
    events = policy.n * policy.replies * policy.max_fresh_queries
    mean = policy.n * policy.columns * b.owner_fresh * (policy.t // 2)
    proxy = policy.eta * policy.t**2 * policy.n * policy.columns * b.owner_fresh**2
    tail = tail_threshold(proxy, policy.kappa, events)
    return Bound(events, mean, proxy, tail, min(b.centered_phase, mean + tail), b.centered_phase)


def verify(policy, claimed):
    # Exact dataclass equality is supplemented by strict field types: bool is
    # not a valid integer witness. Sampling/original authentication is external.
    if (type(claimed) is not Bound or any(type(x) is not int or not 0 <= x < 1 << 256
                                       for x in (claimed.events, claimed.deterministic_mean,
                                                 claimed.fresh_query_twice_proxy, claimed.fresh_query_tail,
                                                 claimed.whole_lifetime_phase, claimed.all_support_phase))
            or claimed != derive(policy)):
        raise ValueError("False or noncanonical conditional phase budget")
    return claimed


class FreshQueryLedger:
    """Owner-only volatile reservation guard; NOT a sampler/provenance proof.

    Reserve before encryption, even if delivery/query/result later aborts.
    Messages, index and error law remain owner-approved outside this object.
    Durable rollback/fork protection and external authentication remain open.
    """

    def __init__(self, policy):
        self.policy, self.bound = policy, derive(policy)
        self._issued, self._lock = set(), threading.Lock()

    def reserve(self, query_id, source_key_id, index_epoch):
        if (type(query_id) is not bytes or len(query_id) != 16
                or type(source_key_id) is not str or source_key_id != self.policy.source_key_id
                or type(index_epoch) is not str or index_epoch != self.policy.index_epoch):
            raise ValueError("Wrong original source epoch or canonical query ID")
        with self._lock:
            if query_id in self._issued:
                raise RuntimeError("Original query already reserved; replay is not fresh")
            if len(self._issued) >= self.policy.max_fresh_queries:
                raise RuntimeError("Fresh-query lifetime exhausted")
            self._issued.add(query_id)
        return self.bound
