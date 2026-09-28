"""E14 one-use fingerprints of the constant-mask oracle's ONLINE relation.

Classic randomized linear checking, not a novel proof or production gate.
Converted index and offline answer MUST already be trusted. This does not
verify their HE computation, authenticate a network peer or stop rollback of
private ticket state. Private Python arithmetic has no side-channel assurance.
The supported ciphertext modulus is prime; a 1/q bound must not be silently
applied to an arbitrary composite RNS modulus.
"""

from __future__ import annotations

import random
import threading

import gmpy2

from experiments.bfv_search_lab import matrix_bgv_oracle as matrix
from experiments.bfv_search_lab import matrix_masked_query as masked


class LinearTicket:
    """Private local check prepared from trusted inputs, with one attempt.

    For fixed nonzero error e over F_q and fresh uniform secret rho,
    Pr[<rho,e>=0]=1/q. Independent repetitions give q**(-rounds).
    That statement requires hidden weights, one response attempt and trusted
    preprocessing. It is not a claim about the entire two-party protocol.
    """

    def __init__(self, index: masked.ConvertedIndex, answer: masked.OfflineAnswer,
                 rng: random.Random, *, rounds: int = 3):
        ctx = index.context
        if (answer.context != ctx or answer.epoch != index.epoch or answer.mask_space != "constant"
                or len(answer.results) != len(index.entries) or not index.entries
                or any(len(row) != ctx.rank or any(len(c.components) != ctx.rank + 1
                                                   or any(len(p) != ctx.n for p in c.components)
                                                   for c in row) for row in index.entries)
                or any(len(c.components) != ctx.rank + 1 or any(len(p) != ctx.n for p in c.components)
                       for c in answer.results)
                or type(rounds) is not int or not 1 <= rounds <= 8 or not gmpy2.is_prime(ctx.q)):
            raise ValueError("Expected trusted constant-mask inputs over a prime ciphertext field")
        self.context, self.epoch, self.token_id = ctx, index.epoch, answer.token_id
        self._bounds = tuple((saved.phase_bound, tuple(c.phase_bound for c in row))
                             for row, saved in zip(index.entries, answer.results, strict=True))
        columns = tuple(tuple(row[j].components[c][h] for row in index.entries
                              for c in range(ctx.rank + 1) for h in range(ctx.n)) for j in range(ctx.rank))
        offset = tuple(x for cipher in answer.results for p in cipher.components for x in p)
        if any(len(column) != len(offset) for column in columns):
            raise ValueError("Invalid trusted preprocessing shape")
        self._weights = tuple(tuple(rng.randrange(ctx.q) for _ in offset) for _ in range(rounds))
        self._fingerprints = tuple(
            (sum(a * b for a, b in zip(rho, offset, strict=True)) % ctx.q,
             tuple(sum(a * b for a, b in zip(rho, column, strict=True)) % ctx.q for column in columns))
            for rho in self._weights)
        self._used, self._lock = False, threading.Lock()

    def verify_once(self, request: masked.Request, result: tuple[matrix.VectorCipher, ...]) -> bool:
        """Consume before parsing/checking; malformed attempts also burn the ticket."""
        with self._lock:
            if self._used:
                raise RuntimeError("Local linear check already consumed")
            self._used = True
        ctx = self.context
        if (request.context != ctx or request.epoch != self.epoch or request.token_id != self.token_id
                or request.mask_space != "constant" or len(request.delta) != ctx.rank
                or any(len(p) != ctx.n or any(type(x) is not int or not 0 <= x < ctx.t for x in p)
                       or any(p[1:]) for p in request.delta)
                or len(result) != len(self._bounds)):
            return False
        weights = tuple(p[0] if p[0] <= ctx.t // 2 else p[0] - ctx.t for p in request.delta)
        for cipher, (saved_bound, entry_bounds) in zip(result, self._bounds, strict=True):
            expected_bound = saved_bound + sum(abs(w) * b for w, b in zip(weights, entry_bounds, strict=True))
            if (cipher.phase_bound != expected_bound or expected_bound >= ctx.q // 2
                    or len(cipher.components) != ctx.rank + 1
                    or any(len(p) != ctx.n or any(type(x) is not int or not 0 <= x < ctx.q for x in p)
                           for p in cipher.components)):
                return False
        output = tuple(x for cipher in result for p in cipher.components for x in p)
        return all(sum(a * b for a, b in zip(rho, output, strict=True)) % ctx.q
                   == (h0 + sum(w * h for w, h in zip(weights, hs, strict=True))) % ctx.q
                   for rho, (h0, hs) in zip(self._weights, self._fingerprints, strict=True))
