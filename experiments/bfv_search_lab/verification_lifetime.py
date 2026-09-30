"""Local verification-attempt accounting across trusted epoch refreshes.

A new fingerprint epoch does not give the malicious server a new lifetime
soundness allowance. Share one AttemptBudget across every trusted checker in
the declared lifetime; burn before malformed, rejected or failing calls too.
This is volatile state with no crash/rollback/concurrent-process protection.
The caller must retain this same object. It is not a durable token service or
a proof of the underlying checker, HE privacy, parameters or private timing.
"""

from __future__ import annotations

import threading


class AttemptBudget:
    def __init__(self, limit):
        if type(limit) is not int or not 1 <= limit <= 65536:
            raise ValueError("Invalid bounded verification lifetime")
        self.limit, self._used, self._lock = limit, 0, threading.Lock()

    @property
    def used(self):
        with self._lock:
            return self._used

    def bind(self, checker):
        """Trusted caller only: do not expose checker construction to a server."""
        return _Bound(self, checker)

    def _burn(self):
        with self._lock:
            if self._used >= self.limit:
                raise RuntimeError("Global verification lifetime budget exhausted")
            self._used += 1


class _Bound:
    def __init__(self, budget, checker):
        self._budget, self._checker = budget, checker

    def prepare_answer(self, answer):
        return self._checker.prepare_answer(answer)

    def verify_once(self, request, output):
        self._budget._burn()
        return self._checker.verify_once(request, output)
