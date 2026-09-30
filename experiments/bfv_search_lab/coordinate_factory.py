"""E49/E50 control: vectorized private plaintext correlation preparation.

Same fresh seeded ciphertexts as masked.prepare, no homomorphic rerandomization
or stronger privacy premise. Owner-private ternary coordinates are retained as
int8 arrays and field dot products use int64. This is an ordinary optimization,
kept as a strong control before attributing gains to an encrypted-index factory.
No private pad is passed to a remote server or GPU. Lifecycle is local/volatile.
"""

from __future__ import annotations

import secrets
import threading

import numpy as np

from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as space
from experiments.bfv_search_lab import owner_bgv as owner


class Factory:
    def __init__(self, s, groups, epoch, client, *, budget=1024):
        masked._context(s, client.pk)
        masked.binding(epoch, bytes(16))
        space.validate_rows(s, groups)
        if type(budget) is not int or not 1 <= budget <= 65536:
            raise ValueError("Invalid plaintext factory lifetime budget")
        if any(x not in (-1, 0, 1) for g in groups for row in g for x in row):
            raise ValueError("Vectorized factory requires certified ternary affine coordinates")
        arrays = tuple(np.asarray(g, dtype=np.int8).reshape(count, f)
                       for g, count, f in zip(groups, s.layout.counts, s.layout.features, strict=True))
        for array in arrays:
            array.setflags(write=False)
        self.space, self.epoch, self.client, self.budget = s, epoch, client, budget
        self._arrays, self._issued, self._lock = arrays, set(), threading.Lock()
        self.coordinate_array_bytes = sum(a.nbytes for a in arrays)

    def scores(self, values):
        weights = space.split(self.space, values)
        t = self.space.layout.context.prime
        if any(not -(t // 2) <= x < t for x in values):
            raise ValueError("Private plaintext factory weight outside bounded field")
        return [(array @ np.asarray(weights[i], dtype=np.int64) % t).tolist()
                for array, i in zip(self._arrays, self.space.map_ids, strict=True)]

    def prepare(self, token_id):
        s, pk = self.space, self.client.pk
        masked.binding(self.epoch, token_id)
        with self._lock:
            if token_id in self._issued or len(self._issued) >= self.budget:
                raise RuntimeError("Plaintext factory token identifier/budget consumed")
            self._issued.add(token_id)
        seed = secrets.token_bytes(32)
        values = masked.mask(s, seed, self.epoch, token_id)
        packets = [self.client.encrypt(p) for p in space.outputs(s.layout, self.scores(values))]
        answer = masked.Answer(s, self.epoch, token_id, tuple(owner.expand(p, pk) for p in packets))
        return masked.MaskTicket(s, seed, self.epoch, token_id), answer, sum(map(len, packets))
