"""E49 trusted local correlation production from an encrypted index.

Y_r = sum_j C_j*alpha_j(r) + fresh Enc(0). Only the FULL Y_r is released;
the zero encryption's seed stays private. This is known HE rerandomization,
not a new primitive or a reviewed alternative to E29's fresh plaintext factory.
Its privacy hybrid needs joint fresh-ciphertext RLWE pseudorandomness with
the authorized index as auxiliary information, not merely IND-CPA closure.

The private r never reaches the compute server/GPU. The trusted factory pays
for its own public native index, fresh encryption, serialization and doubled
circuit noise. All pads remain one-use; the complete old checker stays before
secret decryption. Authentication, durable state and private timing are open.
"""

from __future__ import annotations

import secrets
import threading

from gmpy2 import mpz

from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv


class Factory:
    def __init__(self, index: masked.Index, client: owner.OwnerClient, *, budget: int = 1024):
        if type(budget) is not int or not 1 <= budget <= 65536:
            raise ValueError("Invalid trusted factory lifetime budget")
        masked._context(index.space, client.pk)
        masked.binding(index.epoch, bytes(16))
        pk, s = client.pk, index.space
        count = s.layout.cost.response_ciphertexts
        if len(index.columns) != s.columns:
            raise ValueError("Invalid trusted encrypted factory index")
        for column in index.columns:
            masked.validate_ciphertexts(column, count, pk)
        fresh = pk.t // 2 + pk.t * pk.eta
        # Metadata must not publish the norm of private r. Use one universal
        # envelope over ALL centered coefficient values of ALL future queries.
        input_limits = tuple(sum(degree * (pk.t // 2) * column[i].phase_bound
                                 for degree, column in zip(s.column_degrees, index.columns, strict=True))
                             for i in range(count))
        self.answer_bounds = tuple(fresh + v for v in input_limits)
        self.worst_response_bounds = tuple(fresh + 2 * v for v in input_limits)
        if any(2 * v >= pk.q for v in self.worst_response_bounds):
            raise ValueError("Encrypted factory exceeds the universal complete-response phase budget")
        self.index, self.client, self.budget = index, client, budget
        self._lock, self._issued = threading.Lock(), set()
        self._evaluator = native.NativeIndex(index, pk)

    def prepare(self, token_id: bytes) -> tuple[masked.MaskTicket, masked.Answer, bytes]:
        """Private local call; return complete ciphertext body, never zero seed."""
        s, pk = self.index.space, self.client.pk
        masked.binding(self.index.epoch, token_id)
        with self._lock:
            if token_id in self._issued or len(self._issued) >= self.budget:
                raise RuntimeError("Factory token identifier/budget consumed")
            self._issued.add(token_id)  # Failures cannot recycle identifiers.
        seed = secrets.token_bytes(32)
        values = masked.mask(s, seed, self.index.epoch, token_id)
        zero = (mpz(0),) * pk.n
        empty = masked.Answer(s, self.index.epoch, token_id, tuple(
            bgv.Ciphertext((zero, zero), pk.key_id, 0) for _ in self.answer_bounds))
        request = masked.Request(s, self.index.epoch, token_id, values)
        combined = self._evaluator.evaluate(empty, request)
        ciphertexts = []
        for cipher, bound in zip(combined, self.answer_bounds, strict=True):
            # Keep the seeded zero packet strictly local. Publishing its seed
            # lets a server subtract its C1 and solve for the hidden mask.
            packet = self.client.encrypt([0] * pk.n)
            rerandomizer = owner.expand(packet, pk)
            parts = tuple(tuple((a + b) % pk.q for a, b in zip(x, y, strict=True))
                          for x, y in zip(cipher.components, rerandomizer.components, strict=True))
            ciphertexts.append(bgv.Ciphertext(parts, pk.key_id, bound))
        answer = masked.Answer(s, self.index.epoch, token_id, tuple(ciphertexts))
        body = codec.pack(tuple(int(x) for c in answer.ciphertexts for poly in c.components for x in poly), int(pk.q))
        return masked.MaskTicket(s, seed, self.index.epoch, token_id), answer, body
