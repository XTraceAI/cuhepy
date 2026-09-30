"""Owner-only E35 unreduced phase diagnostics, outside online performance.

Fresh input phases are bounded. Reconstruct the response in an independent
integer ring modulus above twice the UNIVERSAL absolute circuit bound; it
cannot wrap there. Compare every coefficient modulo Q and against output
deterministic metadata. This is a secret diagnostic, never an authorization
gate, public server API or network verifier.
"""

from __future__ import annotations

import hashlib

from gmpy2 import mpz

from cuhepy.bfv.scheme import _ring_product
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv


class Audit:
    def __init__(self, index: masked.Index, pk: bgv.PublicKey, sk: bgv.SecretKey):
        if sk.key_id != pk.key_id:
            raise ValueError("Incorrect owner audit context")
        self.index, self.pk = index, pk
        self.product = owner.TernaryProduct(sk.s, pk.q)
        self.product.prepare(pk.q)
        maximum = crt.cost(index.space, q_bits=max(32, pk.q.bit_length()), eta=pk.eta)["worst_case_phase_bound"]
        if 2 * maximum >= pk.q:
            raise ValueError("Audit requires the complete deterministic circuit bound")
        self.modulus = mpz(2 * maximum + 1)
        self.columns = tuple(tuple(tuple(mpz(x) % self.modulus for x in self.fresh(c)) for c in column)
                             for column in index.columns)

    def fresh(self, cipher: bgv.Ciphertext) -> tuple[int, ...]:
        product = self.product.multiply(cipher.components[1], self.pk.q)
        residues = tuple((a + b) % self.pk.q for a, b in zip(cipher.components[0], product, strict=True))
        phase = tuple(int(x if x <= self.pk.q // 2 else x - self.pk.q) for x in residues)
        if max(map(abs, phase), default=0) > cipher.phase_bound:
            raise AssertionError("Fresh owner phase exceeds its absolute bound")
        return phase

    def measure(self, request: masked.Request, answer: masked.Answer, output: tuple[bgv.Ciphertext, ...]) -> dict:
        short = crt.corrections(self.index.space, request.delta)
        polynomials = [tuple(mpz(x) % self.modulus for x in crt.expand(self.index.space, row)) for row in short]
        digest, maximum = hashlib.sha256(), 0
        masked.validate_ciphertexts(output, len(answer.ciphertexts), self.pk)
        for i, (saved, cipher) in enumerate(zip(answer.ciphertexts, output, strict=True)):
            phase = [mpz(x) % self.modulus for x in self.fresh(saved)]
            for column, poly in zip(self.columns, polynomials, strict=True):
                product = _ring_product(column[i], poly, self.modulus)
                phase = [(a + b) % self.modulus for a, b in zip(phase, product, strict=True)]
            integers = [int(x if x <= self.modulus // 2 else x - self.modulus) for x in phase]
            actual_product = self.product.multiply(cipher.components[1], self.pk.q)
            actual = [(a + b) % self.pk.q for a, b in zip(cipher.components[0], actual_product, strict=True)]
            assert all(a == b % self.pk.q for a, b in zip(actual, integers, strict=True))
            observed = max(map(abs, integers), default=0)
            assert observed <= cipher.phase_bound and 2 * observed < self.pk.q
            maximum = max(maximum, observed)
            digest.update(b"".join(x.to_bytes(16, "little", signed=True) for x in integers))
        return {"maximum_unreduced_integer_phase": maximum,
                "maximum_deterministic_response_bound": max(c.phase_bound for c in output),
                "all_integer_phase_coefficients_match_ciphertext": True,
                "phase_fraction_of_half_q": 2 * maximum / int(self.pk.q),
                "private_phase_digest_diagnostic_only": digest.hexdigest()}
