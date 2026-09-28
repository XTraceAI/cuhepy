"""E29 conditional checking of the complete, unrounded public CRT response.

Known secret Freivalds preprocessing (cf. Slalom), specialized to negacyclic
convolution. The adjoint computes all subring-shift fingerprints with one ring
product per ciphertext component. Index and offline answers MUST be trusted.
No HE secret is used by this checker, and no fingerprint is sent to the server.

With ideal independent uniform field challenges, B verification attempts have
first-false-accept probability at most B/q**rounds. This requires prime q, hidden
state, a bounded verification-only transcript, trusted premises and no private
timing leakage. It is not a proof of the whole masking/HE/network protocol.
The in-memory budget/ticket state has no persistence or rollback protection.
"""

from __future__ import annotations

from collections.abc import Iterator
import random
import secrets
import threading

from Crypto.Hash import SHAKE256
import gmpy2
from gmpy2 import mpz

from cuhepy.bfv.scheme import _ring_product
from cuhepy.types import BFVPolynomial
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import shallow_bgv as bgv

Challenge = tuple[tuple[BFVPolynomial, BFVPolynomial], ...]


def adjoint(poly: BFVPolynomial, q: mpz) -> BFVPolynomial:
    """rho(X^-1): coefficient zero of c*rho* is the coefficient dot product."""
    return (poly[0], *tuple(-x % q for x in reversed(poly[1:])))


class EpochCheck:
    def __init__(self, index: masked.Index, pk: bgv.PublicKey, *, rounds: int = 4,
                 budget: int = 1024, rng: random.Random | None = None):
        crt.validate(index.space)
        masked.binding(index.epoch, bytes(16))
        if (type(rounds) is not int or not 1 <= rounds <= 8 or type(budget) is not int or not 1 <= budget <= 65536
                or not gmpy2.is_prime(pk.q) or (pk.n, pk.t) != (index.space.layout.context.n, index.space.layout.context.prime)
                or len(index.columns) != index.space.columns):
            raise ValueError("Expected bounded trusted CRT inputs over prime Q")
        count = index.space.layout.cost.response_ciphertexts
        for column in index.columns:
            masked.validate_ciphertexts(column, count, pk)
        self.space, self.epoch, self.pk = index.space, index.epoch, pk
        self._column_bounds = tuple(tuple(c.phase_bound for c in column) for column in index.columns)
        self._budget, self._attempts, self._registered = budget, 0, 0
        self._lock = threading.Lock()
        self._pending: dict[bytes, tuple[tuple[int, ...], tuple[mpz, ...]]] = {}
        self._spent: set[bytes] = set()
        sampler = rng if rng is not None else secrets.SystemRandom()
        # Retain private seeds instead of entire coefficient challenge vectors.
        # The ideal-field probability bound consequently needs the PRG hybrid.
        self._seeds = tuple(sampler.randbytes(32) for _ in range(rounds))
        fingerprints = []
        for rho in self._challenges():
            row = []
            for column in index.columns:
                total = [mpz(0)] * pk.n
                for cipher, pair in zip(column, rho, strict=True):
                    for component, weights in zip(cipher.components, pair, strict=True):
                        product = _ring_product(component, adjoint(weights, pk.q), pk.q)
                        total = [(a + b) % pk.q for a, b in zip(total, product, strict=True)]
                # <rho, X^k*c> = coefficient_0(X^k * (c*rho*)).
                row.append(tuple(total[0] if k == 0 else -total[pk.n - k * self.space.stride] % pk.q
                                 for k in range(self.space.slots)))
            fingerprints.append(tuple(row))
        self._fingerprints = tuple(fingerprints)
        # The large encrypted index is intentionally not retained by the checker.

    def _challenges(self) -> Iterator[Challenge]:
        pk = self.pk
        count = self.space.layout.cost.response_ciphertexts * 2 * pk.n
        bits, width = pk.q.bit_length(), (pk.q.bit_length() + 7) // 8
        bit_mask = (mpz(1) << bits) - 1
        for seed in self._seeds:
            stream = SHAKE256.new(data=b"cuhepy/research/crt-private-check/v1\0" + seed + self.epoch
                                 + self.space.binding + bytes.fromhex(pk.key_id))
            values: list[mpz] = []
            while len(values) < count:
                remaining = count - len(values)
                block = gmpy2.unpack(mpz.from_bytes(stream.read(remaining * width), "little"), width * 8)
                block.extend([mpz(0)] * (remaining - len(block)))
                values.extend(value for x in block if (value := x & bit_mask) < pk.q)
            yield tuple((tuple(values[start:start + pk.n]), tuple(values[start + pk.n:start + 2 * pk.n]))
                        for start in range(0, count, 2 * pk.n))

    def _hash(self, values: tuple[bgv.Ciphertext, ...]) -> tuple[mpz, ...]:
        return tuple(sum((a * b for cipher, pair in zip(values, rho, strict=True)
                          for component, weights in zip(cipher.components, pair, strict=True)
                          for a, b in zip(component, weights, strict=True)), mpz(0)) % self.pk.q
                     for rho in self._challenges())

    def prepare_answer(self, answer: masked.Answer) -> None:
        """Register only an owner-generated/trusted answer BEFORE the online query."""
        masked.binding(answer.epoch, answer.token_id)
        if answer.space != self.space or answer.epoch != self.epoch:
            raise ValueError("Stale trusted answer epoch")
        masked.validate_ciphertexts(answer.ciphertexts, self.space.layout.cost.response_ciphertexts, self.pk)
        hashes = self._hash(answer.ciphertexts)
        with self._lock:
            if (answer.token_id in self._pending or answer.token_id in self._spent
                    or self._registered >= self._budget):
                raise RuntimeError("Duplicate token or exhausted local verification pool")
            self._pending[answer.token_id] = tuple(c.phase_bound for c in answer.ciphertexts), hashes
            self._registered += 1

    def verify_once(self, request: masked.Request, output: tuple[bgv.Ciphertext, ...]) -> bool:
        """The caller supplies its pinned request; never accept a server's substitute."""
        with self._lock:
            if self._attempts >= self._budget or request.token_id in self._spent:
                raise RuntimeError("Local verification budget/ticket consumed")
            self._attempts += 1  # All attempts count, including invalid identifiers.
            saved = self._pending.pop(request.token_id, None)
            if saved is not None:
                self._spent.add(request.token_id)
        if saved is None:
            return False
        try:
            masked.validate_request(request)
            if request.space != self.space or request.epoch != self.epoch:
                return False
            masked.validate_ciphertexts(output, len(saved[0]), self.pk)
            coefficients = crt.corrections(self.space, request.delta)
            norms = tuple(sum(map(abs, p)) for p in coefficients)
            for i, cipher in enumerate(output):
                bound = saved[0][i] + sum(norm * bounds[i] for norm, bounds in zip(norms, self._column_bounds, strict=True))
                if cipher.phase_bound != bound or 2 * bound >= self.pk.q:
                    return False
            actual = self._hash(output)
            expected = tuple((h0 + sum((a * b for short, hs in zip(coefficients, row, strict=True)
                                       for a, b in zip(short, hs, strict=True)), mpz(0))) % self.pk.q
                             for h0, row in zip(saved[1], self._fingerprints, strict=True))
            return actual == expected
        except (ValueError, TypeError):
            return False
