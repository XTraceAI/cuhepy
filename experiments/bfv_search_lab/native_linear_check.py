"""E37 isolated native reference/alternative for complete conditional checking.

Both inherit the existing epoch, one-use, budget and canonical response gates.
NativeVectorCheck preserves EXACTLY the old seeded field challenges and PRG
assumption. PolynomialCheck uses a uniform hidden irreducible polynomial over
the SAME F_Q, with a degree/length collision bound, and has a GMP reference.
Neither is a complete malicious-preprocessing or production/private-timing
protocol. No HE private key is accepted, and no check key/digest is public.
"""

from __future__ import annotations

from collections.abc import Iterator
import importlib
import random
import struct
from types import ModuleType

from Crypto.Hash import SHAKE256
from gmpy2 import mpz

from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import polynomial_fingerprint as polynomial
from experiments.bfv_search_lab import shallow_bgv as bgv


def backend() -> ModuleType:
    module = importlib.import_module("experiments.bfv_search_lab._fingerprint._fingerprint")
    if module.ABI_VERSION != 1:
        raise RuntimeError("Unexpected isolated fingerprint ABI")
    return module


class NativeVectorCheck(check.EpochCheck):
    """Same fingerprints as EpochCheck, including its exact SHAKE byte stream."""

    def __init__(self, index: masked.Index, pk: bgv.PublicKey, *, rounds: int = 4,
                 budget: int = 1024, rng: random.Random | None = None):
        polynomial.field(int(pk.q), rounds)
        self._native = backend()
        super().__init__(index, pk, rounds=rounds, budget=budget, rng=rng)

    def _hash(self, values: tuple[bgv.Ciphertext, ...]) -> tuple[mpz, ...]:
        body = native.pack(values)
        pk, count = self.pk, len(body) // 8
        bits, width, q = pk.q.bit_length(), (pk.q.bit_length() + 7) // 8, int(pk.q)
        hashes = []
        for seed in self._seeds:
            stream = SHAKE256.new(data=b"cuhepy/research/crt-private-check/v1\0" + seed + self.epoch
                                 + self.space.binding + bytes.fromhex(pk.key_id))
            offset, total = 0, mpz(0)
            while offset < count:
                raw = stream.read((count - offset) * width)
                kept, partial = self._native.uniform_dot(body, raw, width, bits, q, offset)
                offset += kept
                total = (total + partial) % pk.q
            hashes.append(total)
        return tuple(hashes)


class PolynomialCheck(check.EpochCheck):
    """Same lifecycle, different known hash family; optional word implementation.

    A response is flattened in pinned reply/component/coefficient order as a
    fixed-length ordinary polynomial in FORMAL Z. Z is not an encryption-ring
    root. Complete negacyclic shift digests are prepared by the existing adjoint
    oracle, so no ciphertext-Q carry or negacyclic wrap term is omitted.
    """

    def __init__(self, index: masked.Index, pk: bgv.PublicKey, *, budget: int = 1024,
                 integrity_bits: int = 128, native_backend: bool = False, rng: random.Random | None = None):
        count = 2 * pk.n * index.space.layout.cost.response_ciphertexts
        degree = polynomial.choose(int(pk.q), count, budget=budget, integrity_bits=integrity_bits)
        self._polynomial = polynomial.sample(int(pk.q), degree, rng=rng)
        self._polynomial_body = struct.pack(f"<{degree}Q", *self._polynomial[:-1])
        self._native = backend() if native_backend else None
        self._length = count
        self.degree = degree
        self.collision_bound = polynomial.collision(int(pk.q), degree, count, budget)
        super().__init__(index, pk, rounds=degree, budget=budget, rng=rng)
        # The base class's seeded challenges are not this variant's key.
        self._seeds = ()

    def _challenges(self) -> Iterator[check.Challenge]:
        pk = self.pk
        if self._native is None:
            rows = polynomial.powers(self._length, self._polynomial, int(pk.q))
        else:
            body = self._native.powers(self._length, self._polynomial_body, int(pk.q))
            words = struct.unpack(f"<{len(body) // 8}Q", body)
            rows = tuple(tuple(mpz(x) for x in words[j * self._length:(j + 1) * self._length])
                         for j in range(self.degree))
        for row in rows:
            yield tuple((row[start:start + pk.n], row[start + pk.n:start + 2 * pk.n])
                        for start in range(0, self._length, 2 * pk.n))

    def _hash(self, values: tuple[bgv.Ciphertext, ...]) -> tuple[mpz, ...]:
        if self._native is None:
            words = tuple(x for c in values for row in c.components for x in row)
            return polynomial.digest(words, self._polynomial, int(self.pk.q))
        body = self._native.remainder(native.pack(values), self._polynomial_body, int(self.pk.q))
        return tuple(mpz(x) for x in struct.unpack(f"<{len(body) // 8}Q", body))
