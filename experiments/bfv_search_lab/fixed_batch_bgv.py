"""E32 local fixed-batch BGV with a separate probabilistic correctness type.

The owner fixes all query weights, masks and corrections BEFORE sampling the
encrypted index errors. Each offline answer has fresh independent symmetric
errors. This order supports the CBD tail argument without an adaptive-query
claim. A batch cannot add or replace queries after enrollment.

Index/answer preparation is trusted, as in E29. Exact hidden fingerprints gate
decryption; the public evaluator never receives private checking material.
Old deterministic ciphertext/phase APIs are not relaxed or relabeled.
Research only: no network protocol, durable state, constant-time arithmetic,
RLWE parameter certification, or general adaptive-query security proof.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets
import struct
import threading

import gmpy2
from gmpy2 import mpz

from cuhepy.bfv.scheme import _ring_product, _small_poly, _ternary_poly
from cuhepy.types import BFVPolynomial
from experiments.bfv_search_lab import crt_linear_check as check
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_native_bgv as native
from experiments.bfv_search_lab import crt_noise_budget as noise
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv


@dataclass(frozen=True)
class Context:
    profile: noise.Profile
    pk: bgv.PublicKey
    epoch: bytes


@dataclass(frozen=True)
class StatisticalCiphertext:
    components: tuple[BFVPolynomial, BFVPolynomial]
    key_id: str
    certificate: noise.Certificate  # No deterministic phase_bound field.


def _key_gen(profile: noise.Profile, bits: int, batch_id: bytes) -> tuple[bgv.PublicKey, bgv.SecretKey]:
    noise.validate(profile)
    if type(bits) is not int or not 32 <= bits <= 56:
        raise ValueError("Expected a bounded word-modulus research profile")
    s, eta = profile.space, profile.eta
    n, t = s.layout.context.n, s.layout.context.prime
    q = mpz(((1 << bits) - 2) // (2 * n) * (2 * n) + 1)
    while not gmpy2.is_prime(q):
        q -= 2 * n
    if 2 * noise.certificate(profile).total >= q:
        raise ValueError("Q is too small for the declared fixed-batch tail budget")
    sk = _ternary_poly(n, q)
    a = tuple(mpz(secrets.randbelow(int(q))) for _ in range(n))
    product = _ring_product(a, sk, q)
    b = tuple((t * e - v) % q for e, v in zip(_small_poly(n, eta, q), product, strict=True))
    digest = hashlib.sha256(b"cuhepy/research/fixed-cbd-bgv/v1\0" + profile.binding + batch_id
                            + f"{n}:{t}:{q}:{eta}".encode())
    for poly in (a, b):
        digest.update(b"".join(int(c).to_bytes((bits + 7) // 8, "little") for c in poly))
    key_id = digest.hexdigest()
    return bgv.PublicKey(n, t, q, eta, a, b, key_id), bgv.SecretKey(sk, key_id)


class Batch:
    """Owner lifecycle: immutable inputs -> key/masks -> enrollment -> answers.

    No query API after construction. Optional seeds are reproducible TEST
    fixtures; production-like experiments default to fresh OS seed randomness.
    In-memory one-use semantics only. The fixed batch is additional owner state
    and a different scheduling contract from the ordinary E29 interactive API.
    """
    def __init__(self, s: crt.Space, groups: list[list[list[int]]], weights: tuple[tuple[int, ...], ...], *,
                 q_bits: int = 32, eta: int = 21, correctness_bits: int = 128, query_budget: int = 1024,
                 seeds: tuple[bytes, ...] | None = None):
        crt.validate_rows(s, groups)
        profile = noise.Profile(s, eta, correctness_bits, query_budget)
        noise.validate(profile)
        if (type(weights) is not tuple or not 1 <= len(weights) <= query_budget
                or len(weights) * s.dimension > 1 << 20):
            raise ValueError("Invalid fixed query batch")
        for row in weights:
            if type(row) is not tuple:
                raise ValueError("Expected immutable fixed query coordinates")
            crt.split(s, row)
        if seeds is None:
            seeds = tuple(secrets.token_bytes(32) for _ in weights)
        if (type(seeds) is not tuple or len(seeds) != len(weights)
                or any(type(seed) is not bytes or len(seed) != 32 for seed in seeds)
                or len(set(seeds)) != len(seeds)):
            raise ValueError("Expected distinct private fixed-batch mask seeds")
        self.profile, self._q_bits = profile, q_bits
        self._groups = tuple(tuple(tuple(row) for row in group) for group in groups)
        t = s.layout.context.prime
        self._weights = tuple(tuple(x % t for x in row) for row in weights)
        self._seeds = seeds
        self._state = "new"
        self._client: owner.OwnerClient | None = None
        self._released: set[int] = set()
        self._lock = threading.Lock()

    def keygen(self) -> None:
        if self._state != "new":
            raise RuntimeError("Fixed-batch keys already created")
        batch_id, enrollment_salt = secrets.token_bytes(32), secrets.token_bytes(32)
        self.pk, self.sk = _key_gen(self.profile, self._q_bits, batch_id)
        digest = hashlib.sha256(b"cuhepy/research/fixed-batch-epoch/v1\0" + enrollment_salt
                                + self.profile.binding + bytes.fromhex(self.pk.key_id))
        width = (self.pk.t.bit_length() + 7) // 8
        for group in self._groups:
            digest.update(len(group).to_bytes(4, "little"))
            digest.update(b"".join((x % self.pk.t).to_bytes(width, "little") for row in group for x in row))
        self.context = Context(self.profile, self.pk, digest.digest())
        # Requests become immutable BEFORE any index or answer encryption.
        self._requests = tuple(masked.MaskTicket(self.profile.space, seed, self.context.epoch, i.to_bytes(16, "little"))
                               .consume(row, self.context.epoch)
                               for i, (row, seed) in enumerate(zip(self._weights, self._seeds, strict=True)))
        self._client = owner.OwnerClient(self.pk, self.sk)
        self._state = "fixed"

    def enroll(self) -> tuple[masked.Index, int]:
        if self._state != "fixed" or self._client is None:
            raise RuntimeError("Fix requests once before enrollment")
        self._state = "enrolling"  # A failed attempt may not resample this batch's index.
        index, upload = masked.enroll(self.profile.space, self._rows(), self.context.epoch, self._client)
        self.index = index
        self._state = "enrolled"
        return index, upload

    def _rows(self) -> list[list[list[int]]]:
        return [[list(row) for row in group] for group in self._groups]

    def prepare_answers(self) -> tuple[tuple[masked.Answer, int], ...]:
        if self._state != "enrolled" or self._client is None:
            raise RuntimeError("Prepare each fixed answer pool once after enrollment")
        self._state = "preparing"
        answers = []
        for request, seed in zip(self._requests, self._seeds, strict=True):
            _, answer, packet_bytes = masked.prepare(self.profile.space, self._rows(), self.context.epoch,
                                                     request.token_id, seed, self._client)
            answers.append((answer, packet_bytes))
        self._answers = tuple(answers)
        self._state = "ready"
        return self._answers

    def verifier(self, *, rounds: int = 5) -> Verifier:
        if self._state not in ("enrolled", "ready"):
            raise RuntimeError("Verifier requires the trusted enrolled index")
        return Verifier(self.context, self.index, self._requests, rounds=rounds)

    def release(self, i: int) -> tuple[masked.Request, masked.Answer]:
        with self._lock:
            if self._state != "ready" or type(i) is not int or not 0 <= i < len(self._requests):
                raise RuntimeError("Unknown or unavailable fixed query")
            if i in self._released:
                raise RuntimeError("Fixed query already released")
            self._released.add(i)  # Burn before exposing delta.
            return self._requests[i], self._answers[i][0]

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
        self._state = "closed"
        self._seeds = ()


def _fresh(values: tuple[bgv.Ciphertext, ...], ctx: Context) -> None:
    masked.validate_ciphertexts(values, ctx.profile.space.layout.cost.response_ciphertexts, ctx.pk)
    expected = ctx.pk.t // 2 + ctx.pk.t * ctx.pk.eta
    if any(c.phase_bound != expected for c in values):
        raise ValueError("Require trusted fresh symmetric index/answer ciphertexts")


def _context(ctx: Context, index: masked.Index) -> None:
    noise.validate(ctx.profile)
    pk, s = ctx.pk, ctx.profile.space
    if ((pk.n, pk.t, pk.eta) != (s.layout.context.n, s.layout.context.prime, ctx.profile.eta)
            or not gmpy2.is_prime(pk.q) or not 32 <= pk.q.bit_length() <= 56
            or index.space != s or index.epoch != ctx.epoch or len(index.columns) != s.columns
            or 2 * noise.certificate(ctx.profile).total >= pk.q):
        raise ValueError("Incorrect fixed-batch index/profile")
    for column in index.columns:
        _fresh(column, ctx)


def _call(ctx: Context, index: masked.Index, answer: masked.Answer,
          request: masked.Request) -> tuple[tuple[tuple[int, ...], ...], noise.Certificate]:
    masked.validate_request(request)
    if (answer.space != ctx.profile.space or request.space != ctx.profile.space
            or answer.epoch != ctx.epoch or request.epoch != ctx.epoch or index.epoch != ctx.epoch
            or answer.token_id != request.token_id):
        raise ValueError("Fixed-batch request/answer context mismatch")
    _fresh(answer.ciphertexts, ctx)
    short = crt.corrections(ctx.profile.space, request.delta)
    cert = noise.certificate(ctx.profile, short)
    if 2 * cert.total >= ctx.pk.q:
        raise ValueError("Fixed-batch request exceeds its correctness budget")
    return short, cert


def validate_output(values: tuple[StatisticalCiphertext, ...], ctx: Context, cert: noise.Certificate) -> None:
    if (type(values) is not tuple or len(values) != ctx.profile.space.layout.cost.response_ciphertexts
            or any(type(c) is not StatisticalCiphertext or c.key_id != ctx.pk.key_id or c.certificate != cert
                   or type(c.components) is not tuple or len(c.components) != 2
                   or any(type(poly) is not tuple or len(poly) != ctx.pk.n
                          or any(type(x) not in (int, mpz) or not 0 <= x < ctx.pk.q for x in poly)
                          for poly in c.components) for c in values)):
        raise ValueError("Invalid statistical ciphertext/body/certificate")


def evaluate(ctx: Context, index: masked.Index, answer: masked.Answer,
             request: masked.Request) -> tuple[StatisticalCiphertext, ...]:
    _context(ctx, index)
    short, cert = _call(ctx, index, answer, request)
    polys = [tuple(mpz(x) % ctx.pk.q for x in crt.expand(index.space, row)) for row in short]
    outputs = []
    for i, saved in enumerate(answer.ciphertexts):
        parts = list(saved.components)
        for column, poly, row in zip(index.columns, polys, short, strict=True):
            products = [tuple(x * row[0] % ctx.pk.q for x in c) if len(row) == 1 else _ring_product(c, poly, ctx.pk.q)
                        for c in column[i].components]
            parts = [tuple((a + b) % ctx.pk.q for a, b in zip(old, added, strict=True))
                     for old, added in zip(parts, products, strict=True)]
        outputs.append(StatisticalCiphertext((parts[0], parts[1]), ctx.pk.key_id, cert))
    return tuple(outputs)


class NativeIndex:
    """The existing homemade public NTT arithmetic, with separate output types."""
    def __init__(self, ctx: Context, index: masked.Index):
        _context(ctx, index)
        self.context, self.index = ctx, index
        self._prepared = native.NativeIndex(index, ctx.pk)

    def evaluate(self, answer: masked.Answer, request: masked.Request) -> tuple[StatisticalCiphertext, ...]:
        ctx = self.context
        short, cert = _call(ctx, self.index, answer, request)
        data = native.pack(answer.ciphertexts)
        for positions, handle in self._prepared._handles:
            weights = [x for j in positions for x in short[j]]
            data = self._prepared._native.evaluate(handle, struct.pack(f"<{len(weights)}q", *weights), data)
        words = tuple(mpz(x) for x in struct.unpack(f"<{len(data) // 8}Q", data))
        n = ctx.pk.n
        return tuple(StatisticalCiphertext((words[2 * i * n:(2 * i + 1) * n], words[(2 * i + 1) * n:(2 * i + 2) * n]),
                                          ctx.pk.key_id, cert) for i in range(len(answer.ciphertexts)))


@dataclass(frozen=True)
class CheckedReply:
    token_id: bytes
    ciphertexts: tuple[StatisticalCiphertext, ...]
    _issuer: object


class Verifier(check.EpochCheck):
    """Hidden exact fingerprint gate; only accepted owner receipts can decrypt.

    The receiver pins the fixed owner requests. A receipt is process-local, not
    a serialized proof/signature; compromise of this owner process is excluded.
    Trusted fresh preparation and the CBD correctness assumptions are required.
    """
    def __init__(self, ctx: Context, index: masked.Index, requests: tuple[masked.Request, ...], *, rounds: int = 5):
        _context(ctx, index)
        if (not requests or len(requests) > ctx.profile.query_budget
                or len({r.token_id for r in requests}) != len(requests)):
            raise ValueError("Incorrect fixed request budget")
        for request in requests:
            masked.validate_request(request)
            if request.space != ctx.profile.space or request.epoch != ctx.epoch:
                raise ValueError("Incorrect pinned request epoch")
        super().__init__(index, ctx.pk, rounds=rounds, budget=ctx.profile.query_budget)
        self.context = ctx
        self._pins = {r.token_id: r for r in requests}
        self._issuer = object()
        self._accepted: dict[bytes, tuple[StatisticalCiphertext, ...]] = {}

    def prepare_answer(self, answer: masked.Answer) -> None:
        _fresh(answer.ciphertexts, self.context)
        if answer.token_id not in self._pins:
            raise ValueError("Unknown fixed-batch answer")
        super().prepare_answer(answer)

    def verify_once(self, request: masked.Request, output: tuple[bgv.Ciphertext, ...]) -> bool:
        raise TypeError("Use accept_once for the separate statistical ciphertext type")

    def accept_once(self, request: masked.Request, output: tuple[StatisticalCiphertext, ...]) -> CheckedReply | None:
        with self._lock:
            if self._attempts >= self._budget or request.token_id in self._spent:
                raise RuntimeError("Fixed-batch verification attempt consumed")
            self._attempts += 1
            saved = self._pending.pop(request.token_id, None)
            if saved is not None:
                self._spent.add(request.token_id)
        if saved is None:
            return None
        try:
            if request != self._pins.get(request.token_id):
                return None
            coefficients = crt.corrections(self.space, request.delta)
            cert = noise.certificate(self.context.profile, coefficients)
            validate_output(output, self.context, cert)
            actual = tuple(sum((a * b for cipher, pair in zip(output, rho, strict=True)
                                for component, weights in zip(cipher.components, pair, strict=True)
                                for a, b in zip(component, weights, strict=True)), mpz(0)) % self.pk.q
                           for rho in self._challenges())
            expected = tuple((h0 + sum((a * b for short, hs in zip(coefficients, row, strict=True)
                                       for a, b in zip(short, hs, strict=True)), mpz(0))) % self.pk.q
                             for h0, row in zip(saved[1], self._fingerprints, strict=True))
            if actual != expected:
                return None
        except (ValueError, TypeError):
            return None
        with self._lock:
            self._accepted[request.token_id] = output
        return CheckedReply(request.token_id, output, self._issuer)

    def decrypt_once(self, receipt: CheckedReply, sk: bgv.SecretKey) -> list[list[int]]:
        with self._lock:
            if (type(receipt) is not CheckedReply or receipt._issuer is not self._issuer
                    or self._accepted.get(receipt.token_id) is not receipt.ciphertexts):
                raise ValueError("Require an unspent verified fixed-batch receipt")
            if sk.key_id != self.pk.key_id or len(sk.s) != self.pk.n:
                raise ValueError("Incorrect owner secret context")
            del self._accepted[receipt.token_id]  # Burn before private work.
        result = []
        for cipher in receipt.ciphertexts:
            product = _ring_product(cipher.components[1], sk.s, self.pk.q)
            phase = [(a + b) % self.pk.q for a, b in zip(cipher.components[0], product, strict=True)]
            result.append([int((x if x <= self.pk.q // 2 else x - self.pk.q) % self.pk.t) for x in phase])
        return result
