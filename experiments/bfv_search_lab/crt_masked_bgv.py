"""E29 local seeded BGV over response-transposed CRT coordinate columns.

The owner enrolls columns and independently encrypts every offline random-query
answer. Publishing a deterministic combination of the SAME public ciphertexts
can disclose the mask by linear solving; it is deliberately not a token API.
Preparing tokens needs the plaintext coordinates (or a separately reviewed
trusted service). Upload, state, epochs and wasted tokens are real costs.

Homemade Python/GMP arithmetic, not SEAL. No constant-time, parameter approval,
durable token/replay protection or network protocol is claimed. The old BFV/BGV
service is unchanged. These local objects are not authenticated transport.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets
import threading

from gmpy2 import mpz
import gmpy2

from cuhepy.bfv.scheme import _ring_product, _small_poly, _ternary_poly
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv


def key_gen(s: crt.Space, *, q_bits: int = 40, eta: int = 21) -> tuple[bgv.PublicKey, bgv.SecretKey]:
    """Full-degree RLWE key with a bound for THIS linear circuit, not depth one.

    Smaller q is permitted because seeded fresh phases are m+t*e and the circuit
    only adds plaintext products. This is a correctness bound, not security
    parameter certification. Fresh index encryption under the new key is needed.
    """
    model = crt.cost(s, q_bits=q_bits, eta=eta)
    n, t = s.layout.context.n, s.layout.context.prime
    q = mpz(((1 << q_bits) - 2) // (2 * n) * (2 * n) + 1)
    while not gmpy2.is_prime(q):
        q -= 2 * n
    if 2 * model["worst_case_phase_bound"] >= q:
        raise ValueError("Q is too small for the complete masked linear circuit")
    secret = _ternary_poly(n, q)
    a = tuple(mpz(secrets.randbelow(int(q))) for _ in range(n))
    product = _ring_product(a, secret, q)
    b = tuple((t * e - v) % q for e, v in zip(_small_poly(n, eta, q), product, strict=True))
    h = hashlib.sha256(f"cuhepy/research/crt-linear-bgv/v1:{n}:{t}:{q}:{eta}".encode())
    for poly in (a, b):
        h.update(b"".join(int(c).to_bytes((q_bits + 7) // 8, "little") for c in poly))
    key_id = h.hexdigest()
    return bgv.PublicKey(n, t, q, eta, a, b, key_id), bgv.SecretKey(secret, key_id)


def binding(epoch: bytes, token_id: bytes) -> None:
    if type(epoch) is not bytes or len(epoch) != 32 or type(token_id) is not bytes or len(token_id) != 16:
        raise ValueError("Expected a local epoch digest and token ID")


def mask(s: crt.Space, seed: bytes, epoch: bytes, token_id: bytes) -> tuple[int, ...]:
    binding(epoch, token_id)
    crt.validate(s)
    if type(seed) is not bytes or len(seed) != 32:
        raise ValueError("Expected a private 32-byte seed")
    t = s.layout.context.prime
    width = (t.bit_length() + 7) // 8
    limit = (1 << (8 * width)) // t * t
    xof = hashlib.shake_256(b"cuhepy/research/crt-mask/v1\0" + s.binding + epoch + token_id + seed)
    data, at = xof.digest(max(256, 4 * width * s.dimension)), 0
    result: list[int] = []
    while len(result) < s.dimension:
        if at + width > len(data):
            data = xof.digest(2 * len(data))
        value = int.from_bytes(data[at:at + width], "little")
        at += width
        if value < limit:
            result.append(value % t)
    return tuple(result)


@dataclass(frozen=True)
class Request:
    space: crt.Space
    epoch: bytes
    token_id: bytes
    delta: tuple[int, ...]

    def body(self) -> bytes:
        validate_request(self)
        width = (self.space.layout.context.prime.bit_length() + 7) // 8
        return b"".join(x.to_bytes(width, "little") for x in self.delta)


def validate_request(request: Request) -> None:
    binding(request.epoch, request.token_id)
    crt.validate(request.space)
    if (len(request.delta) != request.space.dimension
            or any(type(x) is not int or not 0 <= x < request.space.layout.context.prime for x in request.delta)):
        raise ValueError("Noncanonical masked CRT request")


class MaskTicket:
    def __init__(self, s: crt.Space, seed: bytes, epoch: bytes, token_id: bytes):
        mask(s, seed, epoch, token_id)
        self.space, self.epoch, self.token_id = s, epoch, token_id
        self._seed: bytes | None = seed
        self._lock = threading.Lock()

    def consume(self, values: tuple[int, ...], epoch: bytes) -> Request:
        crt.split(self.space, values)
        if epoch != self.epoch:
            raise ValueError("Stale local index epoch")
        with self._lock:
            if self._seed is None:
                raise RuntimeError("Local CRT mask already consumed")
            r = mask(self.space, self._seed, self.epoch, self.token_id)
            self._seed = None  # Burn before the delta can escape.
            t = self.space.layout.context.prime
            return Request(self.space, self.epoch, self.token_id, tuple((v - x) % t for v, x in zip(values, r, strict=True)))


@dataclass(frozen=True)
class Index:
    space: crt.Space
    epoch: bytes
    columns: tuple[tuple[bgv.Ciphertext, ...], ...]


@dataclass(frozen=True)
class Answer:
    space: crt.Space
    epoch: bytes
    token_id: bytes
    ciphertexts: tuple[bgv.Ciphertext, ...]


def _context(s: crt.Space, pk: bgv.PublicKey) -> None:
    crt.validate(s)
    if (pk.n, pk.t) != (s.layout.context.n, s.layout.context.prime):
        raise ValueError("Incorrect linear BGV context")


def enroll(s: crt.Space, groups: list[list[list[int]]], epoch: bytes,
           client: owner.OwnerClient) -> tuple[Index, int]:
    _context(s, client.pk)
    binding(epoch, bytes(16))
    columns, packet_bytes = [], 0
    for polys in crt.columns(s, groups):
        packets = [client.encrypt(p) for p in polys]
        packet_bytes += sum(map(len, packets))
        columns.append(tuple(owner.expand(p, client.pk) for p in packets))
    return Index(s, epoch, tuple(columns)), packet_bytes


def prepare(s: crt.Space, groups: list[list[list[int]]], epoch: bytes, token_id: bytes,
            seed: bytes, client: owner.OwnerClient) -> tuple[MaskTicket, Answer, int]:
    """Trusted offline owner has rows; each answer has independent OS randomness."""
    _context(s, client.pk)
    values = mask(s, seed, epoch, token_id)
    packets = [client.encrypt(p) for p in crt.outputs(s.layout, crt.scores(s, groups, values))]
    return (MaskTicket(s, seed, epoch, token_id),
            Answer(s, epoch, token_id, tuple(owner.expand(p, client.pk) for p in packets)), sum(map(len, packets)))


def validate_ciphertexts(values: tuple[bgv.Ciphertext, ...], count: int, pk: bgv.PublicKey) -> None:
    if len(values) != count:
        raise ValueError("Incorrect full response shape")
    for value in values:
        bgv._validate(value, pk)
        if len(value.components) != 2:
            raise ValueError("Expected linear two-component ciphertexts")


def bounds(index: Index, answer: Answer, request: Request, pk: bgv.PublicKey,
           coefficients: tuple[tuple[int, ...], ...]) -> tuple[int, ...]:
    _context(index.space, pk)
    validate_request(request)
    binding(answer.epoch, answer.token_id)
    if (index.space != answer.space or index.space != request.space
            or index.epoch != answer.epoch or index.epoch != request.epoch
            or answer.token_id != request.token_id or len(index.columns) != index.space.columns):
        raise ValueError("Local CRT index/token/request mismatch")
    count = index.space.layout.cost.response_ciphertexts
    validate_ciphertexts(answer.ciphertexts, count, pk)
    for column in index.columns:
        validate_ciphertexts(column, count, pk)
    norms = tuple(sum(map(abs, p)) for p in coefficients)
    result = tuple(saved.phase_bound + sum(norm * column[i].phase_bound for norm, column in zip(norms, index.columns, strict=True))
                   for i, saved in enumerate(answer.ciphertexts))
    if any(2 * b >= pk.q for b in result):
        raise ValueError("Complete linear phase bound exceeds Q")
    return result


def evaluate(index: Index, answer: Answer, request: Request, pk: bgv.PublicKey) -> tuple[bgv.Ciphertext, ...]:
    """Full-q public linear relation; terminal rounding is deliberately absent."""
    coefficients = crt.corrections(index.space, request.delta)
    limits = bounds(index, answer, request, pk, coefficients)
    polys = [tuple(mpz(x) % pk.q for x in crt.expand(index.space, short)) for short in coefficients]
    result = []
    for i, (saved, limit) in enumerate(zip(answer.ciphertexts, limits, strict=True)):
        parts = list(saved.components)
        for column, poly, short in zip(index.columns, polys, coefficients, strict=True):
            products = [tuple(x * short[0] % pk.q for x in c) if index.space.slots == 1 else _ring_product(c, poly, pk.q)
                        for c in column[i].components]
            parts = [tuple((x + y) % pk.q for x, y in zip(part, product, strict=True))
                     for part, product in zip(parts, products, strict=True)]
        result.append(bgv.Ciphertext(tuple(parts), pk.key_id, limit))
    return tuple(result)
