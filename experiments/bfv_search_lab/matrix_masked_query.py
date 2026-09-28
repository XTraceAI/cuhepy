"""E17 local one-use query masks over the tiny matrix-BGV oracle.

Known preprocessing/external-product ingredients, not a new secure protocol.
The experiment moves work offline and charges an expanded index and one stored
encrypted answer per token. No network parser, attestation, persistent replay
protection or rollback resistance is provided. Epoch/ID checks are local
consistency checks, not authentication. The base oracle uses insecure toy
parameters and fixture randomness; never use it for confidential data.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import random
import threading
from typing import Literal

from experiments.bfv_search_lab import matrix_bgv_oracle as matrix

MaskSpace = Literal["full", "constant"]


def _binding(epoch: bytes, token_id: bytes) -> None:
    if type(epoch) is not bytes or len(epoch) != 32 or type(token_id) is not bytes or len(token_id) != 16:
        raise ValueError("Expected local epoch digest and token identifier")


def expand_mask(ctx: matrix.Context, seed: bytes, epoch: bytes, token_id: bytes,
                mask_space: MaskSpace = "full") -> tuple[matrix.Poly, ...]:
    """Owner-only SHAKE expansion with exact rejection sampling over F_t.

    A uniform full-field mask would hide the difference perfectly in isolation;
    replacing it with a short private seed makes that a computational statement.
    This does not prove privacy of the full encrypted preprocessing transcript.
    """
    _binding(epoch, token_id)
    if type(seed) is not bytes or len(seed) != 32 or mask_space not in ("full", "constant"):
        raise ValueError("Expected a 32-byte private mask seed")
    domain = json.dumps(asdict(ctx), sort_keys=True, separators=(",", ":")).encode()
    xof = hashlib.shake_256(b"cuhepy/toy/matrix-mask/v1\0" + seed + epoch + token_id + domain
                           + b"\0" + mask_space.encode())
    width = (ctx.t.bit_length() + 7) // 8
    limit = (1 << (8 * width)) // ctx.t * ctx.t
    dimension = ctx.rank * (ctx.n if mask_space == "full" else 1)
    pool, at = xof.digest(max(256, 4 * dimension * width)), 0
    coefficients: list[int] = []
    while len(coefficients) < dimension:
        if at + width > len(pool):
            pool = xof.digest(2 * len(pool))
        value = int.from_bytes(pool[at:at + width], "little")
        at += width
        if value < limit:
            residue = value % ctx.t
            coefficients.append(residue if residue <= ctx.t // 2 else residue - ctx.t)
    if mask_space == "constant":
        return tuple(ctx.constant(x) for x in coefficients)
    return tuple(ctx.poly(coefficients[i:i + ctx.n]) for i in range(0, len(coefficients), ctx.n))


@dataclass(frozen=True)
class Request:
    context: matrix.Context
    epoch: bytes
    token_id: bytes
    delta: tuple[matrix.Poly, ...]  # Canonical F_t coefficients, not q residues.
    mask_space: MaskSpace = "full"

    def coefficient_body(self) -> bytes:
        width = (self.context.t.bit_length() + 7) // 8
        if self.mask_space not in ("full", "constant") or (
                self.mask_space == "constant" and any(any(p[1:]) for p in self.delta)):
            raise ValueError("Request is outside its declared public query space")
        return b"".join(x.to_bytes(width, "little") for p in self.delta
                        for x in (p if self.mask_space == "full" else p[:1]))


class MaskTicket:
    """Owner-only in-memory lease: consume before exposing a masked request."""

    def __init__(self, ctx: matrix.Context, seed: bytes, epoch: bytes, token_id: bytes,
                 mask_space: MaskSpace = "full"):
        expand_mask(ctx, seed, epoch, token_id, mask_space)  # Validate before accepting state.
        self.context, self.epoch, self.token_id = ctx, epoch, token_id
        self.mask_space = mask_space
        self._seed: bytes | None = seed
        self._lock = threading.Lock()

    def consume(self, weights: tuple[matrix.Poly, ...], epoch: bytes) -> Request:
        ctx = self.context
        if epoch != self.epoch or len(weights) != ctx.rank:
            raise ValueError("Local mask epoch or shape mismatch")
        weights = tuple(ctx.poly(p) for p in weights)
        if self.mask_space == "constant" and any(any(p[1:]) for p in weights):
            raise ValueError("Query lies outside the masked constant subspace")
        with self._lock:
            if self._seed is None:
                raise RuntimeError("Local query mask already consumed")
            mask = expand_mask(ctx, self._seed, self.epoch, self.token_id, self.mask_space)
            delta = tuple(tuple((w - r) % ctx.t for w, r in zip(ctx.centered(p), ctx.centered(m), strict=True))
                          for p, m in zip(weights, mask, strict=True))
            self._seed = None
            return Request(ctx, self.epoch, self.token_id, delta, self.mask_space)


@dataclass(frozen=True)
class OfflineQuery:
    context: matrix.Context
    epoch: bytes
    token_id: bytes
    packet: matrix.Gadget
    mask_space: MaskSpace = "full"


@dataclass(frozen=True)
class OfflineAnswer:
    context: matrix.Context
    epoch: bytes
    token_id: bytes
    results: tuple[matrix.VectorCipher, ...]
    mask_space: MaskSpace = "full"


def prepare(ctx: matrix.Context, secret: matrix.Matrix, output_secret: tuple[matrix.Poly, ...],
            seed: bytes, epoch: bytes, token_id: bytes, rng: random.Random,
            *, mask_space: MaskSpace = "full") -> tuple[MaskTicket, OfflineQuery]:
    """Owner prepares an encrypted random query without knowing the future query."""
    weights = expand_mask(ctx, seed, epoch, token_id, mask_space)
    packet = matrix.gadget_query(ctx, secret, weights, output_secret, rng)
    return (MaskTicket(ctx, seed, epoch, token_id, mask_space),
            OfflineQuery(ctx, epoch, token_id, packet, mask_space))


def evaluate_offline(ctx: matrix.Context, index: matrix.MatrixCipher, query: OfflineQuery) -> OfflineAnswer:
    if query.context != ctx or query.mask_space not in ("full", "constant"):
        raise ValueError("Offline query context mismatch")
    _binding(query.epoch, query.token_id)
    forms = matrix.gadget_forms(ctx, index, ctx.t // 2)
    return OfflineAnswer(ctx, query.epoch, query.token_id,
                         tuple(matrix.switch(ctx, form, query.packet) for form in forms), query.mask_space)


def index_conversion_forms(ctx: matrix.Context, index: matrix.MatrixCipher) -> tuple[tuple[matrix.Form, ...], ...]:
    """One-time conversion into k scalar-output ciphertexts per input row."""
    rows, k = matrix.shape(index.constant)
    if index.side != "right" or k != ctx.rank or matrix.shape(index.mask) != (rows, k):
        raise ValueError("Incorrect index conversion shape")
    return tuple(tuple(matrix.Form(index.constant[i][j],
                                   tuple((("s", a, j), index.mask[i][a]) for a in range(k)),
                                   index.phase_bound) for j in range(k)) for i in range(rows))


@dataclass(frozen=True)
class ConvertedIndex:
    context: matrix.Context
    epoch: bytes
    entries: tuple[tuple[matrix.VectorCipher, ...], ...]

    @property
    def coefficient_bytes(self) -> int:
        ctx = self.context
        return len(self.entries) * ctx.rank * (ctx.rank + 1) * ctx.n * ((ctx.q.bit_length() + 7) // 8)


def convert_index(ctx: matrix.Context, index: matrix.MatrixCipher, linear_key: matrix.Gadget,
                  epoch: bytes) -> ConvertedIndex:
    if type(epoch) is not bytes or len(epoch) != 32:
        raise ValueError("Incorrect local index epoch")
    return ConvertedIndex(ctx, epoch, tuple(tuple(matrix.switch(ctx, form, linear_key) for form in row)
                                            for row in index_conversion_forms(ctx, index)))


def evaluate_online(index: ConvertedIndex, offline: OfflineAnswer, request: Request) -> tuple[matrix.VectorCipher, ...]:
    """Public plaintext/ciphertext dot products plus the stored masked answer.

    No switching or ciphertext-ciphertext products occur here. The original
    encrypted random query, its evaluation and index conversion are offline
    costs, not eliminated costs. The stored answer has one vector ciphertext
    per output row. Server replay alone cannot authorize owner decryption.
    """
    ctx = index.context
    if (offline.context != ctx or request.context != ctx
            or index.epoch != offline.epoch or offline.epoch != request.epoch
            or offline.token_id != request.token_id
            or offline.mask_space != request.mask_space or request.mask_space not in ("full", "constant")
            or len(offline.results) != len(index.entries) or not index.entries
            or len(request.delta) != ctx.rank
            or any(len(p) != ctx.n or any(type(x) is not int or not 0 <= x < ctx.t for x in p)
                   for p in request.delta)):
        raise ValueError("Local masked request/index/token mismatch")
    if request.mask_space == "constant" and any(any(p[1:]) for p in request.delta):
        raise ValueError("Request lies outside the masked constant subspace")
    weights = tuple(ctx.poly([x if x <= ctx.t // 2 else x - ctx.t for x in p]) for p in request.delta)
    results = []
    for entries, saved in zip(index.entries, offline.results, strict=True):
        if (len(entries) != ctx.rank or len(saved.components) != ctx.rank + 1
                or any(len(c.components) != ctx.rank + 1 for c in entries)):
            raise ValueError("Incorrect converted ciphertext shape")
        expansion = ctx.n if request.mask_space == "full" else 1
        bound = saved.phase_bound + expansion * sum(ctx.norm(w) * c.phase_bound
                                                for w, c in zip(weights, entries, strict=True))
        if bound >= ctx.q // 2:
            raise ValueError("Masked-query phase bound exceeds toy modulus")
        parts = list(saved.components)
        for weight, cipher in zip(weights, entries, strict=True):
            products = [ctx.mul(weight, b) if request.mask_space == "full" else ctx.scale(b, ctx.centered(weight)[0])
                        for b in cipher.components]
            parts = [ctx.add(a, b) for a, b in zip(parts, products, strict=True)]
        results.append(matrix.VectorCipher(tuple(parts), bound))
    return tuple(results)
