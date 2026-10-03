"""Complete tiny public BGV admission using checked products and a trusted suffix.

This is a known-control reference, not an enclave, receipt or private-client API.
Only the disclosed E106 N8/count9 geometry is admitted. The untrusted producer supplies
unshifted product/relinearization tiles. No expected output is used for admission;
all final bytes are computed here after fresh whole-polynomial product checks.
Local counters are not durable global lifecycle assurance. No HE secret is loaded.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import struct
import threading
from typing import Callable

from gmpy2 import mpz

from cuhepy.bfv.scheme import _automorphism, _ring_product
from experiments.bfv_search_lab import checked_product_bgv as product
from experiments.bfv_search_lab.checked_switch_bgv import Context as ProductKey, _parse
from experiments.bfv_search_lab import native_boundary_oracle as boundary

DOMAIN = b"cuhepy-complete-checked-bgv-reference-v1\0"
BLOCK_SIZE = 2


def _exact_bytes(value: bytes, size: int) -> bytes:
    if type(value) is not bytes or len(value) != size:
        raise ValueError("Incorrect exact byte field")
    return value


def _hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _ring(left, right, q):
    return tuple(int(x) for x in _ring_product(tuple(map(mpz, left)),
                                            tuple(map(mpz, right)), mpz(q)))


def _add(left, right, q, sign=1):
    return tuple((a+sign*b) % q for a, b in zip(left, right, strict=True))


def _monomial(poly, shift, q):
    out, n = [0]*len(poly), len(poly)
    for i, x in enumerate(poly):
        at = (i+shift) % (2*n)
        out[at % n] = (x if at < n else -x) % q
    return tuple(out)


def _switch(poly, key, ctx):
    """Canonical COMMON full-Q digits; no server digit strings are accepted."""
    boundary.polynomial(poly, ctx.n, ctx.q)
    output = ((0,)*ctx.n, (0,)*ctx.n)
    mask = (1 << ctx.digit_bits)-1
    for j, pair in enumerate(key):
        digits = tuple((x >> (ctx.digit_bits*j)) & mask for x in poly)
        output = tuple(_add(a, _ring(digits, b, ctx.q), ctx.q)
                       for a, b in zip(output, pair, strict=True))
    return output


def _continue_checked(ctx, tiles):
    """Trusted exact suffix, callable only by the composed controller's gate.

    This low-level public helper is not an authentication or release interface.
    The caller must have checked every tile against the enrolled query/index.
    """
    if type(tiles) is not tuple or len(tiles) != len(ctx.index):
        raise ValueError("Incomplete continuation coverage")
    for cipher in tiles:
        if type(cipher) is not tuple or len(cipher) != 2:
            raise ValueError("Wrong checked continuation tile")
        for poly in cipher:
            boundary.polynomial(poly, ctx.n, ctx.q)
    results, rotations = [], 0
    for start in range(0, len(tiles), ctx.padded):
        # The padded=1 GPU stage has NOT applied the full trace's initial shift.
        work = [tuple(_monomial(p, 1-ctx.padded, ctx.q) for p in tile)
                for tile in tiles[start:start+ctx.padded]]
        shift = ctx.padded//2
        for exponent, key in ctx.rotations:
            merged = []
            for i in range(min(shift, len(work))):
                plus, minus = work[i], work[i]
                if i+shift < len(work):
                    right = tuple(_monomial(p, shift, ctx.q) for p in work[i+shift])
                    plus = tuple(_add(a, b, ctx.q) for a, b in zip(work[i], right, strict=True))
                    minus = tuple(_add(a, b, ctx.q, -1) for a, b in zip(work[i], right, strict=True))
                turned = tuple(tuple(int(x) for x in _automorphism(p, exponent, mpz(ctx.q)))
                               for p in minus)
                correction = _switch(turned[1], key, ctx)
                rotated = (_add(turned[0], correction[0], ctx.q), correction[1])
                merged.append(tuple(_add(a, b, ctx.q) for a, b in zip(plus, rotated, strict=True)))
                rotations += 1
            work, shift = merged, shift//2
        if len(work) != 1 or shift:
            raise ValueError("Incomplete trusted butterfly")
        results.append(work[0])
    rounded = []
    for cipher in results:
        pair = []
        for poly in cipher:
            values = []
            for c in poly:
                residue = c % ctx.t
                lift = residue+ctx.t*((2*(ctx.p*c-ctx.q*residue)+ctx.q*ctx.t)//(2*ctx.q*ctx.t))
                if lift % ctx.t != residue or 2*abs(ctx.q*lift-ctx.p*c) >= ctx.q*ctx.t:
                    raise ValueError("Incorrect trusted terminal lift")
                values.append(lift % ctx.p)
            pair.append(tuple(values))
        rounded.append(tuple(pair))
    packet = boundary.serialize(ctx, tuple(rounded))
    boundary.parse_response(ctx, packet)
    return packet, {"groups": len(results), "rotation_nodes": rotations,
                    "terminal_coordinates": len(results)*2*ctx.n,
                    "initial_shift": 1-ctx.padded}


@dataclass(frozen=True)
class BlockSpec:
    start: int
    end: int
    statement_digest: bytes


@dataclass(frozen=True)
class BlockOutput:
    start: int
    end: int
    packet: bytes


@dataclass(frozen=True)
class CompleteResult:
    packet: bytes
    statement_digest: bytes
    response_digest: bytes
    block_coverage: tuple[tuple[int, int], ...]
    product_body_bytes: int
    suffix_counts: dict[str, int]


class Enrollment:
    """Owner-trusted tiny public context and bounded LOCAL parent-attempt state.

    Construction does not prove owner authorization or hardware provenance.
    New enrollment instances can reset these nondurable counters; deployments
    must bind their actual global epoch/attempt budget separately.
    """

    def __init__(self, context: boundary.Context, *, max_requests: int = 8):
        if type(context) is not boundary.Context:
            raise TypeError("An exact owner-approved public context is required")
        context.admit_native_fixture()
        if len(context.ids) != 9 or len(context.index) != 5:
            raise ValueError("Only the fixed nine-row complete reference geometry is admitted")
        if type(max_requests) is not int or not 1 <= max_requests <= 64:
            raise ValueError("Invalid local parent-attempt cap")
        self._context, self._max_requests = context, max_requests
        self._digest = bytes.fromhex(context.digest())
        key = tuple(tuple(tuple(tuple(c % p for c in poly) for poly in pair)
                          for pair in context.relin) for p in context.primes)
        self._product_key = ProductKey(context.n, context.primes, key,
                                      _hash(DOMAIN+self.digest+b"product-key"))
        self._pid, self._gate, self._attempts = os.getpid(), threading.Lock(), 0
        self._seen: set[bytes] = set()
        self._products = []
        for start in range(0, len(context.index), BLOCK_SIZE):
            end = min(start+BLOCK_SIZE, len(context.index))
            positions = struct.pack("<II", start, end)
            index_binding = _hash(DOMAIN+self.digest+positions)
            raw = self.product_key.pack_full(context.index[start:end], 2)
            self._products.append((start, end, product.ProductContext.prepare(
                self.product_key, raw, end-start, index_binding)))

    @property
    def context(self):
        return self._context

    @property
    def digest(self):
        return self._digest

    @property
    def product_key(self):
        return self._product_key

    @property
    def max_requests(self):
        return self._max_requests

    def _process(self):
        if os.getpid() != self._pid:
            raise RuntimeError("Create a new enrollment after fork")

    def __copy__(self):
        raise TypeError("Local enrollment state cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("Local enrollment state cannot be copied")

    def __reduce_ex__(self, protocol):
        raise TypeError("Local enrollment state cannot be serialized")

    def begin(self, original_query: bytes, owner_request_id: bytes):
        self._process()
        with self._gate:
            if self._attempts >= self.max_requests:
                raise RuntimeError("Local parent-attempt budget exhausted")
            self._attempts += 1  # Malformed/duplicate IDs and queries also spend it.
            request_id = _exact_bytes(owner_request_id, 32)
            if request_id in self._seen:
                raise ValueError("Repeated owner request ID")
            self._seen.add(request_id)
        query = boundary.expand_query(self.context, original_query)
        raw = self.product_key.pack_full((query,), 2)
        statement = _hash(DOMAIN+self.digest+request_id+_hash(original_query))
        children = []
        for start, end, ctx in self._products:
            binding = _hash(DOMAIN+statement+struct.pack("<II", start, end))
            children.append((start, end, ctx.begin(raw, binding, mode="local")))
        return Request(self, statement, children)


class Request:
    """One full public attempt; rejection never reaches the release sentinel."""

    def __init__(self, enrollment, statement, children):
        self._enrollment, self.statement_digest = enrollment, statement
        self._children = tuple(children)
        self._pid, self._gate, self._used = os.getpid(), threading.Lock(), False
        self.blocks = tuple(BlockSpec(a, b, child.statement_digest) for a, b, child in children)

    def __copy__(self):
        raise TypeError("Complete attempts cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("Complete attempts cannot be copied")

    def __reduce_ex__(self, protocol):
        raise TypeError("Complete attempts cannot be serialized")

    def frame_block(self, number: int, raw_output: bytes) -> BlockOutput:
        """Public producer framing; it does not check the product arithmetic."""
        if type(number) is not int or not 0 <= number < len(self._children):
            raise ValueError("Wrong product block number")
        start, end, child = self._children[number]
        return BlockOutput(start, end, child.result_packet(raw_output))

    def admit_once(self, blocks: tuple[BlockOutput, ...], *, claimed_response: bytes | None = None,
                   release_sentinel: Callable[[bytes], object] | None = None) -> CompleteResult:
        if os.getpid() != self._pid:
            raise RuntimeError("Create a new complete attempt after fork")
        with self._gate:
            if self._used:
                raise RuntimeError("Complete attempt already consumed")
            self._used = True
        if type(blocks) is not tuple or len(blocks) != len(self._children):
            raise ValueError("Incomplete exact product-block coverage")
        # Validate ALL block grammar/ranges before ANY block challenge is sampled.
        for given, (start, end, child) in zip(blocks, self._children, strict=True):
            if (type(given) is not BlockOutput or type(given.start) is not int
                    or type(given.end) is not int or (given.start, given.end) != (start, end)
                    or type(given.packet) is not bytes):
                raise ValueError("Wrong product-block positions/grammar")
            header = len(product.TAG)+32
            if (len(given.packet) != header+(end-start)*4*self._enrollment.context.n*8
                    or not given.packet.startswith(product.TAG+child.statement_digest)):
                raise ValueError("Wrong complete product-block binding/size")
            _parse(given.packet[header:], self._enrollment.context.n, end-start, 2,
                   self._enrollment.context.primes)
        if claimed_response is not None:
            if type(claimed_response) is not bytes:
                raise ValueError("Wrong claimed response grammar")
            boundary.parse_response(self._enrollment.context, claimed_response)
        if release_sentinel is not None and not callable(release_sentinel):
            raise TypeError("The optional public sentinel must be callable")
        tiles, body_bytes = [], 0
        for given, (start, end, child) in zip(blocks, self._children, strict=True):
            checked = child.check_once(given.packet)
            if not checked.accepted:
                raise ValueError("Product-block arithmetic rejected")
            raw = given.packet[len(product.TAG)+32:]
            body_bytes += len(raw)
            residues = _parse(raw, self._enrollment.context.n, end-start, 2,
                              self._enrollment.context.primes)
            p0, p1 = self._enrollment.context.primes
            inverse = pow(p0, -1, p1)
            for tile in residues:
                tiles.append(tuple(tuple(a+p0*((b-a)*inverse % p1)
                                         for a, b in zip(*part, strict=True)) for part in tile))
        packet, counts = _continue_checked(self._enrollment.context, tuple(tiles))
        if claimed_response is not None and claimed_response != packet:
            raise ValueError("Claimed final response differs from authoritative bytes")
        result = CompleteResult(packet, self.statement_digest, _hash(packet),
                                tuple((a, b) for a, b, _ in self._children), body_bytes, counts)
        if release_sentinel is not None:
            release_sentinel(packet)  # Public test instrumentation; no decoder/signature API.
        return result
