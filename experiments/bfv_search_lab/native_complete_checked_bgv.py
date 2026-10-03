"""Complete public BGV native verification reference and prepared replay control.

The owner enrolls canonical public keys and an ordered encrypted snapshot. An
untrusted producer returns unshifted product tiles. Fresh, private whole-ring
checks cover every tile before this controller computes every rotation and all
terminal bytes itself. No HE secret, expected answer, attestation or signing key
enters admission. This is a known-method experimental control, not a production
authentication API. Local one-use counters do not survive process rollback.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import threading
from typing import Callable

from Crypto.Hash import SHAKE256
import gmpy2
import msgpack

from cuhepy.bfv.scheme import _rns_coefficient_primes
from experiments.bfv_search_lab import checked_product_bgv as product
from experiments.bfv_search_lab import native_boundary_oracle as boundary
from experiments.bfv_search_lab.checked_switch_bgv import Context as ProductKey
from experiments.bfv_search_lab.native_check_bgv import (
    NativeCheckArithmetic,
    NativeProductArithmetic,
)
from experiments.bfv_search_lab.complete_checked_bgv import BlockSpec, BlockOutput, CompleteResult

DOMAIN = b"cuhepy-native-complete-checked-bgv-v1\0"
MAX_TILES = 4096
MAX_GROUPS = 64
MAX_PRODUCT_BYTES = 1 << 30


def _bytes(value, size):
    if type(value) is not bytes or len(value) != size:
        raise ValueError("Incorrect immutable exact byte field")
    return value


def _hash(data):
    return hashlib.sha256(data).digest()


def _poly(poly, n, q):
    if (
        type(poly) is not tuple
        or len(poly) != n
        or any(type(c) is not int or not 0 <= c < q for c in poly)
    ):
        raise ValueError("Expected an immutable canonical full-Q polynomial")


def _pair(pair, n, q):
    if type(pair) is not tuple or len(pair) != 2:
        raise ValueError("Expected exactly two ciphertext components")
    for poly in pair:
        _poly(poly, n, q)


def _fixed(poly):
    return b"".join(c.to_bytes(15, "little") for c in poly)


def load_backend(path: str | Path):
    """Load the separately built, owner-selected homogeneous native control.

    Selection of a local binary is a trusted build choice, not remote code or
    attestation. The evidence runner pins its SHA256 before executing it.
    """
    path = Path(path).resolve(strict=True)
    spec = importlib.util.spec_from_file_location("_bgv_complete", path)
    if spec is None or spec.loader is None:
        raise ValueError("Cannot load the isolated complete-control extension")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class NativeContext:
    n: int
    t: int
    q: int
    primes: tuple[int, int]
    padded: int
    dimension: int
    digit_bits: int
    query_drop: int
    p: int
    key_id: str
    epoch: str
    ids: tuple[int, ...]
    index: tuple
    relin: tuple
    rotations: tuple

    @classmethod
    def from_reference(cls, context: boundary.Context):
        if type(context) is not boundary.Context:
            raise TypeError("Exact frozen reference context required")
        return cls(**{f.name: getattr(context, f.name) for f in fields(cls)})

    @classmethod
    def from_bgv(
        cls, pk, keys, index, count: int, dimension: int, p: int, *, epoch: str, query_drop: int = 0
    ):
        from experiments.bfv_search_lab.butterfly_bgv import validate_keys

        validate_keys(pk, keys)
        if type(count) is not int or not 1 <= count <= 64 * pk.n:
            raise ValueError("Invalid bounded row coverage")

        def convert(pair):
            return tuple(tuple(int(c) for c in poly) for poly in pair)

        return cls(
            pk.n,
            int(pk.t),
            int(pk.q),
            tuple(_rns_coefficient_primes(pk.n, 120)),
            keys.padded,
            dimension,
            keys.digit_bits,
            query_drop,
            int(p),
            pk.key_id,
            epoch,
            tuple(range(count)),
            tuple(convert(c.components) for c in index),
            tuple(convert(c) for c in keys.relin),
            tuple((exponent, tuple(convert(c) for c in key)) for exponent, key in keys.rotations),
        )

    def validate(self):
        ints = ("n", "t", "q", "padded", "dimension", "digit_bits", "query_drop", "p")
        if any(type(getattr(self, name)) is not int for name in ints):
            raise ValueError("Exact integer profile required")
        if (
            not 8 <= self.n <= 16384
            or self.n & (self.n - 1)
            or self.digit_bits != 30
            or not 0 <= self.query_drop < 120
        ):
            raise ValueError("Only the current bounded Q120 native profile is admitted")
        if (
            type(self.primes) is not tuple
            or len(self.primes) != 2
            or any(type(p) is not int for p in self.primes)
            or self.primes != tuple(_rns_coefficient_primes(self.n, 120))
            or self.q != self.primes[0] * self.primes[1]
        ):
            raise ValueError("Mismatched admitted RNS primes")
        if (
            not 1 <= self.dimension <= self.padded <= self.n // 2
            or self.padded & (self.padded - 1)
            or self.t % 2 != 1
            or not 2 * self.dimension < self.t < (1 << 30)
            or not 16 <= self.p.bit_length() <= 60
            or self.p <= 4 * self.t
            or self.p % 2 != 1
            or self.p >= self.q
            or not gmpy2.is_prime(self.p)
            or self.p % self.t != self.q % self.t
        ):
            raise ValueError("Invalid layout or terminal congruence")
        if (
            type(self.key_id) is not str
            or len(self.key_id) != 64
            or any(c not in "0123456789abcdef" for c in self.key_id)
            or type(self.epoch) is not str
            or not 1 <= len(self.epoch.encode()) <= 256
        ):
            raise ValueError("Invalid public key or epoch identifier")
        if (
            type(self.ids) is not tuple
            or not 1 <= len(self.ids) <= MAX_GROUPS * self.n
            or any(type(x) is not int or x != i for i, x in enumerate(self.ids))
        ):
            raise ValueError("Exact ordered contiguous ID coverage required")
        tiles = (len(self.ids) + self.n // self.padded - 1) // (self.n // self.padded)
        if (
            type(self.index) is not tuple
            or len(self.index) != tiles
            or tiles > MAX_TILES
            or tiles * 4 * self.n * 8 > MAX_PRODUCT_BYTES
        ):
            raise ValueError("Incomplete or excessive encrypted-index coverage")
        for cipher in self.index:
            _pair(cipher, self.n, self.q)

        def key(k):
            if type(k) is not tuple or len(k) != 4:
                raise ValueError("Four common full-Q gadget digits required")
            for column in k:
                _pair(column, self.n, self.q)

        key(self.relin)
        if type(self.rotations) is not tuple:
            raise ValueError("Immutable ordered rotation keys required")
        exponents, shift = [], self.padded // 2
        exponent = 1 + 2 * self.n // self.padded
        while shift:
            exponents.append(exponent)
            exponent, shift = exponent * exponent % (2 * self.n), shift // 2
        if len(self.rotations) != len(exponents):
            raise ValueError("Incomplete rotation key coverage")
        for item, expected in zip(self.rotations, exponents, strict=True):
            if (
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not int
                or item[0] != expected
            ):
                raise ValueError("Wrong ordered rotation key")
            key(item[1])

    def digest(self):
        """Streaming snapshot/key binding; no large JSON ciphertext copy."""
        meta = {
            f.name: getattr(self, f.name)
            for f in fields(self)
            if f.name not in ("index", "relin", "rotations")
        }
        h = hashlib.sha256(
            DOMAIN + json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()
        )
        for tag, values in ((b"index", self.index), (b"relin", self.relin)):
            h.update(tag)
            for pair in values:
                for poly in pair:
                    h.update(_fixed(poly))
        h.update(b"rotations")
        for exponent, key in self.rotations:
            h.update(struct.pack("<I", exponent))
            for pair in key:
                for poly in pair:
                    h.update(_fixed(poly))
        return h.digest()


class NativeArithmetic:
    """Immutable prepared public plans; native scratch is per invocation."""

    def __init__(self, context, backend):
        self.context, self.backend = context, backend
        keys = tuple(
            tuple(tuple(_fixed(p) for p in pair) for pair in key)
            for key in (context.relin, *(k for _, k in context.rotations))
        )
        self.handle = backend.create_server(
            context.n, format(context.q, "x"), 30, context.padded, keys, True
        )
        if backend.complete_profile(self.handle) != (
            context.n,
            *context.primes,
            context.padded,
            30,
            4,
        ):
            raise ValueError("Complete/checker native profile mismatch")
        self.index = backend.prepare_index(
            self.handle, tuple(tuple(_fixed(p) for p in pair) for pair in context.index)
        )

    def expand(self, original):
        ctx = self.context
        if type(original) is not bytes or len(original) > (ctx.n * 120 + 7) // 8 + 512:
            raise ValueError("Invalid bounded original query packet")
        fields = msgpack.unpackb(
            original,
            raw=False,
            strict_map_key=True,
            max_array_len=5,
            max_bin_len=(ctx.n * 120 + 7) // 8 + 128,
            max_str_len=64,
            max_map_len=0,
            max_ext_len=0,
        )
        rounded = ctx.query_drop != 0
        tag = boundary.QUERY_TAG if rounded else boundary.SEED_TAG
        if (
            type(fields) is not list
            or len(fields) != (5 if rounded else 4)
            or type(fields[0]) is not bytes
            or fields[0] != tag
            or _bytes(fields[1], 32) != bytes.fromhex(ctx.key_id)
        ):
            raise ValueError("Wrong original query key/grammar")
        seed = _bytes(fields[2], 32)
        if rounded:
            if type(fields[3]) is not int or fields[3] != ctx.query_drop:
                raise ValueError("Wrong original query rounding context")
            body = fields[4]
            if type(body) is not bytes:
                raise ValueError("Immutable rounded query body required")
            packed = self.backend.expand_query_coefficients(
                body, ctx.n, format(ctx.q, "x"), ctx.t, ctx.query_drop
            )
        else:
            packed = _bytes(fields[3], (ctx.n * 120 + 7) // 8)
            self.backend.validate_coefficients(packed, ctx.n, format(ctx.q, "x"))
        c0 = tuple(int(c) for c in gmpy2.unpack(gmpy2.mpz(int.from_bytes(packed, "little")), 120))
        c0 += (0,) * (ctx.n - len(c0))
        # Public SHAKE/rejection expansion, matching the owner codec. A bounded
        # byte budget rejects pathological public seeds rather than looping.
        shake = SHAKE256.new(data=boundary.SEED_TAG + bytes.fromhex(ctx.key_id) + seed)
        c1, read, budget = [], 0, 4 * ctx.n * 15
        while len(c1) < ctx.n:
            size = (ctx.n - len(c1)) * 15
            if read + size > budget:
                raise ValueError("Public query expansion budget exhausted")
            stream = shake.read(size)
            read += size
            for i in range(0, len(stream), 15):
                value = int.from_bytes(stream[i : i + 15], "little")
                if value < ctx.q:
                    c1.append(value)
        return c0, tuple(c1)

    def frame(self, pairs):
        ctx = self.context
        header = [
            boundary.RESPONSE_TAG,
            ctx.n,
            ctx.t,
            ctx.p.to_bytes((ctx.p.bit_length() + 7) // 8, "little"),
            bytes.fromhex(ctx.key_id),
            len(ctx.ids),
            ctx.dimension,
        ]
        packet = msgpack.packb([header, [list(pair) for pair in pairs]], use_bin_type=True)
        self.validate_response(packet)
        return packet

    def validate_response(self, packet):
        ctx = self.context
        groups, width = (len(ctx.ids) + ctx.n - 1) // ctx.n, (ctx.n * ctx.p.bit_length() + 7) // 8
        if type(packet) is not bytes or len(packet) > groups * (2 * width + 32) + 256:
            raise ValueError("Invalid bounded claimed response")
        frame = msgpack.unpackb(
            packet,
            raw=False,
            strict_map_key=True,
            max_array_len=MAX_GROUPS,
            max_bin_len=max(width, 64),
            max_str_len=64,
            max_map_len=0,
            max_ext_len=0,
        )
        expected = [
            boundary.RESPONSE_TAG,
            ctx.n,
            ctx.t,
            ctx.p.to_bytes((ctx.p.bit_length() + 7) // 8, "little"),
            bytes.fromhex(ctx.key_id),
            len(ctx.ids),
            ctx.dimension,
        ]
        if (
            type(frame) is not list
            or len(frame) != 2
            or type(frame[0]) is not list
            or len(frame[0]) != 7
            or frame[0] != expected
            or any(type(a) is not type(b) for a, b in zip(frame[0], expected, strict=True))
            or type(frame[1]) is not list
            or len(frame[1]) != groups
        ):
            raise ValueError("Wrong exact response context/coverage")
        for pair in frame[1]:
            if type(pair) is not list or len(pair) != 2:
                raise ValueError("Wrong response component coverage")
            for poly in pair:
                _bytes(poly, width)
                self.backend.validate_coefficients(poly, ctx.n, format(ctx.p, "x"))

    def replay(self, query):
        expanded = self.expand(query)
        pairs = self.backend.replay_packed(
            self.handle,
            tuple(_fixed(p) for p in expanded),
            self.index,
            self.context.t,
            format(self.context.p, "x"),
        )
        return self.frame(pairs)


class Enrollment:
    """Owner-approved immutable snapshot and nondurable local attempt budget."""

    def __init__(
        self, context: NativeContext, *, backend, max_requests: int = 8, block_size: int = 64
    ):
        if type(context) is not NativeContext:
            raise TypeError("Exact owner-approved native public context required")
        context.validate()
        if type(max_requests) is not int or not 1 <= max_requests <= 64:
            raise ValueError("Invalid local parent-attempt cap")
        if type(block_size) is not int or not 1 <= block_size <= 64:
            raise ValueError("Invalid bounded block size")
        self._context, self._max_requests = context, max_requests
        self._digest = context.digest()
        self._arithmetic = NativeArithmetic(context, backend)
        key = tuple(
            tuple(tuple(tuple(c % p for c in poly) for poly in pair) for pair in context.relin)
            for p in context.primes
        )
        self._product_key = ProductKey(
            context.n, context.primes, key, _hash(DOMAIN + self.digest + b"product-key")
        )
        self._check_arithmetic = NativeCheckArithmetic(self.product_key)
        self._pid, self._gate, self._attempts = os.getpid(), threading.Lock(), 0
        self._seen: set[bytes] = set()
        self._products = []
        for start in range(0, len(context.index), block_size):
            end = min(start + block_size, len(context.index))
            binding = _hash(DOMAIN + self.digest + struct.pack("<II", start, end))
            raw = self.product_key.pack_full(context.index[start:end], 2)
            pc = product.ProductContext.prepare(self.product_key, raw, end - start, binding)
            self._products.append(
                (start, end, pc, NativeProductArithmetic(pc, self._check_arithmetic))
            )
        self._products = tuple(self._products)

    context = property(lambda self: self._context)
    digest = property(lambda self: self._digest)
    product_key = property(lambda self: self._product_key)
    max_requests = property(lambda self: self._max_requests)

    def __copy__(self):
        raise TypeError("Local enrollment state cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("Local enrollment state cannot be copied")

    def __reduce_ex__(self, protocol):
        raise TypeError("Local enrollment state cannot be serialized")

    def begin(self, original_query: bytes, owner_request_id: bytes):
        if os.getpid() != self._pid:
            raise RuntimeError("Create a new enrollment after fork")
        with self._gate:
            if self._attempts >= self.max_requests:
                raise RuntimeError("Local parent-attempt budget exhausted")
            self._attempts += 1
            request_id = _bytes(owner_request_id, 32)
            if request_id in self._seen:
                raise ValueError("Repeated owner request ID")
            self._seen.add(request_id)
        query = self._arithmetic.expand(original_query)
        raw = self.product_key.pack_full((query,), 2)
        statement = _hash(DOMAIN + self.digest + request_id + _hash(original_query))
        children = []
        for start, end, pc, arithmetic in self._products:
            binding = _hash(DOMAIN + statement + struct.pack("<II", start, end))
            children.append((start, end, pc.begin(raw, binding, mode="local", native=arithmetic)))
        return Request(self, statement, tuple(children), raw)

    def replay(self, original_query):
        """Prepared full recomputation control; never entered by admission."""
        if os.getpid() != self._pid:
            raise RuntimeError("Create a new enrollment after fork")
        return self._arithmetic.replay(original_query)

    def resource_ledger(self):
        """Exact logical bodies, separate from allocator/RSS/timing measurements."""
        c = self.context
        groups = (len(c.ids) + c.n - 1) // c.n
        rotations = 0
        for start in range(0, len(c.index), c.padded):
            count, shift = min(c.padded, len(c.index) - start), c.padded // 2
            while shift:
                count = min(shift, count)
                rotations += count
                shift //= 2
        return {
            "tiles": len(c.index),
            "blocks": len(self._products),
            "public_index_full_Q_fixed_bytes": len(c.index) * 2 * c.n * 15,
            "public_switch_keys_full_Q_fixed_bytes": (1 + len(c.rotations)) * 4 * 2 * c.n * 15,
            "product_body_bytes": len(c.index) * 4 * c.n * 8,
            "terminal_packed_body_bytes": groups * 2 * ((c.n * c.p.bit_length() + 7) // 8),
            "groups": groups,
            "rotation_nodes": rotations,
            "terminal_coordinates": groups * 2 * c.n,
            "initial_shift": 1 - c.padded,
            "resident_buffers": [
                "immutable Python snapshot",
                "prepared replay index/keys",
                "RNS checker index blocks/keys",
            ],
            "resident_bytes_measured": False,
            "trusted_suffix_covers_all_response_coordinates": True,
        }


class Request:
    def __init__(self, enrollment, statement, children, raw_query):
        self._enrollment, self.statement_digest, self._children = enrollment, statement, children
        self._raw_query = raw_query
        self._pid, self._gate, self._used = os.getpid(), threading.Lock(), False
        self.blocks = tuple(BlockSpec(a, b, child.statement_digest) for a, b, child in children)

    def __copy__(self):
        raise TypeError("Complete attempts cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("Complete attempts cannot be copied")

    def __reduce_ex__(self, protocol):
        raise TypeError("Complete attempts cannot be serialized")

    def frame_block(self, number, raw_output):
        if type(number) is not int or not 0 <= number < len(self._children):
            raise ValueError("Wrong product block number")
        start, end, child = self._children[number]
        return BlockOutput(start, end, child.result_packet(raw_output))

    def produce_blocks(self):
        """Honest native producer for controls/tests; not called by admission."""
        return tuple(
            self.frame_block(i, arithmetic.evaluate(self._raw_query)[1])
            for i, (_, _, _, arithmetic) in enumerate(self._enrollment._products)
        )

    def admit_once(
        self,
        blocks: tuple[BlockOutput, ...],
        *,
        claimed_response: bytes | None = None,
        release_sentinel: Callable[[bytes], object] | None = None,
    ) -> CompleteResult:
        if os.getpid() != self._pid:
            raise RuntimeError("Create a new complete attempt after fork")
        with self._gate:
            if self._used:
                raise RuntimeError("Complete attempt already consumed")
            self._used = True
        self._raw_query = None
        if type(blocks) is not tuple or len(blocks) != len(self._children):
            raise ValueError("Incomplete exact product-block coverage")
        bodies = []
        for given, (start, end, child) in zip(blocks, self._children, strict=True):
            if (
                type(given) is not BlockOutput
                or type(given.start) is not int
                or type(given.end) is not int
                or (given.start, given.end) != (start, end)
                or type(given.packet) is not bytes
            ):
                raise ValueError("Wrong product-block positions/grammar")
            header = len(product.TAG) + 32
            if len(given.packet) != header + (
                end - start
            ) * 4 * self._enrollment.context.n * 8 or not given.packet.startswith(
                product.TAG + child.statement_digest
            ):
                raise ValueError("Wrong complete product-block binding/size")
            raw = given.packet[header:]
            # Entire immutable grammar across ALL blocks precedes ANY weights.
            self._enrollment._arithmetic.backend.validate_products_rns(
                self._enrollment._arithmetic.handle, raw, end - start
            )
            bodies.append(raw)
        if claimed_response is not None:
            self._enrollment._arithmetic.validate_response(claimed_response)
        if release_sentinel is not None and not callable(release_sentinel):
            raise TypeError("The optional public sentinel must be callable")
        for given, (_, _, child) in zip(blocks, self._children, strict=True):
            if not child.check_once(given.packet).accepted:
                raise ValueError("Product-block arithmetic rejected")
        ctx, arithmetic = self._enrollment.context, self._enrollment._arithmetic
        raw = b"".join(bodies)
        pairs = arithmetic.backend.continue_products_rns_packed(
            arithmetic.handle, raw, len(ctx.index), ctx.t, format(ctx.p, "x")
        )
        packet = arithmetic.frame(pairs)
        if claimed_response is not None and claimed_response != packet:
            raise ValueError("Claimed final response differs from authoritative bytes")
        ledger = self._enrollment.resource_ledger()
        counts = {
            name: ledger[name]
            for name in ("groups", "rotation_nodes", "terminal_coordinates", "initial_shift")
        }
        result = CompleteResult(
            packet,
            self.statement_digest,
            _hash(packet),
            tuple((a, b) for a, b, _ in self._children),
            len(raw),
            counts,
        )
        if release_sentinel is not None:
            release_sentinel(packet)
        return result
