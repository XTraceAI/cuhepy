"""Pinned public circuit policy and bounded setup codec for the BGV TEE experiment.

Admission and conservative correctness checks are NOT a cryptographic security
estimate. The owner authorizes an immutable encrypted index; a measured CPU
evaluator must compute the response. No bounds supplied by a host grant access
to private arithmetic. BFV authentication domains are deliberately not reused.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json

import gmpy2
from gmpy2 import mpz
import msgpack

from cuhepy.bfv.scheme import _rns_coefficient_primes
from experiments.bfv_search_lab import shallow_bgv as bgv, trace_bgv as trace
from experiments.bfv_search_lab import butterfly_bgv as butterfly, compact_bgv as compact
from experiments.bfv_search_lab import compressed_query_bgv as query_codec
from experiments.bfv_search_lab import compressed_response_bgv as response_codec

_SETUP = b"cuhepy-bgv-attested-setup-v1"
CIRCUIT = b"cuhepy-bgv-butterfly-terminal-cpu-v1"


class BGVProtocolError(ValueError):
    """An authenticated BGV experiment failed closed."""


def exact_bytes(value: bytes, size: int) -> bytes:
    if type(value) is not bytes or len(value) != size:
        raise BGVProtocolError("Incorrect BGV protocol field length")
    return value


@dataclass(frozen=True)
class BGVExecutionPolicy:
    """Local configuration, never negotiated with the untrusted server.

    The defaults match the research arithmetic, not a reviewed production
    parameter set. Smaller degrees exist only for inexpensive protocol tests.
    Precision choices are fixed for the lifetime of the index and session.
    """

    n: int = 16384
    t: int = 1031
    eta: int = 21
    dimension: int = 512
    digit_bits: int = 30
    terminal_bits: int = 25
    query_drop_bits: int = 0
    response_drop_bits: int = 0
    owner_index: bool = False
    max_vectors: int = 65536
    max_pending: int = 8
    max_queries: int = 65536
    max_setup_bytes: int = 384 << 20
    max_query_bytes: int = 1 << 20
    max_response_bytes: int = 16 << 20

    def __post_init__(self) -> None:
        fields = asdict(self)
        if any(type(v) is not int for k, v in fields.items() if k != "owner_index"):
            raise ValueError("BGV policy fields must be exact integers")
        if (not 8 <= self.n <= 32768 or self.n & (self.n - 1)
            or not 3 <= self.t < 1 << 30 or self.t % 2 != 1
            or not 1 <= self.eta <= 64 or not 1 <= self.dimension <= self.n // 2
            or self.t <= 2 * self.dimension or not 4 <= self.digit_bits <= 60
            or not 16 <= self.terminal_bits <= 60 or not 0 <= self.query_drop_bits < 120
            or not 0 <= self.response_drop_bits < self.terminal_bits
            or type(self.owner_index) is not bool or not 1 <= self.max_vectors <= 65536
            or not 1 <= self.max_pending <= 64 or not 1 <= self.max_queries <= 65536
            or not 1024 <= self.max_setup_bytes <= 384 << 20
            or not 256 <= self.max_query_bytes <= 1 << 20
            or not 256 <= self.max_response_bytes <= 16 << 20):
            raise ValueError("Invalid BGV execution policy")

    @property
    def q(self) -> mpz:
        p0, p1 = _rns_coefficient_primes(self.n, 120)
        return mpz(p0) * p1

    @property
    def padded(self) -> int:
        return 1 << (self.dimension - 1).bit_length()

    def digest(self) -> bytes:
        return hashlib.sha256(CIRCUIT + json.dumps(
            asdict(self), sort_keys=True, separators=(",", ":")
        ).encode()).digest()

    def check_key(self, pk: bgv.PublicKey) -> None:
        if ((pk.n, pk.t, pk.eta, pk.q) != (self.n, self.t, self.eta, self.q)
            or type(pk.key_id) is not str or len(pk.key_id) != 64
            or any(c not in "0123456789abcdef" for c in pk.key_id)):
            raise BGVProtocolError("BGV key differs from the local policy")

    def index_bound(self, pk: bgv.PublicKey) -> int:
        return pk.t // 2 + pk.t * pk.eta if self.owner_index else pk.fresh_bound

    def response_bounds(self, pk: bgv.PublicKey, count: int) -> list[int]:
        self.check_key(pk)
        if type(count) is not int or not 1 <= count <= min(self.max_vectors, 64 * pk.n):
            raise BGVProtocolError("Invalid BGV vector count")
        qb = (query_codec.parameters(pk, self.query_drop_bits).query_bound
              if self.query_drop_bits else pk.t // 2 + pk.t * pk.eta)
        digits = (120 + self.digit_bits - 1) // self.digit_bits
        error = pk.t * pk.eta * pk.n * ((1 << self.digit_bits) - 1) * digits
        tile_bound = pk.n * qb * self.index_bound(pk) + error
        tiles = (count + pk.n // self.padded - 1) // (pk.n // self.padded)
        p = compact.terminal_modulus(pk.q, pk.t, self.terminal_bits)
        bounds = [compact.reduced_bound(butterfly.schedule(
            self.padded, [tile_bound] * min(self.padded, tiles - start), error
        )[0], pk, p) for start in range(0, tiles, self.padded)]
        if self.response_drop_bits:
            response_codec._settings(pk, count, self.dimension, self.terminal_bits,
                                     bounds, self.response_drop_bits)
        if response_codec.packet_size(pk, count, self.dimension, self.terminal_bits,
                                      self.response_drop_bits or None) > self.max_response_bytes:
            raise BGVProtocolError("BGV response exceeds the local byte budget")
        return bounds


def context(setup: bytes, owner: bytes, epoch: int, policy: BGVExecutionPolicy) -> bytes:
    if (type(setup) is not bytes or not 0 < len(setup) <= policy.max_setup_bytes
        or type(epoch) is not int or not 0 <= epoch < 1 << 64):
        raise BGVProtocolError("Invalid BGV setup or epoch")
    return hashlib.sha256(b"CUHEPY-BGV-ATTESTED-CONTEXT-v1\0" + policy.digest()
                          + hashlib.sha256(setup).digest() + exact_bytes(owner, 32)
                          + epoch.to_bytes(8, "big")).digest()


def _poly(poly: tuple, policy: BGVExecutionPolicy) -> bytes:
    q = policy.q
    if len(poly) != policy.n or any(not 0 <= c < q for c in poly):
        raise BGVProtocolError("Noncanonical BGV setup polynomial")
    return gmpy2.pack(list(poly), 120).to_bytes(15 * policy.n, "little")


def _read_poly(data: bytes, policy: BGVExecutionPolicy) -> tuple[mpz, ...]:
    exact_bytes(data, 15 * policy.n)
    values = gmpy2.unpack(mpz.from_bytes(data, "little"), 120)
    q = policy.q
    if any(c >= q for c in values):
        raise BGVProtocolError("Noncanonical BGV setup coefficient")
    values.extend([mpz(0)] * (policy.n - len(values)))
    return tuple(values)


def pack_setup(pk: bgv.PublicKey, keys: trace.EvaluationKeys, index: list[bgv.Ciphertext],
               count: int, policy: BGVExecutionPolicy) -> bytes:
    """Owner-side serialization of the exact ordered encrypted index and keys."""
    policy.response_bounds(pk, count)
    butterfly.validate_keys(pk, keys)
    capacity = pk.n // policy.padded
    if (keys.padded != policy.padded or keys.digit_bits != policy.digit_bits
        or len(index) != (count + capacity - 1) // capacity):
        raise BGVProtocolError("Incorrect BGV setup layout")
    for tile in index:
        bgv._validate(tile, pk)
        if len(tile.components) != 2 or tile.phase_bound != policy.index_bound(pk):
            raise BGVProtocolError("Incorrect BGV index encryption mode")
    all_keys = [keys.relin, *(key for _, key in keys.rotations)]
    packet = msgpack.packb([
        _SETUP, bytes.fromhex(pk.key_id), _poly(pk.a, policy), _poly(pk.b, policy), count,
        [[[_poly(p, policy) for p in pair] for pair in key] for key in all_keys],
        [[_poly(p, policy) for p in tile.components] for tile in index],
    ], use_bin_type=True)
    if len(packet) > policy.max_setup_bytes:
        raise BGVProtocolError("BGV setup exceeds the local byte budget")
    return packet


def _array(value: list, length: int) -> list:
    if type(value) is not list or len(value) != length:
        raise BGVProtocolError("Incorrect BGV setup array shape")
    return value


def unpack_setup(packet: bytes, policy: BGVExecutionPolicy
                 ) -> tuple[bgv.PublicKey, trace.EvaluationKeys, list[bgv.Ciphertext], int]:
    """Called only AFTER owner registration authentication, before native import."""
    if type(packet) is not bytes or not 0 < len(packet) <= policy.max_setup_bytes:
        raise BGVProtocolError("Invalid BGV setup length")
    try:
        fields = _array(msgpack.unpackb(
            packet, raw=False, max_array_len=max(64, policy.max_vectors), max_map_len=0,
            max_bin_len=max(64, 15 * policy.n), max_str_len=0, max_ext_len=0,
        ), 7)
        tag, key_id, a, b, count, key_data, index_data = fields
        if tag != _SETUP or type(tag) is not bytes:
            raise BGVProtocolError("Wrong BGV setup domain")
        pk = bgv.PublicKey(policy.n, policy.t, policy.q, policy.eta,
                           _read_poly(a, policy), _read_poly(b, policy), exact_bytes(key_id, 32).hex())
        # Reconstruct the scheme's existing fingerprint, rather than trusting a label.
        digest = hashlib.sha256(f"cuhepy-shallow-bgv-v1:{pk.n}:{pk.t}:{pk.q}:{pk.eta}".encode())
        digest.update(a)
        digest.update(b)
        if digest.hexdigest() != pk.key_id:
            raise BGVProtocolError("BGV public key fingerprint mismatch")
        policy.response_bounds(pk, count)
        digits = (120 + policy.digit_bits - 1) // policy.digit_bits
        def read_pair(pair: list) -> tuple[tuple[mpz, ...], tuple[mpz, ...]]:
            left, right = _array(pair, 2)
            return _read_poly(left, policy), _read_poly(right, policy)
        keys = tuple(tuple(read_pair(pair) for pair in _array(key, digits))
                     for key in _array(key_data, policy.padded.bit_length()))
        generator = 1 + 2 * pk.n // policy.padded
        rotations = tuple((pow(generator, 1 << j, 2 * pk.n), key)
                          for j, key in enumerate(keys[1:]))
        evaluation = trace.EvaluationKeys(pk.key_id, policy.padded, policy.digit_bits,
            keys[0], rotations, pk.t * pk.eta * pk.n * ((1 << policy.digit_bits) - 1) * digits)
        capacity = pk.n // policy.padded
        index = [bgv.Ciphertext(tuple(_read_poly(p, policy) for p in _array(pair, 2)),
                               pk.key_id, policy.index_bound(pk))
                 for pair in _array(index_data, (count + capacity - 1) // capacity)]
        butterfly.validate_keys(pk, evaluation)
        return pk, evaluation, index, count
    except (TypeError, OverflowError, msgpack.UnpackException) as error:
        raise BGVProtocolError("Invalid BGV setup encoding") from error
