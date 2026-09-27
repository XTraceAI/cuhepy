"""E13 complete *stage* checker: batched canonical BGV relinearization.

Trusted caller pins the exact input tensors and registered public switch key.
An immutable output packet is copied/parsed before fresh private batch weights
are sampled. Three independent checks per RNS prime compare whole polynomials.
No HE secret, preprocessing pool, attestation, receipt or client authorization
is involved. This reference is variable-time Python/GMP, not a TEE deployment.
Checking a switch of an unverified tensor does NOT verify the preceding product.
"""

from dataclasses import dataclass, field
import hashlib
import os
import secrets
import struct
import threading
import time

import gmpy2

from cuhepy.bfv.scheme import _ring_product, _rns_coefficient_primes
from experiments.bfv_search_lab.butterfly_bgv import validate_keys

TAG = b"cuhepy-bgv-switch-stage-v1\0"
CHECKS = 3
MAX_COEFFICIENTS = 1 << 20


def _size(n, batch):
    if type(batch) is not int or not 1 <= batch <= 64 or batch*n > MAX_COEFFICIENTS:
        raise ValueError("Invalid bounded switch batch")


def _parse(raw, n, batch, components, primes):
    if type(raw) is not bytes or len(raw) != batch*components*2*n*8:
        raise ValueError("Incorrect fixed-size canonical RNS packet")
    words = struct.unpack(f"<{len(raw)//8}Q", raw)
    result, offset = [], 0
    for _ in range(batch):
        parts = []
        for _ in range(components):
            limbs = []
            for p in primes:
                poly = words[offset:offset+n]
                offset += n
                if any(c >= p for c in poly):
                    raise ValueError("Noncanonical RNS residue")
                limbs.append(poly)
            parts.append(tuple(limbs))
        result.append(tuple(parts))
    return tuple(result)


@dataclass(frozen=True)
class Context:
    n: int
    primes: tuple
    key: tuple = field(repr=False)
    digest: bytes

    @classmethod
    def from_bgv(cls, pk, keys):
        validate_keys(pk, keys)
        primes = tuple(_rns_coefficient_primes(pk.n, 120))
        if pk.n > 16384 or pk.q != primes[0]*primes[1] or keys.digit_bits != 30 or len(keys.relin) != 4:
            raise ValueError("Stage fixture requires N<=16384, Q120 RNS and four 30-bit digits")
        key = tuple(tuple(tuple(tuple(int(c % p) for c in poly) for poly in column)
                          for column in keys.relin) for p in primes)
        digest = hashlib.sha256(TAG+bytes.fromhex(pk.key_id)+struct.pack("<IQQ", pk.n, *primes))
        for limb in key:
            for column in limb:
                for poly in column:
                    digest.update(struct.pack(f"<{pk.n}Q", *poly))
        return cls(pk.n, primes, key, digest.digest())

    def pack_full(self, values, components):
        """Fixture adapter from canonical Q coefficients to fixed RNS packets."""
        _size(self.n, len(values))
        if components not in (2, 3):
            raise ValueError("Expected a tensor or relinearized output")
        q, out = self.primes[0]*self.primes[1], bytearray()
        for parts in values:
            if len(parts) != components:
                raise ValueError("Incorrect ciphertext component count")
            for poly in parts:
                if len(poly) != self.n or any(type(c) not in (int, gmpy2.mpz) or not 0 <= c < q for c in poly):
                    raise ValueError("Expected canonical full-Q coefficients")
                for p in self.primes:
                    out.extend(struct.pack(f"<{self.n}Q", *(int(c % p) for c in poly)))
        return bytes(out)

    def begin(self, trusted_tensors, batch, binding, *, native=None):
        return Request(self, trusted_tensors, batch, binding, native=native)


@dataclass(frozen=True)
class Result:
    accepted: bool
    statement_digest: bytes
    output_digest: bytes
    phase_seconds: dict


class Request:
    """One local attempt, including malformed/rejected responses; never a receipt."""

    def __init__(self, context, trusted_tensors, batch, binding, *, native=None):
        _size(context.n, batch)
        if type(binding) is not bytes or len(binding) != 32:
            raise ValueError("Pin a 32-byte parent statement binding")
        # Tuple copies eliminate aliases to caller-owned lists. No challenge yet.
        if native is None:
            tensors = _parse(trusted_tensors, context.n, batch, 3, context.primes)
        else:
            from experiments.bfv_search_lab.native_check_bgv import NativeCheckArithmetic
            if type(native) is not NativeCheckArithmetic or native.context is not context:
                raise ValueError('Wrong native checker context')
            native.validate(trusted_tensors, batch, 3)
            tensors = None
        self._context, self._tensors, self._batch = context, tensors, batch
        self._native, self._raw = native, trusted_tensors if native is not None else None
        self._pid, self._lock, self._used = os.getpid(), threading.Lock(), False
        self.statement_digest = hashlib.sha256(TAG+context.digest+binding+struct.pack("<I", batch)
            +secrets.token_bytes(32)+hashlib.sha256(trusted_tensors).digest()).digest()

    def __copy__(self):
        raise TypeError("Stage attempts cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("Stage attempts cannot be copied")

    def __reduce_ex__(self, protocol):
        raise TypeError("Stage attempts cannot be serialized")

    def result_packet(self, components):
        """Public server-side fixture framing; knows no verifier randomness."""
        if len(components) != self._batch:
            raise ValueError("Incorrect stage output count")
        return TAG+self.statement_digest+self._context.pack_full(components, 2)

    def check_once(self, packet):
        if os.getpid() != self._pid:
            raise RuntimeError("Create a new stage attempt after fork")
        with self._lock:
            if self._used:
                raise RuntimeError("Stage attempt already consumed")
            self._used = True
            tensors, self._tensors = self._tensors, None
            raw, self._raw = self._raw, None
        ctx, n, batch = self._context, self._context.n, self._batch
        started = time.perf_counter()
        if (type(packet) is not bytes or len(packet) != len(TAG)+32+batch*2*2*n*8
            or not packet.startswith(TAG+self.statement_digest)):
            raise ValueError("Incorrect stage output binding/size")
        output_digest = hashlib.sha256(packet).digest()
        if self._native is not None:
            body = packet[len(TAG)+32:]
            self._native.validate(body, batch, 2)
            parsed = time.perf_counter()
            weights = tuple(secrets.randbelow(p) for p in ctx.primes for _ in range(CHECKS) for _ in range(batch))
            packed = struct.pack(f'<{len(weights)}Q', *weights)
            sampled = time.perf_counter()
            accepted = self._native.check_arithmetic(raw, body, packed, batch)
            return Result(bool(accepted), self.statement_digest, output_digest,
                          dict(parse_s=parsed-started, fresh_weights_s=sampled-parsed,
                               native_arithmetic_s=time.perf_counter()-sampled,
                               total_s=time.perf_counter()-started))
        output = _parse(packet[len(TAG)+32:], n, batch, 2, ctx.primes)
        parsed = time.perf_counter()
        p0, p1 = ctx.primes
        inverse, mask = pow(p0, -1, p1), (1 << 30)-1
        digits = []
        for tensor in tensors:
            # Canonical CRT MUST precede decomposition, separately for each item.
            first, second = tensor[2]
            canonical = tuple(a+p0*((b-a)*inverse % p1) for a, b in zip(first, second, strict=True))
            digits.append(tuple(tuple((c >> (30*j)) & mask for c in canonical) for j in range(4)))
        converted = time.perf_counter()
        accepted = True
        sampling_s = folding_s = products_s = 0.0
        # Fresh weights are generated only after the entire immutable result
        # has been pinned and every coefficient checked. No early math rejection.
        for limb, p in enumerate(ctx.primes):
            for _ in range(CHECKS):
                begin = time.perf_counter()
                alpha = tuple(secrets.randbelow(p) for _ in range(batch))
                sampled = time.perf_counter()
                combined = [tuple(sum(alpha[b]*digits[b][j][i] for b in range(batch)) % p
                                  for i in range(n)) for j in range(4)]
                observed = [tuple(sum(alpha[b]*(output[b][k][limb][i]-tensors[b][k][limb][i])
                                      for b in range(batch)) % p for i in range(n)) for k in range(2)]
                folded = time.perf_counter()
                for k in range(2):
                    products = [_ring_product(combined[j], ctx.key[limb][j][k], p) for j in range(4)]
                    expected = tuple(int(sum(poly[i] for poly in products) % p) for i in range(n))
                    accepted &= expected == observed[k]
                sampling_s += sampled-begin
                folding_s += folded-sampled
                products_s += time.perf_counter()-folded
        return Result(bool(accepted), self.statement_digest, output_digest,
                      dict(parse_s=parsed-started, canonical_digits_s=converted-parsed,
                           fresh_weights_s=sampling_s, fold_s=folding_s, products_s=products_s,
                           total_s=time.perf_counter()-started))
