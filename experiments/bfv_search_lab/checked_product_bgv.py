"""E13 bound product + canonical relinearization, not complete search authorization.

Pin a trusted ordered index and query, then fix the full output before sampling.
Witness mode checks GPU-supplied c2; local mode computes c2 inside the verifier.
Both check the same two-component result with fresh whole-polynomial batch
checks. No HE secret, receipt, attestation or secret preprocessing is involved.
"""

from dataclasses import dataclass, field
import hashlib
import os
import secrets
import struct
import threading
import time

from cuhepy.bfv.scheme import _ring_product
from experiments.bfv_search_lab.checked_switch_bgv import Context, Result, CHECKS, _parse, _size

TAG = b"cuhepy-bgv-product-switch-v1\0"
MODES = {"witness": 0, "local": 1}


def _witness(raw, context, batch):
    """Same [batch][component][limb][coefficient] grammar, one component."""
    return _parse(raw, context.n, batch, 1, context.primes)


def _product(a, b, p):
    return tuple(int(c) for c in _ring_product(a, b, p))


@dataclass(frozen=True)
class ProductContext:
    context: Context
    batch: int
    raw_index: bytes = field(repr=False)
    digest: bytes

    @classmethod
    def prepare(cls, context, trusted_index, batch, index_binding):
        _size(context.n, batch)
        if type(index_binding) is not bytes or len(index_binding) != 32:
            raise ValueError("Pin a 32-byte parent index/epoch binding")
        _parse(trusted_index, context.n, batch, 2, context.primes)
        digest = hashlib.sha256(TAG+context.digest+index_binding+struct.pack('<I', batch)
                                +hashlib.sha256(trusted_index).digest()).digest()
        return cls(context, batch, trusted_index, digest)

    def begin(self, trusted_query, binding, *, mode="witness", native=None):
        return Request(self, trusted_query, binding, mode=mode, native=native)


class Request:
    """One immutable proposed product/switch result; never a private-client gate."""

    def __init__(self, context, trusted_query, binding, *, mode="witness", native=None):
        if type(mode) is not str or mode not in MODES or type(binding) is not bytes or len(binding) != 32:
            raise ValueError("Invalid product mode or parent statement binding")
        ctx = context.context
        if native is None:
            _parse(trusted_query, ctx.n, 1, 2, ctx.primes)
        else:
            from experiments.bfv_search_lab.native_check_bgv import NativeProductArithmetic
            if type(native) is not NativeProductArithmetic or native.context is not context:
                raise ValueError("Wrong native product context")
            native.arithmetic.validate(trusted_query, 1, 2)
        self._context, self._query, self._native, self._mode = context, trusted_query, native, mode
        self._pid, self._lock, self._used = os.getpid(), threading.Lock(), False
        self.statement_digest = hashlib.sha256(TAG+context.digest+binding+bytes([MODES[mode]])
            +secrets.token_bytes(32)+hashlib.sha256(trusted_query).digest()).digest()

    def __copy__(self):
        raise TypeError("Product attempts cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("Product attempts cannot be copied")

    def __reduce_ex__(self, protocol):
        raise TypeError("Product attempts cannot be serialized")

    def result_packet(self, output, witness=b""):
        """Public fixture framing over raw RNS words; no challenge is revealed."""
        ctx, batch = self._context.context, self._context.batch
        if self._native is not None:
            self._native.validate_result(witness, output, self._mode)
        else:
            _parse(output, ctx.n, batch, 2, ctx.primes)
            if self._mode == 'witness':
                _witness(witness, ctx, batch)
            elif type(witness) is not bytes or witness:
                raise ValueError("Local-c2 mode has no witness")
        return TAG+self.statement_digest+witness+output

    def check_once(self, packet):
        if os.getpid() != self._pid:
            raise RuntimeError("Create a new product attempt after fork")
        with self._lock:
            if self._used:
                raise RuntimeError("Product attempt already consumed")
            self._used = True
            raw_query, self._query = self._query, None
        started = time.perf_counter()
        ctx, batch = self._context.context, self._context.batch
        n, primes = ctx.n, ctx.primes
        witness_size = batch*2*n*8 if self._mode == 'witness' else 0
        offset = len(TAG)+32
        if (type(packet) is not bytes or len(packet) != offset+witness_size+batch*4*n*8
            or not packet.startswith(TAG+self.statement_digest)):
            raise ValueError("Incorrect product output binding/size")
        digest = hashlib.sha256(packet).digest()
        witness, output = packet[offset:offset+witness_size], packet[offset+witness_size:]
        # The ENTIRE immutable output/witness is validated before any weights.
        if self._native is not None:
            self._native.validate_result(witness, output, self._mode)
        else:
            y = _parse(output, n, batch, 2, primes)
            z = _witness(witness, ctx, batch) if witness_size else None
        parsed = time.perf_counter()
        weights = tuple(tuple(tuple(secrets.randbelow(p) for _ in range(batch))
                              for _ in range(CHECKS)) for p in primes)
        sampled = time.perf_counter()
        if self._native is not None:
            packed = struct.pack(f'<{2*CHECKS*batch}Q', *(a for limb in weights for row in limb for a in row))
            accepted = self._native.check_arithmetic(raw_query, witness, output, packed, self._mode)
        else:
            index = _parse(self._context.raw_index, n, batch, 2, primes)
            query = _parse(raw_query, n, 1, 2, primes)[0]
            if z is None:
                z = tuple((tuple(_product(tile[1][limb], query[1][limb], p)
                                 for limb, p in enumerate(primes)),) for tile in index)
            p0, p1 = primes
            inverse, mask = pow(p0, -1, p1), (1 << 30)-1
            digits = []
            for item in z:
                full = tuple(a+p0*((b-a)*inverse % p1) for a, b in zip(*item[0], strict=True))
                digits.append(tuple(tuple((c >> (30*j)) & mask for c in full) for j in range(4)))
            accepted = True
            for limb, p in enumerate(primes):
                for alpha in weights[limb]:
                    def fold(polys, alpha=alpha, p=p):
                        return tuple(sum(alpha[b]*polys[b][i] for b in range(batch)) % p for i in range(n))
                    a = [fold([tile[k][limb] for tile in index]) for k in range(2)]
                    d = [fold([item[j] for item in digits]) for j in range(4)]
                    if witness_size:
                        accepted &= fold([item[0][limb] for item in z]) == _product(a[1], query[1][limb], p)
                    expected = [_product(a[0], query[0][limb], p),
                                tuple((x+y) % p for x, y in zip(_product(a[0], query[1][limb], p),
                                      _product(a[1], query[0][limb], p), strict=True))]
                    for k in range(2):
                        products = [_product(d[j], ctx.key[limb][j][k], p) for j in range(4)]
                        value = tuple((expected[k][i]+sum(poly[i] for poly in products)) % p for i in range(n))
                        accepted &= value == fold([item[k][limb] for item in y])
        return Result(bool(accepted), self.statement_digest, digest,
                      dict(parse_s=parsed-started, fresh_weights_s=sampled-parsed,
                           arithmetic_s=time.perf_counter()-sampled, total_s=time.perf_counter()-started))
