"""E16 radix layouts for the existing homemade coefficient BGV evaluator.

Balanced packing uses B=2*d+1 and centered signed correlations. Distance packing
uses B=d+1: if S=sum_l (d-2*h_l)*B^l and K=d*sum_l B^l, then
((K-S)/2) mod t = sum_l h_l*B^l. The right side is in [0,B^g-1], so
odd t>=B^g suffices even when the signed correlation itself wraps modulo t.
Division means multiplication by 2^-1 modulo t, not integer halving of S mod t.

This changes the plaintext modulus, index and output contract, not N, Q, the
secret distribution or the public CUDA circuit. It needs separate parameter
review. The envelope is only a bounded synthetic-fixture format, not a protocol
or permission to decrypt. Original layouts/codecs/authentication are retained.
"""

from __future__ import annotations

from dataclasses import dataclass

import gmpy2
import msgpack

from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import joint_precision_bgv as planner
from experiments.bfv_search_lab import compressed_response_bgv as response
from experiments.bfv_search_lab import transport_bgv as wire

TAG = b"cuhepy-lab-bgv-radix-v1"


@dataclass(frozen=True)
class Layout:
    dimension: int
    group: int = 1
    mode: str = "distance"

    def __post_init__(self):
        if (type(self.dimension) is not int or not 1 <= self.dimension <= 512
            or type(self.group) is not int or not 1 <= self.group <= 3
            or self.mode not in ("balanced", "distance")):
            raise ValueError("Invalid radix layout")

    @property
    def base(self):
        return (2 if self.mode == "balanced" else 1)*self.dimension+1

    @property
    def padded(self):
        return 1 << (self.dimension-1).bit_length()

    def plaintext_modulus(self, minimum=1031):
        if type(minimum) is not int or not 3 <= minimum < 1 << 30:
            raise ValueError("Invalid minimum plaintext modulus")
        # Retain the old wire/decoder's t>2*d contract, including g=1 baseline.
        floor = max(minimum-1, 2*self.dimension,
                    self.base**self.group - (self.mode == "distance"))
        t = int(gmpy2.next_prime(floor))
        if t >= 1 << 30:
            raise ValueError("Radix packing exceeds the existing t<2^30 policy")
        return t

    def groups(self, count):
        if type(count) is not int or not 1 <= count <= 64*32768:
            raise ValueError("Invalid radix vector count")
        return (count+self.group-1)//self.group

    def validate(self, n, t, count):
        groups = self.groups(count)
        minimum = self.base**self.group - (self.mode == "distance")
        if (type(n) is not int or not 8 <= n <= 32768 or n & (n-1) or self.padded > n//2
            or type(t) is not int or not max(minimum, 2*self.dimension) < t < 1 << 30
            or t % 2 != 1 or groups > 64*n):
            raise ValueError("Invalid radix ring/plaintext/count context")

    def _bits(self, bits):
        if len(bits) != self.dimension or any(type(b) is not int or b not in (0, 1) for b in bits):
            raise ValueError("Expected an exact-length binary radix vector")

    def inputs(self, query, rows, n):
        self._bits(query)
        self.validate(n, self.plaintext_modulus(), max(1, len(rows)))
        backward, _ = bgv.coefficient_inputs(query, [], n)
        capacity, tiles = n//self.padded, []
        for start in range(0, len(rows), capacity*self.group):
            tile = [0]*n
            for i, row in enumerate(rows[start:start+capacity*self.group]):
                self._bits(row)
                lane, digit = divmod(i, self.group)
                weight = self.base**digit
                for j, bit in enumerate(row):
                    tile[lane*self.padded+j] += (1-2*bit)*weight
            tiles.append(tile)
        return backward, tiles

    def decode_value(self, residue, t, active):
        """Unscaled selected coefficient; incomplete groups have zero missing digits."""
        minimum = self.base**self.group - (self.mode == "distance")
        if (type(t) is not int or not max(minimum, 2*self.dimension) < t < 1 << 30 or t % 2 != 1
            or type(residue) is not int or not 0 <= residue < t
            or type(active) is not int or not 1 <= active <= self.group):
            raise ValueError("Invalid radix residue/tail")
        b, d = self.base, self.dimension
        if self.mode == "distance":
            offset = b**active-1
            value = (offset-residue)*((t+1)//2) % t
        else:
            value = residue if residue <= t//2 else residue-t
        out = []
        for _ in range(active):
            if self.mode == "distance":
                value, distance = divmod(value, b)
            else:
                dot = (value+d) % b - d
                value = (value-dot)//b
                if (d-dot) % 2:
                    raise ValueError("Invalid balanced correlation parity")
                distance = (d-dot)//2
            if not 0 <= distance <= d:
                raise ValueError("Invalid radix distance")
            out.append(distance)
        if value:
            raise ValueError("Radix value exceeds the declared active group")
        return out

    def decode(self, plaintexts, count, n, t):
        self.validate(n, t, count)
        groups = self.groups(count)
        if (len(plaintexts) != (groups+n-1)//n
            or any(len(p) != n or any(type(c) is not int or not 0 <= c < t for c in p) for p in plaintexts)):
            raise ValueError("Invalid canonical radix plaintext shape")
        inverse, capacity, output = pow(self.padded, -1, t), n//self.padded, []
        for i in range(groups):
            response_index, position = divmod(i, n)
            tile, lane = divmod(position, capacity)
            residue = plaintexts[response_index][lane*self.padded+tile]*inverse % t
            output.extend(self.decode_value(residue, t, min(self.group, count-i*self.group)))
        return output

    def _header(self, count, kind):
        self.groups(count)
        if kind not in ("query", "response"):
            raise ValueError("Invalid radix envelope direction")
        return [TAG, kind, self.mode, self.group, count, self.dimension]

    def wrap(self, packet, count, kind):
        if type(packet) is not bytes or not 1 <= len(packet) <= wire.MAX_FRAME-256:
            raise ValueError("Invalid inner radix packet")
        return msgpack.packb([*self._header(count, kind), packet], use_bin_type=True)

    def unwrap(self, packet, count, kind):
        expected = self._header(count, kind)
        if type(packet) is not bytes or not 1 <= len(packet) <= wire.MAX_FRAME:
            raise ValueError("Invalid radix envelope size")
        try:
            fields = msgpack.unpackb(packet, raw=False, max_array_len=7, max_map_len=0,
                                     max_bin_len=wire.MAX_FRAME-256, max_str_len=64, max_ext_len=0)
            if (type(fields) is not list or len(fields) != 7 or fields[:6] != expected
                or any(type(a) is not type(b) for a, b in zip(fields[:6], expected, strict=True))
                or type(fields[6]) is not bytes or not fields[6]):
                raise ValueError("Wrong radix envelope context")
            return fields[6]
        except (msgpack.UnpackException, TypeError, OverflowError) as error:
            raise ValueError("Invalid radix envelope") from error

    def packet_size(self, inner_bytes, count, kind):
        if type(inner_bytes) is not int or not 1 <= inner_bytes <= wire.MAX_FRAME-256:
            raise ValueError("Invalid inner radix size")
        return len(msgpack.packb([*self._header(count, kind), b""], use_bin_type=True))-2+response._binary_cost(inner_bytes)


def plans(server, index, layout, count):
    """Public bound planning includes the larger t and actual number of output groups."""
    pk = server.pk
    layout.validate(pk.n, pk.t, count)
    if index.count != layout.groups(count) or server.keys.padded != layout.padded:
        raise ValueError("Mismatched radix server/index layout")
    first = max(16, ((pk.n+1)*pk.t).bit_length())
    return planner.enumerate_plans(server, index, layout.dimension,
                                   terminal_bits=tuple(b for b in (first, first+1, first+3, first+7) if b <= 60))
