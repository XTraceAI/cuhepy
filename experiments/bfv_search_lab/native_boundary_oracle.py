"""E106 bounded independent integer oracle for native BGV compact-v1.

This replays public work and validates the complete canonical trace. It is a
known recomputation control, not an efficient proof or authenticated service.
No HE secret is used by query parsing, graph replay, or witness checking.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from math import gcd, prod

import msgpack

Poly = tuple[int, ...]
Cipher = tuple[Poly, Poly]
Key = tuple[Cipher, ...]
QUERY_TAG = b"cuhepy-lab-bgv-query-rounded-v1"
SEED_TAG = b"cuhepy-lab-bgv-seeded-query-v1"
RESPONSE_TAG = "cuhepy-lab-bgv-compact-v1"


def polynomial(value, n, modulus=None):
    if (type(value) is not tuple or len(value) != n
            or any(type(x) is not int or (modulus is not None and not 0 <= x < modulus) for x in value)):
        raise ValueError("Noncanonical polynomial")
    return value


def multiply(left, right, q):
    """Independent schoolbook convolution in Z[X]/(X**N+1), then mod q."""
    n, out = len(left), [0]*len(left)
    if len(right) != n:
        raise ValueError("Wrong convolution shape")
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            at = i+j
            out[at % n] += a*b if at < n else -a*b
    return tuple(x % q for x in out)


def add(left, right, q, sign=1):
    return tuple((a+sign*b) % q for a, b in zip(left, right, strict=True))


def monomial(poly, shift, q):
    n, out = len(poly), [0]*len(poly)
    for i, x in enumerate(poly):
        at = (i+shift) % (2*n)
        out[at % n] = (x if at < n else -x) % q
    return tuple(out)


def automorphism(poly, exponent, q):
    n, out = len(poly), [0]*len(poly)
    if exponent % 2 != 1:
        raise ValueError("Odd automorphism required")
    for i, x in enumerate(poly):
        at = i*exponent % (2*n)
        out[at % n] = (x if at < n else -x) % q
    return tuple(out)


def pack_bits(poly, bits):
    if any(type(x) is not int or not 0 <= x < 1 << bits for x in poly):
        raise ValueError("Invalid coefficient word")
    return sum(x << (bits*i) for i, x in enumerate(poly)).to_bytes((len(poly)*bits+7)//8, "little")


def unpack_bits(data, n, bits, modulus):
    if type(data) is not bytes or len(data) != (n*bits+7)//8:
        raise ValueError("Incorrect packed polynomial length")
    value = int.from_bytes(data, "little")
    if value >> (n*bits):
        raise ValueError("Noncanonical bit padding")
    return polynomial(tuple((value >> (bits*i)) & ((1 << bits)-1) for i in range(n)), n, modulus)


@dataclass(frozen=True)
class Context:
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
    index: tuple[Cipher, ...]
    relin: Key
    rotations: tuple[tuple[int, Key], ...]

    @property
    def levels(self):
        return (self.q.bit_length()+self.digit_bits-1)//self.digit_bits

    def validate(self):
        """Bounded generic algebra validation; native admission is separate."""
        if (type(self.n) is not int or not 8 <= self.n <= 64 or self.n & (self.n-1)
                or type(self.t) is not int or not 3 <= self.t < 1 << 30 or self.t % 2 != 1
                or type(self.q) is not int or not 32 <= self.q.bit_length() <= 240 or self.q % 2 != 1
                or type(self.primes) is not tuple or len(self.primes) != 2
                or any(type(p) is not int or p < 3 for p in self.primes)
                or gcd(*self.primes) != 1 or prod(self.primes) != self.q
                or type(self.dimension) is not int or not 1 <= self.dimension <= self.n//2
                or self.t <= 2*self.dimension or type(self.padded) is not int
                or self.padded != 1 << (self.dimension-1).bit_length()
                or type(self.digit_bits) is not int or not 4 <= self.digit_bits <= 60
                or type(self.query_drop) is not int or not 1 <= self.query_drop < self.q.bit_length()
                or type(self.p) is not int or not self.t < self.p < self.q or self.p % 2 != 1
                or (self.p-self.q) % self.t or type(self.key_id) is not str or len(self.key_id) != 64
                or any(c not in "0123456789abcdef" for c in self.key_id)
                or type(self.epoch) is not str or not 1 <= len(self.epoch) <= 64
                or type(self.ids) is not tuple or not 1 <= len(self.ids) <= 64*self.n
                or self.ids != tuple(range(len(self.ids))) or any(type(i) is not int for i in self.ids)):
            raise ValueError("Wrong bounded owner-approved context")
        if type(self.index) is not tuple or len(self.index) != (len(self.ids)+self.n//self.padded-1)//(self.n//self.padded):
            raise ValueError("Wrong complete index coverage")
        if (type(self.rotations) is not tuple or any(type(pair) is not tuple or len(pair) != 2
                or type(pair[0]) is not int for pair in self.rotations)):
            raise ValueError("Wrong native rotation key grammar")
        generator = 1+2*self.n//self.padded
        if tuple(g for g, _ in self.rotations) != tuple(pow(generator, 1 << j, 2*self.n) for j in range(self.padded.bit_length()-1)):
            raise ValueError("Wrong native rotation schedule")
        for cipher in self.index:
            if type(cipher) is not tuple or len(cipher) != 2:
                raise ValueError("Wrong ciphertext shape")
            for poly in cipher:
                polynomial(poly, self.n, self.q)
        for key in (self.relin, *(key for _, key in self.rotations)):
            if type(key) is not tuple or len(key) != self.levels:
                raise ValueError("Wrong switching key")
            for pair in key:
                if type(pair) is not tuple or len(pair) != 2:
                    raise ValueError("Wrong switching key pair")
                for poly in pair:
                    polynomial(poly, self.n, self.q)

    def digest(self):
        self.validate()
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def admit_native_fixture(self):
        """Exact frozen diagnostic profile, not cryptographic parameter approval."""
        self.validate()
        if ((self.n, self.t, self.padded, self.dimension, self.digit_bits, self.query_drop, self.p)
                != (8, 17, 4, 3, 30, 58, 4294966477)
                or self.primes != (1152921504606846577, 1152921504606846097)):
            raise ValueError("Not the frozen native diagnostic profile")


def query_encoding(ctx):
    radix = 1 << ctx.query_drop
    intervals = (radix-1)//ctx.t
    high, tail = divmod(ctx.q-1, radix)
    maximum = high*ctx.t+min(ctx.t-1, tail)
    return maximum.bit_length(), maximum, ctx.t*(intervals//2)


def expand_query(ctx, packet):
    """Independent actual coefficient envelope and SHAKE rejection stream."""
    bits, maximum, center = query_encoding(ctx)
    if type(packet) is not bytes or len(packet) > (ctx.n*bits+7)//8+256:
        raise ValueError("Wrong original query packet size")
    try:
        fields = msgpack.unpackb(packet, raw=False, max_array_len=5, max_map_len=0,
                                max_bin_len=max((ctx.n*bits+7)//8, 64), max_str_len=0, max_ext_len=0)
    except (ValueError, TypeError, OverflowError, msgpack.UnpackException) as error:
        raise ValueError("Malformed original query packet") from error
    if (type(fields) is not list or len(fields) != 5
            or type(fields[0]) is not bytes or fields[0] != QUERY_TAG
            or type(fields[1]) is not bytes or fields[1] != bytes.fromhex(ctx.key_id)
            or type(fields[2]) is not bytes or len(fields[2]) != 32
            or type(fields[3]) is not int or fields[3] != ctx.query_drop):
        raise ValueError("Wrong original query context")
    words = unpack_bits(fields[4], ctx.n, bits, maximum+1)
    c0, radix = [], 1 << ctx.query_drop
    for word in words:
        high, residue = divmod(word, ctx.t)
        base = high*radix
        if residue >= min(radix, ctx.q-base):
            raise ValueError("Compressed coefficient without canonical preimage")
        c0.append((base+residue+center) % ctx.q)
    shake = hashlib.shake_256(SEED_TAG+bytes.fromhex(ctx.key_id)+fields[2])
    width, mask = (ctx.q.bit_length()+7)//8, (1 << ctx.q.bit_length())-1
    c1, offset = [], 0
    while len(c1) < ctx.n:
        end = offset+(ctx.n-len(c1))*width
        block = shake.digest(end)[offset:end]
        offset = end
        for at in range(0, len(block), width):
            value = int.from_bytes(block[at:at+width], "little") & mask
            if value < ctx.q:
                c1.append(value)
    return tuple(c0), tuple(c1)


def crt(values, primes):
    """Independent canonical CRT lift; one shared full-Q digit source follows."""
    if len(values) != 2 or len(primes) != 2:
        raise ValueError("Two CRT limbs required")
    p0, p1 = primes
    if any(type(x) is not int or not 0 <= x < p for x, p in zip(values, primes, strict=True)):
        raise ValueError("Noncanonical CRT limb")
    return values[0]+p0*((values[1]-values[0])*pow(p0, -1, p1) % p1)


def round_lift(c, q, p, t):
    """Choose the closer of two congruent integer neighbors, independently."""
    if any(type(x) is not int for x in (c, q, p, t)) or not 0 <= c < q or not 0 < p < q or t < 1:
        raise ValueError("Wrong public rounding input")
    residue = c % t
    lower = residue+t*((p*c-q*residue)//(q*t))
    upper = lower+t
    return lower if abs(q*lower-p*c) < abs(q*upper-p*c) else upper


@dataclass(frozen=True)
class Switch:
    label: str
    source: Poly
    digits: tuple[Poly, ...]
    output: Cipher


@dataclass(frozen=True)
class Rounding:
    position: tuple[int, int, int]
    source: int
    lift: int
    output: int


@dataclass(frozen=True)
class Transcript:
    binding: str
    query: bytes
    cuts: tuple[Switch, ...]
    preterminal: tuple[Cipher, ...]
    rounding: tuple[Rounding, ...]
    packet: bytes


def binding(ctx, query):
    return hashlib.sha256(b"E106-owner-pinned-public-statement-v1"+bytes.fromhex(ctx.digest())+query).hexdigest()


def serialize(ctx, compact):
    bits = ctx.p.bit_length()
    header = [RESPONSE_TAG, ctx.n, ctx.t, ctx.p.to_bytes((bits+7)//8, "little"),
              bytes.fromhex(ctx.key_id), len(ctx.ids), ctx.dimension]
    body = [[pack_bits(poly, bits) for poly in cipher] for cipher in compact]
    return msgpack.packb([header, body], use_bin_type=True)


def parse_response(ctx, packet):
    groups, bits = (len(ctx.ids)+ctx.n-1)//ctx.n, ctx.p.bit_length()
    width = (ctx.n*bits+7)//8
    if type(packet) is not bytes or len(packet) > 2*groups*width+4096:
        raise ValueError("Wrong complete response size")
    try:
        fields = msgpack.unpackb(packet, raw=False, max_array_len=64, max_map_len=0,
                                max_bin_len=max(width, 32), max_str_len=64, max_ext_len=0)
    except (ValueError, TypeError, OverflowError, msgpack.UnpackException) as error:
        raise ValueError("Malformed complete response") from error
    expected = msgpack.unpackb(serialize(ctx, ()), raw=False)[0]
    if (type(fields) is not list or len(fields) != 2 or type(fields[0]) is not list
            or fields[0] != expected or any(type(a) is not type(b) for a, b in zip(fields[0], expected, strict=True))
            or type(fields[1]) is not list or len(fields[1]) != groups):
        raise ValueError("Wrong complete response context/coverage")
    out = []
    for pair in fields[1]:
        if type(pair) is not list or len(pair) != 2:
            raise ValueError("Wrong complete response pair")
        out.append(tuple(unpack_bits(data, ctx.n, bits, ctx.p) for data in pair))
    return tuple(out)


def replay(ctx, query, supplied=None, *, canonical=True):
    """Replay the actual public schedule; optional witnesses are all checked."""
    ctx.validate()
    if type(canonical) is not bool:
        raise ValueError("Explicit canonical checking mode required")
    statement = binding(ctx, query)
    if supplied is not None and (type(supplied) is not Transcript or supplied.query != query or supplied.binding != statement):
        raise ValueError("Wrong original query/owner statement binding")
    if supplied is not None:
        if (type(supplied.query) is not bytes or type(supplied.binding) is not str
                or type(supplied.cuts) is not tuple or type(supplied.rounding) is not tuple
                or type(supplied.preterminal) is not tuple or type(supplied.packet) is not bytes):
            raise ValueError("Wrong complete transcript grammar")
        for cipher in supplied.preterminal:
            if type(cipher) is not tuple or len(cipher) != 2:
                raise ValueError("Wrong preterminal shape")
            for poly in cipher:
                polynomial(poly, ctx.n, ctx.q)
    query_cipher = expand_query(ctx, query)
    q, n, cuts = ctx.q, ctx.n, []

    def switch(source, key, label):
        source = tuple(crt(tuple(x % p for p in ctx.primes), ctx.primes) for x in source)
        honest_digits = tuple(tuple((x >> (ctx.digit_bits*j)) & ((1 << ctx.digit_bits)-1) for x in source)
                              for j in range(ctx.levels))
        witness = None
        if supplied is not None:
            if len(cuts) >= len(supplied.cuts):
                raise ValueError("Missing switching cut")
            witness = supplied.cuts[len(cuts)]
            if type(witness) is not Switch or type(witness.label) is not str:
                raise ValueError("Wrong switching cut grammar")
            polynomial(witness.source, n, q)
            if type(witness.output) is not tuple or len(witness.output) != 2:
                raise ValueError("Wrong switching output shape")
            for poly in witness.output:
                polynomial(poly, n, q)
            if witness.label != label or witness.source != source:
                raise ValueError("Wrong canonical switching source/order")
            digits = witness.digits
        else:
            digits = honest_digits
        if type(digits) is not tuple or len(digits) != ctx.levels:
            raise ValueError("Wrong digit shape")
        for row in digits:
            polynomial(row, n)
        reconstructed = tuple(sum(row[i] << (ctx.digit_bits*j) for j, row in enumerate(digits)) for i in range(n))
        if tuple(x % q for x in reconstructed) != source:
            raise ValueError("Digit modular reconstruction fails")
        if canonical and (digits != honest_digits or reconstructed != source):
            raise ValueError("Noncanonical global digits/range")
        output = ((0,)*n, (0,)*n)
        for row, pair in zip(digits, key, strict=True):
            output = tuple(add(poly, multiply(row, key_poly, q), q) for poly, key_poly in zip(output, pair, strict=True))
        cut = Switch(label, source, digits, output)
        if witness is not None and witness.output != output:
            raise ValueError("Switching output relation fails")
        cuts.append(cut)
        return output

    work, responses = [], []
    for group_start in range(0, len(ctx.index), ctx.padded):
        work = []
        for tile_number in range(group_start, min(group_start+ctx.padded, len(ctx.index))):
            a, b = query_cipher
            c, d = ctx.index[tile_number]
            c0 = multiply(a, c, q)
            c1 = add(multiply(a, d, q), multiply(b, c, q), q)
            c2 = multiply(b, d, q)
            switched = switch(c2, ctx.relin, f"tile{tile_number}:relin")
            work.append(tuple(monomial(add(poly, correction, q), 1-ctx.padded, q)
                              for poly, correction in zip((c0, c1), switched, strict=True)))
        shift = ctx.padded//2
        for stage, (exponent, key) in enumerate(ctx.rotations):
            merged = []
            for i in range(min(shift, len(work))):
                plus = minus = work[i]
                if i+shift < len(work):
                    right = tuple(monomial(poly, shift, q) for poly in work[i+shift])
                    plus = tuple(add(a, b, q) for a, b in zip(work[i], right, strict=True))
                    minus = tuple(add(a, b, q, -1) for a, b in zip(work[i], right, strict=True))
                rotated = tuple(automorphism(poly, exponent, q) for poly in minus)
                correction = switch(rotated[1], key, f"group{group_start//ctx.padded}:stage{stage}:node{i}")
                result = (add(rotated[0], correction[0], q), correction[1])
                merged.append(tuple(add(a, b, q) for a, b in zip(plus, result, strict=True)))
            work, shift = merged, shift//2
        responses.append(work[0])
    rounding, compact = [], []
    for group, cipher in enumerate(responses):
        pair = []
        for component, poly in enumerate(cipher):
            rounded = []
            for position, c in enumerate(poly):
                lift = round_lift(c, q, ctx.p, ctx.t)
                cell = Rounding((group, component, position), c, lift, lift % ctx.p)
                if supplied is not None:
                    if len(rounding) >= len(supplied.rounding):
                        raise ValueError("Missing complete terminal rounding relation")
                    given = supplied.rounding[len(rounding)]
                    if (type(given) is not Rounding or type(given.position) is not tuple or len(given.position) != 3
                            or any(type(x) is not int for x in given.position)
                            or any(type(x) is not int for x in (given.source, given.lift, given.output))):
                        raise ValueError("Wrong terminal rounding grammar")
                    if given != cell:
                        raise ValueError("Wrong complete terminal rounding relation")
                assert lift % ctx.t == c % ctx.t and 2*abs(q*lift-ctx.p*c) < q*ctx.t
                rounding.append(cell)
                rounded.append(cell.output)
            pair.append(tuple(rounded))
        compact.append(tuple(pair))
    packet = serialize(ctx, tuple(compact))
    if supplied is not None:
        if len(cuts) != len(supplied.cuts) or len(rounding) != len(supplied.rounding):
            raise ValueError("Extra cut/terminal relation")
        if supplied.preterminal != tuple(responses) or supplied.packet != packet:
            raise ValueError("Wrong final full-coefficient/wire relation")
        parse_response(ctx, supplied.packet)
    return Transcript(statement, query, tuple(cuts), tuple(responses), tuple(rounding), packet)


def decrypt_and_rank(ctx, compact, secret):
    """Independent variable-time diagnostics, used only AFTER complete check."""
    polynomial(secret, ctx.n)
    if any(x not in (-1, 0, 1, ctx.q-1) for x in secret):
        raise ValueError("Expected matching signed/canonical ternary diagnostic secret")
    secret = tuple(-1 if x == ctx.q-1 else x for x in secret)
    if type(compact) is not tuple or len(compact) != (len(ctx.ids)+ctx.n-1)//ctx.n:
        raise ValueError("Wrong complete compact response shape")
    for pair in compact:
        if type(pair) is not tuple or len(pair) != 2:
            raise ValueError("Wrong compact response pair")
        for poly in pair:
            polynomial(poly, ctx.n, ctx.p)
    phases, scores = [], []
    for cipher in compact:
        phase = add(cipher[0], multiply(cipher[1], secret, ctx.p), ctx.p)
        centered = tuple(x if x <= ctx.p//2 else x-ctx.p for x in phase)
        phases.append(centered)
    capacity, inverse = ctx.n//ctx.padded, pow(ctx.padded, -1, ctx.t)
    for row in range(len(ctx.ids)):
        group, local = divmod(row, ctx.n)
        tile, lane = divmod(local, capacity)
        dot = phases[group][lane*ctx.padded+tile]*inverse % ctx.t
        dot = dot if dot <= ctx.t//2 else dot-ctx.t
        if not -ctx.dimension <= dot <= ctx.dimension or (ctx.dimension-dot) % 2:
            raise ValueError("Illegal decoded exact correlation")
        scores.append((ctx.dimension-dot)//2)
    top = tuple((i, scores[i]) for i in sorted(ctx.ids, key=lambda i: (scores[i], i))[:3])
    return tuple(phases), tuple(scores), top


def checked_release(ctx, original_query, supplied, decode):
    """Local complete public-replay control; no efficient remote proof implied."""
    verified = replay(ctx, original_query, supplied)
    # No callback/private work occurs on a rejected complete trace or packet.
    return decode(verified.packet)


def first_kernel(matrix, prime):
    """Exact field elimination for a false-witness regression, not hardness."""
    rows = [[x % prime for x in row] for row in matrix]
    columns, pivot_row, pivots = len(rows[0]), 0, []
    for column in range(columns):
        pivot = next((i for i in range(pivot_row, len(rows)) if rows[i][column]), None)
        if pivot is None:
            continue
        rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]
        inv = pow(rows[pivot_row][column], -1, prime)
        rows[pivot_row] = [x*inv % prime for x in rows[pivot_row]]
        for i in range(len(rows)):
            if i != pivot_row:
                factor = rows[i][column]
                rows[i] = [(a-factor*b) % prime for a, b in zip(rows[i], rows[pivot_row], strict=True)]
        pivots.append(column)
        pivot_row += 1
        if pivot_row == len(rows):
            break
    free = next((i for i in range(columns) if i not in pivots), None)
    if free is None:
        raise ValueError("No kernel in this registered matrix")
    vector = [0]*columns
    vector[free] = 1
    for i, pivot in enumerate(pivots):
        vector[pivot] = -rows[i][free] % prime
    assert all(sum(a*b for a, b in zip(row, vector, strict=True)) % prime == 0 for row in matrix)
    return tuple(vector), len(pivots)


def false_digit_cut(ctx, cut, key):
    """RNS-lifted affine kernel retains source AND both switch outputs."""
    columns = []
    for j in range(ctx.levels):
        for i in range(ctx.n):
            unit = tuple(int(k == i) for k in range(ctx.n))
            source = tuple((1 << (j*ctx.digit_bits))*x for x in unit)
            outputs = tuple(multiply(unit, poly, ctx.q) for poly in key[j])
            columns.append(source+outputs[0]+outputs[1])
    matrix = tuple(tuple(column[i] for column in columns) for i in range(3*ctx.n))
    vector, rank = first_kernel(matrix, ctx.primes[0])
    scale = ctx.primes[1]*pow(ctx.primes[1], -1, ctx.primes[0])
    changed = tuple(tuple((x+scale*vector[j*ctx.n+i]) % ctx.q for i, x in enumerate(row))
                    for j, row in enumerate(cut.digits))
    assert changed != cut.digits
    return Switch(cut.label, cut.source, changed, cut.output), rank
