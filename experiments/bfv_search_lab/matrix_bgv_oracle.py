"""E28/E17: tiny, homemade matrix-BGV algebra and gadget-query experiments.

This is a correctness oracle, not a deployable encryption scheme. Small rings,
explicit fixture RNGs, uniform bounded errors and variable-time Python integers
are intentional. No parameter assurance, authentication or security reduction
for the combined key material is provided. See matrix-arithmetic-results.md.

The public evaluator receives ciphertext coefficients and masked switching
material only. Owner-only helpers produce the source values and keys. Ring
arithmetic is schoolbook over Z_q[X]/(X^n+1); no external HE implementation is
imported. Source-polynomial expansion is entrywise, avoiding implicit matrix
commutation or ambiguous vectorization conventions.
"""

from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Literal

Poly = tuple[int, ...]
Matrix = tuple[tuple[Poly, ...], ...]
Source = tuple[str, int, int]
Mode = Literal["right", "right_symmetric", "left_independent", "left_transpose"]


@dataclass(frozen=True)
class Context:
    n: int = 4
    rank: int = 2
    q: int = (1 << 61) - 1
    t: int = 97
    digit_bits: int = 8
    eta: int = 1

    def __post_init__(self) -> None:
        if (type(self.n) is not int or not 1 <= self.n <= 16 or self.n & (self.n - 1)
                or type(self.rank) is not int or not 1 <= self.rank <= 4
                or type(self.t) is not int or not 3 <= self.t <= 65537 or not self.t & 1
                or type(self.q) is not int or not self.q & 1 or not 2 * self.t < self.q < (1 << 256)
                or type(self.digit_bits) is not int or not 1 <= self.digit_bits <= 16
                or type(self.eta) is not int or not 0 <= self.eta <= 4):
            raise ValueError("Expected bounded toy matrix/gadget parameters")

    @property
    def digits(self) -> int:
        return (self.q.bit_length() + self.digit_bits - 1) // self.digit_bits

    @property
    def zero(self) -> Poly:
        return (0,) * self.n

    def poly(self, coefficients: tuple[int, ...] | list[int]) -> Poly:
        if len(coefficients) != self.n or any(type(x) is not int for x in coefficients):
            raise ValueError("Expected n integer coefficients")
        return tuple(x % self.q for x in coefficients)

    def constant(self, value: int) -> Poly:
        return self.poly([value] + [0] * (self.n - 1))

    def add(self, a: Poly, b: Poly) -> Poly:
        return self.poly([x + y for x, y in zip(a, b, strict=True)])

    def scale(self, a: Poly, factor: int) -> Poly:
        return self.poly([factor * x for x in a])

    def mul(self, a: Poly, b: Poly) -> Poly:
        if len(a) != self.n or len(b) != self.n:
            raise ValueError("Incorrect ring operand length")
        out = [0] * self.n
        for i, x in enumerate(a):
            for j, y in enumerate(b):
                out[(i + j) % self.n] += x * y * (-1 if i + j >= self.n else 1)
        return self.poly(out)

    def centered(self, a: Poly) -> Poly:
        return tuple(x % self.q if x % self.q <= self.q // 2 else x % self.q - self.q for x in a)

    def norm(self, a: Poly) -> int:
        return max(map(abs, self.centered(a)))

    def sum(self, values: list[Poly] | tuple[Poly, ...]) -> Poly:
        out = self.zero
        for value in values:
            out = self.add(out, value)
        return out

    def decompose(self, a: Poly) -> tuple[Poly, ...]:
        a = self.poly(a)
        mask = (1 << self.digit_bits) - 1
        return tuple(tuple((x >> (j * self.digit_bits)) & mask for x in a) for j in range(self.digits))


def shape(matrix: Matrix) -> tuple[int, int]:
    if not matrix or not matrix[0] or any(len(row) != len(matrix[0]) for row in matrix):
        raise ValueError("Expected a nonempty rectangular matrix")
    return len(matrix), len(matrix[0])


def transpose(matrix: Matrix) -> Matrix:
    shape(matrix)
    return tuple(tuple(row) for row in zip(*matrix, strict=True))


def matmul(ctx: Context, a: Matrix, b: Matrix) -> Matrix:
    rows, inner = shape(a)
    other, columns = shape(b)
    if inner != other:
        raise ValueError("Incompatible matrix product")
    return tuple(tuple(ctx.sum([ctx.mul(a[i][k], b[k][j]) for k in range(inner)])
                       for j in range(columns)) for i in range(rows))


def matadd(ctx: Context, a: Matrix, b: Matrix) -> Matrix:
    if shape(a) != shape(b):
        raise ValueError("Incompatible matrix sum")
    return tuple(tuple(ctx.add(x, y) for x, y in zip(left, right, strict=True))
                 for left, right in zip(a, b, strict=True))


def sample_matrix(ctx: Context, rows: int, columns: int, rng: random.Random,
                  *, small: bool = False) -> Matrix:
    if rows < 1 or columns < 1:
        raise ValueError("Empty fixture matrix")
    return tuple(tuple(ctx.poly([rng.randint(-ctx.eta, ctx.eta) if small else rng.randrange(ctx.q)
                                 for _ in range(ctx.n)]) for _ in range(columns)) for _ in range(rows))


@dataclass(frozen=True)
class MatrixCipher:
    constant: Matrix
    mask: Matrix
    side: Literal["left", "right"]
    phase_bound: int


def encrypt(ctx: Context, secret: Matrix, message: Matrix, rng: random.Random,
            *, side: Literal["left", "right"] = "right") -> MatrixCipher:
    """Owner-only fresh toy encryption: C0+C1*S or C0+S*C1 = M+tE."""
    rows, columns = shape(message)
    if (shape(secret) != (ctx.rank, ctx.rank) or side not in ("left", "right")
            or (columns if side == "right" else rows) != ctx.rank):
        raise ValueError("Incompatible matrix encryption context")
    mask = sample_matrix(ctx, rows, columns, rng)
    hidden = matmul(ctx, mask, secret) if side == "right" else matmul(ctx, secret, mask)
    errors = sample_matrix(ctx, rows, columns, rng, small=True)
    constant = tuple(tuple(ctx.add(ctx.add(m, ctx.scale(e, ctx.t)), ctx.scale(h, -1))
                           for m, e, h in zip(mrow, erow, hrow, strict=True))
                     for mrow, erow, hrow in zip(message, errors, hidden, strict=True))
    bound = max(ctx.norm(p) for row in message for p in row) + ctx.t * ctx.eta
    if 2 * bound >= ctx.q:
        raise ValueError("Toy input phase bound exceeds modulus")
    return MatrixCipher(constant, mask, side, bound)


def phase(ctx: Context, cipher: MatrixCipher, secret: Matrix) -> Matrix:
    hidden = (matmul(ctx, cipher.mask, secret) if cipher.side == "right"
              else matmul(ctx, secret, cipher.mask))
    return matadd(ctx, cipher.constant, hidden)


@dataclass(frozen=True)
class Form:
    constant: Poly
    terms: tuple[tuple[Source, Poly], ...]
    phase_bound: int


def _term(ctx: Context, terms: dict[Source, Poly], source: Source, value: Poly) -> None:
    terms[source] = ctx.add(terms.get(source, ctx.zero), value)


def product_forms(ctx: Context, left: MatrixCipher, right: MatrixCipher, *,
                  mode: Mode = "right", columns: tuple[int, ...] | None = None) -> tuple[tuple[Form, ...], ...]:
    """Public expansion of the product; never accepts a decryption secret.

    right: S_ab*S_cj stays ordered. right_symmetric identifies commuting
    scalar-ring entries only; it never commutes entire matrices.
    left_independent: contract the adjacent independent secrets to U=S*T.
    left_transpose: T=S^T, so U=S*S^T is symmetric (extra key assumptions).
    """
    rows, k = shape(left.constant)
    other, width = shape(right.constant)
    if (k != ctx.rank or other != k or shape(left.mask) != (rows, k)
            or shape(right.mask) != (k, width) or left.side != "right"
            or mode not in ("right", "right_symmetric", "left_independent", "left_transpose")
            or right.side != ("right" if mode.startswith("right") else "left")
            or (mode.startswith("right") and width != k)):
        raise ValueError("Incompatible oriented ciphertext matrices")
    columns = tuple(range(width)) if columns is None else columns
    if (not columns or len(set(columns)) != len(columns)
            or any(type(j) is not int or not 0 <= j < width for j in columns)):
        raise ValueError("Invalid output projection")
    c, a, d, b = left.constant, left.mask, right.constant, right.mask
    constant = matmul(ctx, c, d)
    cd1 = matmul(ctx, c, b) if mode.startswith("right") else None
    bound = k * ctx.n * left.phase_bound * right.phase_bound
    output = []
    for i in range(rows):
        row = []
        for j in columns:
            terms: dict[Source, Poly] = {}
            for u in range(k):
                for v in range(k):
                    _term(ctx, terms, ("s", u, v), ctx.mul(a[i][u], d[v][j]))
                    if mode.startswith("right"):
                        assert cd1 is not None
                        if v == j:
                            _term(ctx, terms, ("s", u, v), cd1[i][u])
                        for w in range(k):
                            first, second = u * k + v, w * k + j
                            if mode == "right_symmetric":
                                first, second = sorted((first, second))
                            _term(ctx, terms, ("p", first, second), ctx.mul(a[i][u], b[v][w]))
                    elif mode == "left_independent":
                        _term(ctx, terms, ("t", u, v), ctx.mul(c[i][u], b[v][j]))
                        _term(ctx, terms, ("u", u, v), ctx.mul(a[i][u], b[v][j]))
                    else:
                        _term(ctx, terms, ("s", v, u), ctx.mul(c[i][u], b[v][j]))
                        _term(ctx, terms, ("g", min(u, v), max(u, v)), ctx.mul(a[i][u], b[v][j]))
            row.append(Form(constant[i][j], tuple(sorted(terms.items())), bound))
        output.append(tuple(row))
    return tuple(output)


def source_values(ctx: Context, secret: Matrix, sources: set[Source],
                  second_secret: Matrix | None = None) -> dict[Source, Poly]:
    """Owner-only values to mask; the evaluator must never receive this dict."""
    if shape(secret) != (ctx.rank, ctx.rank):
        raise ValueError("Incorrect source secret shape")
    gram = matmul(ctx, secret, transpose(secret))
    joint = matmul(ctx, secret, second_secret) if second_secret is not None else None
    flat = [p for row in secret for p in row]
    result = {}
    for source in sources:
        family, i, j = source
        if family == "s":
            value = secret[i][j]
        elif family == "p":
            value = ctx.mul(flat[i], flat[j])
        elif family == "g":
            value = gram[i][j]
        elif family == "t" and second_secret is not None:
            value = second_secret[i][j]
        elif family == "u" and joint is not None:
            value = joint[i][j]
        else:
            raise ValueError("Unknown source or missing independent secret")
        result[source] = value
    return result


def evaluate_form(ctx: Context, form: Form, values: dict[Source, Poly]) -> Poly:
    """Owner-only algebra check, independent of gadget evaluation."""
    return ctx.add(form.constant, ctx.sum([ctx.mul(coefficient, values[source])
                                          for source, coefficient in form.terms]))


@dataclass(frozen=True)
class VectorCipher:
    components: tuple[Poly, ...]  # phase = c0 + sum_{i=1..k} ci*u_{i-1}
    phase_bound: int


@dataclass(frozen=True)
class Gadget:
    context: Context
    rows: tuple[tuple[Source, tuple[tuple[Poly, ...], ...]], ...]

    @property
    def coefficient_bytes(self) -> int:
        ctx = self.context
        return len(self.rows) * ctx.digits * (ctx.rank + 1) * ctx.n * ((ctx.q.bit_length() + 7) // 8)


def mask_sources(ctx: Context, values: dict[Source, Poly], output_secret: tuple[Poly, ...],
                 rng: random.Random) -> Gadget:
    """Owner-only gadget rows, freshly masked under an independent output key."""
    if len(output_secret) != ctx.rank:
        raise ValueError("Incorrect output module rank")
    rows = []
    for source, value in sorted(values.items()):
        digits = []
        for j in range(ctx.digits):
            a = sample_matrix(ctx, 1, ctx.rank, rng)[0]
            e = sample_matrix(ctx, 1, 1, rng, small=True)[0][0]
            hidden = ctx.sum([ctx.mul(x, s) for x, s in zip(a, output_secret, strict=True)])
            b = ctx.add(ctx.scale(value, 1 << (j * ctx.digit_bits)), ctx.scale(e, ctx.t))
            digits.append((ctx.add(b, ctx.scale(hidden, -1)), *a))
        rows.append((source, tuple(digits)))
    return Gadget(ctx, tuple(rows))


def switch(ctx: Context, form: Form, gadget: Gadget) -> VectorCipher:
    """Public exact digit accumulation, with a conservative no-wrap bound."""
    if gadget.context != ctx:
        raise ValueError("Gadget context mismatch")
    key = dict(gadget.rows)
    if len(key) != len(gadget.rows) or any(source not in key for source, _ in form.terms):
        raise ValueError("Duplicate or missing gadget source")
    error = len(form.terms) * ctx.digits * ctx.n * ((1 << ctx.digit_bits) - 1) * ctx.t * ctx.eta
    bound = form.phase_bound + error
    if type(form.phase_bound) is not int or form.phase_bound < 0 or 2 * bound >= ctx.q:
        raise ValueError("Toy output phase bound exceeds modulus")
    result = [form.constant] + [ctx.zero] * ctx.rank
    for source, coefficient in form.terms:
        digits = ctx.decompose(coefficient)
        if len(key[source]) != ctx.digits:
            raise ValueError("Incorrect gadget digit count")
        for digit, components in zip(digits, key[source], strict=True):
            if len(components) != ctx.rank + 1:
                raise ValueError("Incorrect gadget output rank")
            result = [ctx.add(x, ctx.mul(digit, c)) for x, c in zip(result, components, strict=True)]
    return VectorCipher(tuple(result), bound)


def decrypt(ctx: Context, cipher: VectorCipher, output_secret: tuple[Poly, ...]) -> Poly:
    """Local trusted-fixture decoder; public bounds are not authentication."""
    if (len(cipher.components) != ctx.rank + 1 or len(output_secret) != ctx.rank
            or not 0 <= cipher.phase_bound < ctx.q // 2):
        raise ValueError("Invalid toy output context/bound")
    value = ctx.add(cipher.components[0], ctx.sum([ctx.mul(c, s) for c, s in
                     zip(cipher.components[1:], output_secret, strict=True)]))
    if ctx.norm(value) > cipher.phase_bound:
        raise ValueError("Measured phase exceeds conservative fixture bound")
    return tuple(x % ctx.t for x in ctx.centered(value))


def gadget_query(ctx: Context, secret: Matrix, weights: tuple[Poly, ...],
                 output_secret: tuple[Poly, ...], rng: random.Random) -> Gadget:
    """Owner-prepared query-dependent transfer: mask w and S*w in gadget form.

    This is an external-product/RGSW-style reference, not a novel primitive or
    a conversion of an arbitrary reader's existing short ciphertext. The owner
    knows the index secret and weights; packet size and owner work must be paid.
    """
    if len(weights) != ctx.rank:
        raise ValueError("Incorrect owner query rank")
    sw = matmul(ctx, secret, tuple((p,) for p in weights))
    values = {("v", j, 0): p for j, p in enumerate(weights)}
    values.update({("w", j, 0): row[0] for j, row in enumerate(sw)})
    return mask_sources(ctx, values, output_secret, rng)


def gadget_forms(ctx: Context, index: MatrixCipher, weight_bound: int) -> tuple[Form, ...]:
    """Public index-only forms for the owner-prepared gadget query."""
    if (index.side != "right" or shape(index.constant)[1] != ctx.rank
            or shape(index.mask) != shape(index.constant)
            or type(weight_bound) is not int or weight_bound < 0):
        raise ValueError("Invalid gadget-query index/bound")
    return tuple(Form(ctx.zero, tuple([(("v", j, 0), p) for j, p in enumerate(c)]
                                     + [(("w", j, 0), p) for j, p in enumerate(a)]),
                      ctx.rank * ctx.n * index.phase_bound * weight_bound)
                 for c, a in zip(index.constant, index.mask, strict=True))


def simd_encode(ctx: Context, values: tuple[int, ...]) -> Poly:
    """Tiny independent CRT interpolation over the plaintext field only."""
    if len(values) != ctx.n or (ctx.t - 1) % (2 * ctx.n):
        raise ValueError("Toy SIMD requires n values and t = 1 mod 2n")
    if any(ctx.t % d == 0 for d in range(2, int(ctx.t ** 0.5) + 1)):
        raise ValueError("Toy SIMD plaintext modulus must be prime")
    root = next(x for x in range(1, ctx.t) if pow(x, ctx.n, ctx.t) == ctx.t - 1)
    roots = [pow(root, 2 * i + 1, ctx.t) for i in range(ctx.n)]
    inverse_n = pow(ctx.n, -1, ctx.t)
    coefficients = [sum(v * pow(r, -j, ctx.t) for v, r in zip(values, roots, strict=True))
                    * inverse_n % ctx.t for j in range(ctx.n)]
    return ctx.poly([x if x <= ctx.t // 2 else x - ctx.t for x in coefficients])


def simd_decode(ctx: Context, coefficients: Poly) -> tuple[int, ...]:
    if len(coefficients) != ctx.n or (ctx.t - 1) % (2 * ctx.n):
        raise ValueError("Incompatible toy SIMD context")
    root = next(x for x in range(1, ctx.t) if pow(x, ctx.n, ctx.t) == ctx.t - 1)
    return tuple(sum(x * pow(root, (2 * i + 1) * j, ctx.t) for j, x in enumerate(coefficients)) % ctx.t
                 for i in range(ctx.n))
