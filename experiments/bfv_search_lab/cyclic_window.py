"""E121 exact tiny cyclic-window assurance, not encryption or a tail claim.

The full codec/CBD law retains its E-dependent translated image. Only a
surjective coordinate window permits scalar factoring. The regular-cover
inequality is ordinary Holder; its mechanism is a known generic control.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from fractions import Fraction
from itertools import product
from math import prod

from experiments.bfv_search_lab.nonunit_projection import (
    apply_matrix, multiplication_matrix, rank_mod,
)
from experiments.bfv_search_lab.one_prime_bounds import prime64
from experiments.bfv_search_lab.query_quantizer_law import QuantizerLaw, cbd_mgf


def _integers(*values):
    if any(type(value) is not int for value in values):
        raise ValueError("Expected exact integers")


def cyclic_windows(n, length):
    _integers(n, length)
    if n not in (2, 4, 8) or not 1 <= length <= n:
        raise ValueError("Expected a tiny nonempty cyclic window")
    return tuple(tuple((start + i) % n for i in range(length)) for start in range(n))


def regular_cover(n, windows):
    """Check a regular coordinate cover; no inter-window independence claim."""
    _integers(n)
    if n not in (2, 4, 8) or type(windows) is not tuple or not 1 <= len(windows) <= 8:
        raise ValueError("Invalid tiny cover")
    counts = [0] * n
    for window in windows:
        if (type(window) is not tuple or not window
                or any(type(i) is not int or not 0 <= i < n for i in window)
                or len(set(window)) != len(window)):
            raise ValueError("Expected distinct literal coefficient positions")
        for i in window:
            counts[i] += 1
    if not counts[0] or len(set(counts)) != 1:
        raise ValueError("Cover must have positive equal coordinate multiplicities")
    return counts[0]


@dataclass(frozen=True)
class Context:
    n: int
    q: int
    root: int
    secret: tuple[int, ...]
    window_length: int

    def validate(self):
        _integers(self.n, self.q, self.root, self.window_length)
        if (self.n not in (2, 4, 8) or not 3 <= self.q <= 257 or not prime64(self.q)
                or self.q % (2 * self.n) != 1 or not 0 < self.root < self.q
                or pow(self.root, self.n, self.q) != self.q - 1
                or type(self.secret) is not tuple or len(self.secret) != self.n
                or any(type(x) is not int or abs(x) > 32 for x in self.secret)
                or not any(self.secret) or not 1 <= self.window_length <= self.n):
            raise ValueError("Invalid public tiny split-ring context")
        return self

    @property
    def windows(self):
        self.validate()
        return cyclic_windows(self.n, self.window_length)

    @property
    def matrix(self):
        self.validate()
        return multiplication_matrix(self.secret)


def window_ranks(ctx):
    if type(ctx) is not Context:
        raise ValueError("Expected a public context")
    matrix = ctx.matrix
    return tuple(rank_mod(tuple(matrix[i] for i in window), ctx.q) for window in ctx.windows)


def column_basis(ctx):
    """Greedy public column basis; a separate schoolbook control checks it."""
    matrix = ctx.matrix
    columns = []
    indices = []
    for j in range(ctx.n):
        candidate = columns + [tuple(row[j] for row in matrix)]
        candidate_rows = tuple(tuple(column[i] for column in candidate) for i in range(ctx.n))
        if rank_mod(candidate_rows, ctx.q) > len(columns):
            columns = candidate
            indices.append(j)
    return tuple(indices), tuple(columns)


@dataclass(frozen=True)
class Image:
    context: Context
    basis_indices: tuple[int, ...]
    points: tuple[tuple[int, ...], ...]

    def validate(self):
        if type(self.context) is not Context:
            raise ValueError("Expected a public context")
        ctx = self.context.validate()
        if ctx.n > 4 or ctx.q > 17:
            raise ValueError("Image oracle is restricted to tiny disclosed work")
        matrix = ctx.matrix
        if (type(self.basis_indices) is not tuple or not self.basis_indices
                or any(type(j) is not int or not 0 <= j < ctx.n for j in self.basis_indices)
                or len(set(self.basis_indices)) != len(self.basis_indices)):
            raise ValueError("Invalid image basis indices")
        basis = tuple(tuple(row[j] for j in self.basis_indices) for row in matrix)
        rank = len(self.basis_indices)
        if rank_mod(basis, ctx.q) != rank or rank_mod(matrix, ctx.q) != rank:
            raise ValueError("Basis does not span the actual multiplication image")
        if (type(self.points) is not tuple or len(self.points) != ctx.q ** rank
                or any(type(point) is not tuple or len(point) != ctx.n
                       or any(type(x) is not int or not 0 <= x < ctx.q for x in point)
                       for point in self.points)
                or len(set(self.points)) != len(self.points)):
            raise ValueError("Incomplete, repeated or noncanonical image")
        # No second image enumeration: membership + exact cardinality proves
        # this unique point cache is the entire rank-dimensional image.
        for point in self.points:
            augmented = tuple(row + (point[i],) for i, row in enumerate(basis))
            if rank_mod(augmented, ctx.q) != rank:
                raise ValueError("Point outside the actual multiplication image")
        return self

    @property
    def rank(self):
        return len(self.basis_indices)


def enumerate_image(ctx):
    if type(ctx) is not Context:
        raise ValueError("Expected a public context")
    ctx.validate()
    if ctx.n > 4 or ctx.q > 17:
        raise ValueError("No high-dimensional image enumeration")
    indices, columns = column_basis(ctx)
    basis = tuple(tuple(column[i] for column in columns) for i in range(ctx.n))
    points = tuple(apply_matrix(basis, coefficients, ctx.q)
                   for coefficients in product(range(ctx.q), repeat=len(indices)))
    return Image(ctx, indices, points).validate()


def _vector(vector, n, cap):
    if (type(vector) is not tuple or len(vector) != n
            or any(type(x) is not int or abs(x) > cap for x in vector)):
        raise ValueError("Expected a bounded exact integer vector")


def translated_histograms(image, message, error, t):
    if type(image) is not Image:
        raise ValueError("Expected an exact public image cache")
    image.validate()
    ctx = image.context
    _vector(message, ctx.n, ctx.q)
    _vector(error, ctx.n, 1)
    _integers(t)
    if not 3 <= t < ctx.q or not t & 1:
        raise ValueError("Invalid scalar plaintext modulus")
    counters = [Counter() for _ in ctx.windows]
    for point in image.points:
        coefficient = tuple((a + t * e - v) % ctx.q
                            for a, e, v in zip(message, error, point, strict=True))
        for histogram, window in zip(counters, ctx.windows, strict=True):
            histogram[tuple(coefficient[i] for i in window)] += 1
    return tuple(tuple(sorted(histogram.items())) for histogram in counters)


def cbd_one_states(n):
    _integers(n)
    if n not in (2, 4):
        raise ValueError("CBD law oracle restricted to dimensions two/four")
    return tuple((error, prod(2 if x == 0 else 1 for x in error))
                 for error in product((-1, 0, 1), repeat=n))


def _counts(counts, denominator):
    _integers(denominator)
    if (denominator < 1 or type(counts) is not tuple or not counts
            or any(type(item) is not tuple or len(item) != 2
                   or type(item[0]) is not int or abs(item[0]) > 4096 or type(item[1]) is not int
                   or item[1] <= 0 for item in counts)
            or len({item[0] for item in counts}) != len(counts)
            or sum(mass for _, mass in counts) != denominator):
        raise ValueError("Malformed exact exponent law")


def moment(counts, denominator, base=Fraction(2)):
    _counts(counts, denominator)
    if type(base) is not Fraction or not 1 < base <= 16:
        raise ValueError("Expected bounded exact exponential base above one")
    return sum((mass * base ** exponent for exponent, mass in counts), Fraction()) / denominator


@dataclass(frozen=True)
class JointLaw:
    n: int
    windows: tuple[tuple[int, ...], ...]
    denominator: int
    full_exponents: tuple[tuple[int, int], ...]
    window_exponents: tuple[tuple[tuple[int, int], ...], ...]
    error_vectors: int
    image_points: int
    tuple_visits: int
    scalar_lookups: int
    window_sums: int
    scalar_cache_entries: int

    def compare(self, base=Fraction(2)):
        _integers(self.n, self.denominator, self.error_vectors, self.image_points,
                  self.tuple_visits, self.scalar_lookups, self.window_sums,
                  self.scalar_cache_entries)
        q = self.scalar_cache_entries
        if (self.n not in (2, 4) or not 3 <= q <= 17 or not prime64(q)
                or q % (2 * self.n) != 1
                or self.image_points not in tuple(q ** rank for rank in range(1, self.n + 1))
                or type(self.window_exponents) is not tuple):
            raise ValueError("Malformed bounded joint-law grammar")
        multiplicity = regular_cover(self.n, self.windows)
        if (len(self.window_exponents) != len(self.windows)
                or self.error_vectors != 3 ** self.n
                or self.denominator != 4 ** self.n * self.image_points
                or self.tuple_visits != self.error_vectors * self.image_points
                or self.scalar_lookups != self.n * self.tuple_visits
                or self.window_sums != len(self.windows) * self.tuple_visits):
            raise ValueError("Malformed joint-law counter certificate")
        lhs_moment = moment(self.full_exponents, self.denominator, base)
        window_moments = tuple(moment(counts, self.denominator, base)
                               for counts in self.window_exponents)
        # full_exponents already multiply T by the cover multiplicity;
        # each window exponent multiplies its sum by the number of windows.
        lhs = lhs_moment ** len(self.windows)
        rhs = prod(window_moments)
        return {"cover_multiplicity": multiplicity, "full_moment": lhs_moment,
                "window_moments": window_moments, "lhs": lhs, "rhs": rhs,
                "holder_holds": lhs <= rhs, "ordinary_control_rhs": rhs,
                "ordinary_control_ratio": Fraction(1)}


def joint_law(image, message, weights, law):
    """One exact traversal of the same-E translated-image Cartesian law."""
    if type(image) is not Image:
        raise ValueError("Expected an exact public image cache")
    image.validate()
    ctx = image.context
    if type(law) is not QuantizerLaw or law.q != ctx.q:
        raise ValueError("Expected the same formal whole-Q scalar codec law")
    _vector(message, ctx.n, ctx.q)
    _vector(weights, ctx.n, 8)
    windows = ctx.windows
    multiplicity = regular_cover(ctx.n, windows)
    if any(rank != len(window) for rank, window in zip(window_ranks(ctx), windows, strict=True)):
        raise ValueError("Window scalar factoring requires surjective projections")
    errors = cbd_one_states(ctx.n)
    delta = tuple(law.added_error(coefficient) // law.t for coefficient in range(ctx.q))
    full = Counter()
    window_counts = [Counter() for _ in windows]
    visits = 0
    for error, mass in errors:
        shift = tuple((a + law.t * e) % ctx.q for a, e in zip(message, error, strict=True))
        for point in image.points:
            y = tuple(w * (e + delta[(a - v) % ctx.q])
                      for w, e, a, v in zip(weights, error, shift, point, strict=True))
            full[multiplicity * sum(y)] += mass
            for counts, window in zip(window_counts, windows, strict=True):
                counts[len(windows) * sum(y[i] for i in window)] += mass
            visits += 1
    return JointLaw(ctx.n, windows, 4 ** ctx.n * len(image.points),
                    tuple(sorted(full.items())),
                    tuple(tuple(sorted(counts.items())) for counts in window_counts),
                    len(errors), len(image.points), visits, ctx.n * visits,
                    len(windows) * visits, len(delta))


def factored_window_moments(ctx, weights, law, base=Fraction(2)):
    """Known scalar control; ONLY windows get codec/CBD independence."""
    if type(ctx) is not Context or type(law) is not QuantizerLaw or law.q != ctx.q:
        raise ValueError("Expected matching public context and whole-Q law")
    ctx.validate()
    _vector(weights, ctx.n, 8)
    if type(base) is not Fraction or not 1 < base <= 16:
        raise ValueError("Expected bounded exact exponential base")
    if any(rank != len(window) for rank, window in zip(window_ranks(ctx), ctx.windows, strict=True)):
        raise ValueError("Non-surjective windows cannot be factored")
    # Cache each signed coefficient weight equally for the generic adapter.
    scalars = {w: law.mgf(base ** (len(ctx.windows) * w))
               * cbd_mgf(1, base ** (len(ctx.windows) * w)) for w in set(weights)}
    return tuple(prod(scalars[weights[i]] for i in window) for window in ctx.windows)


def indicator_control(image, positions, base=Fraction(2)):
    """Untranslated-image diagnostic: arbitrary subsets need not be IID."""
    if type(image) is not Image:
        raise ValueError("Expected an exact public image cache")
    image.validate()
    ctx = image.context
    if (type(positions) is not tuple or not positions
            or any(type(i) is not int or not 0 <= i < ctx.n for i in positions)
            or len(set(positions)) != len(positions)
            or type(base) is not Fraction or not 1 < base <= 16):
        raise ValueError("Malformed indicator diagnostic")
    if ctx.n % ctx.window_length:
        raise ValueError("Unscaled diagnostic requires integral Holder exponent")
    direct = Fraction()
    marginals = [Fraction() for _ in positions]
    windows = [Fraction() for _ in ctx.windows]
    for point in image.points:
        indicators = tuple(int(point[i] == 0 and i in positions) for i in range(ctx.n))
        direct += base ** sum(indicators)
        for j, i in enumerate(positions):
            marginals[j] += base ** indicators[i]
        for j, window in enumerate(ctx.windows):
            windows[j] += base ** ((ctx.n // ctx.window_length)
                                  * sum(indicators[i] for i in window))
    count = len(image.points)
    direct /= count
    marginal_moments = tuple(x / count for x in marginals)
    window_moments = tuple(x / count for x in windows)
    return {"direct_moment": direct, "fake_iid_moment": prod(marginal_moments),
            "marginal_moments": marginal_moments, "window_moments": window_moments,
            "direct_power": direct ** ctx.n, "holder_power": prod(window_moments),
            "ordinary_holder_equality": direct ** ctx.n == prod(window_moments)}
