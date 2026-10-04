"""Q74 packed-query expansion followed by feature-major exact BGV search.

These are homemade small-ring research references, built from known methods.
The public relation copies owner inputs and connects every source and complete
terminal frame to them. It has no HE secret, release authority or entropy API.
The producer and private diagnostics are variable time. This is neither an
attested service nor a security/parameter approval; enrollment is local only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import secrets

from gmpy2 import mpz
import msgpack

from cuhepy.bfv.scheme import _automorphism, _ring_product, _small_poly
from experiments.bfv_search_lab import compact_bgv as compact
from experiments.bfv_search_lab import native_boundary_oracle as oracle
from experiments.bfv_search_lab import noise_cut_relation as relation
from experiments.bfv_search_lab import propagated_gadget_bgv as gadget
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import trace_bgv as trace
from experiments.bfv_search_lab.shared_query_bounds import Profile


@dataclass(frozen=True)
class Keys:
    key_id: str
    padded: int
    relin: trace.SwitchKey
    rotations: tuple[tuple[int, trace.SwitchKey], ...]


def evaluation_keys(pk, sk, dimension):
    """Fresh owner-only expansion keys; gallery butterfly keys are different."""
    if type(dimension) is not int or not 3 <= dimension <= pk.n // 2:
        raise ValueError("Wrong expansion dimension")
    padded = 1 << (dimension - 1).bit_length()
    relin = trace.evaluation_keys(pk, sk, 1, 30).relin

    def make_key(target):
        result = []
        for j in range((pk.q.bit_length() + 29) // 30):
            a = tuple(mpz(secrets.randbelow(int(pk.q))) for _ in range(pk.n))
            e = _small_poly(pk.n, pk.eta, pk.q)
            product = _ring_product(a, sk.s, pk.q)
            b = tuple(
                ((1 << (30 * j)) * x + pk.t * y - z) % pk.q
                for x, y, z in zip(target, e, product, strict=True)
            )
            result.append((b, a))
        return tuple(result)

    rotations = tuple(
        (exponent, make_key(_automorphism(sk.s, exponent, pk.q)))
        for exponent in (1 + pk.n // (1 << level) for level in range(padded.bit_length() - 1))
    )
    return Keys(pk.key_id, padded, relin, rotations)


def encode_query(bits, n, t):
    if (
        type(bits) is not tuple
        or not 3 <= len(bits) <= n // 2
        or any(type(x) is not int or x not in (0, 1) for x in bits)
    ):
        raise ValueError("Immutable binary query required")
    inverse = pow(1 << (len(bits) - 1).bit_length(), -1, t)
    return [((1 - 2 * x) * inverse) % t for x in bits] + [0] * (n - len(bits))


def encode_index(rows, n, dimension):
    if (
        type(rows) is not tuple
        or not rows
        or any(
            type(row) is not tuple
            or len(row) != dimension
            or any(type(x) is not int or x not in (0, 1) for x in row)
            for row in rows
        )
    ):
        raise ValueError("Immutable binary index required")
    return tuple(
        [1 - 2 * row[j] for row in rows[start : start + n]]
        + [0] * (n - len(rows[start : start + n]))
        for start in range(0, len(rows), n)
        for j in range(dimension)
    )


@dataclass(frozen=True)
class Context:
    profile: Profile
    key_id: str
    query: tuple
    index: tuple
    ids: tuple[int, ...]
    relin: tuple
    rotations: tuple

    @property
    def groups(self):
        return (len(self.ids) + self.profile.n - 1) // self.profile.n

    @property
    def digest(self):
        return hashlib.sha256(
            json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


def enroll(profile, pk, query, index, ids, keys):
    """Copy a trusted synthetic enrollment, including origin bounds and IDs.

    Origin metadata must be authenticated in a service. It is never taken from
    a response here. This deliberately accepts no server-supplied graph/plan.
    """
    if type(profile) is not Profile:
        raise ValueError("Enrolled public profile required")
    profile.require_safe()  # Before polynomial copying or public arithmetic.
    if profile.n > 64 or (profile.n, profile.t, profile.q, profile.eta) != (
        pk.n,
        pk.t,
        int(pk.q),
        pk.eta,
    ):
        raise ValueError("Small exact reference/profile mismatch")
    if (
        type(ids) is not tuple
        or not 1 <= len(ids) <= 2 * pk.n
        or any(type(x) is not int or not 0 <= x < 1 << 64 for x in ids)
        or len(set(ids)) != len(ids)
    ):
        raise ValueError("Complete unique ordered IDs required")

    def copy_cipher(value, bound):
        if (
            type(value) is not bgv.Ciphertext
            or value.key_id != pk.key_id
            or value.phase_bound != bound
            or len(value.components) != 2
        ):
            raise ValueError("Wrong ciphertext or trusted origin envelope")
        return tuple(
            oracle.polynomial(tuple(map(int, row)), pk.n, int(pk.q)) for row in value.components
        )

    if (
        type(index) is not tuple
        or len(index) != ((len(ids) + pk.n - 1) // pk.n) * profile.dimension
    ):
        raise ValueError("Wrong complete feature-major index coverage")
    if (
        type(keys) is not Keys
        or keys.key_id != pk.key_id
        or keys.padded != profile.padded
        or tuple(g for g, _ in keys.rotations)
        != tuple(1 + pk.n // (1 << level) for level in range(profile.levels))
    ):
        raise ValueError("Wrong shared expansion key schedule")

    def copy_key(key):
        if (
            type(key) is not tuple
            or len(key) != profile.ell
            or any(type(column) is not tuple or len(column) != 2 for column in key)
        ):
            raise ValueError("Wrong complete gadget key")
        return tuple(
            tuple(oracle.polynomial(tuple(map(int, row)), pk.n, int(pk.q)) for row in column)
            for column in key
        )

    return Context(
        profile,
        pk.key_id,
        copy_cipher(query, profile.query_bound),
        tuple(copy_cipher(x, profile.index_bound) for x in index),
        ids,
        copy_key(keys.relin),
        tuple((g, copy_key(key)) for g, key in keys.rotations),
    )


def _program(graph, profile, groups, public, *, karatsuba=False, paired=False):
    """The identical graph program serves concrete and known symbolic controls."""
    n, q, d, ell = profile.n, profile.q, profile.dimension, profile.ell
    layouts, residuals, anchors, pairs = [], [], [], []

    def source(group, level, node, value):
        slot = len(layouts)
        layouts.append((group, level, node, 30))
        digits = tuple(graph.input(("source-digit", slot, j)) for j in range(ell))
        residuals.append(
            graph.sub(value, graph.sum(graph.scale(a, 1 << (30 * j)) for j, a in enumerate(digits)))
        )
        return digits

    def switch(digits, kind, level):
        return tuple(
            graph.sum(graph.multiply(a, public((kind, level, j, c))) for j, a in enumerate(digits))
            for c in range(2)
        )

    frontier = [((graph.input(("query", 0)), graph.input(("query", 1))), None)]
    for level in range(profile.levels):
        exponent, shift = 1 + n // (1 << level), -(1 << level)
        even, odd = [], []
        for node, (pair, state) in enumerate(frontier):
            rotated = tuple(graph.permute(a, exponent) for a in pair)
            derived = profile.policy == "derived_last30" and level == profile.levels - 1
            if derived:
                if state is None:
                    raise ValueError("Missing bound query-branch state")
                digits = tuple(graph.permute(a, exponent) for a in state)
            else:
                digits = source(-1, level, node, rotated[1])
            switched = switch(digits, "rotation", level)
            rotated = (graph.add(rotated[0], switched[0]), switched[1])
            plus = tuple(graph.add(a, b) for a, b in zip(pair, rotated, strict=True))
            minus = tuple(
                graph.permute(graph.sub(a, b), shift=shift)
                for a, b in zip(pair, rotated, strict=True)
            )
            states = (None, None)
            if profile.policy == "derived_last30" and level == profile.levels - 2:
                left = tuple(graph.permute(a, pow(exponent, -1, 2 * n)) for a in digits)
                correction = tuple(
                    graph.sum(
                        graph.multiply(a, public(("rotation-digit", level, k, j)))
                        for k, a in enumerate(digits)
                    )
                    for j in range(ell)
                )
                states = (
                    tuple(graph.add(a, b) for a, b in zip(left, correction, strict=True)),
                    tuple(
                        graph.permute(graph.sub(a, b), shift=shift)
                        for a, b in zip(left, correction, strict=True)
                    ),
                )
            even.append((plus, states[0]))
            odd.append((minus, states[1]))
            if paired:
                anchors.extend((*plus, *minus))
                pairs.extend((plus, minus))
        frontier = even + odd
    for group in range(groups):
        terms = [[], [], []]
        for j in range(d):
            c0, c1 = frontier[j][0]
            tile = group * d + j
            a = graph.multiply(c0, public(("index", tile, 0)))
            b = graph.multiply(c1, public(("index", tile, 1)))
            terms[0].append(a)
            terms[2].append(b)
            if karatsuba:
                query_sum = graph.add(c0, c1)
                cross = graph.sub(
                    graph.sub(graph.multiply(query_sum, public(("index-sum", tile))), a), b
                )
                terms[1].append(cross)
                if paired:
                    anchors.extend((query_sum, a, b))
                    pairs.append((a, b))
            else:
                terms[1].extend(
                    (
                        graph.multiply(c0, public(("index", tile, 1))),
                        graph.multiply(c1, public(("index", tile, 0))),
                    )
                )
        product = tuple(graph.sum(row) for row in terms)
        digits = source(group, -1, 0, product[2])
        switched = switch(digits, "relin", 0)
        for c in range(2):
            residuals.append(
                graph.sub(graph.add(product[c], switched[c]), graph.input(("output", group, c)))
            )
    return tuple(layouts), tuple(residuals), tuple(anchors), tuple(pairs)


def public_constants(ctx):
    constants = {}
    for tile, pair in enumerate(ctx.index):
        for c, row in enumerate(pair):
            constants["index", tile, c] = row
        constants["index-sum", tile] = tuple(
            (x + y) % ctx.profile.q for x, y in zip(*pair, strict=True)
        )
    for kind, schedule in (("rotation", ctx.rotations), ("relin", ((0, ctx.relin),))):
        for level, (_, key) in enumerate(schedule):
            for k, column in enumerate(key):
                for c, row in enumerate(column):
                    constants[kind, level, k, c] = row
                if (
                    kind == "rotation"
                    and ctx.profile.policy == "derived_last30"
                    and level == ctx.profile.levels - 2
                ):
                    for j, row in enumerate(gadget.canonical_digits(column[1], ctx.profile.q, 30)):
                        constants["rotation-digit", level, k, j] = row
    return constants


def compile_relation(ctx):
    if type(ctx) is not Context:
        raise ValueError("Trusted copied context required")
    ctx.profile.require_safe()
    graph = relation.Builder(ctx.profile.n, ctx.profile.q)
    constants = public_constants(ctx)
    layouts, residuals, _anchors, _pairs = _program(
        graph, ctx.profile, ctx.groups, constants.__getitem__
    )
    return relation.Relation(
        graph.n,
        graph.q,
        ctx.groups,
        layouts,
        tuple(graph.nodes),
        residuals,
        tuple((("query", c), row) for c, row in enumerate(ctx.query)),
        ctx.digest,
    )


def symbolic_graph(profile, groups, *, karatsuba=False, paired=False):
    """No coefficients/keys allocated; known affine control, not timing."""
    from experiments.bfv_search_lab import noise_cut_fusion as fusion

    profile.require_safe()
    if type(groups) is not int or not 1 <= groups <= 64:
        raise ValueError("Bounded complete source groups required")
    graph = fusion.Builder(profile.n, profile.q)
    layouts, residuals, anchors, pairs = _program(
        graph, profile, groups, fusion.Public, karatsuba=karatsuba, paired=paired
    )
    return fusion.Graph(graph.n, graph.q, tuple(graph.nodes), residuals, anchors, pairs), layouts


@dataclass(frozen=True)
class Transcript:
    statement_digest: str
    sources: tuple[relation.Source, ...]
    full_output: tuple
    response: bytes


def branch_states(digits, exponent, shift, a_digits):
    """Both signed integer siblings, including every radix convolution term."""
    plus = gadget.unary_state(digits, exponent, a_digits)
    left = tuple(gadget.permute(row, pow(exponent, -1, 2 * len(row))) for row in digits)
    minus = tuple(
        gadget.permute(tuple(2 * a - b for a, b in zip(x, y, strict=True)), shift=shift)
        for x, y in zip(left, plus, strict=True)
    )
    return plus, minus


def produce(ctx, pk):
    """Homemade public evaluator and canonical-source extractor (small rings)."""
    ctx.profile.require_safe()
    if ctx.profile.n > 64 or (pk.n, int(pk.q), pk.t, pk.key_id) != (
        ctx.profile.n,
        ctx.profile.q,
        ctx.profile.t,
        ctx.key_id,
    ):
        raise ValueError("Wrong small public producer context")
    p, sources, frontier = ctx.profile, [], [(ctx.query, None)]
    expanded = None
    for level, (exponent, key) in enumerate(ctx.rotations):
        even, odd = [], []
        for node, (pair, state) in enumerate(frontier):
            rotated = tuple(
                tuple(map(int, _automorphism(tuple(map(mpz, a)), exponent, pk.q))) for a in pair
            )
            if p.policy == "derived_last30" and level == p.levels - 1:
                digits = tuple(gadget.permute(row, exponent) for row in state)
                gadget.validate_digits(rotated[1], digits, 30, p.q, p.retained_state_bound)
            else:
                digits = gadget.canonical_digits(rotated[1], p.q, 30)
                sources.append(relation.Source(-1, level, node, rotated[1]))
            b, a = gadget.switched(digits, key, p.q)
            rotated = (oracle.add(rotated[0], b, p.q), a)
            plus = tuple(oracle.add(x, y, p.q) for x, y in zip(pair, rotated, strict=True))
            minus = tuple(
                oracle.monomial(oracle.add(x, y, p.q, -1), -(1 << level), p.q)
                for x, y in zip(pair, rotated, strict=True)
            )
            states = (None, None)
            if p.policy == "derived_last30" and level == p.levels - 2:
                states = branch_states(
                    digits, exponent, -(1 << level), gadget.public_a_digits(key, p.q, 30)
                )
                for child, rows in zip((plus, minus), states, strict=True):
                    gadget.validate_digits(child[1], rows, 30, p.q, p.retained_state_bound)
            even.append((plus, states[0]))
            odd.append((minus, states[1]))
        frontier = even + odd
    expanded = tuple(pair for pair, _ in frontier)
    outputs = []
    for group in range(ctx.groups):
        total = [(0,) * p.n for _ in range(3)]
        for j in range(p.dimension):
            left, right = expanded[j], ctx.index[group * p.dimension + j]

            def product(a, b):
                return tuple(map(int, _ring_product(tuple(map(mpz, a)), tuple(map(mpz, b)), pk.q)))

            pieces = (
                product(left[0], right[0]),
                oracle.add(product(left[0], right[1]), product(left[1], right[0]), p.q),
                product(left[1], right[1]),
            )
            total = [oracle.add(a, b, p.q) for a, b in zip(total, pieces, strict=True)]
        sources.append(relation.Source(group, -1, 0, total[2]))
        switched = gadget.switched(gadget.canonical_digits(total[2], p.q, 30), ctx.relin, p.q)
        outputs.append(
            tuple(oracle.add(a, b, p.q) for a, b in zip(total[:2], switched, strict=True))
        )
    outputs = tuple(outputs)
    bound = p.envelope()["output_phase_bound"]
    compact_ciphers = [
        compact.compact(
            bgv.Ciphertext(tuple(tuple(map(mpz, a)) for a in pair), ctx.key_id, bound),
            pk,
            p.p.bit_length(),
        )
        for pair in outputs
    ]
    if any(int(x.modulus) != p.p for x in compact_ciphers):
        raise ValueError("Non-enrolled terminal modulus")
    packet = compact.pack(compact_ciphers, len(ctx.ids), p.dimension, pk)
    return Transcript(ctx.digest, tuple(sources), outputs, packet), expanded


def expected_frame(ctx, outputs):
    """Independent whole terminal rounding and framing; no producer/private math."""
    p = ctx.profile
    header = [
        "cuhepy-lab-bgv-compact-v1",
        p.n,
        p.t,
        p.p.to_bytes((p.p.bit_length() + 7) // 8, "little"),
        bytes.fromhex(ctx.key_id),
        len(ctx.ids),
        p.dimension,
    ]
    body = [
        [
            oracle.pack_bits(
                tuple(oracle.round_lift(x, p.q, p.p, p.t) % p.p for x in row), p.p.bit_length()
            )
            for row in pair
        ]
        for pair in outputs
    ]
    return msgpack.packb([header, body], use_bin_type=True)


def accepts(ctx, rel, transcript):
    """Public whole-vector oracle only; not an authorization/decryption API."""
    try:
        ctx.profile.require_safe()
        return (
            type(transcript) is Transcript
            and type(transcript.statement_digest) is str
            and rel.statement_digest == ctx.digest == transcript.statement_digest
            # This small public oracle recompiles to reject a caller-supplied
            # weakened graph. A service must compile/cache inside enrollment.
            and rel == compile_relation(ctx)
            and type(transcript.response) is bytes
            and relation.holds(rel, transcript.sources, transcript.full_output)
            and transcript.response == expected_frame(ctx, transcript.full_output)
        )
    except (ValueError, TypeError, IndexError, KeyError, AttributeError, OverflowError):
        return False
