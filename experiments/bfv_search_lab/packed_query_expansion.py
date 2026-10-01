"""E73 partial SealPIR-style expansion of packed CRT subring queries.

Homemade known-control arithmetic; all secrets/ciphertexts have full degree N.
Expanded queries require key switching. Evaluation alone does NOT verify their
relation to the original packed query. A trusted client can expand locally and
pin that exact result in E72; its work is charged. No proof, parameter, KDM,
private-timing or production assurance is supplied by this bounded oracle.
"""

from __future__ import annotations

from dataclasses import dataclass
import secrets

from gmpy2 import mpz

from cuhepy.bfv.scheme import _automorphism, _ring_product, _small_poly
from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import encrypted_query_certificate as encrypted
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import trace_bgv as trace


@dataclass(frozen=True)
class Keys:
    key_id: str
    factor: int
    digit_bits: int
    switch_error_bound: int
    rotations: tuple[tuple[int, trace.SwitchKey], ...]


@dataclass(frozen=True)
class Query:
    space_binding: bytes
    epoch: bytes
    token_id: bytes
    ciphertext: bgv.Ciphertext


def factor(s):
    crt.validate(s)
    h = 1 << (s.columns-1).bit_length()
    if (not 8 <= s.layout.context.n <= 64 or s.columns > 32
            or any((s.layout.context.n//degree) % h for degree in s.column_degrees)):
        raise ValueError("Query columns do not fit disjoint expansion residues")
    return h


def _exponents(n, h):
    return tuple(1+n//(1 << j) for j in range(h.bit_length()-1))


def key_gen(s, pk, sk, *, digit_bits=4):
    """Owner-generated related-secret switch keys, only for requested levels."""
    h = factor(s)
    masked._context(s, pk)
    if (sk.key_id != pk.key_id or len(sk.s) != pk.n or type(digit_bits) is not int
            or not 4 <= digit_bits <= 30):
        raise ValueError("Wrong expansion secret/gadget context")
    digits = (int(pk.q).bit_length()+digit_bits-1)//digit_bits
    rotations = []
    for exponent in _exponents(pk.n, h):
        target, columns = _automorphism(sk.s, exponent, pk.q), []
        for j in range(digits):
            a = tuple(mpz(secrets.randbelow(int(pk.q))) for _ in range(pk.n))
            noise = _small_poly(pk.n, pk.eta, pk.q)
            product = _ring_product(a, sk.s, pk.q)
            power = mpz(1) << (j*digit_bits)
            b = tuple((power*v+pk.t*e-x) % pk.q for v, e, x in zip(target, noise, product, strict=True))
            columns.append((b, a))
        rotations.append((exponent, tuple(columns)))
    error = pk.t*pk.eta*pk.n*((1 << digit_bits)-1)*digits
    return Keys(pk.key_id, h, digit_bits, error, tuple(rotations))


def _keys(keys, s, pk):
    h = factor(s)
    if (type(keys) is not Keys or keys.key_id != pk.key_id or keys.factor != h
            or type(keys.digit_bits) is not int or not 4 <= keys.digit_bits <= 30):
        raise ValueError("Wrong owner-pinned expansion keys")
    digits = (int(pk.q).bit_length()+keys.digit_bits-1)//keys.digit_bits
    error = pk.t*pk.eta*pk.n*((1 << keys.digit_bits)-1)*digits
    if (keys.switch_error_bound != error or tuple(g for g, _ in keys.rotations) != _exponents(pk.n, h)
            or any(len(key) != digits or any(len(pair) != 2 or any(len(p) != pk.n or any(not 0 <= x < pk.q for x in p)
                                                                 for p in pair) for pair in key)
                   for _, key in keys.rotations)):
        raise ValueError("Wrong expansion gadget shape/error")


def expanded_bound(s, pk, keys):
    _keys(keys, s, pk)
    return keys.factor*(pk.t//2+pk.t*pk.eta)+(keys.factor-1)*keys.switch_error_bound


def output_bound(index, pk, keys):
    encrypted._context(index, pk)
    bound = pk.n*index.space.columns*(pk.t//2+pk.t*pk.eta)*expanded_bound(index.space, pk, keys)
    if 2*bound >= pk.q:
        raise ValueError("Packed query product correctness bound exceeds Q")
    return bound


def plaintext(s, values):
    """Independent declared-subring embedding, predivided by expansion factor."""
    h, t, n = factor(s), s.layout.context.prime, s.layout.context.n
    result, inverse = [0]*n, pow(h, -1, t)
    for column, short in enumerate(crt.corrections(s, values)):
        full = crt.expand(s, short)
        for at, value in enumerate(full):
            if value:
                # h divides this column's stride, so residues never overlap.
                result[at+column] = value*inverse % t
    return result


def plaintext_oracle(s, coefficients):
    """Coefficient selection oracle, without ciphertexts or automorphisms."""
    n, h = s.layout.context.n, factor(s)
    if len(coefficients) != n:
        raise ValueError("Expected full ring coefficients")
    return tuple(tuple(h*coefficients[at+j] % s.layout.context.prime if at % h == 0 else 0
                       for at in range(n)) for j in range(s.columns))


def make_query(s, epoch, token_id, values, client):
    masked.binding(epoch, token_id)
    packet = client.encrypt(plaintext(s, values))
    return Query(s.binding, epoch, token_id, owner.expand(packet, client.pk)), len(packet)


def expand(request, s, pk, keys):
    """Public deterministic expansion; no index or secret key is an input."""
    _keys(keys, s, pk)
    if type(request) is not Query or request.space_binding != s.binding:
        raise ValueError("Wrong packed original query binding")
    masked.binding(request.epoch, request.token_id)
    masked.validate_ciphertexts((request.ciphertext,), 1, pk)
    if request.ciphertext.phase_bound != pk.t//2+pk.t*pk.eta:
        raise ValueError("Expected fresh owner packed ciphertext")
    if 2*expanded_bound(s, pk, keys) >= pk.q:
        raise ValueError("Expanded query bound exceeds Q")
    work = (request.ciphertext,)
    for level, (exponent, switch_key) in enumerate(keys.rotations):
        half = 1 << level
        even, odd = [], []
        for cipher in work:
            a0, a1 = (_automorphism(p, exponent, pk.q) for p in cipher.components)
            b, a = trace._switch(a1, switch_key, pk, keys.digit_bits)
            rotated = (tuple((x+y) % pk.q for x, y in zip(a0, b, strict=True)), a)
            bound = 2*cipher.phase_bound+keys.switch_error_bound
            plus = tuple(tuple((x+y) % pk.q for x, y in zip(p, r, strict=True))
                         for p, r in zip(cipher.components, rotated, strict=True))
            minus = tuple(tuple((x-y) % pk.q for x, y in zip(p, r, strict=True))
                          for p, r in zip(cipher.components, rotated, strict=True))
            even.append(bgv.Ciphertext(plus, pk.key_id, bound))
            odd.append(trace._monomial(bgv.Ciphertext(minus, pk.key_id, bound), -half, pk))
        work = tuple(even+odd)
    return encrypted.Query(s.binding, request.epoch, request.token_id, work[:s.columns])


def evaluate(index, expanded, pk, keys):
    """Multiplication control. Caller must separately bind expansion to query."""
    bound = output_bound(index, pk, keys)
    if (type(expanded) is not encrypted.Query or expanded.space_binding != index.space.binding
            or expanded.epoch != index.epoch):
        raise ValueError("Wrong expanded query context")
    masked.validate_ciphertexts(expanded.ciphertexts, index.space.columns, pk)
    if any(c.phase_bound != expanded_bound(index.space, pk, keys) for c in expanded.ciphertexts):
        raise ValueError("Wrong pinned expansion bound")
    outputs = []
    for reply in range(index.space.layout.cost.response_ciphertexts):
        parts = [[mpz(0)]*pk.n for _ in range(3)]
        for column, query in zip(index.columns, expanded.ciphertexts, strict=True):
            product = bgv.multiply(column[reply], query, pk, karatsuba=True)
            parts = [[(x+y) % pk.q for x, y in zip(p, r, strict=True)]
                     for p, r in zip(parts, product.components, strict=True)]
        outputs.append(bgv.Ciphertext(tuple(tuple(p) for p in parts), pk.key_id, bound))
    return tuple(outputs)


def cost(s, pk, keys):
    _keys(keys, s, pk)
    digits = (int(pk.q).bit_length()+keys.digit_bits-1)//keys.digit_bits
    bit_width, levels = int(pk.q).bit_length(), len(keys.rotations)
    body = codec.pack(tuple(x for _, key in keys.rotations for pair in key for p in pair for x in p), int(pk.q))
    return {"expansion_factor": keys.factor, "expansion_levels": levels, "gadget_bits": keys.digit_bits,
            "gadget_digits": digits, "evaluation_key_full_coefficient_body_bytes": len(body),
            "packed_seeded_query_coefficient_and_seed_body_bytes": (pk.n*bit_width+7)//8+32,
            "unpacked_seeded_query_coefficient_and_seed_body_bytes": (s.columns*pk.n*bit_width+7)//8+32*s.columns,
            "key_switches_per_expansion": keys.factor-1,
            "ring_products_per_expansion": 2*digits*(keys.factor-1),
            "fresh_query_phase_bound": pk.t//2+pk.t*pk.eta,
            "expanded_query_phase_bound": expanded_bound(s, pk, keys),
            "trusted_client_expansion_required_for_E72_without_an_extra_proof": True,
            "scope": "Coefficient/seed bodies only. Full unseeded switch keys measured; metadata/transport, KDM/privacy/parameters and actual resident memory excluded."}
