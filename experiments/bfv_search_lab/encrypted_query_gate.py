"""E72 reusable dense full-Q checks of projected encrypted-query outputs.

Known fingerprint control, not a new/reviewed encryption or proof protocol.
One trusted registration replaces per-query owner answers/point hints with
large private state. Queries are the actual depth-one E71 ciphertexts. Only
supported C0 and full C1/C2 travel; every supplied coordinate is gated before
secret arithmetic. Private timing, parameters and durable state are open.
"""

from __future__ import annotations

from dataclasses import dataclass
import secrets
import threading

from gmpy2 import mpz

from cuhepy.bfv.scheme import _ring_product
from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import decryption_support as support
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import encrypted_query_certificate as encrypted
from experiments.bfv_search_lab import verification_lifetime as lifetime


@dataclass(frozen=True)
class Reply:
    c0_supported: tuple[tuple[int, ...], ...]
    c1: tuple[tuple[int, ...], ...]
    c2: tuple[tuple[int, ...], ...]


def adjoint(generator, weights, q):
    """Transpose negacyclic convolution using a(X^-1), independently tested."""
    inverse = (generator[0] % q, *(-x % q for x in reversed(generator[1:])))
    return _ring_product(tuple(map(mpz, inverse)), tuple(mpz(x) % q for x in weights), mpz(q))


def compile_row(index, challenge, pk):
    """Apply the projected ciphertext operator's transpose to one private row."""
    if len(challenge) != index.space.layout.cost.response_ciphertexts:
        raise ValueError("Wrong response fingerprint shape")
    result = []
    for column in index.columns:
        z0, z1 = [mpz(0)]*pk.n, [mpz(0)]*pk.n
        for cipher, (w0, w1, w2) in zip(column, challenge, strict=True):
            a0, a1 = cipher.components
            terms = (adjoint(a0, w0, pk.q), adjoint(a1, w1, pk.q),
                     adjoint(a0, w1, pk.q), adjoint(a1, w2, pk.q))
            z0 = [(x+a+b) % pk.q for x, a, b in zip(z0, *terms[:2], strict=True)]
            z1 = [(x+a+b) % pk.q for x, a, b in zip(z1, *terms[2:], strict=True)]
        result.append((tuple(z0), tuple(z1)))
    return tuple(result)


def _dot(a, b, q):
    return sum(x*y for x, y in zip(a, b, strict=True)) % q


def project(output, index, pk):
    """Public-only packaging, including all full-Q C1 and quadratic terms."""
    encrypted.pack_output(output, index, pk)  # Validate exact shape/context/bound.
    certificate = support.certify(index.space.layout)
    return Reply(tuple(tuple(int(c.components[0][i]) for i in kept)
                       for c, kept in zip(output, certificate.kept_c0, strict=True)),
                 tuple(tuple(map(int, c.components[1])) for c in output),
                 tuple(tuple(map(int, c.components[2])) for c in output))


def pack(reply, pk):
    return codec.pack(tuple(x for components in zip(reply.c0_supported, reply.c1, reply.c2, strict=True)
                            for row in components for x in row), int(pk.q))


def parse(body, certificate, pk):
    count = sum(map(len, certificate.kept_c0)) + 2*pk.n*len(certificate.kept_c0)
    values = codec.unpack(body, count, int(pk.q))
    c0, c1, c2, cursor = [], [], [], 0
    for kept in certificate.kept_c0:
        c0.append(values[cursor:cursor+len(kept)])
        cursor += len(kept)
        c1.append(values[cursor:cursor+pk.n])
        cursor += pk.n
        c2.append(values[cursor:cursor+pk.n])
        cursor += pk.n
    return Reply(tuple(c0), tuple(c1), tuple(c2))


def _decode(reply, pk, sk, certificate, layout, bound):
    """Only selected full-Q phases are centered before reducing to t."""
    if sk.key_id != pk.key_id or len(sk.s) != pk.n:
        raise ValueError("Wrong secret for owner-pinned encrypted-query decoder")
    squared = _ring_product(sk.s, sk.s, pk.q)
    carriers = []
    for c0, c1, c2, kept in zip(reply.c0_supported, reply.c1, reply.c2, certificate.kept_c0, strict=True):
        linear = _ring_product(tuple(map(mpz, c1)), sk.s, pk.q)
        quadratic = _ring_product(tuple(map(mpz, c2)), squared, pk.q)
        phase = [0]*pk.n
        for at, value in zip(kept, c0, strict=True):
            residue = (value+linear[at]+quadratic[at]) % pk.q
            centered = residue if residue <= pk.q//2 else residue-pk.q
            if abs(centered) > bound:
                raise AssertionError("Approved selected phase exceeded its honest bound")
            phase[at] = int(centered % pk.t)
        carriers.append(phase)
    return tuple(tuple(row) for row in tree.unpack(layout, carriers))


class Gate:
    """Owner-local registration and pinned queries; no per-query index hint.

    Challenges are independent uniform FIELD vectors, not ring-root samples.
    The remote input is a coefficient body for an already pinned request ID.
    There is no extra quotient or independently probeable proof-round input.
    Reuse the same AttemptBudget across trusted epochs. Volatile variable-time
    Python code is not a production receiver or a private-timing assurance.
    """

    def __init__(self, index, pk, ids, binding, attempts, *, rounds=4):
        self.bound = encrypted._context(index, pk)
        flat = tuple(i for group in ids for i in group) if type(ids) is tuple else ()
        if (type(ids) is not tuple or len(ids) != len(index.space.layout.counts)
                or any(type(g) is not tuple or len(g) != count for g, count in
                       zip(ids, index.space.layout.counts, strict=True))
                or not flat or any(type(i) is not int or not 0 <= i < 1 << 64 for i in flat)
                or len(flat) != len(set(flat)) or type(binding) is not str or len(binding) != 64
                or set(binding)-set("0123456789abcdef")
                or type(attempts) is not lifetime.AttemptBudget or type(rounds) is not int
                or not 1 <= rounds <= 32):
            raise ValueError("Expected bounded owner-approved IDs, identity and lifetime")
        self.pk, self.space, self.epoch = pk, index.space, index.epoch
        self.output_ids, self.owner_plan_binding = ids, binding
        self.certificate = support.certify(self.space.layout)
        self._attempts, self.rounds = attempts, rounds
        kept_sets = tuple(frozenset(p) for p in self.certificate.kept_c0)
        self._rows = tuple(tuple((tuple(mpz(secrets.randbelow(int(pk.q))) if i in kept else mpz(0)
                                        for i in range(pk.n)),
                                  tuple(mpz(secrets.randbelow(int(pk.q))) for _ in range(pk.n)),
                                  tuple(mpz(secrets.randbelow(int(pk.q))) for _ in range(pk.n)))
                                 for kept in kept_sets) for _ in range(rounds))
        self._hints = tuple(compile_row(index, row, pk) for row in self._rows)
        self._issued, self._pending, self._lock = set(), {}, threading.Lock()
        # No index, plaintext rows or HE secret retained by this object.

    def pin_query(self, request):
        """Trusted client enrollment of its ORIGINAL immutable ciphertexts."""
        encrypted._query(request, self.space.binding, self.epoch, self.space.columns, self.pk)
        with self._lock:
            if request.token_id in self._issued or len(self._issued) >= self._attempts.limit:
                raise RuntimeError("Original query ID/lifetime already consumed")
            self._issued.add(request.token_id)
            self._pending[request.token_id] = request

    def open_body_once(self, token_id, body, sk):
        self._attempts._burn()  # Malformed, replayed and rejected calls count.
        with self._lock:
            request = self._pending.pop(token_id, None) if type(token_id) is bytes else None
            if request is None:
                raise RuntimeError("Original query not pinned or already consumed")
        try:
            reply = parse(body, self.certificate, self.pk)
        except (ValueError, TypeError):
            return None
        decisions = []
        for challenge, hints in zip(self._rows, self._hints, strict=True):
            expected = sum(_dot(z, b, self.pk.q) for hint, cipher in
                           zip(hints, request.ciphertexts, strict=True)
                           for z, b in zip(hint, cipher.components, strict=True)) % self.pk.q
            supplied = sum(_dot(w0, c0, self.pk.q)+_dot(w1, c1, self.pk.q)+_dot(w2, c2, self.pk.q)
                           for (w0_full, w1, w2), c0, c1, c2, kept in
                           zip(challenge, reply.c0_supported, reply.c1, reply.c2,
                               self.certificate.kept_c0, strict=True)
                           for w0 in (tuple(w0_full[i] for i in kept),)) % self.pk.q
            decisions.append(expected == supplied)
        if not all(decisions):
            return None
        return _decode(reply, self.pk, sk, self.certificate, self.space.layout, self.bound)


def rounds_for(q, budget, target_bits):
    if type(q) is not int or q <= 2 or type(budget) is not int or budget < 1 or type(target_bits) is not int or target_bits < 1:
        raise ValueError("Invalid algebraic soundness count")
    count = 1
    while q**count < budget*(1 << target_bits):
        count += 1
    return count


def body_cost(index, pk, rounds):
    encrypted._context(index, pk)
    if type(rounds) is not int or not 1 <= rounds <= 32:
        raise ValueError("Invalid bounded repetition")
    n, h, r, bits = pk.n, index.space.columns, index.space.layout.cost.response_ciphertexts, int(pk.q).bit_length()
    kept = sum(map(len, support.certify(index.space.layout).kept_c0))
    return {"seeded_query_coefficient_and_seed_body_bytes": (h*n*bits+7)//8+32*h,
            "projected_three_component_response_body_bytes": ((kept+2*r*n)*bits+7)//8,
            "full_three_component_response_body_bytes": (3*r*n*bits+7)//8,
            "private_compiled_fingerprint_body_bytes": (rounds*2*h*n*bits+7)//8,
            "private_challenge_body_bytes": (rounds*(kept+2*r*n)*bits+7)//8,
            "registration_negacyclic_products": rounds*4*h*r,
            "client_check_field_products_per_query": rounds*(2*h*n+kept+2*r*n),
            "server_GMP_Karatsuba_products_per_query": 3*h*r,
            "per_query_owner_answer_or_point_hint_preparation_required": False,
            "extra_challenge_round_trips": 0,
            "scope": "Canonical coefficient/seed bodies; actual packets separately measured. Python object overhead, timing assurance, durable enrollment and transport excluded."}
