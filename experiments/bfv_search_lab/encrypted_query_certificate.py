"""E71 depth-one encrypted CRT query with one-use quotient verification.

Homemade known-control composition, not a reviewed/new crypto protocol. The
owner need not encrypt a mask answer, but prepares fresh private index-point
hints for EVERY receiver. Three-component responses and quotient bodies are
full-Q. No rescaling, relinearization, durable delivery or constant time claim.
The two-stage local object fixes output bytes before public batching weights.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets
import threading

from gmpy2 import mpz

from experiments.bfv_search_lab import coefficient_body as codec
from experiments.bfv_search_lab import convolution_batch_certificate as batch
from experiments.bfv_search_lab import convolution_certificate_oracle as polynomial
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import crt_query_space as crt
from experiments.bfv_search_lab import dyadic_crt as tree
from experiments.bfv_search_lab import owner_bgv as owner
from experiments.bfv_search_lab import shallow_bgv as bgv
from experiments.bfv_search_lab import verification_lifetime as lifetime


@dataclass(frozen=True)
class Query:
    space_binding: bytes
    epoch: bytes
    token_id: bytes
    ciphertexts: tuple[bgv.Ciphertext, ...]


@dataclass(frozen=True)
class Challenge:
    statement_digest: str
    weights: tuple[tuple[int, ...], ...]


def _context(index, pk):
    masked._context(index.space, pk)
    masked.binding(index.epoch, bytes(16))
    replies = index.space.layout.cost.response_ciphertexts
    if (not 8 <= pk.n <= 64 or index.space.columns > 32 or 3*replies > 64
            or len(index.columns) != index.space.columns):
        raise ValueError("Outside bounded encrypted-query oracle")
    fresh = pk.t//2 + pk.t*pk.eta
    for column in index.columns:
        masked.validate_ciphertexts(column, replies, pk)
        if any(c.phase_bound != fresh for c in column):
            raise ValueError("Expected owner-pinned fresh index ciphertexts")
    bound = pk.n*index.space.columns*fresh**2
    if 2*bound >= pk.q:
        raise ValueError("Depth-one query correctness bound exceeds Q")
    return bound


def _query(request, space_binding, epoch, columns, pk):
    if type(request) is not Query:
        raise ValueError("Expected pinned original encrypted query")
    masked.binding(request.epoch, request.token_id)
    masked.validate_ciphertexts(request.ciphertexts, columns, pk)
    if (request.space_binding != space_binding or request.epoch != epoch
            or any(c.phase_bound != pk.t//2+pk.t*pk.eta for c in request.ciphertexts)):
        raise ValueError("Wrong encrypted query context or fresh phase bound")


def make_query(s, epoch, token_id, values, client):
    """The owner encrypts only query polynomials with independent OS errors."""
    masked._context(s, client.pk)
    masked.binding(epoch, token_id)
    packets = tuple(client.encrypt(crt.expand(s, short)) for short in crt.corrections(s, values))
    return (Query(s.binding, epoch, token_id, tuple(owner.expand(p, client.pk) for p in packets)),
            sum(map(len, packets)))


def evaluate(index, request, pk):
    """Public GMP multiplication; products retain the s^2 component."""
    bound = _context(index, pk)
    _query(request, index.space.binding, index.epoch, len(index.columns), pk)
    outputs = []
    for reply in range(index.space.layout.cost.response_ciphertexts):
        parts = [[mpz(0)]*pk.n for _ in range(3)]
        for column, query in zip(index.columns, request.ciphertexts, strict=True):
            product = bgv.multiply(column[reply], query, pk, karatsuba=True)
            parts = [[(a+b) % pk.q for a, b in zip(row, p, strict=True)]
                     for row, p in zip(parts, product.components, strict=True)]
        outputs.append(bgv.Ciphertext(tuple(tuple(row) for row in parts), pk.key_id, bound))
    return tuple(outputs)


def factor_groups(index, request, pk):
    """Independently expose ordinary polynomial products, including cross terms."""
    _context(index, pk)
    _query(request, index.space.binding, index.epoch, len(index.columns), pk)
    groups = []
    for reply in range(index.space.layout.cost.response_ciphertexts):
        c0, c1, c2 = [], [], []
        for column, query in zip(index.columns, request.ciphertexts, strict=True):
            a0, a1 = (tuple(int(x) for x in p) for p in column[reply].components)
            b0, b1 = (tuple(int(x) for x in p) for p in query.components)
            c0.append((a0, b0))
            c1.extend(((a0, b1), (a1, b0)))
            c2.append((a1, b1))
        groups.extend((tuple(c0), tuple(c1), tuple(c2)))
    return tuple(groups)


def pack_output(output, index, pk):
    bound = _context(index, pk)
    if (type(output) is not tuple or len(output) != index.space.layout.cost.response_ciphertexts
            or any(type(c) is not bgv.Ciphertext or len(c.components) != 3
                   or c.phase_bound != bound for c in output)):
        raise ValueError("Wrong depth-one response shape/bounds")
    for c in output:
        bgv._validate(c, pk)
    return codec.pack(tuple(x for c in output for p in c.components for x in p), int(pk.q))


def prove(index, request, pk, challenge):
    if type(challenge) is not Challenge:
        raise ValueError("Expected post-output public challenge")
    h = batch.quotients(factor_groups(index, request, pk), challenge.weights, int(pk.q))
    return codec.pack(tuple(x for row in h for x in row), int(pk.q))


class Receiver:
    """Owner-prepared one-use private hints; no plaintext index retained online.

    Index enrollment, points, original query and metadata are trusted inputs.
    Server-controlled stages supply only bounded coefficient bodies. Every
    receiver has independent OS-random points; none are publicly sent or reused.
    State is volatile, variable time, and not serializable provisioning.
    """

    def __init__(self, index, pk, token_id, attempts, *, rounds=4):
        self.bound = _context(index, pk)
        masked.binding(index.epoch, token_id)
        if (type(attempts) is not lifetime.AttemptBudget or type(rounds) is not int
                or not 1 <= rounds <= 32):
            raise ValueError("Invalid receiver repetition/budget")
        self.pk, self.space, self.epoch = pk, index.space, index.epoch
        self.token_id, self.rounds, self._attempts = token_id, rounds, attempts
        self._points = tuple(secrets.randbelow(int(pk.q)) for _ in range(rounds))
        self._hints = tuple(tuple(tuple(tuple(polynomial.evaluate(p, x, pk.q) for p in c.components)
                                        for c in column) for column in index.columns) for x in self._points)
        index_body = codec.pack(tuple(x for column in index.columns for c in column for p in c.components for x in p), int(pk.q))
        self._index_digest = hashlib.sha256(index.space.binding+index.epoch+bytes.fromhex(pk.key_id)+index_body).digest()
        self._stage, self._statement, self._request, self._weights = "ready", None, None, None
        self._lock = threading.Lock()

    def freeze_once(self, request, body):
        """Burn ticket, parse/fix complete output, then disclose random weights."""
        self._attempts._burn()
        with self._lock:
            if self._stage != "ready":
                raise RuntimeError("Receiver already consumed or output frozen")
            self._stage = "consumed"
            try:
                _query(request, self.space.binding, self.epoch, self.space.columns, self.pk)
                if request.token_id != self.token_id:
                    raise ValueError("Wrong owner-pinned request ID")
                count = 3*self.space.layout.cost.response_ciphertexts
                values = tuple(int(x) for x in codec.unpack(body, count*self.pk.n, int(self.pk.q)))
                outputs = tuple(values[i*self.pk.n:(i+1)*self.pk.n] for i in range(count))
                statement = batch.freeze(outputs, int(self.pk.q))
                query_body = codec.pack(tuple(x for c in request.ciphertexts for p in c.components for x in p), int(self.pk.q))
                digest = hashlib.sha256(self._index_digest+request.token_id+query_body+bytes.fromhex(statement.digest)).hexdigest()
                weights = batch.challenge(statement, int(self.pk.q), self.rounds, secrets.SystemRandom())
            except (ValueError, TypeError, AttributeError):
                return None
            self._statement, self._request, self._weights = statement, request, weights
            self._stage = "frozen"
            return Challenge(digest, weights)

    def open_once(self, quotient_body, sk):
        with self._lock:
            if self._stage != "frozen":
                raise RuntimeError("Receiver not frozen or already consumed")
            self._stage = "consumed"  # Includes malformed/false quotient attempts.
            pk, q = self.pk, int(self.pk.q)
            try:
                words = codec.unpack(quotient_body, self.rounds*(pk.n-1), q)
                witnesses = tuple(words[i*(pk.n-1):(i+1)*(pk.n-1)] for i in range(self.rounds))
            except (ValueError, TypeError):
                return None
            decisions = []
            for point, hints, beta, witness in zip(self._points, self._hints, self._weights, witnesses, strict=True):
                query = tuple(tuple(polynomial.evaluate(p, point, q) for p in c.components) for c in self._request.ciphertexts)
                expected = []
                for r in range(self.space.layout.cost.response_ciphertexts):
                    expected.extend((sum(column[r][0]*b[0] for column, b in zip(hints, query, strict=True)) % q,
                                     sum(column[r][0]*b[1]+column[r][1]*b[0] for column, b in zip(hints, query, strict=True)) % q,
                                     sum(column[r][1]*b[1] for column, b in zip(hints, query, strict=True)) % q))
                lhs = sum(b*x for b, x in zip(beta, expected, strict=True)) % q
                rhs = (sum(b*polynomial.evaluate(c, point, q) for b, c in zip(beta, self._statement.values, strict=True))
                       + (pow(point, pk.n, q)+1)*polynomial.evaluate(witness, point, q)) % q
                decisions.append(lhs == rhs)
            if not all(decisions):
                return None
            # Only this accepted branch can reach the long-lived HE secret.
            polys = self._statement.values
            ciphertexts = tuple(bgv.Ciphertext(tuple(tuple(mpz(x) for x in row) for row in polys[i:i+3]), pk.key_id, self.bound)
                                for i in range(0, len(polys), 3))
            return tuple(tuple(row) for row in tree.unpack(self.space.layout, [bgv.decrypt(c, pk, sk) for c in ciphertexts]))


def body_cost(index, pk, rounds):
    _context(index, pk)
    if type(rounds) is not int or not 1 <= rounds <= 32:
        raise ValueError("Invalid bounded repetition count")
    n, q, h, r = pk.n, int(pk.q), index.space.columns, index.space.layout.cost.response_ciphertexts
    bits = q.bit_length()
    return {"full_index_coefficient_body_bytes": (2*h*r*n*bits+7)//8,
            "full_query_coefficient_body_bytes": (2*h*n*bits+7)//8,
            "seeded_query_coefficient_and_seed_body_bytes": (h*n*bits+7)//8+32*h,
            "full_three_component_response_body_bytes": (3*r*n*bits+7)//8,
            "batched_quotient_body_bytes": (rounds*(n-1)*bits+7)//8,
            "public_weights_body_bytes": (rounds*3*r*bits+7)//8,
            "one_use_private_hint_and_point_body_bytes_per_request": (rounds*(2*h*r+1)*bits+7)//8,
            "ticket_preparation_coefficient_evaluation_steps": rounds*2*h*r*n,
            "GMP_Karatsuba_ring_products_per_request": 3*h*r,
            "owner_encrypted_answer_preparation_required": False,
            "fresh_private_point_hints_per_request_required": True,
            "extra_public_challenge_round_trips": 1,
            "scope": "Coefficient/seed bodies only; actual query packets measured separately. Bounds/metadata/framing/durability/provisioning transport and security approval excluded."}
