"""E77 seed-conditioned affine packing/checking control, not a reviewed protocol.

Fixed C1 makes every gadget/carry offset query independent. S_j(C0) is linear,
but the offsets still need a fresh trusted computation. The online receiver
is small because a separate trusted factory keeps the large fingerprints.
All such state/work is charged; no deployable provisioning/durability/timing
or novel security proof is supplied. Synthetic zero-C0 inputs are never decrypted.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import secrets
import threading

from gmpy2 import mpz

from experiments.bfv_search_lab import encrypted_query_gate as dense
from experiments.bfv_search_lab import crt_masked_bgv as masked
from experiments.bfv_search_lab import packed_query_expansion as packed
from experiments.bfv_search_lab import verification_lifetime as lifetime


def selection(poly, column, factor, q):
    """Closed-form S_j, independently compared to canonical expansion."""
    if (type(column) is not int or type(factor) is not int or not 0 <= column < factor
            or factor < 1 or factor & (factor - 1) or len(poly) % factor):
        raise ValueError("Invalid coefficient selector")
    return tuple(factor * poly[i + column] % q if i % factor == 0 else mpz(0) for i in range(len(poly)))


def compile_vector(expanded_hints, factor, q):
    """Sum S_j^T Z0_j. Disjoint residues need no field-linear gadget claim."""
    if (type(expanded_hints) is not tuple or not expanded_hints or len(expanded_hints) > factor
            or factor < 1 or factor & (factor - 1)):
        raise ValueError("Invalid expanded fingerprint geometry")
    n = len(expanded_hints[0][0])
    if n % factor or any(len(pair) != 2 or any(len(p) != n for p in pair) for pair in expanded_hints):
        raise ValueError("Invalid expanded fingerprint shape")
    result = [mpz(0)] * n
    for column, (z0, _z1) in enumerate(expanded_hints):
        for i in range(0, n, factor):
            result[i + column] = factor * z0[i] % q
    return tuple(result)


def seed_digest(request, pk):
    width = (int(pk.q).bit_length() + 7) // 8
    return hashlib.sha256(b"cuhepy/research/seed-affine/c1/v1\0" + bytes.fromhex(pk.key_id)
                          + b"".join(int(x).to_bytes(width, "little") for x in request.ciphertext.components[1])).hexdigest()


def offset_query(request, s, pk, keys):
    """Public algebra only: zero C0, fixed C1, same canonical expansion circuit."""
    synthetic = replace(request, ciphertext=replace(request.ciphertext,
                                                     components=((mpz(0),) * pk.n, request.ciphertext.components[1])))
    return packed.expand(synthetic, s, pk, keys)


@dataclass(frozen=True)
class SeedHint:
    owner_binding: str
    token_id: bytes
    c1_digest: str
    constants: tuple[int, ...]


class Factory:
    """Trusted private checker factory, not an untrusted public helper."""

    def __init__(self, index, pk, keys, ids, binding, attempts, *, rounds=4):
        bound = packed.expanded_bound(index.space, pk, keys)
        self._dense = dense.Gate(index, pk, ids, binding, attempts, rounds=rounds, query_phase_bound=bound)
        self.pk, self.space, self.epoch, self.keys = pk, index.space, index.epoch, keys
        self.owner_binding = hashlib.sha256(bytes.fromhex(binding) + self.space.binding + self.epoch
                                             + bytes.fromhex(pk.key_id) + repr(keys).encode()
                                             + secrets.token_bytes(32)).hexdigest()
        self._vectors = tuple(compile_vector(row, keys.factor, pk.q) for row in self._dense._hints)
        self._ids, self._seeds, self._limit, self._lock = set(), set(), attempts.limit, threading.Lock()

    def _validate_original(self, request):
        if (type(request) is not packed.Query or request.space_binding != self.space.binding
                or request.epoch != self.epoch):
            raise ValueError("Wrong seed-affine original query context")
        masked.binding(request.epoch, request.token_id)
        masked.validate_ciphertexts((request.ciphertext,), 1, self.pk)
        if request.ciphertext.phase_bound != self.pk.t // 2 + self.pk.t * self.pk.eta:
            raise ValueError("Expected owner-pinned fresh original bound")

    def prepare_seed(self, request):
        """Consumes a fresh C1; C0 is deliberately not an input to the hint."""
        self._validate_original(request)
        identity = seed_digest(request, self.pk)
        with self._lock:
            if request.token_id in self._ids or identity in self._seeds or len(self._ids) >= self._limit:
                raise RuntimeError("Seed/identifier/factory lifetime consumed")
            self._ids.add(request.token_id)
            self._seeds.add(identity)
        offsets = offset_query(request, self.space, self.pk, self.keys)
        constants = tuple(int(sum(dense._dot(z, c, self.pk.q)
                                  for pair, cipher in zip(row, offsets.ciphertexts, strict=True)
                                  for z, c in zip(pair, cipher.components, strict=True)) % self.pk.q)
                          for row in self._dense._hints)
        return SeedHint(self.owner_binding, request.token_id, identity, constants)


class Receiver:
    """Trusted constructor copies small vectors/challenges, not large factory hints."""

    def __init__(self, factory, attempts):
        if (type(factory) is not Factory or type(attempts) is not lifetime.AttemptBudget
                or attempts is not factory._dense._attempts):
            raise ValueError("Trusted seed factory and shared lifetime required")
        reference = factory._dense
        self.pk, self.space, self.epoch = factory.pk, factory.space, factory.epoch
        self.output_ids, self.owner_binding = reference.output_ids, factory.owner_binding
        self.certificate, self.bound = reference.certificate, reference.bound
        self._rows, self._vectors = reference._rows, factory._vectors
        self._attempts = attempts
        self._issued, self._seeds, self._hints, self._pending, self._lock = set(), set(), {}, {}, threading.Lock()
        # No factory, expansion keys, large expanded fingerprints, index or HE secret retained.

    def register_seed(self, hint):
        # Owner binding identifies a trusted local registration. It is NOT a
        # MAC or permission to take private hints from a remote server.
        if (type(hint) is not SeedHint or hint.owner_binding != self.owner_binding
                or type(hint.c1_digest) is not str or len(hint.c1_digest) != 64
                or set(hint.c1_digest) - set("0123456789abcdef")
                or type(hint.constants) is not tuple or len(hint.constants) != len(self._rows)
                or any(type(x) is not int or not 0 <= x < self.pk.q for x in hint.constants)):
            raise ValueError("Wrong owner-private seed hint")
        masked.binding(self.epoch, hint.token_id)
        with self._lock:
            if hint.token_id in self._issued or hint.c1_digest in self._seeds or len(self._issued) >= self._attempts.limit:
                raise RuntimeError("Seed/identifier/receiver lifetime consumed")
            self._issued.add(hint.token_id)
            self._seeds.add(hint.c1_digest)
            self._hints[hint.token_id] = hint

    def pin_query(self, request):
        if (type(request) is not packed.Query or request.space_binding != self.space.binding
                or request.epoch != self.epoch):
            raise ValueError("Wrong pinned seed-affine original")
        masked.binding(request.epoch, request.token_id)
        masked.validate_ciphertexts((request.ciphertext,), 1, self.pk)
        if request.ciphertext.phase_bound != self.pk.t // 2 + self.pk.t * self.pk.eta:
            raise ValueError("Wrong owner-pinned original bound")
        with self._lock:
            hint = self._hints.pop(request.token_id, None)
            if hint is None or hint.c1_digest != seed_digest(request, self.pk):
                raise RuntimeError("Fresh seed not registered for this original")
            self._pending[request.token_id] = (request, hint)

    def open_body_once(self, token_id, body, sk):
        self._attempts._burn()
        with self._lock:
            saved = self._pending.pop(token_id, None) if type(token_id) is bytes else None
            if saved is None:
                raise RuntimeError("Original seed-affine query not pinned or consumed")
        request, hint = saved
        try:
            reply = dense.parse(body, self.certificate, self.pk)
        except (ValueError, TypeError):
            return None
        decisions = []
        for challenge, vector, constant in zip(self._rows, self._vectors, hint.constants, strict=True):
            expected = (dense._dot(vector, request.ciphertext.components[0], self.pk.q) + constant) % self.pk.q
            supplied = sum(dense._dot(tuple(w0[i] for i in kept), c0, self.pk.q)
                           + dense._dot(w1, c1, self.pk.q) + dense._dot(w2, c2, self.pk.q)
                           for (w0, w1, w2), c0, c1, c2, kept in
                           zip(challenge, reply.c0_supported, reply.c1, reply.c2, self.certificate.kept_c0, strict=True)) % self.pk.q
            decisions.append(expected == supplied)
        if not all(decisions):
            return None
        return dense._decode(reply, self.pk, sk, self.certificate, self.space.layout, self.bound)


def cost(factory, receiver):
    pk, s, count = factory.pk, factory.space, len(receiver._rows)
    n, h, bits = pk.n, s.columns, int(pk.q).bit_length()
    active = n * h // factory.keys.factor
    return {"online_receiver_compiled_vector_body_bytes": (count * n * bits + 7) // 8,
            "online_receiver_possible_active_packed_vector_body_bytes_model": (count * active * bits + 7) // 8,
            "old_expanded_gate_compiled_fingerprint_body_bytes": (count * 2 * h * n * bits + 7) // 8,
            "trusted_factory_retained_expanded_fingerprint_body_bytes": (count * 2 * h * n * bits + 7) // 8,
            "shared_private_challenge_body_bytes": (count * (sum(map(len, receiver.certificate.kept_c0))
                                                            + 2 * n * len(receiver.certificate.kept_c0)) * bits + 7) // 8,
            "private_constants_per_fresh_seed_body_bytes": (count * bits + 7) // 8,
            "original_pending_c0_coefficient_body_bytes": (n * bits + 7) // 8,
            "seed_hint_requires_trusted_full_canonical_expansion": True,
            "factory_seed_hint_field_products": count * 2 * h * n,
            "receiver_input_field_products_per_query": count * n,
            "scope": "Body models, not RSS. Receiver currently stores full vectors and original ciphertexts. IDs, C1 digest, original C1/public key and seed/replay sets also retained. Factory challenge/vector storage shares objects locally but no helper role is free."}
